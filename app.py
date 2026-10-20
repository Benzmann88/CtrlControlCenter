import asyncio, hashlib, hmac, ipaddress, json, logging, os, re, secrets, socket, sqlite3, time
from contextlib import closing
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import aiohttp
from aiohttp import web

BASE = os.getenv('BASE_DOMAIN', 'ctrl.example.com').lower()
SCHEME = os.getenv('PUBLIC_SCHEME', 'https')
TILE_PARENT = os.getenv('TILE_PARENT_DOMAIN', '').lower().strip('.')
def tile_host(sid):
    return f'ctrl-{sid}.{TILE_PARENT}' if TILE_PARENT else f'{sid}.{BASE}'
def tile_sid(h):
    if TILE_PARENT:
        m = re.fullmatch(r'ctrl-([a-f0-9]{16})\.' + re.escape(TILE_PARENT), h)
    else:
        m = re.fullmatch(r'([a-f0-9]{16})\.' + re.escape(BASE), h)
    return m.group(1) if m else None
DB = os.getenv('DB_PATH', '/data/styringar.db')
COOKIE = '__Host-styringar' if SCHEME == 'https' else 'styringar'
PROXY_COOKIE = '__Host-styringar_proxy' if SCHEME == 'https' else 'styringar_proxy'
TTL = 8 * 3600
HOP = {'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','content-length'}
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('styringar')

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def password_hash(p, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(p.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def verify(p, stored):
    return hmac.compare_digest(password_hash(p, stored.split(':')[0]), stored)

def token_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()

def audit(c, uid, action, detail=''):
    c.execute('INSERT INTO audit(uid,action,detail,created) VALUES(?,?,?,?)', (uid,action,detail[:500],int(time.time())))

def init_db():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    with closing(db()) as c, c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS approved_destinations(host TEXT NOT NULL,port INTEGER NOT NULL,allow_private INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(host,port));
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL,scope TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tickets(token TEXT PRIMARY KEY,uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,site TEXT NOT NULL,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sites(id TEXT PRIMARY KEY,uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,target TEXT NOT NULL,category TEXT NOT NULL DEFAULT 'General',color TEXT NOT NULL DEFAULT '#6d8dff');
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,uid INTEGER,action TEXT,detail TEXT,created INTEGER);
        ''')
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            pw = os.getenv('ADMIN_PASSWORD','')
            if len(pw) < 14:
                raise RuntimeError('First startup requires ADMIN_PASSWORD with at least 14 characters. No default password exists.')
            c.execute('INSERT INTO users(username,password,admin) VALUES(?,?,1)', (os.getenv('ADMIN_USERNAME','admin'),password_hash(pw)))
            audit(c, None, 'bootstrap')
    # ctrl-branding-migration-v1
    # One-time migration; future GUI renames remain possible.
    with closing(db()) as c,c:
        if not c.execute("SELECT 1 FROM settings WHERE key=?", ("ctrl_branding_v1",)).fetchone():
            c.execute("INSERT INTO settings(key,value) VALUES('portal_name','CTRL') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            c.execute("INSERT INTO settings(key,value) VALUES('ctrl_branding_v1','done')")
    # gui-destinations-v1
    with closing(db()) as c,c:
        if not c.execute("SELECT 1 FROM settings WHERE key=?", ("gui_destinations_v1",)).fetchone():
            for item in os.getenv('ALLOWED_TARGETS','').split(','):
                item=item.strip().lower()
                if not item: continue
                try:
                    parsed=urlsplit('http://'+item)
                    if parsed.hostname and parsed.port:
                        c.execute('INSERT OR IGNORE INTO approved_destinations VALUES(?,?,?)',(parsed.hostname,parsed.port,int(os.getenv('ALLOW_PRIVATE_TARGETS','false').lower()=='true')))
                except ValueError: pass
            c.execute("INSERT INTO settings VALUES('gui_destinations_v1','done')")
    # shared-tiles-v1
    with closing(db()) as c,c:
        if 'shared' not in {r['name'] for r in c.execute('PRAGMA table_info(sites)')}:
            c.execute('ALTER TABLE sites ADD COLUMN shared INTEGER NOT NULL DEFAULT 0')
    os.chmod(DB, 0o600)

def host(req):
    return req.host.lower().split(':')[0]

def user(req, scope='portal'):
    cookie = COOKIE if scope == 'portal' else PROXY_COOKIE
    t = req.cookies.get(cookie,'')
    with closing(db()) as c:
        return c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE s.token=? AND s.scope=? AND s.expires>? AND u.active=1', (token_hash(t),scope,int(time.time()))).fetchone()

def require(req, admin=False):
    u = user(req)
    if not u: raise web.HTTPUnauthorized(text='Please sign in.')
    if admin and not u['admin']: raise web.HTTPForbidden(text='Administrator access required.')
    return u

def cookie_set(resp, name, value):
    resp.set_cookie(name,value,max_age=TTL,secure=SCHEME=='https',httponly=True,samesite='Strict',path='/')

def new_session(c, uid, scope):
    t = secrets.token_urlsafe(32)
    c.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
    c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(token_hash(t),uid,int(time.time())+TTL,scope))
    return t

def destination_policy(hostname,port):
    with closing(db()) as c:
        row=c.execute('SELECT allow_private FROM approved_destinations WHERE host=? AND port=?',(hostname.lower(),port)).fetchone()
    return None if row is None else bool(row['allow_private'])

def validate_address(ip,allow_private):
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise ValueError('Loopback, link-local, unspecified, multicast and reserved addresses are blocked.')
    if not ip.is_global and not allow_private:
        raise ValueError('Private destination: an administrator must approve private-network access in the GUI.')

def clean_target(raw,require_approved=True):
    raw=raw.strip()
    if '://' not in raw: raw='http://'+raw
    p=urlsplit(raw)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('','/'):
        raise ValueError('Use an HTTP(S) origin or IP:port, without credentials, paths, query or fragment.')
    hostname=p.hostname.lower()
    if not re.fullmatch(r'[a-z0-9.-]+',hostname): raise ValueError('Use an IPv4 address or DNS hostname.')
    port=p.port if p.port is not None else (443 if p.scheme=='https' else 80)
    if not 1 <= port <= 65535: raise ValueError('Invalid port.')
    private=destination_policy(hostname,port) if require_approved else False
    if require_approved and private is None:
        raise ValueError('Destination not approved. An administrator can approve it in Add site or Destinations.')
    try: ip=ipaddress.ip_address(hostname)
    except ValueError: ip=None
    if ip: validate_address(ip,private if require_approved else True)
    return f'{p.scheme}://{hostname}:{port}'

def approve_destination(raw,allow_private):
    target=clean_target(raw,require_approved=False)
    p=urlsplit(target)
    try: ip=ipaddress.ip_address(p.hostname)
    except ValueError: ip=None
    if ip: validate_address(ip,allow_private)
    with closing(db()) as c,c:
        c.execute('INSERT INTO approved_destinations VALUES(?,?,?) ON CONFLICT(host,port) DO UPDATE SET allow_private=excluded.allow_private',(p.hostname,p.port,int(allow_private)))
    return target

class PinnedResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, hostname, port=0, family=socket.AF_INET):
        loop = asyncio.get_running_loop()
        entries = await loop.getaddrinfo(hostname,port,type=socket.SOCK_STREAM,family=socket.AF_INET)
        private = destination_policy(hostname,port)
        if private is None: raise OSError('Destination approval revoked.')
        result=[]
        for _,_,_,_,addr in entries:
            ip=ipaddress.ip_address(addr[0])
            try: validate_address(ip,private)
            except ValueError as e: raise OSError(str(e)) from e
            result.append({'hostname':hostname,'host':addr[0],'port':port,'family':socket.AF_INET,'proto':0,'flags':0})
        return result
    async def close(self): pass

@web.middleware
async def security(req, handler):
    h = host(req)
    if h != BASE and not tile_sid(h):
        raise web.HTTPMisdirectedRequest()
    if h == BASE and req.path.startswith('/api/') and req.method not in ('GET','HEAD','OPTIONS'):
        if req.headers.get('Origin') != f'{SCHEME}://{BASE}':
            raise web.HTTPForbidden(text='Invalid request origin.')
    try:
        resp=await handler(req)
    except (ValueError,KeyError,TypeError) as e:
        resp=web.json_response({'error':str(e)},status=400)
    except web.HTTPException as e:
        resp=e
    if h==BASE:
        resp.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        resp.headers['X-Frame-Options']='DENY'
        resp.headers['X-Content-Type-Options']='nosniff'
        resp.headers['Referrer-Policy']='no-referrer'
        resp.headers['Cache-Control']='no-store'
    return resp

async def api(req):
    action=req.match_info['action']
    method=req.method
    # branding-settings-v1
    if action=='branding':
        if method=='GET':
            with closing(db()) as c:
                row=c.execute("SELECT value FROM settings WHERE key='portal_name'").fetchone()
            return web.json_response({'portal_name':row['value'] if row else 'CTRL'})
        if method=='POST':
            admin=require(req,admin=True)
            data=await req.json()
            name=data.get('portal_name')
            if not isinstance(name,str):
                raise ValueError('Portal name must be text.')
            name=name.strip()
            if not 1 <= len(name) <= 60 or any(ord(ch)<32 or ord(ch)==127 for ch in name):
                raise ValueError('Use 1-60 characters without control characters.')
            with closing(db()) as c,c:
                c.execute("INSERT INTO settings(key,value) VALUES('portal_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(name,))
                audit(c,admin['id'],'portal_renamed',name)
            return web.json_response({'portal_name':name})
        raise web.HTTPMethodNotAllowed(method,['GET','POST'])
    if action=='login' and method=='POST':
        data=await req.json()
        name=str(data.get('username',''))[:80]
        now=time.time()
        # Global + username throttles do not trust spoofable forwarding headers.
        buckets=req.app['attempts']
        keys=['global','user:'+name.lower()]
        for k in keys: buckets[k]=[t for t in buckets.get(k,[]) if now-t<900]
        if len(buckets['global'])>=100 or len(buckets[keys[1]])>=10:
            raise web.HTTPTooManyRequests(text='Too many login attempts. Try again later.')
        for k in keys: buckets[k].append(now)
        with closing(db()) as c,c:
            u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(name,)).fetchone()
            stored=u['password'] if u else req.app['dummy_hash']
            ok=await asyncio.to_thread(verify,str(data.get('password',''))[:1024],stored)
            if not ok or not u:
                audit(c,None,'login_failed',name)
                c.commit()
                raise web.HTTPUnauthorized(text='Invalid username or password.')
            t=new_session(c,u['id'],'portal'); audit(c,u['id'],'login')
        r=web.json_response({'ok':True}); cookie_set(r,COOKIE,t); return r
    u=require(req,action in ('users','audit'))
    if action=='me' and method=='GET':
        return web.json_response({'username':u['username'],'admin':bool(u['admin']),'domain':BASE})
    if action=='logout' and method=='POST':
        with closing(db()) as c,c:
            # Revoke portal and site sessions together.
            c.execute('DELETE FROM sessions WHERE uid=?',(u['id'],)); c.execute('DELETE FROM tickets WHERE uid=?',(u['id'],))
        r=web.json_response({'ok':True}); r.del_cookie(COOKIE,path='/'); return r
    if action=='password' and method=='POST':
        d=await req.json()
        if not verify(str(d.get('current','')),u['password']): raise web.HTTPForbidden(text='Current password is incorrect.')
        if len(str(d.get('password','')))<14: raise ValueError('Password must have at least 14 characters.')
        with closing(db()) as c,c:
            c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(d['password']),u['id']))
            c.execute('DELETE FROM sessions WHERE uid=?',(u['id'],)); c.execute('DELETE FROM tickets WHERE uid=?',(u['id'],)); audit(c,u['id'],'password_changed')
        return web.json_response({'ok':True})
    if action=='destinations':
        admin=require(req,admin=True)
        with closing(db()) as c:
            if method=='GET':
                return web.json_response([dict(x) for x in c.execute('SELECT host,port,allow_private FROM approved_destinations ORDER BY host,port')])
        d=await req.json()
        if method=='POST':
            target=approve_destination(str(d.get('target','')),d.get('allow_private') is True)
            with closing(db()) as c,c: audit(c,admin['id'],'destination_approved',target)
            return web.json_response({'ok':True})
        if method=='DELETE':
            with closing(db()) as c,c:
                c.execute('DELETE FROM approved_destinations WHERE host=? AND port=?',(str(d.get('host','')).lower(),int(d['port'])))
                audit(c,admin['id'],'destination_revoked',str(d.get('host',''))+':'+str(d['port']))
            return web.json_response({'ok':True})
        raise web.HTTPMethodNotAllowed(method,['GET','POST','DELETE'])
    if action=='sites':
        if method=='POST':
            payload=await req.json()
            if payload.get('approve_destination') is True:
                require(req,admin=True)
                target=approve_destination(str(payload.get('target','')),payload.get('allow_private') is True)
                with closing(db()) as approval_db,approval_db: audit(approval_db,u['id'],'destination_approved',target)
        with closing(db()) as c,c:
            if method=='GET':
                return web.json_response([dict(s) for s in c.execute('SELECT s.id,s.name,s.target,s.category,s.color,s.shared,(s.uid=?) AS can_manage FROM sites s JOIN users owner ON owner.id=s.uid WHERE owner.active=1 AND (s.uid=? OR s.shared=1) ORDER BY s.category,s.name',(u['id'],u['id']))])
            d=await req.json()
            if method=='POST':
                target=clean_target(str(d.get('target','')))
                name=str(d.get('name','')).strip()[:100]
                if not name: raise ValueError('A tile name is required.')
                color=str(d.get('color','#6d8dff'))
                if not re.fullmatch('#[a-fA-F0-9]{6}',color): raise ValueError('Invalid color.')
                sid=secrets.token_hex(8)
                c.execute('INSERT INTO sites(id,uid,name,target,category,color,shared) VALUES(?,?,?,?,?,?,?)',(sid,u['id'],name,target,str(d.get('category','General'))[:60] or 'General',color,int(d.get('shared') is True)))
                audit(c,u['id'],'site_added',sid)
                return web.json_response({'ok':True},status=201)
            if method=='PATCH':
                sid=str(d.get('id',''))
                if not c.execute('SELECT 1 FROM sites WHERE id=? AND uid=?',(sid,u['id'])).fetchone():
                    raise web.HTTPForbidden(text='Only the tile owner can change sharing.')
                if not isinstance(d.get('shared'),bool): raise ValueError('Shared must be true or false.')
                c.execute('UPDATE sites SET shared=? WHERE id=?',(int(d['shared']),sid))
                # Invalidate old launch tickets and all site sessions on a sharing change.
                c.execute('DELETE FROM tickets WHERE site=?',(sid,))
                c.execute('DELETE FROM sessions WHERE scope=?',('site:'+sid,))
                audit(c,u['id'],'site_sharing_changed',sid+':'+str(d['shared']))
                return web.json_response({'ok':True})
            if method=='DELETE':
                c.execute('DELETE FROM sites WHERE id=? AND uid=?',(str(d.get('id','')),u['id']))
                audit(c,u['id'],'site_deleted',str(d.get('id','')))
                return web.json_response({'ok':True})
    if action=='users':
        with closing(db()) as c,c:
            if method=='GET': return web.json_response([dict(x) for x in c.execute('SELECT id,username,admin,active FROM users ORDER BY username')])
            d=await req.json()
            if method=='POST':
                name=str(d.get('username','')).strip()
                if not re.fullmatch(r'[a-zA-Z0-9_.@-]{2,80}',name): raise ValueError('Username must be 2-80 letters, digits, dots, @, underscores or hyphens.')
                if len(str(d.get('password','')))<14: raise ValueError('Password must have at least 14 characters.')
                try: c.execute('INSERT INTO users(username,password,admin) VALUES(?,?,?)',(name,password_hash(d['password']),int(bool(d.get('admin')))))
                except sqlite3.IntegrityError: raise ValueError('Username already exists.')
                audit(c,u['id'],'user_created',name)
                return web.json_response({'ok':True},status=201)
            if method=='PATCH':
                uid=int(d['id'])
                if uid==u['id']: raise ValueError('Use Change password for your own account. You cannot disable yourself.')
                if 'password' in d:
                    if len(str(d['password']))<14: raise ValueError('Password must have at least 14 characters.')
                    c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(d['password']),uid))
                if 'active' in d: c.execute('UPDATE users SET active=? WHERE id=?',(int(bool(d['active'])),uid))
                c.execute('DELETE FROM sessions WHERE uid=?',(uid,)); c.execute('DELETE FROM tickets WHERE uid=?',(uid,))
                audit(c,u['id'],'user_updated',str(uid)); return web.json_response({'ok':True})
    if action=='audit' and method=='GET':
        with closing(db()) as c:
            return web.json_response([dict(x) for x in c.execute('SELECT a.created,u.username,a.action,a.detail FROM audit a LEFT JOIN users u ON u.id=a.uid ORDER BY a.id DESC LIMIT 100')])
    raise web.HTTPNotFound()

def site_access(sid,uid):
    with closing(db()) as c:
        return bool(c.execute('SELECT 1 FROM sites s JOIN users owner ON owner.id=s.uid WHERE s.id=? AND owner.active=1 AND (s.uid=? OR s.shared=1)',(sid,uid)).fetchone())

async def launch(req):
    u=require(req)
    sid=req.match_info['sid']
    with closing(db()) as c,c:
        s=c.execute('SELECT s.* FROM sites s JOIN users owner ON owner.id=s.uid WHERE s.id=? AND owner.active=1 AND (s.uid=? OR s.shared=1)',(sid,u['id'])).fetchone()
        if not s: raise web.HTTPNotFound()
        t=secrets.token_urlsafe(32)
        c.execute('DELETE FROM tickets WHERE expires<?',(int(time.time()),))
        c.execute('INSERT INTO tickets VALUES(?,?,?,?)',(token_hash(t),u['id'],sid,int(time.time())+30))
        audit(c,u['id'],'site_opened',sid)
    raise web.HTTPFound(f'{SCHEME}://{tile_host(sid)}/__styringar_auth?ticket={t}')

async def proxy(req):
    sid=tile_sid(host(req))
    scope='site:'+sid
    with closing(db()) as c,c:
        s=c.execute('SELECT * FROM sites WHERE id=?',(sid,)).fetchone()
        if not s: raise web.HTTPNotFound()
        if req.path=='/__styringar_auth':
            t=req.query.get('ticket','')
            row=c.execute('SELECT t.* FROM tickets t JOIN users u ON u.id=t.uid WHERE t.token=? AND t.site=? AND t.expires>? AND u.active=1',(token_hash(t),sid,int(time.time()))).fetchone()
            if not row or not site_access(sid,row['uid']): raise web.HTTPForbidden(text='Launch this tile from the dashboard.')
            c.execute('DELETE FROM tickets WHERE token=?',(token_hash(t),))
            tok=new_session(c,row['uid'],scope)
            r=web.HTTPFound('/'); cookie_set(r,PROXY_COOKIE,tok)
            r.headers['Referrer-Policy']='no-referrer'; r.headers['Cache-Control']='no-store'; return r
    u=user(req,scope)
    if not u or not site_access(sid,u['id']):
        return web.Response(status=401,text='Session expired. Open this tile again from the CTRL dashboard.')
    try: target=clean_target(s['target'])
    except ValueError: raise web.HTTPForbidden(text='This destination is no longer approved.')
    upstream=target+req.rel_url.raw_path_qs
    headers={k:v for k,v in req.headers.items() if k.lower() not in HOP|{'host','cookie','authorization','forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','accept-encoding'}}
    # Device Authorization headers are allowed; portal auth uses cookies only.
    if req.headers.get('Authorization'): headers['Authorization']=req.headers['Authorization']
    cookies=SimpleCookie()
    for k,v in req.cookies.items():
        if k not in (COOKIE,PROXY_COOKIE): cookies[k]=v
    if cookies: headers['Cookie']='; '.join(m.OutputString() for m in cookies.values())
    headers['Accept-Encoding']='identity'
    headers['Host']=urlsplit(target).netloc
    headers['X-Forwarded-Proto']=SCHEME
    headers['X-Forwarded-Host']=host(req)
    public=f'{SCHEME}://{host(req)}'
    if headers.get('Origin')==public: headers['Origin']=target
    if headers.get('Referer','').startswith(public+'/'): headers['Referer']=target+headers['Referer'][len(public):]
    client=req.app['client']
    try:
        if req.headers.get('Upgrade','').lower()=='websocket':
            async with client.ws_connect(upstream,headers=headers,protocols=[x.strip() for x in req.headers.get('Sec-WebSocket-Protocol','').split(',') if x.strip()],autoping=True) as remote:
                ws=web.WebSocketResponse(protocols=[remote.protocol] if remote.protocol else [],max_msg_size=16*1024*1024)
                await ws.prepare(req)
                async def relay(src,dst):
                    async for m in src:
                        # Re-check access for long-lived connections.
                        if not user(req,scope) or not site_access(sid,u['id']): break
                        if m.type==aiohttp.WSMsgType.TEXT: await dst.send_str(m.data)
                        elif m.type==aiohttp.WSMsgType.BINARY: await dst.send_bytes(m.data)
                        elif m.type in (aiohttp.WSMsgType.CLOSE,aiohttp.WSMsgType.ERROR): break
                tasks=[asyncio.create_task(relay(ws,remote)),asyncio.create_task(relay(remote,ws))]
                try: await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks: task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
                    await ws.close()
                return ws
        async with client.request(req.method,upstream,headers=headers,data=req.content,allow_redirects=False) as remote:
            r=web.StreamResponse(status=remote.status)
            for k,v in remote.headers.items():
                if k.lower() not in HOP|{'set-cookie','location','strict-transport-security','clear-site-data','alt-svc'}:
                    r.headers.add(k,v)
            if 'Location' in remote.headers:
                loc=remote.headers['Location']; parsed=urlsplit(loc)
                if loc.startswith(target+'/') or loc==target: loc=public+loc[len(target):]
                elif parsed.netloc and parsed.netloc==urlsplit(target).netloc:
                    loc=urlunsplit((SCHEME,host(req),parsed.path,parsed.query,parsed.fragment))
                elif parsed.netloc:
                    raise web.HTTPBadGateway(text='Upstream redirects to another origin. Configure its public/base URL to this tile hostname.')
                r.headers['Location']=loc
            for value in remote.headers.getall('Set-Cookie',[]):
                jar=SimpleCookie(); jar.load(value)
                for key,m in jar.items():
                    if key in (COOKIE,PROXY_COOKIE): continue
                    m['domain']=''  # Never allow upstream cookies to cover the portal or sibling sites.
                    if SCHEME=='https': m['secure']=True
                    r.headers.add('Set-Cookie',m.OutputString())
            await r.prepare(req)
            async for chunk in remote.content.iter_chunked(65536): await r.write(chunk)
            await r.write_eof(); return r
    except (aiohttp.ClientError,asyncio.TimeoutError,OSError) as e:
        log.warning('Upstream failed for site %s: %s',sid,type(e).__name__)
        raise web.HTTPBadGateway(text='Remote site unavailable. Check port forwarding, source-IP allowlist, destination approval and TLS certificate.')

async def route(req):
    if host(req)!=BASE: return await proxy(req)
    if req.path=='/healthz': return web.json_response({'status':'ok'})
    if req.path.startswith('/api/'): return await api(req)
    if req.path.startswith('/open/'): return await launch(req)
    if req.path in ('/','/app.js','/style.css'):
        name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[req.path]
        return web.FileResponse(Path(__file__).parent/'static'/name)
    raise web.HTTPNotFound()

async def startup(app):
    init_db()
    app['attempts']={}; app['dummy_hash']=password_hash(secrets.token_hex(24))
    app['client']=aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=PinnedResolver(),use_dns_cache=False),cookie_jar=aiohttp.DummyCookieJar(),timeout=aiohttp.ClientTimeout(total=None,connect=15,sock_read=120),auto_decompress=False)

async def cleanup(app): await app['client'].close()

def create_app():
    app=web.Application(middlewares=[security],client_max_size=64*1024*1024)
    app.router.add_route('*','/api/{action}',route)
    app.router.add_route('GET','/open/{sid}',route)
    app.router.add_route('*','/{tail:.*}',route)
    app.on_startup.append(startup); app.on_cleanup.append(cleanup)
    return app

if __name__=='__main__': web.run_app(create_app(),host='0.0.0.0',port=8080,access_log=None)
