FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY --chown=app:app app.py /app/app.py
COPY --chown=app:app static /app/static
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request; r=urllib.request.Request('http://127.0.0.1:8080/healthz',headers={'Host':__import__('os').environ.get('BASE_DOMAIN','ctrl.example.com')}); urllib.request.urlopen(r,timeout=3)" || exit 1
CMD ["python", "app.py"]
