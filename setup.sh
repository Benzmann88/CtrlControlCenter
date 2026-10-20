#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -e .env ]; then
  echo '.env already exists; leaving it unchanged.'
  exit 0
fi
umask 077
cp .env.example .env
PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
sed -i "s/^ADMIN_PASSWORD=$/ADMIN_PASSWORD=$PASSWORD/" .env
printf '\nCreated .env with a random bootstrap password.\nRead it with: cat .env\nSet ALLOWED_TARGETS and confirm BIND_IP before starting.\n'
