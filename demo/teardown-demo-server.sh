#!/usr/bin/env bash
# Undo setup-demo-server.sh on a throwaway VM (best effort). Destroying the VM
# is cleaner; this is for when you want the box back without a rebuild.
#   sudo bash demo/teardown-demo-server.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
for svc in nginx apache2 haproxy mariadb postgresql; do
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
done
apt-get purge -y -qq nginx 'nginx-*' apache2 'apache2-*' haproxy \
    mariadb-server 'mariadb-*' postgresql 'postgresql-*' >/dev/null 2>&1 || true
apt-get autoremove -y -qq >/dev/null 2>&1 || true

rm -rf /var/www/acme-crm.pl /var/www/sklep-kowalski.pl /opt/acme
rm -f /etc/nginx/sites-enabled/acme-crm.pl /etc/nginx/sites-available/acme-crm.pl
hostnamectl set-hostname localhost 2>/dev/null || true
printf '127.0.0.1\tlocalhost\n' > /etc/hosts

echo "Demo artifacts removed. (The proxy repo + its .venv are left intact.)"
