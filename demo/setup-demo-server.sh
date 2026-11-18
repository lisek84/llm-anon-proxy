#!/usr/bin/env bash
# =============================================================================
# llm-anon-proxy — DEMO server provisioner
#
# Stands up a realistic-looking Ubuntu server (nginx + apache + haproxy + MySQL
# + PostgreSQL) populated with FAKE but realistic sensitive data: internal
# hostnames/IPs, DB passwords, API tokens, a Slack webhook, and customer records
# with Polish PESEL/NIP/REGON numbers. Then you run the proxy with the ready
# demo dictionary and watch it all get anonymized.
#
#   ⚠  RUN ONLY ON A THROWAWAY UBUNTU VM. It installs packages, sets the
#      hostname, rewrites /etc/hosts and writes fake secrets under /var/www,
#      /opt and /etc. Destroy the VM when you're done.
#
#   sudo bash demo/setup-demo-server.sh
#   bash demo/run-demo.sh            # then watch the anonymization
# =============================================================================
set -uo pipefail   # intentionally NOT -e: best-effort, continue past a flaky service

if [ "$(id -u)" != 0 ]; then
    echo "Run with sudo:  sudo bash demo/setup-demo-server.sh" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_USER="${SUDO_USER:-root}"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

cat <<'BANNER'
-----------------------------------------------------------------------------
 This provisions a THROWAWAY demo server with FAKE sensitive data.
 Do NOT run it on a machine you care about. Ctrl-C now to abort.
-----------------------------------------------------------------------------
BANNER
sleep 3

# ── 1. packages (best effort — the demo reads planted files regardless) ───────
say "Installing services (nginx, apache, haproxy, mariadb, postgresql) — best effort"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || true
apt-get install -y -qq nginx apache2 haproxy mariadb-server postgresql \
                       python3-venv git curl >/dev/null 2>&1 \
    || echo "   (some packages failed to install — the file-based demo still works)"

# ── 2. identity: hostname + internal hosts ────────────────────────────────────
say "Setting hostname and /etc/hosts (internal network 10.14.8.0/24)"
hostnamectl set-hostname acme-prod-01 2>/dev/null || hostname acme-prod-01 2>/dev/null || true
cat > /etc/hosts <<'EOF'
127.0.0.1       localhost acme-prod-01
10.14.8.10      acme-prod-01
10.14.8.11      web-fra-01
10.14.8.12      db-prod-01
10.14.8.13      cache-redis-01
10.14.8.20      backup-node-07
10.14.8.1       edge-gw-fra1
fd00:14:8::20   backup-node-07
185.12.34.56    edge-public
EOF

# ── 3. secrets assembled from parts (so this committed script holds no literal
#       token; the FILES written on the VM get the full value) ────────────────
GH="ghp_"; SKL="sk_""live_"; AKIA="AKIA"; XOXB="xoxb-"
GH_TOK="${GH}DEMOdemoDEMOdemoDEMOdemoDEMOdemo0000"
STRIPE="${SKL}DEMOfake0123456789abcdefDEMOfa"
AWS="${AKIA}IOSFODNN7EXAMPLE"
SLACK="https://hooks.slack.com/services/T0ACMEDEMO/B0ACMEDEMO/Zx9kLmDEMOwErTyUiOp12"
BEARER="Bearer demoDEMO0123456789abcdefABCDEF0123"

say "Writing web roots and secrets under /var/www and /opt/acme"
mkdir -p /var/www/acme-crm.pl /var/www/sklep-kowalski.pl /opt/acme/deploy /opt/acme/demo

cat > /var/www/acme-crm.pl/.env <<EOF
APP_URL=https://acme-crm.pl
APP_ENV=production
DB_HOST=db-prod-01
DB_NAME=acme_crm
DB_USER=acme_app
DB_PASSWORD=Pg_s3cr3t!2024
REDIS_URL=redis://cache-redis-01:6379/0
ADMIN_EMAIL=admin@acme-crm.pl
GITHUB_TOKEN=${GH_TOK}
STRIPE_SECRET_KEY=${STRIPE}
AWS_ACCESS_KEY_ID=${AWS}
SLACK_WEBHOOK_URL=${SLACK}
EOF

cat > /var/www/sklep-kowalski.pl/wp-config.php <<'EOF'
<?php
define( 'DB_NAME', 'shop_kowalski' );
define( 'DB_USER', 'wpadmin' );
define( 'DB_PASSWORD', 'wpP4ss_x1!' );
define( 'DB_HOST', 'db-prod-01' );
define( 'WP_SITEURL', 'https://sklep-kowalski.pl' );
define( 'WP_HOME', 'https://www.sklep-kowalski.pl' );
EOF

cat > /opt/acme/deploy/secrets.yml <<EOF
deploy_user: deploy_bot
ssh_target: backup-node-07
slack_webhook: ${SLACK}
api_authorization: ${BEARER}
backup_host: backup-node-07
backup_ipv6: fd00:14:8::20
EOF

cat > /etc/haproxy/haproxy.cfg <<'EOF'
global
    stats socket /run/haproxy/admin.sock mode 660
    maxconn 4096
defaults
    mode http
    timeout connect 5s
    timeout client  30s
    timeout server  30s
frontend public_in
    bind *:80
    default_backend web_pool
backend web_pool
    stats auth pgadmin:Haproxy_St4ts!
    server web-fra-01 10.14.8.11:8080 check
    server db-prod-01 10.14.8.12:8081 check backup
    server mysql-bkp 10.14.8.20:3306 check backup
EOF

# nginx + apache vhosts (so the box feels real; services started below)
cat > /etc/nginx/sites-available/acme-crm.pl <<'EOF'
server {
    listen 8080;
    server_name acme-crm.pl www.acme-crm.pl status.acme-crm.pl;
    root /var/www/acme-crm.pl;
    location / { proxy_pass http://10.14.8.11:9000; }
}
EOF
ln -sf /etc/nginx/sites-available/acme-crm.pl /etc/nginx/sites-enabled/acme-crm.pl 2>/dev/null || true

# ── 4. customer records with Polish IDs (PESEL/NIP/REGON) — a DB dump that the
#       demo feeds to the proxy. All IDs below are VALID by checksum. ──────────
say "Writing customer records (PESEL / NIP / REGON) dump"
cat > /opt/acme/demo/customers_dump.sql <<'EOF'
-- MySQL dump: acme_crm.customers  (fake data for the demo)
INSERT INTO customers (name, email, phone, pesel, nip) VALUES
 ('Jan Kowalski',   'jan.kowalski@sniadanie.com', '+48 601 234 567', '93022751939', '3263222811'),
 ('Anna Nowak',     'anna.nowak@acme-crm.pl',     '+48 602 345 678', '76020802692', '3864512761'),
 ('Piotr Wiśniewski','p.wisniewski@acme-crm.pl',  '+48 603 456 789', '45070146515', NULL);
-- company: Kowalski i Wspólnicy sp.k., REGON 959938258 (14-digit: 27545051494994)
EOF

# ── 5. seed the real databases too (best effort) ─────────────────────────────
say "Seeding MySQL + PostgreSQL (best effort)"
mysql -u root 2>/dev/null <<'SQL' && echo "   MySQL seeded" || echo "   (MySQL seed skipped)"
CREATE DATABASE IF NOT EXISTS acme_crm;
USE acme_crm;
CREATE TABLE IF NOT EXISTS customers (id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80), email VARCHAR(120), phone VARCHAR(20), pesel CHAR(11), nip CHAR(10));
INSERT INTO customers (name,email,phone,pesel,nip) VALUES
 ('Jan Kowalski','jan.kowalski@sniadanie.com','+48 601 234 567','93022751939','3263222811');
SQL
sudo -u postgres psql 2>/dev/null <<'SQL' && echo "   PostgreSQL seeded" || echo "   (PostgreSQL seed skipped)"
CREATE ROLE pgadmin LOGIN PASSWORD 'Pg_s3cr3t!2024';
CREATE DATABASE acme_billing OWNER pgadmin;
SQL

# ── 6. start services (best effort) ──────────────────────────────────────────
for svc in nginx apache2 haproxy mariadb postgresql; do
    systemctl enable --now "$svc" >/dev/null 2>&1 || true
done

# ── 7. a single readable "admin session" the demo feeds to the proxy ─────────
say "Assembling the demo input a real admin session would send to Claude"
{
  echo "### SSH ops session captured from acme-prod-01 (10.14.8.10) ###"
  echo
  echo "\$ ssh deploy_bot@backup-node-07   # 10.14.8.20 / fd00:14:8::20"
  echo "\$ cat /var/www/acme-crm.pl/.env"
  cat /var/www/acme-crm.pl/.env
  echo
  echo "\$ cat /opt/acme/deploy/secrets.yml"
  cat /opt/acme/deploy/secrets.yml
  echo
  echo "\$ grep -E 'server|auth' /etc/haproxy/haproxy.cfg"
  grep -E 'server |stats auth' /etc/haproxy/haproxy.cfg
  echo
  echo "\$ mysql acme_crm -e 'select * from customers'   # customer PII"
  cat /opt/acme/demo/customers_dump.sql
} > /opt/acme/demo/admin-session.txt
chown "$DEMO_USER":"$DEMO_USER" /opt/acme/demo/admin-session.txt 2>/dev/null || true
chmod 0644 /opt/acme/demo/admin-session.txt

# ── 8. make sure the proxy's venv exists (owned by the demo user) ────────────
if [ ! -x "$REPO_DIR/.venv/bin/python" ]; then
    say "Setting up the proxy (.venv) via scripts/setup-proxy.sh"
    sudo -u "$DEMO_USER" bash "$REPO_DIR/scripts/setup-proxy.sh" || \
        echo "   (setup-proxy.sh failed — run it manually: bash scripts/setup-proxy.sh)"
fi

cat <<EOF

==> Demo server ready.  Hostname: acme-prod-01

Now watch llm-anon-proxy anonymize it (nothing leaves the machine):

    bash demo/run-demo.sh            # dictionary + regex + checksum layers
    bash demo/run-demo.sh --llm      # also the local Ollama contextual layer

Explore what was planted:
    cat /var/www/acme-crm.pl/.env
    cat /opt/acme/deploy/secrets.yml
    cat /opt/acme/demo/customers_dump.sql

When done, just destroy the VM (or: sudo bash demo/teardown-demo-server.sh).
EOF
