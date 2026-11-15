#!/usr/bin/env bash
# Create a dedicated OS user to run the proxy, so the Claude Code agent (running
# as YOUR user) cannot read the vault / dictionary / secret key.
#
# REVIEW before running. It uses sudo. It does NOT start anything.
#
#   sudo bash scripts/setup-isolated-user.sh
#
# After it runs, as YOUR user:
#   export ANONPROXY_CLIENT_USER=$USER      # the user that runs Claude Code
#   sudo -u anonproxy -H ANONPROXY_CLIENT_USER=$USER ANONPROXY_ISOLATION=enforce \
#        /opt/anonproxy/.venv/bin/python -m anonproxy
# then point Claude Code at it:
#   export ANTHROPIC_BASE_URL=http://127.0.0.1:8787

set -euo pipefail

PROXY_USER="${ANONPROXY_USER:-anonproxy}"
INSTALL_DIR="${ANONPROXY_INSTALL_DIR:-/opt/anonproxy}"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash scripts/setup-isolated-user.sh"; exit 1
fi

echo "==> Creating system user '${PROXY_USER}' (no login shell)"
if ! id "${PROXY_USER}" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "/home/${PROXY_USER}" \
            --shell /usr/sbin/nologin "${PROXY_USER}"
fi

echo "==> Installing a copy of the proxy to ${INSTALL_DIR} owned by ${PROXY_USER}"
mkdir -p "${INSTALL_DIR}"
# Copy source only (not .venv/.git/data); the dedicated user builds its own venv.
rsync -a --delete \
    --exclude '.venv' --exclude '.git' --exclude 'data' \
    --exclude 'dictionary.yaml' --exclude '__pycache__' \
    "${SRC_DIR}/" "${INSTALL_DIR}/"
chown -R "${PROXY_USER}:${PROXY_USER}" "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"

echo "==> Building venv as ${PROXY_USER}"
sudo -u "${PROXY_USER}" -H bash -lc "
    cd '${INSTALL_DIR}'
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip -q
    ./.venv/bin/pip install -r requirements.txt -q
    [ -f dictionary.yaml ] || cp dictionary.example.yaml dictionary.yaml
    chmod 700 . ; mkdir -p data ; chmod 700 data ; chmod 600 dictionary.yaml
"

echo
echo "==> Done. The proxy lives at ${INSTALL_DIR}, owned by ${PROXY_USER}."
echo "    Its data dir is 0700 and unreadable by your user — that is the point."
echo
echo "    Edit the dictionary as the proxy user:"
echo "      sudo -u ${PROXY_USER} -H nano ${INSTALL_DIR}/dictionary.yaml"
echo
echo "    Start it (enforced isolation):"
echo "      sudo -u ${PROXY_USER} -H env ANONPROXY_CLIENT_USER=\$USER \\"
echo "           ANONPROXY_ISOLATION=enforce \\"
echo "           ${INSTALL_DIR}/.venv/bin/python -m anonproxy"
echo
echo "    Then, as your user:"
echo "      export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude"
