#!/usr/bin/env bash
# Set up the proxy itself (venv + dependencies + a dictionary to edit).
# Does not install or start Ollama — see install-ollama-wsl.sh or
# docker-compose.ollama.yml for that. Starts nothing.
#
#   bash scripts/setup-proxy.sh

set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
    echo "==> Creating .venv"
    python3 -m venv .venv
fi
echo "==> Installing dependencies"
./.venv/bin/pip install --upgrade pip -q
./.venv/bin/pip install -r requirements.txt -q

if [ ! -f dictionary.yaml ]; then
    cp dictionary.example.yaml dictionary.yaml
    chmod 600 dictionary.yaml
    echo "==> Created dictionary.yaml (edit it with YOUR values)"
fi

echo
echo "==> Done. Next:"
echo "    1. edit dictionary.yaml   (or: python scripts/gen_dictionary.py --from .env --hostname)"
echo "    2. . .venv/bin/activate && python -m anonproxy"
echo "    3. export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude"
