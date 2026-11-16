#!/usr/bin/env bash
# Start the anonymization proxy (foreground, so you see the live log).
# Run this in one window; run ./claude_anon in another to use Claude Code
# through it. Stop with Ctrl-C.
#
# Override any setting by exporting it before running, e.g.:
#   ANONPROXY_PORT=9000 ./start_proxy.sh
#   ANONPROXY_LLM=true ./start_proxy.sh            # enable the Ollama layer
#   ANONPROXY_UI_SHOW_ORIGINALS=true ./start_proxy.sh   # show real values in /ui
#   ANONPROXY_CLIENT_USER=$USER ANONPROXY_ISOLATION=enforce ./start_proxy.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

export ANONPROXY_HOST="${ANONPROXY_HOST:-127.0.0.1}"
export ANONPROXY_PORT="${ANONPROXY_PORT:-8787}"

PY="$DIR/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "No Python found. Run scripts/setup-proxy.sh first." >&2; exit 1; }

if [ ! -f "$DIR/dictionary.yaml" ]; then
    echo "WARNING: dictionary.yaml not found — only regex rules will apply." >&2
    echo "         cp dictionary.example.yaml dictionary.yaml  and edit it." >&2
fi

# Optional reset before start (safe only between sessions):
#   ANONPROXY_RESET=1          ./start_proxy.sh   # forget all mappings (same key)
#   ANONPROXY_RESET=new-key    ./start_proxy.sh   # also rotate the secret key
#   ANONPROXY_RESET=all        ./start_proxy.sh   # mappings + key + logs
case "${ANONPROXY_RESET:-}" in
    "")        ;;
    new-key)   "$PY" -m anonproxy.reset --new-key --yes ;;
    all)       "$PY" -m anonproxy.reset --all --yes ;;
    *)         "$PY" -m anonproxy.reset --yes ;;
esac

echo "anonproxy → http://${ANONPROXY_HOST}:${ANONPROXY_PORT}   (dashboard: /ui)"
echo "point Claude Code at it with:  ./claude_anon"
exec "$PY" -m anonproxy
