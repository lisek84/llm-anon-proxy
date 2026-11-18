#!/usr/bin/env bash
# =============================================================================
# llm-anon-proxy — DEMO runner
#
# Feeds the fake sensitive data planted by setup-demo-server.sh through the
# proxy's OFFLINE preview, using the ready demo dictionary. It shows, for each
# source, every value caught (original -> surrogate) and the fully anonymized
# text — i.e. exactly what WOULD leave the machine. Nothing is sent anywhere.
#
#   bash demo/run-demo.sh            # dictionary + regex + checksum layers
#   bash demo/run-demo.sh --llm      # also the local Ollama contextual layer
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."                      # repo root
PY=.venv/bin/python
DICT="demo/dictionary.demo.yaml"
LLM=""
[ "${1:-}" = "--llm" ] && LLM="--llm"

if [ ! -x "$PY" ]; then
    echo "The proxy isn't set up yet. Run:  bash scripts/setup-proxy.sh" >&2
    echo "(or: sudo bash demo/setup-demo-server.sh)" >&2
    exit 1
fi
export ANONPROXY_DICT="$DICT"

hr()  { printf '\033[1;36m%s\033[0m\n' "============================================================"; }
head(){ hr; printf '\033[1;33m  %s\033[0m\n' "$1"; hr; }

found=0

# The consolidated "admin session" is the headline demo; fall back to live files.
MAIN="/opt/acme/demo/admin-session.txt"
if [ -r "$MAIN" ]; then
    head "What an admin would paste to Claude  →  what the proxy lets leave"
    $PY -m anonproxy.preview $LLM --file "$MAIN"; found=1
    echo
fi

# Also show a couple of raw sources individually (if readable).
for f in /var/www/acme-crm.pl/.env /opt/acme/deploy/secrets.yml /opt/acme/demo/customers_dump.sql; do
    if [ -r "$f" ]; then
        head "$f"
        $PY -m anonproxy.preview $LLM --file "$f"; found=1
        echo
    fi
done

if [ "$found" = 0 ]; then
    echo "No demo data found. Provision it first on a throwaway VM:" >&2
    echo "    sudo bash demo/setup-demo-server.sh" >&2
    exit 1
fi

cat <<'EOF'
------------------------------------------------------------------------------
That "anonymized text" block is what Claude (and Anthropic) would actually see.
Note that you never listed the passwords, API tokens, the Slack webhook, or the
PESEL/NIP numbers in the dictionary — the regex + checksum layers caught those
on their own. Only your domains, hosts, IPs and brand names come from the dict.

Next: run it live.  export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 and start
the proxy (./start_proxy.sh) with this dictionary, then point Claude Code at it.
When you're happy, destroy the VM and build your own dictionary.yaml.
------------------------------------------------------------------------------
EOF
