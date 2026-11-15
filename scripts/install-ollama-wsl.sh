#!/usr/bin/env bash
# Option B — install Ollama natively (WSL / Linux), no Docker.
#
# Installs the Ollama service, starts it, and pulls the detector model.
# Review before running. Nothing here needs root except the official installer,
# which uses sudo itself. Re-running is safe (idempotent).
#
#   bash scripts/install-ollama-wsl.sh
#
# Then enable the LLM layer for the proxy:
#   export ANONPROXY_LLM=true
#   python -m anonproxy

set -euo pipefail

MODEL="${ANONPROXY_OLLAMA_MODEL:-qwen3.5:4b}"
OLLAMA_HOST_URL="${ANONPROXY_OLLAMA_HOST:-http://localhost:11434}"

echo "==> Model to install: ${MODEL}"

# 1) Install Ollama if missing.
if command -v ollama >/dev/null 2>&1; then
    echo "==> Ollama already installed: $(ollama --version 2>/dev/null || echo present)"
else
    echo "==> Installing Ollama via the official script (uses sudo)…"
    curl -fsSL https://ollama.com/install.sh | sh
fi

# 2) Make sure the server is running.
#    On WSL with systemd, the installer registers a service. Without systemd,
#    start it in the background.
start_server() {
    if curl -fsS "${OLLAMA_HOST_URL}/api/tags" >/dev/null 2>&1; then
        echo "==> Ollama server already responding at ${OLLAMA_HOST_URL}"
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ollama'; then
        echo "==> Enabling and starting the ollama systemd service…"
        sudo systemctl enable --now ollama || true
    fi
    if ! curl -fsS "${OLLAMA_HOST_URL}/api/tags" >/dev/null 2>&1; then
        echo "==> Starting 'ollama serve' in the background (log: /tmp/ollama.log)…"
        nohup ollama serve >/tmp/ollama.log 2>&1 &
    fi
}
start_server

# 3) Wait for it to come up.
echo -n "==> Waiting for Ollama"
for _ in $(seq 1 30); do
    if curl -fsS "${OLLAMA_HOST_URL}/api/tags" >/dev/null 2>&1; then echo " — up."; break; fi
    echo -n "."; sleep 1
done
curl -fsS "${OLLAMA_HOST_URL}/api/tags" >/dev/null 2>&1 || {
    echo; echo "!! Ollama did not start. Check /tmp/ollama.log"; exit 1; }

# 4) Pull the model.
echo "==> Pulling ${MODEL} (first time downloads a few GB)…"
ollama pull "${MODEL}"

echo
echo "==> Done. Verify with:  ollama list"
echo "    Then run the proxy with the LLM layer on:"
echo "      export ANONPROXY_LLM=true"
echo "      export ANONPROXY_OLLAMA_MODEL=${MODEL}"
echo "      python -m anonproxy"
echo
echo "Note: 'goose' (the agent) is NOT required — the proxy only needs a plain"
echo "chat model for contextual detection. qwen3.5:4b is the tuned default."
