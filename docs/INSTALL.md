# Installation

Two parts: the **proxy** (always), and the optional **Ollama** contextual layer
(choose Docker *or* native). Nothing here starts a public service — the proxy
binds to `127.0.0.1` only.

## 1. The proxy

```bash
cd ~/llm-anon-proxy
bash scripts/setup-proxy.sh        # venv + deps + a dictionary.yaml to edit
```

Or by hand:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp dictionary.example.yaml dictionary.yaml && chmod 600 dictionary.yaml
```

Then fill in `dictionary.yaml` — see [USAGE.md](USAGE.md). You can seed it from
local files:

```bash
python scripts/gen_dictionary.py --from .env --hostname --git
# review dictionary.generated.yaml, merge what you want into dictionary.yaml
```

The regex + dictionary layers work on their own. The Ollama layer below is only
needed to catch *contextual* names (bare hostnames, org/person names in prose).

## 2. Ollama (optional contextual layer)

Default model: **`qwen3.5:4b`** — in a local benchmark it caught every
contextual entity with no false positives at ~0.55 s median per call on an
8 GB GPU. The 9 B model was slower with no gain here.

### Option A — Docker

Runs Ollama in a container; the proxy stays on the host and connects to it.

```bash
docker compose -f docker-compose.ollama.yml up -d     # starts Ollama, pulls the model
```

* Binds Ollama to `127.0.0.1:11434` only.
* GPU is used via the NVIDIA Container Toolkit. No toolkit? Delete the `deploy:`
  block in `docker-compose.ollama.yml` to run on CPU.
* Change the model: `ANONPROXY_OLLAMA_MODEL=qwen3.5:9b docker compose -f docker-compose.ollama.yml up -d`
* Stop: `docker compose -f docker-compose.ollama.yml down`

### Option B — Native (WSL / Linux, no Docker) — this is the setup here

Installs Ollama as a service and pulls the model.

```bash
bash scripts/install-ollama-wsl.sh
```

* Uses the official installer (it calls `sudo` itself).
* Works with or without systemd; without it, starts `ollama serve` in the
  background (`/tmp/ollama.log`).
* `goose` (the agent) is **not** required — only a plain chat model is used.

### Enable the layer in the proxy

```bash
export ANONPROXY_LLM=true
export ANONPROXY_OLLAMA_MODEL=qwen3.5:4b     # optional; this is the default
python -m anonproxy
```

When enabled and Ollama is unreachable, requests are **blocked** (fail-closed)
rather than sent half-anonymized. Set `ANONPROXY_LLM_FAIL_CLOSED=false` to fall
back to dictionary+regex instead.

## 3. Isolate the proxy from the agent (required for real use)

The proxy's files are a full de-anonymization oracle; the Claude Code agent must
not be able to read them. Run the proxy as a **dedicated user** (or container /
WSL distro / host). Helper (review first; uses sudo, starts nothing):

```bash
sudo bash scripts/setup-isolated-user.sh     # creates user 'anonproxy' at /opt/anonproxy
```

Then enforce it at startup:

```bash
export ANONPROXY_CLIENT_USER=$USER     # the user that runs Claude Code
export ANONPROXY_ISOLATION=enforce     # refuse to start if not isolated
```

Full rationale and the weaker/stronger options: [THREAT-MODEL.md](THREAT-MODEL.md).

## Point Claude Code at the proxy

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

## Verify

```bash
curl -s http://127.0.0.1:8787/health          # {"status":"ok",...}
python -m pytest -q                            # 45 passing
python scripts/dev/bench_llm.py qwen3.5:4b     # LLM layer score (needs Ollama)
```
