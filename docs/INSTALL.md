# Installation

**English** · [Polski](INSTALL.pl.md)

Two ways to run it: **Docker** (turnkey, best on a machine with Docker) or
**native** (what WSL uses, since Docker isn't available there). Pick one. Nothing
here starts a public service — the proxy binds to `127.0.0.1` only.

## Docker (turnkey)

On a machine with Docker, the whole environment comes up with one command and all
state is written next to the compose file.

```bash
git clone <repo> /llm-anon-proxy && cd /llm-anon-proxy
cp dictionary.example.yaml dictionary.yaml     # then edit with YOUR values

# The container runs as a DEDICATED UID (991), deliberately NOT your user —
# that separate owner on the 0700 vault dir is what keeps the Claude Code agent
# (running as you) from reading mappings.db / secret.key. Create ./data owned by
# it (needs sudo once). Do NOT remap the container to $(id -u): that defeats the
# isolation. Override only to another NON-agent uid:  ANONPROXY_UID=… ANONPROXY_GID=…
sudo install -d -o 991 -g 991 -m 0700 data

docker compose up -d                           # builds + starts the proxy (dict + regex)
```

With the local LLM layer too (pulls the model; GPU via the NVIDIA toolkit):

```bash
ANONPROXY_LLM=true docker compose --profile llm up -d
```

Then in your working console:

```bash
./claude_anon          # or: export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude
```

* The proxy is published on `127.0.0.1:8787` only. Dashboard: `http://127.0.0.1:8787/ui`.
* State (vault, secret key, rotation + audit logs) is written to **`./data`** next
  to `docker-compose.yml`; the dictionary is bind-mounted read-only from `./dictionary.yaml`.
* Inspect logs from the container:
  `docker compose exec proxy python -m anonproxy.rotate` (and `… anonproxy.audit`).
* Show real values in the dashboard: `ANONPROXY_UI_SHOW_ORIGINALS=true docker compose up -d`.
* Stop: `docker compose down` (add `--profile llm` if you started the LLM layer).
* Isolation note: `./data` on the host holds the de-anonymization vault
  (`mappings.db`, `secret.key`). The container runs as a dedicated UID (991) and
  the dir is 0700, so the Claude Code agent — running as *your* user — can't read
  it. This only holds if you keep it that way: don't `chown` `./data` to yourself
  and don't set `ANONPROXY_UID=$(id -u)`. Running the proxy in a **different WSL
  distro / user / host** from Claude Code is the stronger boundary. The
  dictionary (`./dictionary.yaml`) holds your real values too — keep it
  unreadable by the agent's user if that matters to you. See
  [THREAT-MODEL.md](THREAT-MODEL.md).

The rest of this page is the **native** path (no Docker).

## 1. The proxy (native)

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
python -m anonproxy.gendict auto                                         # scan this machine
cat /etc/hosts | python -m anonproxy.gendict ips --merge dictionary.yaml  # or pipe specifics in
# review dictionary.yaml afterwards — it emits identifiers only, never secrets
```

The regex + dictionary layers work on their own. The Ollama layer below is only
needed to catch *contextual* names (bare hostnames, org/person names in prose).

## 2. Ollama (optional contextual layer)

Default model: **`qwen3.5:4b`** — in a local benchmark it caught every
contextual entity with no false positives at ~0.55 s median per call on an
8 GB GPU. The 9 B model was slower with no gain here.

### Option A — Docker

If you deployed with Docker above, just add the LLM profile — Ollama runs as a
service and the proxy talks to it automatically:

```bash
ANONPROXY_LLM=true docker compose --profile llm up -d
```

Change the model with `ANONPROXY_OLLAMA_MODEL=qwen3.5:9b`. No NVIDIA toolkit?
Remove the `deploy:` block from the `ollama` service to run on CPU.

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

## Remote use — encrypt the connection (TLS)

The proxy serves **plain HTTP** by default, which is fine only on `127.0.0.1`.
If you run it on one machine and point other hosts at it
(`ANTHROPIC_BASE_URL=…`), the traffic — your real data on the way back — must not
cross the network unencrypted. Three options:

**1. Built-in self-signed TLS** (quickest):

```bash
ANONPROXY_TLS=true ANONPROXY_HOST=0.0.0.0 ANONPROXY_TLS_SAN=proxy.mylan \
  ANONPROXY_TOKEN=$(openssl rand -hex 24) python -m anonproxy
```

It generates `data/tls-cert.pem` / `tls-key.pem` (reused on restart). Clients use
`https://`. Claude Code (Node) rejects an untrusted cert, so on each client point
Node at the cert:

```bash
export NODE_EXTRA_CA_CERTS=/path/to/tls-cert.pem
export ANTHROPIC_BASE_URL=https://proxy.mylan:8787/<token>
claude
```

**2. Your own cert** (e.g. an internal CA or Let's Encrypt): set
`ANONPROXY_TLS_CERT` and `ANONPROXY_TLS_KEY` instead — then clients need no
`NODE_EXTRA_CA_CERTS`.

**3. Terminate TLS at a reverse proxy** (recommended for production): run this
proxy on loopback and put nginx / haproxy / Caddy in front with a real
certificate, forwarding to `127.0.0.1:8787`. Example nginx:

```nginx
server {
    listen 443 ssl;
    server_name proxy.mylan;
    ssl_certificate     /etc/letsencrypt/live/proxy.mylan/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.mylan/privkey.pem;
    location / { proxy_pass http://127.0.0.1:8787; proxy_buffering off; }
}
```

In every remote case also set `ANONPROXY_TOKEN` (a URL path-prefix secret) and a
firewall rule — the proxy has no per-user auth of its own. And remember the
isolation rule still applies: the box running the proxy holds the vault, so keep
its `data/` unreadable by anyone who could also reach Claude Code's files.

## Verify

```bash
curl -s http://127.0.0.1:8787/health          # {"status":"ok",...}
python -m pytest -q                            # 65 passing
python scripts/dev/bench_llm.py qwen3.5:4b     # LLM layer score (needs Ollama)
```
