# llm-anon-proxy

A local proxy that sits between Claude Code and the Anthropic API and keeps your
own data off the wire. It replaces your private values (domains, IPs, hostnames,
credentials, tokens…) with deterministic placeholders **before** anything leaves
the machine, and restores the real values in the response — including inside
`tool_use` arguments — so commands still run against your real hosts.

```
you / ssh / files ─► Claude Code ─► [this proxy] ─► api.anthropic.com
                                       │  onlyfans.com      → aqurel-vous.example
                                       │  185.12.34.56      → 198.18.x.x
                                       │  Sup3rS3cret!      → [CRED_XXXXXXXXXX]
                                       ▼
                        restores real values on the way back
```

It is a **risk-reduction layer, not a guarantee**. Encrypted blobs, data derived
from a value (hashes, base64), and context ("a creators payout table") cannot be
scrubbed by substitution. Do what you can, and keep the rotation log.

## Why a proxy and not hooks

The proxy sees the entire request: your prompt, the full message history,
`tool_use` inputs and tool outputs, and the system prompt. Hooks cannot rewrite
all of that. Everything is anonymized on the way out and restored on the way in.

## Docs

* **[docs/INSTALL.md](docs/INSTALL.md)** — proxy setup + the two Ollama options.
* **[docs/USAGE.md](docs/USAGE.md)** — daily workflow, the dictionary, contexts,
  the rotation log, verifying, troubleshooting.

## Setup

```bash
cd ~/llm-anon-proxy
bash scripts/setup-proxy.sh                  # venv + deps + dictionary.yaml
```

Edit `dictionary.yaml` — your domains, hosts, IPs, usernames, org/brand names,
sensitive paths. These are the deterministic first layer; listing a registrable
domain also covers its subdomains. You can seed identifiers from local files:

```bash
python scripts/gen_dictionary.py --from .env --hostname --git   # review, then merge
```

## Run

```bash
# terminal 1 — start the proxy (loopback only)
python -m anonproxy

# terminal 2 — point Claude Code at it
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

Your API credentials pass straight through to Anthropic and are never logged.

## Detection layers

1. **Dictionary** — your exact values (deterministic, highest priority).
2. **Regex** — IPs, CIDRs, MACs, emails, domains, API keys/tokens (AWS, GitHub,
   Stripe, Slack, GitLab, Google, JWT), PEM private keys, crypt/htpasswd hashes,
   and assignment-style secrets (`password:`, `PGPASSWORD=`, `mysql -p…`,
   `define('DB_PASSWORD', …)`, `requirepass`, DSN `user:pass@host`, `Bearer …`).
3. **Local LLM (optional, off by default)** — contextual hostnames / org / person
   names that regex cannot catch. Uses your local Ollama (Docker or native —
   see [docs/INSTALL.md](docs/INSTALL.md)):

   ```bash
   export ANONPROXY_LLM=true
   export ANONPROXY_OLLAMA_MODEL=qwen3.5:4b
   ```

   Default model `qwen3.5:4b`: in a local benchmark (`scripts/dev/bench_llm.py`)
   it caught every contextual entity with zero false positives at ~0.55 s median
   per call on an 8 GB GPU. Tool names, protocols, versions and CVE IDs are
   filtered deterministically so the model never mangles them. When enabled and
   Ollama is unreachable, requests are **blocked** rather than sent
   half-anonymized (set `ANONPROXY_LLM_FAIL_CLOSED=false` to change that).

## Surrogates

Deterministic (HMAC with a local secret in `data/secret.key`, `0600`) and
collision-free — the vault guarantees a 1:1 reverse map, so a restored command
can never be routed to the wrong host. Shapes are preserved: public IPs →
`198.18.0.0/15`, private IPs stay private, domains keep sub-labels, tokens keep
their recognizable prefix and length class.

## Rotation log

Every secret-shaped value seen is appended to `data/rotate.log.jsonl` (`0600`,
type + masked preview + SHA-256 only, never the full value):

* `intercepted` — replaced before sending; rotate as a precaution.
* `leaked` — found in the bytes actually sent upstream; **rotate these**.

Review after a session:

```bash
python -m anonproxy.rotate
```

## Per-client isolation

Set `ANONPROXY_CONTEXT=client-x` to keep each project's mappings separate (the
same IP maps to different surrogates in different contexts).

## Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `ANONPROXY_HOST` / `ANONPROXY_PORT` | `127.0.0.1` / `8787` | listen address |
| `ANONPROXY_UPSTREAM` | `https://api.anthropic.com` | real API |
| `ANONPROXY_CONTEXT` | `default` | mapping isolation id |
| `ANONPROXY_DICT` | `dictionary.yaml` | your values |
| `ANONPROXY_LLM` | `false` | enable the Ollama layer |
| `ANONPROXY_OLLAMA_MODEL` | `qwen3.5:4b` | model id |
| `ANONPROXY_DATA_DIR` | `./data` | db, secret key, rotation log |

## Limitations

* Substitution only — it cannot scrub encrypted material or values that were
  transformed (hashed, re-encoded) after you saw them.
* Context can still identify you (paths, schema names, service layout).
* Local transcripts in `~/.claude/projects/*.jsonl` still hold real values; the
  proxy sits downstream of them. Protect or clear them separately.
* Streaming restores values at whitespace boundaries; a surrogate is never split.

## Tests

```bash
python -m pytest -q
```

Covers round-trips, the previously-leaking secret patterns, collision-free and
restart-stable surrogates, the allowlist, the outgoing leak scan, and a full
proxy round-trip (request anonymized, streamed response restored) against a fake
upstream — no network.

## Prior art

Design informed by a review of `zeroc00I/DontFeedTheAI` (MIT). The regex ideas
and the fail-closed-on-LLM-down principle come from there; the collision-free
deterministic vault, full-history + `tool_use` coverage, real streaming
restoration, loopback-only binding, and the rotation log are this project's.
