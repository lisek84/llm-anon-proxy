# llm-anon-proxy

**English** · [Polski](README.pl.md)

> Keep your private data out of Claude Code's API traffic — replace IPs,
> domains, hostnames and secrets with reversible surrogates before requests
> leave the machine, and restore them in the response.

A local proxy that sits between Claude Code and the Anthropic API and keeps your
own data off the wire. It replaces your private values (domains, IPs, hostnames,
credentials, tokens…) with deterministic placeholders **before** anything leaves
the machine, and restores the real values in the response — including inside
`tool_use` arguments — so commands still run against your real hosts.

```
you / ssh / files ─► Claude Code ─► [this proxy] ─► api.anthropic.com
                                       │  example.com      → aqurel-vous.example
                                       │  185.12.34.56      → 198.18.x.x
                                       │  Sup3rS3cret!      → [CRED_XXXXXXXXXX]
                                       ▼
                        restores real values on the way back
```

It is a **risk-reduction layer, not a guarantee**. Encrypted blobs, data derived
from a value (hashes, base64), and context ("a creators payout table") cannot be
scrubbed by substitution. Do what you can, and keep the rotation log.

## ⚠️ Do not run the proxy where Claude Code runs

The proxy's files — `data/mappings.db` (the full original↔surrogate table),
`dictionary.yaml`, and `data/secret.key` — are a complete de-anonymization
oracle. If the Claude Code agent runs as the **same OS user**, it can simply read
them with its file tools and reverse everything; no code can stop a same-UID
reader. **Run the proxy as a different OS user / container / WSL distro / host**,
so Claude Code reaches it only over the port. A startup preflight enforces this —
see **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)**.

```bash
export ANONPROXY_CLIENT_USER=<user-that-runs-claude-code>
export ANONPROXY_ISOLATION=enforce      # refuse to start if not isolated
```

## Why a proxy and not hooks

The proxy sees the entire request: your prompt, the full message history,
`tool_use` inputs and tool outputs, and the system prompt. Hooks cannot rewrite
all of that. Everything is anonymized on the way out and restored on the way in.

## Docs

* **[docs/INSTALL.md](docs/INSTALL.md)** — Docker (turnkey) and native setup, plus the Ollama layer.
* **[docs/USAGE.md](docs/USAGE.md)** — daily workflow, the dictionary, contexts,
  the rotation log, verifying, troubleshooting.
* **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** — why the proxy must be
  isolated from the agent, how to deploy it, and what it does not protect.

## Setup

**Docker (turnkey)** — on a machine with Docker, one command brings up the whole
environment and writes all state next to the compose file:

```bash
git clone <repo> /llm-anon-proxy && cd /llm-anon-proxy
cp dictionary.example.yaml dictionary.yaml   # edit with YOUR values

id 991; getent passwd 991                    # both must print nothing (also covers LDAP/NSS)
sudo chown 991:991 dictionary.yaml && sudo chmod 600 dictionary.yaml  # originals, agent-unreadable
sudo install -d -o 991 -g 991 -m 0700 data   # vault dir owned by the proxy UID, not you
sudo chown -R 991:991 data                   # fix any files already inside too

docker compose up -d                         # proxy (dict + regex); add: --profile llm for Ollama
./claude_anon                                # in your working console
```

**Native** (what WSL uses — no Docker needed):

```bash
cd ~/llm-anon-proxy
bash scripts/setup-proxy.sh                  # venv + deps + dictionary.yaml
```

Edit `dictionary.yaml` — your domains, hosts, IPs, usernames, org/brand names,
sensitive paths. These are the deterministic first layer; listing a registrable
domain also covers its subdomains. You can seed identifiers from local files:

```bash
cat /etc/hosts | python -m anonproxy.gendict ips --merge dictionary.yaml  # pipe-friendly
python -m anonproxy.gendict auto                                          # scan this machine
```

## Run

```bash
# terminal 1 — start the proxy (loopback only)
./start_proxy.sh

# terminal 2 — launch Claude Code through it
./claude_anon
```

`claude_anon` refuses to start if the proxy isn't reachable, so you never run
Claude Code against the real API by accident. Equivalent by hand:

```bash
python -m anonproxy                                   # terminal 1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude   # terminal 2
```

Your API credentials pass straight through to Anthropic and are never logged.

## Detection layers

1. **Dictionary** — your exact values (deterministic, highest priority).
2. **Regex** — IPs (v4/v6), CIDRs, MACs, emails, domains, Polish national IDs
   (PESEL/NIP/REGON, checksum-validated), API keys/tokens (AWS, GitHub,
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

## Seeing what it caught

```bash
python -m anonproxy.audit         # every value caught: original -> surrogate, type, where
python -m anonproxy.preview < .env  # offline dry run — what WOULD leave the machine
python -m anonproxy.rotate        # secret-shaped values to rotate
```

The proxy also logs each request live (`anonymized N … (M new)` out,
`restored N` back). Full detail: [docs/USAGE.md](docs/USAGE.md#verifying-it-works--where-to-see-the-trace).

### Live dashboard

Open **`http://127.0.0.1:8787/ui`** in a browser next to your Claude Code window
for a color-coded, auto-updating feed of what the proxy catches as it works —
entity type, source, original → surrogate, and running counts. No login.

By default the dashboard **masks** originals (type, masked preview, and the full
surrogate) so the HTTP view is not a de-anonymization oracle — important when the
proxy is isolated from the agent. To show real values (loopback only; the agent
could then read them too): `ANONPROXY_UI_SHOW_ORIGINALS=true`. Disable the UI
entirely with `ANONPROXY_UI=false`.

**Securing it for remote use.** The dashboard is open and unencrypted by default
(fine next to your work, on loopback). If you expose the proxy off-loopback, put
it behind TLS (`ANONPROXY_TLS=true`, same as the API) and add a login:

```bash
python -m anonproxy.uiauth add alice     # prompts for a password; now /ui needs login
python -m anonproxy.uiauth list
python -m anonproxy.uiauth disable       # remove all viewers → dashboard open again
```

Adding the first viewer turns on HTTP Basic auth automatically (passwords are
stored hashed in `data/ui-users.json`). Use it together with TLS — Basic auth
over plain HTTP sends the password reversibly.

## Rotation log

Every secret-shaped value seen is appended to `data/rotate.log.jsonl` (`0600`,
type + masked preview + SHA-256 only, never the full value):

* `intercepted` — replaced before sending; rotate as a precaution.
* `leaked` — found in the bytes actually sent upstream; **rotate these**.

```bash
python -m anonproxy.rotate
```

The audit trail `data/audit.log.jsonl` (`0600`) holds the real
`original -> surrogate` pairs — it is sensitive and never served over HTTP.

## Per-client isolation

Set `ANONPROXY_CONTEXT=client-x` to keep each project's mappings separate (the
same IP maps to different surrogates in different contexts).

## Clearing / rotating the vault

Mappings persist (same original → same surrogate per context). Clear them
**between sessions, never during one**:

```bash
python -m anonproxy.reset                 # forget all mappings (same key)
python -m anonproxy.reset --context acme  # forget one context only
python -m anonproxy.reset --new-key       # also rotate the key → all-new surrogates
python -m anonproxy.reset --all --yes     # mappings + key + logs, no prompt
```

Forgetting with the same key regenerates identical surrogates (a clean-up);
`--new-key` is a true rotation. `start_proxy.sh` can do it on launch:

```bash
ANONPROXY_RESET=1       ./start_proxy.sh   # forget mappings
ANONPROXY_RESET=new-key ./start_proxy.sh   # forget mappings + rotate key
ANONPROXY_RESET=all     ./start_proxy.sh   # mappings + key + logs
```

Details and consequences: [docs/USAGE.md](docs/USAGE.md#mappings-persist--clearing-and-rotating).

## Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `ANONPROXY_HOST` / `ANONPROXY_PORT` | `127.0.0.1` / `8787` | listen address |
| `ANONPROXY_UPSTREAM` | `https://api.anthropic.com` | real API |
| `ANONPROXY_CONTEXT` | `default` | mapping isolation id |
| `ANONPROXY_DICT` | `dictionary.yaml` | your values |
| `ANONPROXY_SUBDOMAIN_POLICY` | `preserve` | `preserve` sub-label names or `mask` them |
| `ANONPROXY_DETECT_PL_ID` | `true` | detect Polish PESEL/NIP/REGON by checksum |
| `ANONPROXY_DETECT_PL_ID_BARE` | `false` | also catch bare 10-digit NIP / 9-digit REGON (~9% FP) |
| `ANONPROXY_LLM` | `false` | enable the Ollama layer |
| `ANONPROXY_OLLAMA_MODEL` | `qwen3.5:4b` | model id |
| `ANONPROXY_DATA_DIR` | `./data` | db, secret key, rotation + audit logs |
| `ANONPROXY_AUDIT` | `true` | write the `original -> surrogate` audit trail |
| `ANONPROXY_ISOLATION` | `warn` | `warn` / `enforce` / `off` (see THREAT-MODEL) |
| `ANONPROXY_CLIENT_USER` | _(unset)_ | the OS user running Claude Code (preflight checks it can't read the vault) |
| `ANONPROXY_CLIENT_UID` / `_GIDS` | _(unset)_ | numeric identity for the preflight in a container (`id -u` / `id -G`) |
| `ANONPROXY_UI` | `true` | serve the live dashboard at `/ui` |
| `ANONPROXY_UI_SHOW_ORIGINALS` | `false` | reveal real values in the dashboard |
| `ANONPROXY_UI_VERBOSE` | `false` | re-show caught values on every request (once per distinct value), not only the first time — verbose but reassuring |
| `ANONPROXY_INJECT_HINT` | `false` | append a note to the system prompt telling the model to treat placeholder-looking identifiers as real and not speculate about anonymization |
| `ANONPROXY_RESET` | _(unset)_ | `start_proxy.sh` only: `1` forget mappings · `new-key` also rotate key · `all` + logs |
| `ANONPROXY_BLOCK_UNSCANNABLE` | `false` | block (503) requests with image/binary-document blocks instead of forwarding |
| `ANONPROXY_BLOCK_UNKNOWN` | `false` | block (403) endpoints other than `/v1/messages[/count_tokens]` |
| `ANONPROXY_BLOCK_MCP` | `false` | block (503) requests with `mcp_servers` (remote MCP url+token can't be anonymized) |
| `ANONPROXY_TOKEN` | _(unset)_ | require this secret (X-Anonproxy-Token header, or `…:8787/<token>` path); non-loopback use |
| `ANONPROXY_TLS` | `false` | serve HTTPS with an auto-generated self-signed cert (data dir) |
| `ANONPROXY_TLS_CERT` / `ANONPROXY_TLS_KEY` | _(unset)_ | serve HTTPS with your own cert/key instead |
| `ANONPROXY_TLS_SAN` | _(unset)_ | extra host names/IPs for the self-signed cert (comma-separated) |

## Limitations

* Substitution only. For **declared** values it also catches their common
  encodings (base64/base32/hex/URL/JSON `\uXXXX`) and is Unicode-normalized
  (NFC/NFD), so e.g. a user `Łukasz` is covered plain and encoded. It cannot
  scrub encryption, compression, or arbitrary encodings of undeclared values.
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

## License

MIT — see [LICENSE](LICENSE).

## Repository metadata

GitHub topics and the About description are set in the repo UI (Settings → About),
not from a file. Suggested values, recorded here for reference:

**Description:** Local proxy that keeps your private data out of Claude Code's API
traffic — swaps domains, IPs, hostnames, credentials and tokens for deterministic
surrogates before requests leave the machine and restores them on the way back.

**Topics:** `claude-code` `anthropic` `claude` `llm` `privacy` `anonymization`
`pseudonymization` `redaction` `data-loss-prevention` `pii` `secrets-detection`
`proxy` `ollama` `fastapi` `python`
