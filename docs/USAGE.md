# Usage

## The daily workflow

```bash
# 1. start the proxy (one terminal, leave it running)
cd ~/llm-anon-proxy && . .venv/bin/activate
python -m anonproxy

# 2. in another terminal, run Claude Code through it
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

Work normally — ssh into servers, read `.env` files, grep configs. On the way
out, your values become surrogates; on the way back, real values are restored,
so a command Claude proposes like `ssh root@<surrogate>` actually runs against
your real host. You never have to think about it mid-session.

At the end of a session, review what was exposed and rotate as needed:

```bash
python -m anonproxy.rotate
```

## The dictionary

`dictionary.yaml` is the deterministic first layer: your own values, each in a
section that fixes the surrogate shape. Matching is case-insensitive and
substring-based, longest first, so a registrable domain also covers subdomains.

```yaml
domains:        # cdn3.site.com is covered by listing site.com
  - example-prod.pl
hosts:          # bare machine names (no dots)
  - of-prod-db01
ips:
  - 185.12.34.56
cidrs:
  - 10.20.0.0/16
emails:
  - admin@example-prod.pl
usernames:
  - of_app
organizations: # brand / project / company names, incl. bare words
  - example
keywords:       # bare words caught as a component anywhere:
  - example     #   /var/www/example, example.conf, example-worker
paths:          # sensitive absolute paths
  - /home/lisek/example-ops
```

`keywords` are matched as substrings wherever they appear, so a project name
embedded in a path or filename is caught. A longer value still wins first, so
listing both `keywords: example` and `domains: example.com` keeps a full domain
handled as a domain (`cdn3.example.com`) while a bare `/var/www/example` uses
the keyword surrogate.

What to put here: the high-value things a scan cannot infer — brand/project
names, internal hostnames, service accounts, sensitive paths. Identifiers like
domains/IPs/emails can be seeded automatically:

```bash
python scripts/gen_dictionary.py --from .env --from /etc/nginx/conf.d/app.conf --hostname --git
```

It writes `dictionary.generated.yaml` (never touches your real file) with only
identifiers — **never secrets**. Review and merge.

Edits are picked up on proxy restart.

> Do **not** put passwords/tokens in the dictionary. Secrets are caught
> dynamically by the regex layer; the dictionary is not a secret store.

## What gets replaced — and what doesn't

Replaced: dictionary values; IPs, CIDRs, MACs, emails, domains; API keys and
tokens (AWS, GitHub, Stripe, Slack, GitLab, Google, JWT); PEM private keys;
crypt/htpasswd hashes; and assignment-style secrets (`password:`,
`PGPASSWORD=`, `mysql -p…`, `define('DB_PASSWORD', …)`, `requirepass`, DSN
`user:pass@host`, `Bearer …`).

Left intact on purpose: loopback and well-known IPs (`127.0.0.1`, `8.8.8.8`,
`169.254.169.254`…), and tooling domains (`anthropic.com`, `github.com`,
`pypi.org`…) — so advice and package references still work. Edit the allowlists
in `anonproxy/regex_detector.py` if yours differ.

With the LLM layer on, bare hostnames and org/person names in prose are caught
too; tool names, protocols, versions and CVE IDs are filtered out
deterministically so they are never mangled.

## Per-client isolation

Keep each client's mappings separate so the same IP maps to different surrogates
per client (and nothing bleeds across):

```bash
ANONPROXY_CONTEXT=client-acme python -m anonproxy
```

Each context is a partition in the same SQLite vault (`data/mappings.db`).

## The rotation log

Everything secret-shaped that passes through is appended to
`data/rotate.log.jsonl` (mode `600`; stores only a type, a masked preview and a
SHA-256 — never the full value). Two categories:

* **intercepted** — replaced before leaving the machine. It still touched local
  history/logs, so rotate it as a precaution.
* **leaked** — found in the bytes *actually sent* upstream (a post-anonymization
  scan). This one reached the API — **rotate it**.

```bash
python -m anonproxy.rotate     # grouped report, leaked first
```

After a day of work, walk the list and rotate each credential at its source.

## Verifying it works — where to see the trace

There are four places, from live to forensic:

**1. The live proxy log (stdout of `python -m anonproxy`).** Each request prints
what happened on the way out and back:

```
anonymized 5 value(s) [tool_result] (3 new): credential=1 domain=1 hostname=1 ip_address=2
← restored 4 surrogate(s) in streamed response
```

`(N new)` are values seen for the first time; re-sent history stays quiet. The
`restored` line confirms the return path put your real values back. A
`secret-shaped value still present` warning means something slipped through (it
is also logged for rotation — see below).

**2. The audit trail — the record of exactly what was caught.** Every value is
logged the first time it is seen, `original -> surrogate`, with its type and
where it appeared:

```bash
python -m anonproxy.audit            # full list, grouped by type
python -m anonproxy.audit -n 20      # just the last 20
```

```
2026-11-15T20:33:39Z  [DOMAIN    ] message      'cdn3.example.com' -> 'xzrbxf-ulpor.example'
2026-11-15T20:33:39Z  [CREDENTIAL] tool_result  'Hunter2pass'       -> '[CRED_J9724CV11M]'
```

This file (`data/audit.log.jsonl`) holds **real values**, so it lives in the
protected data dir (`0600`) and is never served over HTTP. It is the answer to
"what did the proxy actually catch in this session." Disable with
`ANONPROXY_AUDIT=false`.

**3. A dry run before you trust it — offline, sends nothing.** Paste or pipe a
real file and see precisely what would leave the machine:

```bash
python -m anonproxy.preview < .env
python -m anonproxy.preview --file /etc/nginx/conf.d/app.conf --llm
```

It prints every catch (`original -> surrogate`) and the fully anonymized text,
in a throwaway context that never touches your real vault or logs. Use it to
confirm your `dictionary.yaml` and the regex rules catch your data *before* a
real session.

**4. The test suite — a hard guarantee.**

```bash
python -m pytest -q    # asserts known secret patterns never survive, responses round-trip
```

Typical first real session: run `python -m anonproxy.preview < some-real-config`
to confirm your values are caught, start the proxy, do a short session, then
`python -m anonproxy.audit` to see the full list of what was intercepted and
`python -m anonproxy.rotate` for anything to rotate.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Claude Code ignores the proxy | Confirm `echo $ANTHROPIC_BASE_URL` = `http://127.0.0.1:8787` in the *same* shell that runs `claude`. |
| 503 `anonymizer_unavailable` | LLM layer is on but Ollama is down. Start Ollama, or set `ANONPROXY_LLM=false`, or `ANONPROXY_LLM_FAIL_CLOSED=false`. |
| A value of yours leaked | Add it to `dictionary.yaml` and restart; check `python -m anonproxy.rotate`. |
| A tool/domain got mangled | Add it to the allowlist in `anonproxy/regex_detector.py`, or (if contextual) to `_SAFE_LLM_TERMS` in `anonproxy/anonymizer.py`. |
| Responses feel slow with LLM on | Use `qwen3.5:4b`; the 9B is slower with no accuracy gain in the benchmark. |

## Limitations

Substitution only. For values **in your dictionary** it also catches their
common encodings (base64, base32, hex, URL-encoding, JSON `\uXXXX`) and matches
them regardless of Unicode normalization (NFC/NFD) — so a user named `Łukasz` is
covered in plain and encoded forms. It cannot scrub encrypted or compressed data,
arbitrary encodings of values you did not declare, or context (paths, schema
names, service layout) that identifies you indirectly. Local Claude Code
transcripts in `~/.claude/projects/*.jsonl` still hold real values — protect or
clear them separately. See [THREAT-MODEL.md](THREAT-MODEL.md) for the full list.
