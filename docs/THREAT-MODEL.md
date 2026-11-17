# Threat model

**English** · [Polski](THREAT-MODEL.pl.md)

## The core assumption

This tool only works if the thing it is hiding data *from* cannot read the data
it uses to do the hiding.

The proxy keeps, on disk:

| File | Why it is dangerous |
|---|---|
| `data/mappings.db` | the **full** original ↔ surrogate table — a complete reverse lookup |
| `dictionary.yaml` | your real domains, hosts, IPs, usernames, org names, paths |
| `data/secret.key` | the HMAC key that derives every surrogate |
| `data/rotate.log.jsonl` | masked, but confirms which secrets existed |

Anyone — or any process — that can read these can undo the anonymization
completely. The single most important one is `mappings.db`: it *is* the answer
key.

## Why "don't run it where Claude Code runs" matters

Claude Code is an agent with file tools (`Read`, `Grep`, `Bash`). If it runs as
the **same OS user** as the proxy, it can just read `mappings.db` and
`dictionary.yaml` directly — the network anonymization becomes theatre. The
model would be one `cat` away from every real value.

**No code in the proxy can prevent this** when the agent shares the proxy's UID:
same user ⇒ same file permissions. The protection has to come from the operating
system, not from the application.

## Required deployment: isolate the proxy

Run the proxy somewhere Claude Code's file tools cannot reach its files. In
increasing order of strength:

1. **A dedicated OS user** (simplest on one machine). The proxy runs as
   `anonproxy` with a `0700` data dir; Claude Code runs as you and cannot read
   it. Helper (review first, it uses sudo, starts nothing):

   ```bash
   sudo bash scripts/setup-isolated-user.sh
   ```

2. **A container** — Ollama and/or the proxy in Docker. This isolates **only if
   the vault is not readable by the host user that runs Claude Code**. The
   bundled compose runs the container as a dedicated UID (991) and the `./data`
   bind mount is `0700`, owned by that UID — so the agent's user can't read
   `mappings.db`/`secret.key`. It stops isolating the moment you `chown` the data
   to yourself or set `ANONPROXY_UID=$(id -u)`; a bind mount the host user owns
   gives no isolation at all.

3. **A separate WSL distro** — run the proxy in a second distro; the agent in
   your working distro sees only `127.0.0.1:8787` (or the mapped port).

4. **A separate host / VPS** with an SSH tunnel — the agent's machine never has
   the files at all. Strongest, and the right choice for shared or team use.

In every case Claude Code talks to the proxy **only over the port**
(`ANTHROPIC_BASE_URL`), never its filesystem.

## The built-in preflight

On startup the proxy runs `anonproxy/preflight.py`, which:

* hardens permissions (`data/` → `0700`, secret files → `0600`), and
* checks isolation against `ANONPROXY_CLIENT_USER` (the user that runs Claude
  Code): it refuses the obvious co-located case (proxy user == client user) and
  verifies that user cannot read the sensitive files.

Modes via `ANONPROXY_ISOLATION`:

| Mode | Behaviour |
|---|---|
| `warn` (default) | harden perms, log a prominent warning if not isolated |
| `enforce` | **refuse to start** unless isolation from `CLIENT_USER` is confirmed |
| `off` | skip the check (not recommended) |

Run it on its own any time:

```bash
ANONPROXY_CLIENT_USER=$USER python -m anonproxy.preflight ; echo "exit=$?"
# exit 0 = isolated, 1 = problems found
```

Recommended for real use:

```bash
export ANONPROXY_CLIENT_USER=<the-user-that-runs-claude-code>
export ANONPROXY_ISOLATION=enforce
```

The check is a backstop, not the mechanism. It can tell you that you are *not*
isolated; only the OS boundary actually isolates you. A same-UID agent that is
determined and reads files before the proxy starts is out of scope — the answer
there is a different user/container/host, which is why `enforce` insists on it.

## Encodings and Unicode

Plain substitution misses a value that has been re-encoded. The proxy closes the
common keyless cases **for values you declare in the dictionary** — it also
registers their encoded forms:

* base64 (standard and url-safe, padded and unpadded, with and without the
  trailing newline `echo` adds), base32, and hex (upper/lower);
* URL/percent-encoding and JSON `\uXXXX` escapes.

Encoded forms are matched token-bounded so a short value's encoding never
partially matches inside a longer blob, and `KEY=<base64>` still matches. One-way
hashes (md5/sha, standard lengths) are scrubbed by the regex HASH rule because
their *shape* is recognized, even though the proxy cannot know which value they
came from.

Unicode is normalized to NFC on both sides, so an accented or Polish value
(`Łukasz`, `Kraków`) matches whether the input arrived as NFC or NFD, and its
encodings are computed from UTF-8 bytes. Declare such values exactly as they
appear; matching is case-insensitive for plain text.

Still **not** covered: encodings of a value that is *not* in the dictionary (an
arbitrary base64 blob cannot be assumed sensitive without drowning you in false
positives — the same limit as encryption); compression (gzip/deflate) or
encryption; double-encoding; a value split across messages; and exotic encodings
(HTML entities, ROT13, custom schemes). For anything you care about, put the real
value in the dictionary.

## Correctness of substitution

Both directions replace by **position over the original text in a single pass**,
with overlaps resolved longest-first, so a value or surrogate is never matched
inside text that was just substituted. A domain keeps its subdomains
(`cdn.acme.pl` → `cdn.<surrogate>`), a keyword inside a path is swapped without
touching a neighbouring domain surrogate's `.example` TLD, and restoring never
double-expands (no `acme.pl` → `acme.pl.pl`). Surrogates contain no whitespace,
so streamed responses are restored whole. Logging a catch is best-effort and can
never break or partially skip anonymization.

If the LLM layer is enabled but Ollama is down, the request is **blocked**
(fail-closed, default) or **degrades to dictionary+regex for the whole request**
(fail-open) — it is never forwarded half-anonymized. Fail-closed covers *any*
Ollama transport or HTTP error (connect, timeout, HTTP 500…), not only a dropped
connection.

### Optional fail-closed / security-by-default toggles

Default behaviour favours not breaking Claude Code; these make it strict:

* `ANONPROXY_BLOCK_UNSCANNABLE=true` — reject (503) a request carrying content
  the proxy cannot scrub (image blocks, binary document blocks) instead of
  forwarding it with a warning.
* `ANONPROXY_BLOCK_UNKNOWN=true` — reject (403) any endpoint other than the
  anonymized `/v1/messages` and `/v1/messages/count_tokens`, instead of
  forwarding it raw.
* `ANONPROXY_TOKEN=<secret>` — for a non-loopback deployment (separate host/VPS),
  require the secret either as an `X-Anonproxy-Token` header (preferred — it does
  not land in URL/access logs) or, for clients that can only set a base URL like
  Claude Code, as a URL path prefix
  (`ANTHROPIC_BASE_URL=https://host:8787/<secret>`); requests without it get 403.
  The proxy still has no per-user auth beyond this, so keep it behind the SSH
  tunnel / firewall and prefer the header where the client can send one.

The startup preflight checks classic Unix owner/group/mode and directory
traversal. It **detects** the presence of an extended POSIX ACL (via the
`system.posix_acl_access` xattr) and a failed permission check and treats either
as *isolation not confirmed* (a problem in `enforce` mode), but it does **not**
resolve named ACL entries to decide who they grant, nor does it evaluate
capabilities or access via a Docker socket / privileged process — treat it as a
backstop, not proof of isolation (only the OS/user/host boundary isolates you).

The outgoing leak scan is **leak detection** (rotatable CREDENTIAL/TOKEN still
present), not full **privacy verification**: a plain host like `prod-db-01` that
no dictionary or LLM match caught will not be flagged by it. To verify coverage
of your own values before a session, use `python -m anonproxy.preview`.

Whenever content is forwarded **without** anonymization — an image or binary
document block, or an unknown endpoint — every occurrence is surfaced on the
dashboard (a red `UNANON` row and a counter) and logged, so a silent
un-anonymized transmission cannot go unnoticed. The malformed-LLM-response case
is also fail-closed now: an unparseable or structurally-wrong Ollama reply raises
`LLMUnavailable` (only a valid `{"entities": []}` counts as "nothing found").

## Remote MCP connector (`mcp_servers`)

Anthropic's remote MCP connector (the top-level `mcp_servers` request field)
cannot be anonymized: Anthropic *itself* connects to the MCP server, so it needs
the real `url` and `authorization_token`. Substituting surrogates would break the
connection. The proxy therefore forwards them as-is, with a dashboard notice and
a best-effort leak scan, so you know the real URL + token left the machine; set
`ANONPROXY_BLOCK_MCP=true` to refuse such requests instead. The same applies to
the values a remote MCP tool call carries at Anthropic's side. The proxy *does*
anonymize the conversation-side MCP blocks that go upstream in the history —
`mcp_tool_use` inputs, `mcp_tool_result` content and `mcp_tool_listing`
descriptions — like their non-MCP counterparts. For full control over
infrastructure exposed to a remote MCP server, run that MCP server itself behind
this proxy, or use a local MCP server instead of the remote connector.

For the preflight to verify isolation inside a container (where the host
username doesn't resolve), set `ANONPROXY_CLIENT_UID`/`ANONPROXY_CLIENT_GIDS` to
the agent user's numeric `id -u` / `id -G` instead of `ANONPROXY_CLIENT_USER`.

## Detection is value-based, not positional

Regex detection decides per *value*, not per occurrence, and the anonymizer then
replaces every occurrence of a caught value in the block. Consequences worth
knowing:

* **Context-dependent exceptions are per-value, not per-position.** If the same
  string appears once in a skipped context and once in a caught one, both get
  replaced. `v4.14.5.1 … version 4.14.5.1` — the `v`-prefixed form is skipped,
  but the second occurrence is caught as an IP, so *both* are replaced.
* **Two-label domains on an ambiguous TLD are not caught in plain prose**
  (`firma.it`, `foo.io`, `bar.es`): they collide with file names and code, so
  they are only caught with ≥3 labels or a network context (`@`, `://`, `:port`,
  `/path`). Put your own such domains in the dictionary.
* **IPs written with hyphens in PTR names are not seen as IPs**
  (`ec2-52-90-38-71.compute-1.amazonaws.com`). Do **not** add such provider
  domains to `allow:`, or the embedded address rides along un-anonymized.
* **`name.ext:NN` with a line number but no trailing colon** (`see deploy.sh:12
  for details`) is shape-identical to `host.io:8080`, so it is caught as a
  domain. `file:line:` (trailing colon, as grep prints) is not — only this
  bare-line-number form, which is unresolvable without context.
* **Cosmetic:** an scp target `git@host.tld:path` is caught whole as an email,
  so the model sees `x@y.example:path` and loses the "this is git" cue.

## What escaped — the rotation log

A post-anonymization scan runs over the **string values** of the outgoing body
(not its JSON serialization, which would create escape-boundary false matches),
skipping protocol fields such as `metadata` (the caller's own Anthropic account
id lives there and is not a secret to rotate). Rotation-worthy secrets still
present — credentials and tokens — are written to `data/rotate.log.jsonl` under
`leaked` (vs `intercepted` for values replaced before sending). Hashes/checksums
and ids are intentionally not recorded as leaks (too noisy, not rotatable).
Review with `python -m anonproxy.rotate` and rotate every `leaked` entry. Bodies
forwarded unchanged by the catch-all (unknown endpoints) are logged as a warning
and scanned too.

## What this tool still does not protect against

* **Encrypted or compressed data** — it substitutes literals; it cannot scrub a
  value that was encrypted or gzip'd after you saw it. Reversible *encodings* of
  declared values are handled (see above); arbitrary ones are not.
* **Context** — paths, schema names and service layout can identify you even
  with every literal replaced.
* **Prompt injection** from tool output (a server banner telling the model to do
  something) — unaffected by anonymization.
* **Local Claude Code transcripts** in `~/.claude/projects/*.jsonl`, which store
  the real values the agent saw. Protect or clear them separately.
* **Compromise of the proxy host/user** itself.
