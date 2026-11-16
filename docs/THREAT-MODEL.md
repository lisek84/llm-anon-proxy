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

2. **A container** — Ollama and/or the proxy in Docker, data in a volume the
   host user does not mount. Claude Code on the host reaches only the port.

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
(fail-open) — it is never forwarded half-anonymized.

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
