"""Central configuration, read from environment with safe local defaults."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("ANONPROXY_DATA_DIR", str(BASE_DIR / "data")))


class Config:
    # Listen only on loopback by default — never expose the vault on the LAN.
    HOST: str = os.getenv("ANONPROXY_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("ANONPROXY_PORT", "8787"))

    # Upstream real API.
    UPSTREAM_URL: str = os.getenv("ANONPROXY_UPSTREAM", "https://api.anthropic.com").rstrip("/")

    # Per-context isolation of mappings (like an "engagement"/project id).
    CONTEXT_ID: str = os.getenv("ANONPROXY_CONTEXT", "default")

    # How a domain's sub-labels are surrogated:
    #   "preserve" (default) — keep them literal: prod-db01.acme.pl ->
    #       prod-db01.<base>.example. Best for the model (it sees infra structure),
    #       but sub-label names (prod-db01, vpn, dc01, a client name) are exposed.
    #   "mask" — replace each sub-label with a deterministic inert token, keeping
    #       the level count and the shared base: prod-db01.acme.pl ->
    #       k7f2d9.<base>.example. Hides the names, keeps structure + consistency.
    SUBDOMAIN_POLICY: str = os.getenv("ANONPROXY_SUBDOMAIN_POLICY", "preserve").lower()

    # Polish national identifiers (PESEL / NIP / REGON), detected by checksum.
    #   DETECT_PL_ID (default on): PESEL + REGON-14 bare (low false-positive), and
    #     NIP / REGON-9 only in a clear context (`NIP: …`, `PL1234567890`,
    #     `REGON: …`) — their 10/9-digit length otherwise collides with unix
    #     timestamps and phone numbers at ~9-10%.
    #   DETECT_PL_ID_BARE (default off): ALSO flag bare 10-digit NIP / 9-digit
    #     REGON by checksum — higher recall, but accept ~9% over-anonymization of
    #     timestamps/phones (safe direction: round-trips, never leaks).
    DETECT_PL_ID: bool = os.getenv("ANONPROXY_DETECT_PL_ID", "true").lower() == "true"
    DETECT_PL_ID_BARE: bool = os.getenv("ANONPROXY_DETECT_PL_ID_BARE", "false").lower() == "true"

    DATA_DIR: Path = DATA_DIR
    DB_PATH: Path = Path(os.getenv("ANONPROXY_DB", str(DATA_DIR / "mappings.db")))

    # Secret used to derive deterministic surrogates. Kept local; never sent.
    # If unset, a random key is generated and persisted with 0600 perms.
    SECRET_KEY_PATH: Path = DATA_DIR / "secret.key"

    # User dictionary of exact strings to always replace (domains, IPs, hosts…).
    DICT_PATH: Path = Path(os.getenv("ANONPROXY_DICT", str(BASE_DIR / "dictionary.yaml")))

    # Rotation log: every secret-shaped value seen, for later credential rotation.
    LEAKLOG_PATH: Path = Path(os.getenv("ANONPROXY_LEAKLOG", str(DATA_DIR / "rotate.log.jsonl")))

    # Local LLM (optional second detection layer). Empty host disables it.
    OLLAMA_HOST: str = os.getenv("ANONPROXY_OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("ANONPROXY_OLLAMA_MODEL", "qwen3.5:4b")
    OLLAMA_TIMEOUT: int = int(os.getenv("ANONPROXY_OLLAMA_TIMEOUT", "60"))
    LLM_ENABLED: bool = os.getenv("ANONPROXY_LLM", "false").lower() == "true"

    # If the LLM layer is enabled but unreachable, block the request rather
    # than forward partially-anonymized data.
    LLM_FAIL_CLOSED: bool = os.getenv("ANONPROXY_LLM_FAIL_CLOSED", "true").lower() == "true"

    # ── Fail-closed options (security-by-default toggles) ─────────────────────
    # Block (instead of forward) a request that carries content the proxy cannot
    # scrub: image blocks and binary (non-text) document blocks.
    BLOCK_UNSCANNABLE: bool = os.getenv("ANONPROXY_BLOCK_UNSCANNABLE", "false").lower() == "true"
    # Block (instead of forward) any endpoint other than the anonymized ones
    # (/v1/messages, /v1/messages/count_tokens). Forwards raw otherwise.
    BLOCK_UNKNOWN_ENDPOINTS: bool = os.getenv("ANONPROXY_BLOCK_UNKNOWN", "false").lower() == "true"
    # Block a request carrying `mcp_servers` (Anthropic's remote MCP connector).
    # Its url + authorization_token CANNOT be anonymized — Anthropic needs the
    # real values to reach the MCP server — so by default they are forwarded with
    # a dashboard notice; set this to refuse such requests instead.
    BLOCK_MCP_SERVERS: bool = os.getenv("ANONPROXY_BLOCK_MCP", "false").lower() == "true"
    # Optional shared secret for non-loopback deploys. If set, every request must
    # carry it as a URL path prefix: ANTHROPIC_BASE_URL=http://host:8787/<token>.
    TOKEN: str = os.getenv("ANONPROXY_TOKEN", "")

    # ── TLS (for remote connections — never send this over plain HTTP) ────────
    # Provide your own cert/key, or set ANONPROXY_TLS=true to auto-generate a
    # self-signed pair into the data dir. Clients then use https:// and must
    # trust the cert (NODE_EXTRA_CA_CERTS for Claude Code). For production,
    # terminating TLS at nginx/haproxy in front of the proxy is also fine.
    TLS: bool = os.getenv("ANONPROXY_TLS", "false").lower() == "true"
    TLS_CERT: str = os.getenv("ANONPROXY_TLS_CERT", "")
    TLS_KEY: str = os.getenv("ANONPROXY_TLS_KEY", "")
    # Host names / IPs to put in the self-signed cert's SAN (comma-separated).
    TLS_SAN: str = os.getenv("ANONPROXY_TLS_SAN", "")

    # ── Isolation from the Claude Code agent ──────────────────────────────────
    # The vault, dictionary and secret key together are a full de-anonymization
    # oracle. If the agent can read them, the tool is pointless. The proxy must
    # run where Claude Code's file tools cannot reach those files — a different
    # OS user, container, WSL distro or host. Claude Code only ever talks to the
    # proxy over the loopback/network port, never its filesystem.
    #   off     — no check (not recommended)
    #   warn    — harden perms and log a prominent warning (default)
    #   enforce — refuse to start unless isolation from CLIENT_USER is confirmed
    ISOLATION: str = os.getenv("ANONPROXY_ISOLATION", "warn").lower()
    # The OS username that runs Claude Code. When set, the preflight verifies
    # that user cannot read the proxy's secret files.
    CLIENT_USER: str = os.getenv("ANONPROXY_CLIENT_USER", "")
    # Numeric alternative, for containers where the host username doesn't resolve
    # in the container's /etc/passwd: pass the agent user's `id -u` and `id -G`.
    # Takes precedence over CLIENT_USER when set.
    CLIENT_UID: int | None = (int(os.environ["ANONPROXY_CLIENT_UID"])
                              if os.getenv("ANONPROXY_CLIENT_UID", "").strip().lstrip("-").isdigit()
                              else None)
    CLIENT_GIDS: frozenset = frozenset(
        int(x) for x in os.getenv("ANONPROXY_CLIENT_GIDS", "").replace(",", " ").split()
        if x.strip().lstrip("-").isdigit())

    # ── Audit trail ───────────────────────────────────────────────────────────
    # A time-ordered record of every value caught (first time it is seen):
    # original -> surrogate, with type and where it appeared. It contains real
    # values, so it lives in the protected data dir (0600) alongside the vault
    # and is NEVER exposed over HTTP. This is the trace you review to confirm the
    # proxy is actually catching your data.
    AUDIT_ENABLED: bool = os.getenv("ANONPROXY_AUDIT", "true").lower() == "true"
    AUDIT_PATH = Path(os.getenv("ANONPROXY_AUDIT_PATH", str(DATA_DIR / "audit.log.jsonl")))

    # ── Live web dashboard ────────────────────────────────────────────────────
    # A read-only page at /ui showing proxy activity in real time. Served on the
    # same loopback port. By default it MASKS the original values (shows type,
    # source, masked preview and the surrogate) so the HTTP view is not a full
    # de-anonymization oracle — important when the proxy is isolated from the
    # agent. Set UI_SHOW_ORIGINALS=true to reveal real values (accept that the
    # agent, sharing loopback, could then read them over HTTP).
    UI_ENABLED: bool = os.getenv("ANONPROXY_UI", "true").lower() == "true"
    UI_SHOW_ORIGINALS: bool = os.getenv("ANONPROXY_UI_SHOW_ORIGINALS", "false").lower() == "true"
    # Re-show caught values on EVERY request (once per distinct value per request),
    # not only the first time they enter the vault. Verbose but reassuring — you
    # see the substitutions happen each turn. Default off (keeps the feed quiet,
    # since Claude Code resends the whole history every request).
    UI_VERBOSE: bool = os.getenv("ANONPROXY_UI_VERBOSE", "false").lower() == "true"

    def __init__(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)


config = Config()
