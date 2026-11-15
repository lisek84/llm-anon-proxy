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

    def __init__(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)


config = Config()
