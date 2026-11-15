"""
Offline preview — see what WOULD be anonymized, sending nothing anywhere.

Paste or pipe text (an .env, a config, a transcript) and it shows every value
the pipeline catches, original -> surrogate, plus the fully anonymized text.
Runs in a throwaway context, so it never touches your real vault or logs.

    python -m anonproxy.preview < .env
    python -m anonproxy.preview --file /etc/nginx/conf.d/app.conf
    echo "ssh root@185.12.34.56 for onlyfans.com" | python -m anonproxy.preview
    python -m anonproxy.preview --llm < notes.txt      # also use the Ollama layer
"""
import asyncio
import sys
import tempfile
from pathlib import Path

from .config import config


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Preview anonymization offline.")
    ap.add_argument("--file", help="read this file (default: stdin)")
    ap.add_argument("--llm", action="store_true", help="also run the Ollama contextual layer")
    args = ap.parse_args()

    text = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file \
        else sys.stdin.read()
    if not text.strip():
        print("(no input)")
        return 0

    # Isolate everything in a throwaway dir so the real vault/logs are untouched.
    tmp = Path(tempfile.mkdtemp(prefix="anonproxy-preview-"))
    config.DATA_DIR = tmp
    config.DB_PATH = tmp / "preview.db"
    config.AUDIT_ENABLED = False
    config.LEAKLOG_PATH = tmp / "rotate.jsonl"
    config.CONTEXT_ID = "preview"
    config.SECRET_KEY_PATH = tmp / "secret.key"

    from . import vault, dictionary, anonymizer, llm_detector  # after config tweak
    vault.init()
    dictionary.load()

    llm_matches = []
    if args.llm:
        config.LLM_ENABLED = True
        try:
            llm_matches = asyncio.run(llm_detector.detect(text))
        except Exception as exc:  # noqa: BLE001
            print(f"(LLM layer unavailable: {exc})", file=sys.stderr)

    entities = anonymizer._collect(text, llm_matches)
    anon = anonymizer.anonymize(text, llm_matches=llm_matches, source="preview")

    if not entities:
        print("No values caught. Nothing here would be anonymized.")
        print("(If you expected a hit, add it to dictionary.yaml or check the regex layer.)")
        return 0

    pairs = []
    for original in sorted(entities, key=len, reverse=True):
        sur = vault.lookup_surrogate(original) or "(unchanged)"
        pairs.append((entities[original], original, sur))

    print(f"Caught {len(pairs)} value(s):\n")
    for etype, original, sur in pairs:
        print(f"  [{etype:12}] {original!r}  ->  {sur!r}")
    print("\n--- anonymized text (this is what would leave the machine) ---\n")
    print(anon)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
