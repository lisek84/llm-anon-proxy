"""
Thin wrapper around `python -m anonproxy.gendict` (kept for back-compat).

The real tool lives in anonproxy/gendict.py. Prefer calling it directly:

    cat /etc/hosts | python -m anonproxy.gendict ips
    python -m anonproxy.gendict auto                 # scan this machine
    python -m anonproxy.gendict all *.conf --merge dictionary.yaml

See `python -m anonproxy.gendict --help`.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from anonproxy.gendict import _main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(_main())
