"""
Anonymization performance benchmark / regression check.

    python scripts/dev/bench_anon.py            # ~500 KB text, ~1000 dict entries
    python scripts/dev/bench_anon.py 2000 2000  # entries, KB

Prints first-pass, cached and deanonymize timings. Aho-Corasick (pyahocorasick)
makes the first pass ~20x faster on large dictionaries; without it the regex
fallback is used (slower).
"""
import os
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

N_ENTRIES = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
KB = int(sys.argv[2]) if len(sys.argv) > 2 else 500

D = tempfile.mkdtemp(prefix="anonproxy-bench-")
os.environ["ANONPROXY_DATA_DIR"] = D
os.environ["ANONPROXY_DB"] = os.path.join(D, "t.db")
dictf = Path(D) / "dict.yaml"

doms, ips = [], []
lines = ["domains:"]
for i in range(N_ENTRIES // 2):
    d = f"host{i}-corp{i}.example{i % 20}.pl"
    doms.append(d)
    lines.append(f"  - {d}")
lines.append("ips:")
for i in range(N_ENTRIES // 4):
    ip = f"10.{i % 255}.{(i * 7) % 255}.{(i * 13) % 255}"
    ips.append(ip)
    lines.append(f"  - {ip}")
lines.append("keywords:")
for i in range(N_ENTRIES // 4):
    lines.append(f"  - projekt{i}kryptonim")
dictf.write_text("\n".join(lines))
os.environ["ANONPROXY_DICT"] = str(dictf)

from anonproxy import vault, dictionary, anonymizer  # noqa: E402
from anonproxy.config import config  # noqa: E402

config.DICT_PATH = dictf
vault.init()
dictionary.load()

filler = "lorem ipsum dolor sit amet nginx apache mysql systemd " * 12
chunks = []
target = KB * 1024
while len("\n".join(chunks)) < target:
    chunks.append(filler)
    if random.random() < 0.1 and doms:
        chunks.append(f" connect {random.choice(doms)} at {random.choice(ips)} "
                      f"for projekt{random.randint(0, N_ENTRIES // 4 - 1)}kryptonim ")
text = "\n".join(chunks)

print(f"ahocorasick: {dictionary._HAVE_AC}  dict entries (incl. encodings): {len(dictionary._entries)}")
print(f"text size: {len(text) // 1024} KB")

t = time.perf_counter(); a = anonymizer.anonymize(text, source="bench"); first = time.perf_counter() - t
t = time.perf_counter(); anonymizer.anonymize(text, source="bench"); cached = time.perf_counter() - t
t = time.perf_counter(); back = anonymizer.deanonymize(a); deanon = time.perf_counter() - t
print(f"anonymize first:  {first * 1000:8.1f} ms")
print(f"anonymize cached: {cached * 1000:8.1f} ms")
print(f"deanonymize:      {deanon * 1000:8.1f} ms")
print(f"round-trip ok:    {back == text}")
