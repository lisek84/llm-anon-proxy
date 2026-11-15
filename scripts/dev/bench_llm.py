"""Benchmark the contextual LLM detector across models/prompts.

Usage: python scripts/dev/bench_llm.py [model ...]
Scores recall on entities that only the LLM can catch, and counts false
positives on things it must leave alone. Prints latency too.
"""
import asyncio
import os
import sys
import time

os.environ["ANONPROXY_LLM"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from anonproxy import llm_detector, anonymizer
from anonproxy.config import config

# (text, {should-flag substrings}, {must-NOT-flag substrings})
CASES = [
    ("Logged into DC01 and FILESERVER-PRD as CORP\\jsmith to pull the share.",
     {"DC01", "FILESERVER-PRD", "jsmith"}, {"share"}),
    ("The webserver web-prod-01 hosts the Acme Payments portal for Contoso.",
     {"web-prod-01", "Acme Payments", "Contoso"}, {"webserver", "portal"}),
    ("Service account svc_backup runs the nightly job on node db-ash-07.",
     {"svc_backup", "db-ash-07"}, {"account", "nightly"}),
    ("nmap scan of the host showed 445/tcp open smb and 3389/tcp rdp.",
     set(), {"nmap", "smb", "rdp", "host", "445", "3389"}),
    ("Author: Pedro Alves committed the fix; reviewed by Hannah Weiss.",
     {"Pedro Alves", "Hannah Weiss"}, {"Author", "committed"}),
    ("kubectl get pods -n kube-system shows the ingress controller running.",
     set(), {"kubectl", "kube-system", "ingress", "controller"}),
    ("The workgroup WORKGROUP joined domain FABRIKAM via the PDC.",
     {"FABRIKAM"}, {"WORKGROUP", "domain", "PDC"}),
    ("mysql running on Ubuntu 22.04 with OpenSSH 8.9; patch per CVE-2024-6387.",
     set(), {"mysql", "Ubuntu", "OpenSSH", "CVE-2024-6387"}),
    ("Deploy the onlyfans-media service to cluster prod-eu-1 for the creators team.",
     {"onlyfans-media", "prod-eu-1"}, {"cluster", "creators team", "Deploy"}),
    ("User rafael.moura reset the password for the Northwind Traders tenant.",
     {"rafael.moura", "Northwind Traders"}, {"password", "tenant", "User"}),
    ("The box BACKUP01 and the app server APPSRV-12 are both unreachable.",
     {"BACKUP01", "APPSRV-12"}, {"box", "app server"}),
    ("Please restart the service and check the logs; everything looks fine.",
     set(), {"service", "logs", "restart", "fine"}),
]


async def run_model(model: str):
    config.OLLAMA_MODEL = model
    tp = fn = fp = 0
    total_expected = 0
    lat = []
    # warmup
    try:
        await llm_detector.detect("warmup DC01 Contoso")
    except Exception as e:
        print(f"  {model}: UNAVAILABLE ({e})"); return
    for text, should, mustnot in CASES:
        t0 = time.perf_counter()
        try:
            matches = await llm_detector.detect(text)
        except Exception as e:
            print(f"  error on case: {e}"); matches = []
        lat.append((time.perf_counter() - t0) * 1000)
        # Score the end-to-end result (detector + deterministic safe-term guard
        # + precedence), i.e. what would actually be anonymized.
        found = set(anonymizer._collect(text, matches))
        total_expected += len(should)
        for s in should:
            if any(s == f or s in f or f in s for f in found):
                tp += 1
            else:
                fn += 1
        for bad in mustnot:
            if any(bad == f for f in found):
                fp += 1
    recall = tp / total_expected if total_expected else 0
    print(f"  {model:22} recall={recall:4.0%} ({tp}/{total_expected})  "
          f"missed={fn}  false_pos={fp}  "
          f"lat med={sorted(lat)[len(lat)//2]:.0f}ms max={max(lat):.0f}ms")


async def main():
    models = sys.argv[1:] or ["qwen3.5:4b"]
    print(f"cases={len(CASES)}")
    for m in models:
        await run_model(m)


asyncio.run(main())
