#!/usr/bin/env python3
"""D7 — model extraction / behavioural cloning (LLM10, MITRE ATLAS AML.T0024).

The attack: an uncapped, unmetered /chat endpoint is not "just a chat box" — it
is a model you can copy. Query it many times, keep every (prompt, answer) pair,
and you walk away with ``stolen.jsonl`` — a dataset that reproduces the target's
behaviour. No weights are stolen and no breach is logged; the theft *is* ordinary
traffic. That the endpoint has no rate limit or budget is the LLM10 Unbounded
Consumption enabler, and it is why the query loop can run at all.

We also print a *behavioural-similarity* estimate: the fraction of repeated
prompts that got an identical answer. A deterministic target scores 100% —
maximally cloneable. A sampled model scores lower, and you would harvest more.

Live path: HTTP to /chat. Offline path (``--offline`` or endpoint down): drive
RedVault's own ``pipeline.chat()`` in-process — the SAME code the endpoint runs,
labelled in the output as the fallback. Nothing here is fabricated.

  python d7_extract_model.py --queries 200 --out stolen.jsonl
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import redvault_client as rv

# The attacker's question bank. Widening these is how you cover more of the
# target's behaviour; they are ordinary support questions, not attacks.
SEED_QUESTIONS = [
    "Summarize our refund policy.",
    "How long do refunds take?",
    "What is the onboarding process?",
    "Who do I report phishing to?",
    "How are cloud vendors chosen?",
    "What is the policy on passwords?",
    "Explain the returns process.",
    "What training is required before accessing customer records?",
]
SUFFIXES = ["", " Please be brief.", " In one sentence.", " As a list.",
            " Explain simply.", " For a new hire."]


def _gen_query(rng: random.Random) -> str:
    return rng.choice(SEED_QUESTIONS) + rng.choice(SUFFIXES)


def _offline_asker():
    """Import RedVault's real pipeline for the no-server path. This needs the app
    installed (its venv) — run under ../../../src/.venv/bin/python if the stack is
    down. Returns a callable(msg) -> answer that runs the exact endpoint code."""
    src = Path(__file__).resolve().parents[3] / "src"
    sys.path.insert(0, str(src))
    try:
        from redvault.pipeline import chat as pipeline_chat
        from redvault.db import Database
        from redvault.config import load_settings
    except ModuleNotFoundError as exc:
        raise SystemExit(
            f"\nOffline extraction needs RedVault importable, but: {exc}\n"
            f"  Either start the stack (so this runs over HTTP):\n"
            f"    cd src && REDVAULT_MODE=vulnerable docker compose up -d\n"
            f"  or run this demo under RedVault's own venv, which has the deps:\n"
            f"    ../../../src/.venv/bin/python d7_extract_model.py ...\n"
        )
    settings = load_settings()
    db = Database()  # reads the same src/data/redvault.db `make seed` wrote
    return lambda msg: pipeline_chat(msg, db=db, settings=settings)["answer"]


def harvest(queries: int = 200, out: str = "stolen.jsonl", seed: int = 1337,
            offline: bool = False) -> dict:
    """Run the extraction loop and write ``out``. Returns a small result dict so
    the acceptance run can read the numbers without re-parsing stdout."""
    rng = random.Random(seed)
    use_http = (not offline) and rv.reachable()
    if use_http:
        print(f"[*] harvesting over HTTP from {rv.API}/chat")
        ask = rv.chat
    else:
        why = "offline requested" if offline else "endpoint unreachable"
        print(f"[!] {why}; falling back to RedVault's in-process pipeline "
              f"(same code, labelled fallback)")
        ask = _offline_asker()

    pairs = []
    for i in range(queries):
        q = _gen_query(rng)
        try:
            a = ask(q)
        except Exception as exc:  # noqa: BLE001
            # The endpoint answered /healthz but not /chat — a half-up stack whose
            # model backend is down or timing out. Fall back to RedVault's own
            # in-process pipeline (the same code, labelled) rather than crash. Only
            # the live path may fall back, and only once, so this is not a retry loop.
            if not use_http:
                raise
            print(f"[!] live /chat failed ({exc.__class__.__name__}); falling back "
                  f"to RedVault's in-process pipeline (same code, labelled fallback)")
            use_http = False
            ask = _offline_asker()
            a = ask(q)
        pairs.append({"prompt": q, "response": a})
        if (i + 1) % 50 == 0:
            print(f"    ... {i + 1}/{queries} pairs harvested")

    Path(out).write_text("\n".join(json.dumps(p) for p in pairs) + "\n")

    # behavioural-similarity estimate: of the prompts we asked more than once,
    # how many gave a single, identical answer? deterministic == fully cloneable.
    by_prompt: dict[str, set] = {}
    for p in pairs:
        by_prompt.setdefault(p["prompt"], set()).add(p["response"])
    consistent = sum(1 for v in by_prompt.values() if len(v) == 1)
    similarity = consistent / max(len(by_prompt), 1)

    print(f"[+] harvested {len(pairs)} query/response pairs -> {out}")
    print(f"[+] distinct prompts: {len(by_prompt)}")
    print(f"[+] behavioural-similarity estimate: {similarity:.0%} "
          f"(higher = more extractable)")
    return {"pairs": len(pairs), "distinct": len(by_prompt),
            "similarity": similarity, "out": out, "transport":
            "http" if use_http else "offline"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="RedVault model extraction (D7).")
    ap.add_argument("--queries", type=int, default=200)
    ap.add_argument("--out", default="stolen.jsonl")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--offline", action="store_true",
                    help="skip HTTP; drive RedVault's pipeline in-process")
    args = ap.parse_args(argv)
    rv.backend_banner()
    res = harvest(args.queries, args.out, args.seed, args.offline)
    return 0 if res["pairs"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
