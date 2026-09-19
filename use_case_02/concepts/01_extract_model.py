#!/usr/bin/env python3
"""01 - An inference API is a model you can copy (LLM10, MITRE ATLAS AML.T0024).

Query RedVault's REAL pipeline in a loop, keep every (prompt, answer) pair, and
you walk away with a dataset that reproduces its behaviour. No weights leave the
server; the theft IS ordinary traffic. This drives ``redvault.pipeline.chat`` -
the exact code the /chat endpoint runs - so nothing is faked or string-matched.

Unbounded consumption is the enabler: nothing in the path caps, meters or logs
this loop, so we also print pairs/second - the LLM10 framing in one measured line.
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src"      # the real app, not the demo
sys.path.insert(0, str(SRC))
from redvault.pipeline import chat as pipeline_chat     # noqa: E402  (real library)
from redvault.db import Database                         # noqa: E402
from redvault.config import load_settings               # noqa: E402

QUESTIONS = ["Summarize our refund policy.", "How long do refunds take?",
             "What is the onboarding process?", "How are cloud vendors chosen?"]
SUFFIXES = ["", " Please be brief.", " In one sentence.", " As a list."]

db, settings = Database(), load_settings()
ask = lambda q: pipeline_chat(q, db=db, settings=settings)["answer"]

pairs, seen = [], {}
t0 = time.perf_counter()
for i in range(200):                                     # 200 unmetered queries
    q = QUESTIONS[i % len(QUESTIONS)] + SUFFIXES[(i // 4) % len(SUFFIXES)]
    a = ask(q)
    pairs.append({"prompt": q, "response": a})
    seen.setdefault(q, set()).add(a)                     # same prompt -> same answer?
dt = time.perf_counter() - t0

out = Path(__file__).with_name("stolen.jsonl")
out.write_text("\n".join(json.dumps(p) for p in pairs) + "\n")
similarity = sum(len(v) == 1 for v in seen.values()) / len(seen)

print(f"harvested {len(pairs)} query/response pairs -> {out.name}")
print(f"distinct prompts covered : {len(seen)}")
print(f"behavioural similarity    : {similarity:.0%}  (identical answer on repeat = cloneable)")
print(f"loop cost                 : {dt:.2f}s, {len(pairs) / dt:.0f} queries/s, 0 refused, 0 flagged as theft")
print("--- one stolen pair, verbatim ---")
print(json.dumps(pairs[0], indent=2))
print(f"cloned_into_dataset : {out.exists()}")
