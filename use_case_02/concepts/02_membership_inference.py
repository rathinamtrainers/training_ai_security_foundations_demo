#!/usr/bin/env python3
"""02 - Membership inference: was this text in the store? (MITRE ATLAS AML.T0024).

A vector store leaks facts about its private corpus through *confidence* alone.
Embed a candidate phrase with RedVault's REAL embedder and take its highest cosine
to any stored vector. A phrase lifted from an indexed document shares tokens with
that document's embedding and scores materially higher than an invented phrase
that was never indexed. The GAP between a known member and a known non-member is
the signal an attacker thresholds on to decide "is this record in your store?".

Reads the seeded store read-only; the maths is the app's own embeddings module.
Needs: cd src && make seed   (writes src/data/redvault.db).
"""
from __future__ import annotations
import sqlite3, sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(SRC))
from redvault import embeddings as emb                   # noqa: E402  (real library)

DB = SRC / "data" / "redvault.db"
con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)   # read-only
STORE = [emb.from_bytes(b) for (b,) in con.execute("SELECT embedding FROM documents")]

MEMBER = "security awareness module before accessing customer records"   # in a seeded doc
NON_MEMBER = "quarterly bonus payout schedule for summer interns"        # never indexed

def best_cosine(phrase: str) -> float:
    qv = emb.embed(phrase)
    return max(emb.cosine(qv, v) for v in STORE)

m, n = best_cosine(MEMBER), best_cosine(NON_MEMBER)
print(f"MEMBER phrase     : {MEMBER!r}")
print(f"  best cosine     : {m:.3f}")
print(f"NON-MEMBER phrase : {NON_MEMBER!r}")
print(f"  best cosine     : {n:.3f}")
print(f"confidence gap    : {m - n:+.3f}  (positive => the member is distinguishable)")
print(f"member_is_separable : {m - n > 0}")
