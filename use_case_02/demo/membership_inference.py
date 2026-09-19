#!/usr/bin/env python3
"""Membership inference — a reasoned STRETCH illustration (ATLAS AML.T0024).

The backlog keeps membership inference a *reasoned* item, not a built shadow-model
attack, so this is deliberately the simple, honest version of the idea: "was this
specific text indexed in the store?"

Signal: embed a candidate phrase and measure its highest cosine similarity to any
stored document vector. A phrase drawn from an indexed document shares tokens with
that document's embedding and scores materially higher than an invented phrase
that was never indexed. The *gap* between a known member and a known non-member is
the membership signal an attacker would threshold on.

This is illustrative, not a metric to trust blindly: RedVault stores whole
documents as one vector, so the separation is real but soft. The numbers below are
computed live against the seeded store — nothing is hard-coded.

  python membership_inference.py
"""
from __future__ import annotations

import numpy as np

import embed_mini as emb
import store_reader

# A phrase lifted from a seeded document (a true MEMBER of the corpus)...
MEMBER = "security awareness module before accessing customer records"
# ...and a plausible-but-never-indexed phrase (a true NON-MEMBER).
NON_MEMBER = "quarterly bonus payout schedule for summer interns"


def best_match(phrase: str) -> tuple[float, dict | None]:
    """Highest cosine of ``phrase`` to any stored document vector, and that doc."""
    qv = emb.embed(phrase)
    best_score, best_doc = 0.0, None
    for r in store_reader.all_documents():
        s = emb.cosine(qv, emb.from_bytes(r["embedding"]))
        if s > best_score:
            best_score, best_doc = s, r
    return best_score, best_doc


def run() -> dict:
    m_score, m_doc = best_match(MEMBER)
    n_score, n_doc = best_match(NON_MEMBER)
    gap = m_score - n_score

    print("[*] membership inference by nearest-neighbour confidence (stretch)")
    print(f"    MEMBER phrase     : {MEMBER!r}")
    print(f"      best cosine     : {m_score:.3f}  "
          f"(nearest doc: {m_doc['title']!r})" if m_doc else "")
    print(f"    NON-MEMBER phrase : {NON_MEMBER!r}")
    print(f"      best cosine     : {n_score:.3f}  "
          f"(nearest doc: {n_doc['title']!r})" if n_doc else "")
    print(f"    confidence gap    : {gap:+.3f} "
          f"(positive => the member is distinguishable from the non-member)")
    inferred = "member is separable" if gap > 0 else "gap too small to call"
    print(f"[+] inference: {inferred}")
    return {"member_score": m_score, "non_member_score": n_score, "gap": gap,
            "separable": gap > 0}


if __name__ == "__main__":
    run()
