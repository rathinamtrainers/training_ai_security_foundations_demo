#!/usr/bin/env python3
"""03 - An embedding is not a one-way hash (OWASP LLM08, MITRE ATLAS AML.T0024).

A stored embedding is treated as safe, anonymised numbers. It is not: given the
model's vocabulary, the salient words peel straight back out of the vector. We
read ONE row's ``embedding`` BLOB and reconstruct its private words WITHOUT ever
reading the ``text`` column - so a vector-store leak is a *text* leak.

The maths is RedVault's own ``embeddings.invert`` (greedy residual: repeatedly
pick the vocabulary word that best explains what is left of the vector, subtract
it, repeat). We invert row 5 - Globex's confidential pricing row.

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
con.row_factory = sqlite3.Row

# The attacker's candidate word list = every word visible in the store.
vocab = set()
for r in con.execute("SELECT title, text FROM documents"):
    vocab |= set(emb.tokenize(r["title"])) | set(emb.tokenize(r["text"]))

row = con.execute("SELECT * FROM documents WHERE id = 5").fetchone()   # Globex pricing
target_vec = emb.from_bytes(row["embedding"])            # only ever touch the vector
recovered = emb.invert(target_vec, sorted(vocab), max_tokens=10)

original = set(emb.tokenize(row["text"]))                # used ONLY to score, after
overlap = len(set(recovered) & original) / len(original)

print(f"target row 5  title={row['title']!r}  (text column never read by the attack)")
print("reconstructed private text from the stored vector alone:")
print("    " + " ".join(recovered))
print(f"token-recovery overlap with the original : {overlap:.0%}")
print(f"vector_is_reversible : {overlap > 0}")
