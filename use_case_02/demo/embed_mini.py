"""embed_mini.py — a byte-for-byte replica of RedVault's embedder.

The room clones this one folder, so this file is a *copy* of
``src/redvault/embeddings.py`` — not an import. The teaching point of the whole
use case depends on it matching the app's maths exactly: the vector we invert is
the exact float32 blob RedVault stored, so if our token vectors differed by even
one bit the inversion would recover garbage. It matches, so the reconstruction is
genuine, not staged.

What the maths says, in one sentence: every token gets a fixed pseudo-random
*unit* vector seeded from a hash of the token, and a document's embedding is the
L2-normalised sum of its token vectors. Because those token vectors are
near-orthogonal, the sum still "points toward" each word it contains — which is
exactly what makes a stored embedding reversible back to its words.
"""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache

import numpy as np

# These three constants MUST match src/redvault/embeddings.py exactly.
DIM = 256
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@lru_cache(maxsize=200_000)
def token_vector(token: str) -> tuple:
    # seed = first 16 hex chars of sha256(token) -> the token's fixed identity.
    seed = int(hashlib.sha256(token.encode()).hexdigest()[:16], 16)
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(DIM)
    v /= np.linalg.norm(v) + 1e-12
    return tuple(v.tolist())


def from_bytes(blob: bytes) -> np.ndarray:
    """Turn a stored embedding BLOB back into a float32 vector. This is the same
    little-endian float32 layout whether the row came from SQLite or pgvector, so
    the attack is backend-agnostic."""
    return np.frombuffer(blob, dtype=np.float32)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def embed(text: str) -> np.ndarray:
    """Only used by the membership-inference demo (to embed a candidate phrase)."""
    toks = tokenize(text)
    if not toks:
        return np.zeros(DIM, dtype=np.float32)
    acc = np.zeros(DIM, dtype=np.float64)
    for t in toks:
        acc += np.asarray(token_vector(t))
    n = np.linalg.norm(acc)
    if n > 0:
        acc /= n
    return acc.astype(np.float32)


def invert(vec: np.ndarray, vocabulary: list[str], max_tokens: int = 40,
           threshold: float = 0.18) -> list[str]:
    """Greedy embedding inversion — the actual attack.

    Start from the stored vector as a "residual". Repeatedly pick the vocabulary
    word whose token vector best explains what is left of the residual, record it,
    and subtract it out. Stop when nothing explains the residual well enough
    (``threshold``) or we hit ``max_tokens``. The recovered list is the salient
    words of the original private text — recovered from the vector alone.
    """
    residual = np.asarray(vec, dtype=np.float64).copy()
    vocab_vecs = {w: np.asarray(token_vector(w)) for w in set(vocabulary)}
    recovered: list[str] = []
    for _ in range(max_tokens):
        best, best_score = None, threshold
        for w, wv in vocab_vecs.items():
            s = float(np.dot(residual, wv))
            if s > best_score:
                best, best_score = w, s
        if best is None:
            break
        recovered.append(best)
        residual -= np.asarray(token_vector(best))
    return recovered
