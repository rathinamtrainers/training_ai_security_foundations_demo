"""store_reader.py — open RedVault's vector store READ-ONLY.

The inversion and membership-inference attacks go at the store *behind* /chat,
not the chat endpoint. On a laptop that store is the SQLite file RedVault writes
at ``src/data/redvault.db`` (schema in ``src/redvault/db.py``:
``documents(id, tenant, title, text, embedding BLOB)``). On the Docker stack the
same rows live in Postgres + pgvector, carrying the identical float32 blob.

We open the file with ``mode=ro`` so a demo can *never* mutate the application it
is attacking — an attacker reading a leaked DB file has read access, and that is
all this needs. Point it elsewhere with REDVAULT_DB_PATH.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

# Default: the DB `make seed` writes, three levels up in the shared app.
_DEFAULT = Path(__file__).resolve().parents[3] / "src" / "data" / "redvault.db"


def db_path() -> Path:
    return Path(os.environ.get("REDVAULT_DB_PATH", str(_DEFAULT)))


def _connect() -> sqlite3.Connection:
    p = db_path()
    if not p.exists():
        raise SystemExit(
            f"\nNo RedVault store at {p}\n"
            f"  Seed it first. From src/ in a WSL shell:  make seed\n"
            f"  Or point this demo at a store file with REDVAULT_DB_PATH=...\n"
        )
    # read-only URI connection: the demo cannot write to the app's database.
    conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_document(row_id: int) -> dict | None:
    with _connect() as conn:
        r = conn.execute("SELECT * FROM documents WHERE id=?", (row_id,)).fetchone()
    return dict(r) if r is not None else None


def all_documents() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM documents ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def vocabulary(tokenize, tenant: str | None = None) -> list[str]:
    """The candidate word list the attacker inverts against. In the vulnerable
    store there is no tenant scoping, so the attacker sees every document's words
    (``tenant=None``). ``tenant`` restricts it to one tenant — the shape the UC9
    isolation control imposes."""
    vocab: set[str] = set()
    for r in all_documents():
        if tenant is not None and r["tenant"] != tenant:
            continue
        vocab.update(tokenize(r["text"]))
        vocab.update(tokenize(r["title"]))
    return sorted(vocab)
