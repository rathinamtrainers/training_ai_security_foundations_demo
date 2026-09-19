#!/usr/bin/env python3
"""D8 — embedding inversion (OWASP LLM08, MITRE ATLAS AML.T0024).

The attack: a stored embedding is not a safe, one-way hash of private text. Given
the model's vocabulary, the salient words peel straight back out of the vector.
We read one row's ``embedding`` BLOB from RedVault's store *without ever reading
its ``text`` column*, and reconstruct the private words from the vector alone. A
vector-store leak is therefore a *text* leak.

Two rows make the point:
  * an ``acme`` row the attacker's own tenant owns, and
  * row 5, the ``globex`` confidential-pricing row — a *different* tenant. In the
    vulnerable store there is no isolation, so an ``acme`` attacker inverts it too.
    That cross-tenant reach is exactly the gap UC9 ``make harden-rag`` closes;
    against a hardened build this same call is denied (and reports ``[blocked]``).

  python d8_invert_embedding.py --row 1                 # acme, own tenant
  python d8_invert_embedding.py --row 5 --tenant acme   # cross-tenant globex row
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import embed_mini as emb
import store_reader


def _posture_is_hardened() -> bool:
    """Mirror RedVault's own tenant-isolation gate. Prefer the app's real
    load_settings (dependency-free config module); fall back to REDVAULT_MODE if
    the app is not importable. Vulnerable => cross-tenant inversion is allowed."""
    src = Path(__file__).resolve().parents[3] / "src"
    sys.path.insert(0, str(src))
    try:
        from redvault.config import load_settings
        return bool(load_settings().rag_hardened)
    except Exception:
        return os.environ.get("REDVAULT_MODE", "vulnerable").strip().lower() == "hardened"


def invert_row(row_id: int, attacker_tenant: str = "acme",
               max_tokens: int = 40) -> dict:
    """Invert one stored vector. Returns a result dict; ``blocked`` is True when a
    hardened store refuses a cross-tenant read."""
    row = store_reader.get_document(row_id)
    if row is None:
        raise SystemExit(f"[!] no document with id {row_id} "
                         f"(seed the store: cd src && make seed)")

    hardened = _posture_is_hardened()
    cross_tenant = row["tenant"] != attacker_tenant

    if hardened and cross_tenant:
        print(f"[blocked] cross-tenant vector access denied: row {row_id} belongs "
              f"to tenant '{row['tenant']}', caller is '{attacker_tenant}' "
              f"(UC9 tenant isolation)")
        return {"row": row_id, "blocked": True, "tenant": row["tenant"],
                "overlap": 0.0}

    # The attacker only ever touches the vector, never the text column.
    target_vec = emb.from_bytes(row["embedding"])
    # Attacker vocabulary: words from documents they can see. When hardened the
    # store would scope this to their own tenant; vulnerable => the whole corpus.
    vocab = store_reader.vocabulary(
        emb.tokenize, tenant=(attacker_tenant if hardened else None))
    recovered = emb.invert(target_vec, vocab, max_tokens=max_tokens)

    original = set(emb.tokenize(row["text"]))  # only to SCORE the attack, after
    overlap = len(set(recovered) & original) / max(len(original), 1)

    print(f"[+] target row {row_id} (tenant={row['tenant']}, title={row['title']!r})")
    print(f"[+] reconstructed private text from the vector alone:")
    print("    " + " ".join(recovered))
    print(f"[+] token-recovery overlap with the original: {overlap:.0%}")
    return {"row": row_id, "blocked": False, "tenant": row["tenant"],
            "recovered": recovered, "overlap": overlap}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="RedVault embedding inversion (D8).")
    ap.add_argument("--row", type=int, default=1, help="document id to invert")
    ap.add_argument("--tenant", default="acme",
                    help="attacker's own tenant (isolation scope when hardened)")
    ap.add_argument("--max-tokens", type=int, default=40)
    args = ap.parse_args(argv)
    res = invert_row(args.row, args.tenant, args.max_tokens)
    return 2 if res.get("blocked") else 0


if __name__ == "__main__":
    raise SystemExit(main())
