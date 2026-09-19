#!/usr/bin/env python3
"""04 - Vector-store privacy: no tenant boundary (OWASP LLM08, cross-tenant).

Inversion (03) turns a vector into text. This is the access gap that makes it a
*cross-tenant* breach: RedVault's store has no tenant scoping in the vulnerable
posture, so a caller from tenant ``acme`` is handed tenant ``globex``'s vectors -
which 03 then reads back to "$9,000 per seat". We drive the app's REAL
``Database.search`` both ways to show the one missing argument that is the whole
control:

  * vulnerable: search(..., tenant=None)   -> globex row returned to an acme caller
  * hardened  : search(..., tenant="acme") -> globex row filtered out (UC9)

Needs: cd src && make seed   (writes src/data/redvault.db).
"""
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(SRC))
from redvault.db import Database                          # noqa: E402  (real library)

db = Database()
query = "enterprise pricing per seat"                     # an acme user's innocent query

print("VULNERABLE posture - retrieval NOT scoped to the caller's tenant (tenant=None):")
hits = db.search(query, k=3, tenant=None)
for r, score in hits:
    flag = "  <== CROSS-TENANT LEAK" if r["tenant"] != "acme" else ""
    print(f"    {score:+.3f}  tenant={r['tenant']:<7} {r['title']!r}{flag}")
leaked = any(r["tenant"] != "acme" for r, _ in hits)

print("\nHARDENED posture - retrieval scoped to the acme caller (tenant='acme'):")
for r, score in db.search(query, k=3, tenant="acme"):
    print(f"    {score:+.3f}  tenant={r['tenant']:<7} {r['title']!r}")

print(f"\ncross_tenant_row_leaked_to_acme : {leaked}")
