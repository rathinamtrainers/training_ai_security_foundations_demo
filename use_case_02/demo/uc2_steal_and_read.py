#!/usr/bin/env python3
"""UC2 acceptance run — steal the model, then read a stored embedding.

Chains the two adversarial-ML attacks of use case 2 into one run and prints a
single ``UC2 RESULT: PASS/PARTIAL/FAIL`` line — the verifier's success criterion
and the thing the room watches for.

  Step 1  extraction   -> stolen.jsonl + behavioural-similarity  (LLM10, AML.T0024)
  Step 2  membership    -> reasoned stretch illustration          (AML.T0024)
  Step 3  inversion     -> reconstruct row 1 (own tenant) AND      (LLM08, AML.T0024)
                           row 5 (globex, cross-tenant) from the vector alone

PASS means: RedVault was cloned into stolen.jsonl AND private text was
reconstructed from stored vectors including the cross-tenant row — i.e. the
vulnerable posture. Against a HARDENED build the cross-tenant read is denied and
this prints FAIL *by design*: that is UC9's win, not UC2's.
"""
from __future__ import annotations

import sys

import d7_extract_model as d7
import d8_invert_embedding as d8
import membership_inference as mi
import redvault_client as rv

GLOBEX_ROW = 5   # the seeded globex confidential-pricing row (a different tenant)
OWN_ROW = 1      # an acme row the attacker's tenant owns


def _hr(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main() -> int:
    print("UC2 — Steal the model and read a stored embedding")
    rv.backend_banner()

    _hr("STEP 1 — Model extraction (LLM10 / AML.T0024): clone RedVault")
    ext = d7.harvest(queries=200, out="stolen.jsonl")

    _hr("STEP 2 — Membership inference (stretch, AML.T0024)")
    try:
        mi.run()
    except Exception as exc:   # stretch item never blocks the acceptance result
        print(f"[!] membership-inference illustration skipped: {exc}")

    _hr("STEP 3 — Embedding inversion (LLM08 / AML.T0024): read stored vectors")
    print("-- own-tenant row --")
    own = d8.invert_row(OWN_ROW, attacker_tenant="acme")
    print("\n-- cross-tenant row (attacker=acme, row belongs to globex) --")
    cross = d8.invert_row(GLOBEX_ROW, attacker_tenant="acme")

    # ---- decide the acceptance line ----
    # The headline deliverable is "stolen.jsonl clones RedVault" + "private text
    # reconstructed from a stored (cross-tenant) row", so PASS gates on those two.
    # Own-tenant inversion is shown for teaching; on a long document the shared
    # recovery threshold may surface only the salient/repeated tokens, so it is
    # reported, not required.
    extracted = ext["pairs"] > 0
    read_own = (not own.get("blocked")) and own.get("overlap", 0) > 0
    read_cross = (not cross.get("blocked")) and cross.get("overlap", 0) > 0

    _hr("UC2 acceptance")
    print(f"  extraction landed     : {extracted}  "
          f"({ext['pairs']} pairs, similarity {ext['similarity']:.0%}, "
          f"transport={ext['transport']})")
    print(f"  own-tenant inversion  : {read_own}  "
          f"(row {OWN_ROW}, overlap {own.get('overlap', 0):.0%})")
    print(f"  cross-tenant inversion: {read_cross}  "
          f"(row {GLOBEX_ROW} globex, "
          f"{'DENIED' if cross.get('blocked') else 'overlap %.0f%%' % (cross.get('overlap', 0) * 100)})")

    if extracted and read_cross:
        print(f"UC2 RESULT: PASS - cloned RedVault into stolen.jsonl "
              f"(similarity {ext['similarity']:.0%}) and reconstructed private text "
              f"from stored vectors, including a cross-tenant row.")
        return 0
    if extracted and cross.get("blocked"):
        print("UC2 RESULT: FAIL - extraction landed, but the cross-tenant read was "
              "DENIED. The store is hardened (REDVAULT_MODE=hardened / "
              "make harden-rag) — that is UC9's control, not the vulnerable posture "
              "UC2 demonstrates.")
        return 1
    if extracted or read_own or read_cross:
        print("UC2 RESULT: PARTIAL - some steps landed but not all. Check the store "
              "is seeded (cd src && make seed) and the posture is vulnerable.")
        return 1
    print("UC2 RESULT: FAIL - no attack landed. Seed the store (make seed) and, for "
          "live extraction, start the stack or run under RedVault's venv.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
