"""UC4 — Poison the tools and the corpus (end-to-end).

Runs both attacks against the *running, vulnerable* RedVault and prints one
acceptance line, so the room sees the whole use case in a single command:

  D10  a poisoned MCP tool DESCRIPTION hijacks the agent on load  (MCP03)
  D12  one poisoned RAG document steers every answer              (LLM04 / LLM09)

This is the UC4 `Delivers` line from the backlog
(015_project/use_case_plan.md, row 4):
  "A poisoned MCP tool *description* hijacks the agent on load;
   one poisoned RAG doc steers all answers."

Nothing here modifies the app. D12 drives RedVault over plain HTTP; D10 also uses
RedVault's own CLI to place the poisoned tool, because tool poisoning is a
supply-chain step with no HTTP endpoint (see redvault_supplychain.py).

The posture is unchanged by this use case: RedVault is vulnerable before and after.
Both attacks land precisely because the supply-chain and RAG-ingest controls are
OFF — turning them on is UC9's job, and this same script is what UC9 replays to
prove the attacks then fail.

Run:  python uc4_poison_tools_and_corpus.py [--no-place]
"""
from __future__ import annotations

import sys

import d10_tool_poisoning as d10
import d12_rag_steering as d12
import redvault_client as rv


def main() -> int:
    place = "--no-place" not in sys.argv

    print("\n########################################################################")
    print("# UC4 — Poison the tools and the corpus")
    print("# Master AI Security (Foundations) · RedVault backlog, use case 4")
    print("########################################################################")

    health = rv.healthz()
    print(f"\nTarget: {rv.API}  |  mode={health.get('mode')}  "
          f"llm={health.get('llm')}  guards={health.get('guards')}")
    if health.get("mode") != "vulnerable":
        print("\nNOTE: posture is not 'vulnerable'. UC4 is an ATTACK use case; both\n"
              "      attacks are expected to land only on the vulnerable build.")

    d10_ok = d10.run(place=place)
    print("\n")
    d12_ok = d12.run()

    print("\n########################################################################")
    print("# UC4 acceptance")
    print("########################################################################")
    print(f"  D10 tool poisoning (MCP03)         : {'LANDED' if d10_ok else 'no'}")
    print(f"  D12 RAG steering  (LLM04/LLM09)    : {'LANDED' if d12_ok else 'no'}")

    if d10_ok and d12_ok:
        verdict = "PASS — both poisons landed against vulnerable RedVault."
        code = 0
    elif d10_ok or d12_ok:
        verdict = "PARTIAL — one poison landed; see the sections above."
        code = 1
    else:
        verdict = "FAIL — neither landed; is the stack up and in vulnerable mode?"
        code = 1
    print(f"\n  {verdict}")
    print("########################################################################\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
