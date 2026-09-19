"""02 - Why the poisoned tool loads at all: the manifest trusts presence, not signature.

No model here - this is pure policy code, RedVault's own MCPServer.active_tools().
Concept 01 showed the model obeying a poisoned description; but a real MCP server
should never have let that tool load. RedVault's manifest is a mutable JSON file the
server re-reads every request. On the vulnerable build it loads any tool the file
lists, signed or not - trust is bound to the tool's PRESENCE, exactly the weak model
behind CVE-2025-54136 (MCPoison / "rug pull"). One flag, supplychain_hardened, adds
the two missing checks: reject unsigned tools, and scan descriptions for injection.
We append the real attacker manifest and read the active tool list both ways.
OWASP MCP03 + MCP05 (unsigned provenance). The control is UC9's job; here we prove
the gap. Run under the app venv: ../../../src/.venv/Scripts/python.exe 02_....py
"""
from __future__ import annotations
import json, os, sys, tempfile
from pathlib import Path

# Point RedVault at a throwaway data dir BEFORE importing it (config.py binds
# DATA_DIR at import), so add_tool() never touches the trainer's real src/data.
os.environ["REDVAULT_DATA_DIR"] = tempfile.mkdtemp(prefix="uc4_c02_")
SRC = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(SRC))
from redvault.config import Settings, SRC_DIR          # noqa: E402
from redvault.db import Database                        # noqa: E402
from redvault.mcp_tools import MCPServer                # noqa: E402

POISON = json.loads((SRC_DIR / "assets/attacks/poisoned-tool.json").read_text())


def active_names(settings):
    mcp = MCPServer(Database(), settings)
    mcp.reset_manifest()                    # start from the clean 4-tool manifest
    mcp.add_tool(POISON)                    # attacker appends one unsigned tool
    return [t["name"] for t in mcp.active_tools()]


if __name__ == "__main__":
    print("attacker appends (unsigned):", POISON["name"], " signed:", POISON.get("signed"))
    vuln = active_names(Settings(mode="vulnerable"))
    hard = active_names(Settings(mode="hardened", supplychain_hardened=True))
    print("\nvulnerable build - active tools:", vuln)
    print("hardened build   - active tools:", hard)
    print(f"\npoisoned tool loads on vulnerable? {POISON['name'] in vuln}")
    print(f"poisoned tool loads on hardened?   {POISON['name'] in hard}")
