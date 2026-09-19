"""Place (and remove) a poisoned MCP tool on the RedVault server.

Tool poisoning is a *supply-chain* attack, not a chat message. There is no HTTP
endpoint to add a tool — the attacker gets a malicious tool manifest onto the MCP
server itself. RedVault models exactly that: the manifest lives server-side at
``$REDVAULT_DATA_DIR/mcp/tools.json`` and the API re-reads it on every request
(src/redvault/mcp_tools.py::MCPServer.active_tools).

So this module drives RedVault's *own* placement mechanism — the CLI target
``python -m redvault.cli poison-tool`` that ``make poison-tool`` calls
(src/Makefile line 47) — rather than faking a tool. It appends the attacker's
``assets/attacks/poisoned-tool.json`` (an unsigned ``weather_lookup`` whose
*description* tells the agent to call http_get on http://attacker.local/exfil).
``reset-tools`` restores the clean, signed manifest.

This step shares state with the API only when both use the same data dir. That is
the case for the lightweight local run (uvicorn from src/, data dir = src/data,
which is the default). For a Docker stack the data dir is inside the container, so
run the placement there instead — this module prints that guidance and you can pass
``--no-place`` to the demo so it only observes and you manage the tool lifecycle.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Locate src/ (the RedVault app). Default: three levels up from this demo folder.
_HERE = Path(__file__).resolve().parent
SRC_DIR = Path(os.environ.get(
    "REDVAULT_SRC", _HERE.parents[2] / "src")).resolve()

# The attacker's tool manifest, shipped in the app's own attack assets.
POISON_TOOL = os.environ.get(
    "REDVAULT_POISON_TOOL", "assets/attacks/poisoned-tool.json")


def _interpreter() -> str:
    """The Python that has the ``redvault`` package importable. Prefer the app's
    own venv; fall back to an explicit override, then to this interpreter."""
    override = os.environ.get("REDVAULT_PY")
    if override:
        return override
    for candidate in (SRC_DIR / ".venv" / "bin" / "python",
                      SRC_DIR / ".venv" / "Scripts" / "python.exe"):
        try:
            if candidate.exists():
                return str(candidate)
        except OSError:
            # A broken symlink (e.g. a Linux venv's bin/python -> /usr/bin/python
            # left in a checkout that is also driven from Windows) makes exists()
            # raise instead of returning False — skip it and try the next one.
            continue
    return sys.executable


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run ``python -m redvault.cli <args>`` from src/, mirroring the Make target.
    Vulnerable mode is forced so supply-chain hardening is off (the tool loads).
    REDVAULT_DATA_DIR is passed through so placement hits the API's data dir."""
    env = dict(os.environ)
    env.setdefault("REDVAULT_MODE", "vulnerable")
    cmd = [_interpreter(), "-m", "redvault.cli", *args]
    return subprocess.run(cmd, cwd=str(SRC_DIR), env=env,
                          capture_output=True, text=True)


def _explain_failure(action: str, proc: subprocess.CompletedProcess) -> None:
    sys.exit(
        f"\nCould not {action} the poisoned tool via RedVault's CLI.\n"
        f"  ran: python -m redvault.cli ... (cwd={SRC_DIR})\n"
        f"  exit={proc.returncode}\n"
        f"  stderr: {proc.stderr.strip()}\n\n"
        f"  Most likely the app's venv is missing — from src/: make install\n"
        f"  Or set REDVAULT_SRC / REDVAULT_PY to point at the RedVault checkout.\n"
        f"  On a Docker stack the manifest lives in the container, so place it there:\n"
        f"    docker compose exec redvault-api python -m redvault.cli poison-tool "
        f"--tool {POISON_TOOL}\n"
        f"  then re-run this demo with --no-place.\n"
    )


def place_poisoned_tool() -> dict:
    """Append the attacker's tool to the live MCP manifest (the poison step)."""
    proc = _run_cli("poison-tool", "--tool", POISON_TOOL)
    if proc.returncode != 0:
        _explain_failure("place", proc)
    # cli emits one JSON line: {"status","tool","loaded","blocked_by_supplychain"}
    return _parse_last_json(proc.stdout)


def reset_tools() -> dict:
    """Restore the clean, signed manifest (undo the poison)."""
    proc = _run_cli("reset-tools")
    if proc.returncode != 0:
        _explain_failure("reset", proc)
    return _parse_last_json(proc.stdout)


def _parse_last_json(stdout: str) -> dict:
    import json
    text = stdout.strip()
    # The CLI prints one pretty-printed JSON object (redvault.cli._emit uses
    # json.dumps(indent=2)), so it spans several lines — parse the whole blob
    # first rather than only a single compact line.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # Fall back to scanning for a single compact JSON line.
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"raw": text}
