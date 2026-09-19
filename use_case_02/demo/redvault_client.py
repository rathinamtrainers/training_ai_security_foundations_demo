"""redvault_client.py — a tiny stdlib HTTP client for RedVault's /chat.

Model extraction only needs the endpoint's public contract: send ``message`` in,
read ``answer`` out (``ChatRequest``/response in ``src/redvault/api.py`` and
``src/redvault/pipeline.py``). It uses nothing but the Python standard library,
so the harvest loop installs no packages — the same way an outside attacker with
only a URL would clone the model.

It also reads /healthz so every run prints which backend answered (stub vs
ollama). That honesty note decides what the room may claim: the stub is a
deterministic, GPU-free concept-prover; ollama is the real model.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("REDVAULT_API", "http://localhost:8000").rstrip("/")


def _request(path: str, payload: dict | None = None, timeout: int = 60) -> dict:
    url = f"{API}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def reachable() -> bool:
    """True if the API answers /healthz. Lets the caller decide between the live
    HTTP harvest and the offline in-process fallback without a crash."""
    try:
        _request("/healthz", timeout=5)
        return True
    except (urllib.error.URLError, OSError):
        return False


def chat(message: str) -> str:
    """One user turn. Returns just the answer string — all the harvest needs."""
    return _request("/chat", {"message": message}).get("answer", "")


def backend_banner() -> str:
    """Print mode/backend/guards from /healthz; return the backend name."""
    try:
        h = _request("/healthz", timeout=5)
    except (urllib.error.URLError, OSError):
        print(f"RedVault at {API}: unreachable (will fall back to offline pipeline)")
        return "offline"
    backend = h.get("llm", "unknown")
    print(f"RedVault at {API}: mode={h.get('mode')} backend={backend} "
          f"guards={h.get('guards')}")
    if backend == "stub":
        print("  NOTE: backend is the STUB (deterministic, GPU-free). Behavioural "
              "similarity of 100% is\n"
              "        exactly what a deterministic target looks like — maximally "
              "extractable. Set REDVAULT_LLM=ollama\n"
              "        on the API for the realistic, sampled version of this attack.")
    return backend


if __name__ == "__main__":  # tiny smoke aid, not part of the demo flow
    print(backend_banner())
    sys.exit(0)
