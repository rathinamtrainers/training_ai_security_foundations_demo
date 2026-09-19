"""Tiny stdlib HTTP client for RedVault's /chat, /reset and /healthz.

One job: talk to the *running* RedVault API over plain HTTP using nothing but the
Python standard library, so the room installs nothing to drive the agent. This is a
self-contained copy for UC3 — it deliberately does NOT import from UC1/UC2's folders
or from src/. It speaks only the request/response shape that
src/redvault/api.py::ChatRequest and pipeline.chat() actually use:

    POST /chat   {"message": "...", "session": "...", "tenant": "..."}
        -> {"answer": ..., "tool_calls": [...], "labels": [...],
            "leaked_secret": bool, "retrieved": [...], "trace_id": ...}
    POST /reset  {}   -> reseeds the corpus + records (undeletes records)
    GET  /healthz     -> {"mode", "llm", "guards", "version"}

Why session AND tenant matter for UC3: RedVault stores agent memory scoped by
*tenant* (src/redvault/db.py::recall filters on tenant, not session). So a memory
planted in one session is recalled in a *different* session of the same tenant —
that cross-session persistence is the whole point of the memory-poisoning demo.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

# Where the RedVault API is. Default matches the live stack on :8000.
API = os.environ.get("REDVAULT_API", "http://localhost:8000").rstrip("/")


def _request(path: str, payload: dict | None = None, timeout: int = 60) -> dict:
    """POST json when given a payload, else GET. Fail loudly with a human
    sentence — a silent stack trace from the back of the room teaches nothing."""
    url = f"{API}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()
        except Exception:
            pass
        sys.exit(f"\nRedVault returned HTTP {exc.code} for {url}\n  body: {body}\n")
    except urllib.error.URLError as exc:
        sys.exit(
            f"\nCannot reach RedVault at {url}\n"
            f"  reason: {exc}\n"
            f"  Is the stack up? From src/ (WSL): "
            f"REDVAULT_MODE=vulnerable docker compose up -d\n"
            f"  Or the lightweight $0 path from src/: "
            f".venv/bin/python -m uvicorn redvault.api:app --port 8000\n"
            f"  Or point this demo elsewhere with REDVAULT_API=...\n"
        )


def healthz() -> dict:
    """GET /healthz — mode, llm backend, guards, version."""
    return _request("/healthz", None, timeout=5)


def reset() -> dict:
    """POST /reset — rebuild the clean corpus + records so a run starts from a
    known state (this is what undeletes the record we are about to delete)."""
    return _request("/reset", {}, timeout=30)


def chat(message: str, session: str = "default", tenant: str | None = None) -> dict:
    """Send one user turn to /chat as a given session and tenant."""
    payload: dict = {"message": message, "session": session}
    if tenant is not None:
        payload["tenant"] = tenant
    return _request("/chat", payload)
