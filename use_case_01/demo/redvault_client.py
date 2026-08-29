"""Tiny HTTP client for RedVault's /chat, /documents, /reset and /healthz.

One job: talk to the running RedVault API over HTTP using nothing but the Python
standard library — exactly the way RedVault itself calls Ollama (urllib), so the
room installs nothing to run these demos. Every demo file in this folder imports
these three helpers so the *one* thing they must agree on — which model backend
is answering — is decided in a single place and printed the same way everywhere.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

# Where the RedVault API is. Default matches session.md: the live stack on :8000.
API = os.environ.get("REDVAULT_API", "http://localhost:8000").rstrip("/")


def _request(path: str, payload: dict | None = None) -> dict:
    """POST json when given a payload, otherwise GET. Returns the parsed body.

    Fails loudly with a human sentence if the API is not up — a silent stack
    trace from the back of the room teaches nothing."""
    url = f"{API}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # The API answered, but with an error status (422 bad field, 500, 405…).
        # Show the code and body — that body is the most useful thing on screen
        # when a demo misbehaves live. HTTPError must be caught BEFORE URLError,
        # of which it is a subclass, or "is the stack up?" masks a real 500.
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
            f"  Or point this demo elsewhere with REDVAULT_API=...\n"
        )


def chat(message: str) -> dict:
    """Send one user turn to /chat. Response fields we use: answer, labels,
    leaked_secret, retrieved (see src/redvault/pipeline.py)."""
    return _request("/chat", {"message": message})


def add_document(title: str, text: str) -> dict:
    """Plant a knowledge-base article via the realistic ingest surface the
    browser submit page also uses (POST /documents in src/redvault/api.py)."""
    return _request("/documents", {"title": title, "text": text})


def reset() -> dict:
    """Rebuild the clean corpus (drops every submitted doc). POST /reset.

    An empty dict forces the POST method (the endpoint is @app.post and takes no
    body); without it _request would GET and the API would answer 405."""
    return _request("/reset", {})


def backend_banner() -> str:
    """Read /healthz and return the model backend ('stub' or 'ollama').

    This is the single source of truth for the honesty note every demo prints:
    the stub is a deterministic, GPU-free concept-prover, the ollama path is
    the real llama3.1. What the room may claim about a result depends on which
    one answered, so we always show it."""
    h = _request("/healthz")
    backend = h.get("llm", "unknown")
    print(f"RedVault at {API}: mode={h.get('mode')} "
          f"backend={backend} guards={h.get('guards')}")
    if backend == "stub":
        print("  NOTE: backend is the STUB (deterministic, no model). It PROVES "
              "the concept by pattern-matching;\n"
              "        it does not 'reason'. Set REDVAULT_LLM=ollama on the API "
              "for the genuine live-model attack.")
    return backend
