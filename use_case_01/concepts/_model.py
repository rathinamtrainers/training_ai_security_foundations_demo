"""Tiny REAL client for the local model the course actually runs.

One job: send one (system, user) turn to Ollama's /api/chat and return the
model's genuine text. No stub, no string-match, no canned reply — the same live
llama3.1 that answers RedVault on the live stack (src/redvault/llm.py routes to
this exact Ollama HTTP API). Stdlib only (urllib), exactly as RedVault calls
Ollama, so a concept file installs nothing.

Needs, in one command from src/ (or anywhere):  ollama pull llama3.1
and the daemon up (it runs as a service; `ollama serve` if not). On a 16 GB
laptop use MODEL=llama3.1:1b to fit; the behaviour is the same, the prose weaker.
"""
from __future__ import annotations
import json, os, sys, urllib.error, urllib.request

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
if not OLLAMA.startswith("http"):            # env may hold a bare host:port
    OLLAMA = "http://" + OLLAMA
if OLLAMA.startswith("http://0.0.0.0"):      # a bind address is not a dial address
    OLLAMA = OLLAMA.replace("0.0.0.0", "localhost")
MODEL = os.environ.get("MODEL", "llama3.1")


def ask(system: str, user: str) -> str:
    """Return the model's real answer to one system+user turn (temperature 0)."""
    body = {
        "model": MODEL, "stream": False,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "options": {"temperature": 0},
    }
    req = urllib.request.Request(
        f"{OLLAMA}/api/chat", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["message"]["content"]
    except urllib.error.URLError as e:
        sys.exit(f"\nCannot reach Ollama at {OLLAMA} ({e}).\n"
                 f"  Start it and pull the model:  ollama pull {MODEL}\n")
