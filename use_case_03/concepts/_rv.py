"""Shared bootstrap for the UC3 concept examples.

It does two things, in the order that matters, BEFORE any `redvault` import:

  1. Force REDVAULT_DATA_DIR to a throwaway temp dir, so these examples never
     touch the trainer's real src/data/ (we delete a record and poison memory
     below). config.py computes DATA_DIR at import time, so this must happen
     first — the same ordering src/tests/conftest.py keeps.
  2. Put <repo>/src on sys.path so `from redvault import ...` loads the REAL app
     modules — the exact code the running RedVault and the UC3 demo lean on.

This file is the UC3 analogue of UC1's `_model.py`. It
imports NOTHING from ../demo/ — sharing the app's library is not sharing the
demo's code.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# 1. isolate our data dir (force, do not setdefault — never touch real lab state)
os.environ["REDVAULT_DATA_DIR"] = tempfile.mkdtemp(prefix="uc3_concept_")
os.environ.setdefault("REDVAULT_MODE", "vulnerable")

# 2. make the real app package importable
_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
