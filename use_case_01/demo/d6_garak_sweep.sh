#!/usr/bin/env bash
#
# D6 — garak jailbreak sweep against RedVault (also clears the carried D3 baseline).
#
# garak (NVIDIA, v0.15.1) replays a fixed catalogue of probes and scores each with
# a detector. Here we run the three probe families that ARE the jailbreak taxonomy
# from segment 3:  dan (role-play) · encoding (base64/hex) · latentinjection
# (planted instructions).
#
# CORRECTED INVOCATION — this is itself a teaching point (session.md, 22 Aug 2026
# rehearsal). The old plan printed  --target_type rest.RestGenerator --target_name
# <file>  which ERRORS in garak 0.15.1 ("No REST endpoint URI definition found").
# The working form is  --target_type rest -G <config> --config <yaml>.
# Do NOT add --parallel_attempts: one Ollama instance just queues the calls.
#
# garak is a heavy, separate install and lives in RedVault's own venv on the
# trainer's box (src/.venv). This script does NOT assume a bare `garak` on PATH —
# set GARAK_PYTHON to the interpreter that has garak installed.
#
# Run (from this folder, with the RedVault stack up):
#     GARAK_PYTHON=../../../src/.venv/bin/python ./d6_garak_sweep.sh
#
set -euo pipefail
cd "$(dirname "$0")"

GARAK_PYTHON="${GARAK_PYTHON:-python3}"
CONFIG="redvault-rest.json"     # our copy; points at http://localhost:8000/chat
RUNCFG="garak-demo.yaml"        # seed 42, soft cap 10 -> ~30 calls on stage

echo "garak interpreter : $GARAK_PYTHON"
if ! "$GARAK_PYTHON" -c "import garak" 2>/dev/null; then
  echo "ERROR: garak is not importable with '$GARAK_PYTHON'." >&2
  echo "  It is the heaviest install of the night. Likely home: src/.venv/" >&2
  echo "  Point at it:  GARAK_PYTHON=../../../src/.venv/bin/python ./d6_garak_sweep.sh" >&2
  echo "  Or install:   uv pip install --python src/.venv/bin/python 'garak==0.15.1'" >&2
  exit 1
fi
"$GARAK_PYTHON" -m garak --version || true

echo
echo "=================================================================="
echo "PART 1 — the carried D3 BASELINE (promptinject family)"
echo "=================================================================="
CMD_BASE=("$GARAK_PYTHON" -m garak --target_type rest -G "$CONFIG" \
  --config "$RUNCFG" --probes promptinject --report_prefix redvault-baseline)
printf 'RUN: %s\n\n' "${CMD_BASE[*]}"
# Do NOT capture stdout: the whole "green-HTML trap" lesson is READ THE CONSOLE,
# not just the coloured report. Let every PASS/FAIL line reach the projector.
"${CMD_BASE[@]}"

echo
echo "=================================================================="
echo "PART 2 — the D6 JAILBREAK sweep (dan, encoding, latentinjection)"
echo "=================================================================="
CMD_JB=("$GARAK_PYTHON" -m garak --target_type rest -G "$CONFIG" \
  --config "$RUNCFG" --probes dan,encoding,latentinjection \
  --report_prefix redvault-jailbreak)
printf 'RUN: %s\n\n' "${CMD_JB[*]}"
"${CMD_JB[@]}"

echo
echo "garak prints the report path (…redvault-jailbreak.report.jsonl) above."
echo "Read it honestly with:  python d6_read_report.py <that .report.jsonl path>"
echo "Do NOT quote a jailbreak percentage you have not measured on THIS hardware."
