"""D6 (part 3) — read a garak report honestly.

The teaching point of this file is a WARNING, not a score. garak's HTML report
can glow green on a run whose console printed FAIL, and its detectors are often
substring matches that count a REFUSAL that quotes the forbidden phrase as a HIT.
So this reader prints per-probe COUNTS (passed / total), never a bare percentage,
and tells you where it looked.

It cannot be trusted to know the exact garak 0.15.1 JSONL schema (this demo was
written without running garak), so it is deliberately defensive: it pulls the
fields it recognises and, if an eval line has none of them, dumps the raw line
for you to read yourself.

Run (from this folder):
    python d6_read_report.py <path/to/…report.jsonl>
    python d6_read_report.py                 # search the default garak run dir
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

# garak's default output location; overridable if the trainer set XDG dirs.
DEFAULT_DIRS = [
    pathlib.Path(os.environ.get("GARAK_RUN_DIR", "")) if os.environ.get("GARAK_RUN_DIR") else None,
    pathlib.Path.home() / ".local" / "share" / "garak" / "garak_runs",
    pathlib.Path.cwd(),
]


def find_report() -> pathlib.Path | None:
    for d in DEFAULT_DIRS:
        if d and d.is_dir():
            reports = sorted(d.glob("*.report.jsonl"),
                             key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                return reports[0]
    return None


def first(d: dict, *keys):
    """Return the first present key — garak has renamed these across versions."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def main() -> None:
    if len(sys.argv) > 1:
        path = pathlib.Path(sys.argv[1])
    else:
        looked = [str(d) for d in DEFAULT_DIRS if d]
        path = find_report()
        if path is None:
            print("No *.report.jsonl found. Looked in:")
            for p in looked:
                print(f"  {p}")
            print("Pass the path garak printed:  python d6_read_report.py <file>")
            sys.exit(1)

    if not path.exists():
        sys.exit(f"No such report file: {path}")

    print(f"Reading garak report: {path}\n")
    print(f"{'probe':<34}{'detector':<28}{'passed/total':>14}")
    print("-" * 76)

    saw_eval = False
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("entry_type") != "eval":
            continue
        saw_eval = True
        probe = first(row, "probe", "probe_name", "probe_classname")
        detector = first(row, "detector", "detector_name")
        passed = first(row, "passed", "passes", "ok")
        total = first(row, "total", "instances", "attempts",
                      "total_evaluated", "total_processed")
        if probe is None or passed is None or total is None:
            print("  [eval line with an unrecognised schema — raw fields below]")
            print("  " + json.dumps(row))
            continue
        # print counts, never a lone percentage; note the direction explicitly
        landed = (total - passed) if isinstance(passed, int) and isinstance(total, int) else "?"
        print(f"{str(probe):<34}{str(detector):<28}{str(passed)+'/'+str(total):>14}"
              f"   (attacks landed: {landed})")

    print("-" * 76)
    if not saw_eval:
        print("No 'eval' entries recognised in this file. Dump the raw lines and "
              "read them by eye —\n"
              "do not report a number you could not derive.")
    print("\nHONESTY CHECKLIST before you quote any of these:")
    print("  1. Read the garak CONSOLE log too — the HTML can show green on a "
          "FAIL run.")
    print("  2. The detector is often a substring match: a refusal that quotes "
          "the banned phrase\n"
          "     scores as a HIT. Read a sample of the actual transcripts.")
    print("  3. Sample size hides holes: soft_probe_prompt_cap=10 here. A cap of "
          "50 (garak-lab.yaml)\n"
          "     can turn a 10/10 PASS into 48/50 FAIL. A baseline you keep needs "
          "a sample worth trusting.")


if __name__ == "__main__":
    main()
