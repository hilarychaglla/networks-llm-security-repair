#!/usr/bin/env python3
"""
make_reference_patch.py  (post-hoc diagnostic, NOT part of the official results)

Builds the "reference patch" of a case: the authors' official fix, as a unified diff between
workspaces/<ID>/vulnerable and workspaces/<ID>/fixed, limited to the same files the model
sees: .py source code, without tests, without backported_support and without hidden or
installation folders (.venv, build, ...).

It works as a control: if the official fix obtains V = 1 with the same evaluator, the
instrument works for that case and a V = 0 of the model is attributable to its patch. If the
official fix does not obtain V = 1 either, the case cannot be verified with this instrument.

Usage:
    python scripts/make_reference_patch.py --ids CVE-2023-47163 CVE-2024-6866 --out /tmp/ref/gpt
    python scripts/evaluate.py --agent gpt --runs /tmp/ref
"""
import argparse
import difflib
import sys
from pathlib import Path

EXCLUDED_DIRS = {"__pycache__", "backported_support", "venv", "env", "site-packages",
                 "build", "dist", "node_modules"}


def is_source(rel: Path) -> bool:
    for part in rel.parts:
        if (part.startswith(".") or part in EXCLUDED_DIRS or part.startswith("test")
                or part.endswith(".egg-info")):
            return False
    return rel.suffix == ".py"


def read_lines(p: Path):
    return p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if p.exists() else []


def reference_patch(case_dir: Path):
    """-> (unified diff text, list of changed files)."""
    vul, fix = case_dir / "vulnerable", case_dir / "fixed"
    if not vul.is_dir() or not fix.is_dir():
        raise FileNotFoundError(f"{vul} or {fix} is missing")
    rels = sorted({p.relative_to(vul) for p in vul.rglob("*.py")} |
                  {p.relative_to(fix) for p in fix.rglob("*.py")})
    out, changed = [], []
    for rel in rels:
        if not is_source(rel):
            continue
        a, b = read_lines(vul / rel), read_lines(fix / rel)
        if a == b:
            continue
        changed.append(rel.as_posix())
        for line in difflib.unified_diff(a, b, f"a/{rel.as_posix()}" if a else "/dev/null",
                                         f"b/{rel.as_posix()}" if b else "/dev/null"):
            out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out), changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ids", nargs="+", required=True)
    ap.add_argument("--workspaces", type=Path, default=Path("workspaces"))
    ap.add_argument("--out", type=Path, required=True, help="output folder <runs>/<agent>")
    args = ap.parse_args()
    for cid in args.ids:
        text, changed = reference_patch(args.workspaces / cid)
        d = args.out / cid
        d.mkdir(parents=True, exist_ok=True)
        (d / "patch.diff").write_text(text, encoding="utf-8")
        print(f"{cid}: {len(changed)} file(s): {changed}")
        if not changed:
            print(f"  [!] {cid}: the official fix does not change any .py source file", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
