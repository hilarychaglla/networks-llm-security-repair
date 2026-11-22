#!/usr/bin/env python3
"""
make_reference_patch.py  (diagnostico posterior, NO forma parte del resultado oficial)

Construye el "parche de referencia" de un caso: la correccion oficial de los autores,
como unified diff entre workspaces/<ID>/vulnerable y workspaces/<ID>/fixed, limitada a
los mismos archivos que ve el modelo: codigo fuente .py, sin pruebas, sin backported_support
y sin carpetas ocultas o de instalacion (.venv, build, ...).

Sirve como control: si la correccion oficial obtiene V = 1 con el mismo evaluador, el
instrumento funciona para ese caso y un V = 0 del modelo es atribuible a su parche. Si la
correccion oficial tampoco obtiene V = 1, el caso no es verificable con este instrumento.

Uso:
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
    """-> (texto del unified diff, lista de archivos cambiados)."""
    vul, fix = case_dir / "vulnerable", case_dir / "fixed"
    if not vul.is_dir() or not fix.is_dir():
        raise FileNotFoundError(f"faltan {vul} o {fix}")
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
    ap.add_argument("--out", type=Path, required=True, help="carpeta <runs>/<agent> de salida")
    args = ap.parse_args()
    for cid in args.ids:
        text, changed = reference_patch(args.workspaces / cid)
        d = args.out / cid
        d.mkdir(parents=True, exist_ok=True)
        (d / "patch.diff").write_text(text, encoding="utf-8")
        print(f"{cid}: {len(changed)} archivo(s): {changed}")
        if not changed:
            print(f"  [!] {cid}: la correccion oficial no cambia codigo fuente .py", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
