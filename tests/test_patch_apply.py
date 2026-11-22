"""Aplicacion de parches con git real (scripts/vul4py.py y la comprobacion de evaluate.py).

    python -m pytest tests/ -v
"""
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import evaluate  # noqa: E402
import vul4py  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git no instalado")

# Conteos "@@ -1,9 +1,9 @@" incorrectos (el hunk tiene 3 lineas), como los escribe a veces un LLM.
WRONG_COUNTS = "--- a/pkg/m.py\n+++ b/pkg/m.py\n@@ -1,9 +1,9 @@\n a = 1\n-b = 2\n+b = 20\n c = 3\n"
BEGIN_PATCH = "*** Begin Patch\n*** Update File: pkg/m.py\n@@\n-b = 2\n+b = 20\n*** End Patch\n"


def project(tmp_path):
    d = tmp_path / "candidate" / "pkg"
    d.mkdir(parents=True)
    (d / "m.py").write_text("a = 1\nb = 2\nc = 3\n")
    return tmp_path / "candidate"


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_wrong_hunk_counts_apply_with_recount(tmp_path):
    proj = project(tmp_path)
    patch = write(tmp_path, "p.diff", WRONG_COUNTS)
    assert evaluate.patch_precheck(proj, patch)[0] is True
    vul4py.apply_unidiff_patch(proj, patch, tmp_path / "logs")
    assert (proj / "pkg" / "m.py").read_text() == "a = 1\nb = 20\nc = 3\n"


def test_begin_patch_format_still_rejected(tmp_path):
    proj = project(tmp_path)
    patch = write(tmp_path, "p.diff", BEGIN_PATCH)
    ok, why = evaluate.patch_precheck(proj, patch)
    assert ok is False and "No valid patches" in why
    with pytest.raises(RuntimeError):
        vul4py.apply_unidiff_patch(proj, patch, tmp_path / "logs")
    assert (proj / "pkg" / "m.py").read_text() == "a = 1\nb = 2\nc = 3\n"   # sin cambios
