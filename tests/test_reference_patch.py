"""Tests of scripts/make_reference_patch.py (diagnostic reference control)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from make_reference_patch import is_source, reference_patch  # noqa: E402


def test_only_source_files_are_included():
    assert is_source(Path("pkg/core.py"))
    assert is_source(Path("remarshal.py"))
    for excluded in ("tests/test_a.py", "pkg/tests/test_io.py", "test_x.py", ".venv/lib/x.py",
                     "backported_support/fix.py", "build/lib/pkg/core.py", "pkg.egg-info/x.py",
                     "README.md"):
        assert not is_source(Path(excluded)), excluded


def test_reference_patch_contains_only_the_source_change(tmp_path):
    for version, body in (("vulnerable", "x = 1\n"), ("fixed", "x = 2\n")):
        (tmp_path / version / "pkg").mkdir(parents=True)
        (tmp_path / version / "pkg" / "core.py").write_text(body)
        (tmp_path / version / "tests").mkdir()
        (tmp_path / version / "tests" / "test_core.py").write_text(f"# {version}\n")
        (tmp_path / version / ".venv").mkdir()
        (tmp_path / version / ".venv" / "lib.py").write_text(f"# {version}\n")
    text, changed = reference_patch(tmp_path)
    assert changed == ["pkg/core.py"]
    assert "--- a/pkg/core.py" in text and "+x = 2" in text and "test_core" not in text
