"""Tests of the verdict rules of scripts/evaluate.py (A, F, S, V, FA).

They neither call the API nor run Vul4Py: the outputs of vul4py.py and the junit XML reports
written by pytest are simulated. Run from the repository root:

    python -m pytest tests/ -v
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import evaluate  # noqa: E402
from evaluate import interpret  # noqa: E402


def junit(tests=0, failed=0, errored=0, skipped=0):
    passed = max(0, tests - failed - errored - skipped)
    return {"tests": tests, "passed": passed, "failed": failed,
            "errored": errored, "skipped": skipped, "failed_cases": []}


# ---------------------------------------------------------------- interpret()

@pytest.mark.parametrize("rc, j, expected", [
    (0, junit(tests=10), (True, "ok")),                          # all passed
    (1, junit(tests=10, failed=2), (False, "ok")),               # failed tests
    (2, junit(tests=1, errored=1), (False, "ok")),               # collection error (e.g. syntax broken by the patch)
    (0, junit(tests=5, skipped=5), (None, "no_tests_executed")), # all skipped: proves nothing
    (5, junit(tests=0), (None, "no_tests_executed")),            # pytest rc 5: 0 tests collected
    (4, None, (None, "infra_error_no_junit")),                   # pytest never ran
    (3, None, (None, "infra_error_no_junit")),
    (999, None, (None, "no_tests")),                             # vul4py: no test files
    (124, None, (None, "timeout")),
    (-2, None, (None, "timeout")),
    (-1, None, (None, "infra_error")),                           # exception in the runner
    (139, None, (False, "ok")),                                  # SIGSEGV: crash caused by the exploit
    (None, None, (None, "rc_not_found")),
])
def test_interpret(rc, j, expected):
    assert interpret(rc, j) == expected


def test_rc_zero_without_junit_is_incomplete():
    # rc 0 without a junit report: no evidence that any test ran.
    assert interpret(0, None) == (None, "infra_error_no_junit")


# --------------------------------------------- junit reader reused from vul4py

JUNIT_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="1" skipped="1" tests="4">
<testcase classname="tests.test_a" name="test_ok" file="tests/test_a.py"/>
<testcase classname="tests.test_a" name="test_ok2" file="tests/test_a.py"/>
<testcase classname="tests.test_a" name="test_skip"><skipped/></testcase>
<testcase classname="tests.test_a" name="test_bad" file="tests/test_a.py"><failure message="x"/></testcase>
</testsuite></testsuites>"""


def test_parse_junit_and_summary(tmp_path):
    p = tmp_path / "functional_gpt_candidate.junit.xml"
    p.write_text(JUNIT_XML)
    j = evaluate._parse_junit(p)
    assert (j["tests"], j["passed"], j["failed"], j["skipped"]) == (4, 2, 1, 1)
    assert interpret(1, j) == (False, "ok")
    s = evaluate.junit_summary(j)
    assert s["failed_cases"] == ["tests/test_a.py::test_bad"]


def test_missing_or_corrupt_junit_is_none(tmp_path):
    assert evaluate._parse_junit(tmp_path / "missing.junit.xml") is None
    bad = tmp_path / "broken.junit.xml"
    bad.write_text("<testsuites><testsuite")
    assert evaluate._parse_junit(bad) is None


# ------------------------------------------ evaluate_one() end to end (simulated)

CID = "CVE-0000-0001"


def make_case(tmp_path, claim=1):
    ws, runs = tmp_path / "workspaces", tmp_path / "runs"
    case = ws / CID
    (case / "vulnerable").mkdir(parents=True)
    (case / "meta.json").write_text("{}")
    run_dir = runs / "gpt" / CID
    run_dir.mkdir(parents=True)
    (run_dir / "patch.diff").write_text("--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n")
    (run_dir / "llm_response.json").write_text(json.dumps({"claim": claim, "confidence": 0.9}))
    return ws, runs, case


def fake_vul4py(case, fork_rc=0, func=(0, None), expl=(0, None), stale=False):
    """Simulates vul4py.py. func/expl = (printed rc, junit content or None)."""
    logs = case / "logs"
    logs.mkdir(exist_ok=True)
    if stale:   # a "passed" junit report left over from a previous evaluation
        (logs / "functional_gpt_candidate.junit.xml").write_text(xml(tests=3))
        (logs / "exploit_gpt_candidate.junit.xml").write_text(xml(tests=1))

    def run(args, log_lines, timeout):
        cmd = args[args.index("--cve-id") + 2]
        if cmd == "fork":
            return evaluate.Res(fork_rc, "", "", False)
        rc, content = func if cmd == "functional" else expl
        name = "functional" if cmd == "functional" else "exploit"
        if content is not None:
            (logs / f"{name}_gpt_candidate.junit.xml").write_text(content)
        out = f"  rc={rc}\n" if cmd == "functional" else f"  gpt_candidate: rc={rc}\n"
        return evaluate.Res(0, out, "", False)
    return run


def xml(tests=0, failures=0, errors=0, skipped=0):
    return (f'<testsuites><testsuite tests="{tests}" failures="{failures}" '
            f'errors="{errors}" skipped="{skipped}"/></testsuites>')


def evaluate_with(tmp_path, monkeypatch, claim=1, **kw):
    ws, runs, case = make_case(tmp_path, claim)
    monkeypatch.setattr(evaluate, "run_vul4py", fake_vul4py(case, **kw))
    monkeypatch.setattr(evaluate, "patch_precheck", lambda v, p: (False, "corrupt patch"))
    return evaluate.evaluate_one(ws, runs, "gpt", CID, timeout=60)


def test_verified_repair(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, func=(0, xml(tests=8)), expl=(0, xml(tests=1)))
    assert v["verification_status"] == "complete"
    assert (v["patch_applied"], v["functional_pass"], v["security_pass"]) == (1, 1, 1)
    assert (v["verified_repair"], v["false_assurance"]) == (1, 0)
    assert v["functional_junit"]["passed"] == 8


def test_security_fails_gives_false_assurance(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, func=(0, xml(tests=8)), expl=(1, xml(tests=1, failures=1)))
    assert (v["functional_pass"], v["security_pass"], v["verified_repair"], v["false_assurance"]) == (1, 0, 0, 1)


def test_claim_zero_no_false_assurance(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, claim=0, func=(1, xml(tests=8, failures=3)), expl=(0, xml(tests=1)))
    assert (v["verified_repair"], v["false_assurance"]) == (0, 0)


def test_patch_not_applied(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, fork_rc=1)
    assert v["verification_status"] == "complete"
    assert (v["patch_applied"], v["functional_pass"], v["security_pass"], v["false_assurance"]) == (0, 0, 0, 1)


def test_all_skipped_is_incomplete_not_success(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, func=(0, xml(tests=4, skipped=4)), expl=(0, xml(tests=1)))
    assert v["verification_status"] == "incomplete"
    assert v["verified_repair"] is None and v["false_assurance"] is None
    assert "no_tests_executed" in v["incomplete_reason"]


def test_pytest_rc5_is_incomplete(tmp_path, monkeypatch):
    v = evaluate_with(tmp_path, monkeypatch, func=(0, xml(tests=8)), expl=(5, xml(tests=0)))
    assert v["verification_status"] == "incomplete"


def test_stale_junit_is_never_read(tmp_path, monkeypatch):
    # vul4py "fails" without writing junit; the old passed report must NOT count.
    v = evaluate_with(tmp_path, monkeypatch, stale=True, func=(4, None), expl=(4, None))
    assert v["verification_status"] == "incomplete"
    assert v["functional_junit"] is None
