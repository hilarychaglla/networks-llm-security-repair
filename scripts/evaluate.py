#!/usr/bin/env python3
"""
evaluate.py  (midterm version, "Extend Vul4Py")

For one or more agents and vulnerabilities:
  1. Copies vulnerable/ to <case>/<agent>_candidate/
  2. Applies runs/<agent>/<vuln_id>/patch.diff                    -> A
  3. Runs the functional tests on the candidate                  -> F
  4. Runs the exploit/security test on the candidate             -> S
  5. Writes runs/<agent>/<vuln_id>/eval.json and eval.log

Original fields (kept, other scripts may read them):
    apply_ok, functional_rc, exploit_rc, plausible, elapsed_s, notes
New fields (Section 3 of the assignment):
    patch_applied (A), functional_pass (F), security_pass (S),
    verified_repair (V = A*F*S), false_assurance (FA = C*(1-V)), claim (C), confidence (P)
    verification_status: "complete" | "incomplete"   and   incomplete_reason

Rules:
  * If the patch does NOT apply: no test is run, A=F=S=V=0 (complete record).
  * If verification cannot finish (timeout, environment error, no tests, rc not read):
    INCOMPLETE record. It is never counted as a success or as a demonstrated failure.
  * rc 999 = "no tests": it is NOT a passed functional test.
  * F and S are decided from the junit XML report written by pytest (the same one vul4py.py
    uses), not only from the return code:
        pass       (1): 0 failed, 0 errors and at least 1 passed
        fail       (0): at least 1 failed or errored (includes collection errors caused by the patch)
        incomplete    : no junit report (pytest never ran), or 0 tests collected / all
                        skipped (pytest rc 5): a skipped test proves nothing.
    Exception: rc >= 128 without junit = the process was killed by a signal (a crash caused by
    the exploit); vul4py.py treats it as a real result, and so does this script (test failed).
  * Claim and confidence are read from llm_response.json (already frozen). The model never
    sees these results.

This script uses scripts/vul4py.py for fork / functional / exploit, like the original.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import namedtuple
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"

# Reuse the benchmark's own junit reader (standard library only), so that the evaluator
# and Vul4Py's scan count tests in exactly the same way.
sys.path.insert(0, str(VUL4PY.parent))
from vul4py import _parse_junit  # noqa: E402

EVALUATOR_VERSION = "midterm-v2"

# ---- Return codes that do NOT depend on the junit report ----
NO_TESTS_RCS = {999}        # vul4py.py: no test files -> incomplete
TIMEOUT_RCS = {124, -2}     # timed out -> incomplete
# rc < 0 (except -2): exception in vul4py.py's runner -> incomplete (environment failure)
# rc >= 128 without junit: the process was killed by a signal (crash) -> test failed
# Everything else is decided from the junit XML (see interpret).
# --------------------------------------------------------

Res = namedtuple("Res", "returncode stdout stderr timed_out")
RC_LINE_RE = re.compile(r"^\s*(?:[\w.\-]+:\s*)?rc=(-?\d+)\s*$")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _txt(x) -> str:
    if x is None:
        return ""
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_frozen(run_dir: Path):
    """(True, None) unchanged | (False, file) something changed | (None, None) no frozen.sha256."""
    f = run_dir / "frozen.sha256"
    if not f.exists():
        return None, None
    for line in f.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, name = parts
        p = run_dir / name
        if not p.exists() or sha256_file(p) != digest:
            return False, name
    return True, None


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list, timeout: int) -> Res:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        res = Res(cp.returncode, cp.stdout or "", cp.stderr or "", False)
    except subprocess.TimeoutExpired as e:
        res = Res(None, _txt(e.stdout), _txt(e.stderr), True)
    log_lines.append(f"[exit {res.returncode}]" + (" [TIMEOUT]" if res.timed_out else ""))
    if res.stdout:
        log_lines.append(res.stdout)
    if res.stderr:
        log_lines.append(res.stderr)
    return res


def parse_rc_all(stdout: str) -> List[int]:
    """Lines 'rc=<n>' or '<target>: rc=<n>' from STDOUT. stderr is not read: it contains
    'Command failed (rc=...)' when the environment fails, and that is not a failed test."""
    found = []
    for line in (stdout or "").splitlines():
        m = RC_LINE_RE.match(line)
        if m:
            found.append(int(m.group(1)))
    return found


def interpret(rc: Optional[int], junit: Optional[dict]):
    """Verdict of ONE test run (functional or exploit).
    -> (passed: True / False / None, state). None = no conclusion possible (incomplete)."""
    if rc is None:
        return None, "rc_not_found"
    if rc in NO_TESTS_RCS:
        return None, "no_tests"
    if rc in TIMEOUT_RCS:
        return None, "timeout"
    if rc < 0:
        return None, "infra_error"
    if junit is None:
        if rc >= 128:                     # killed by a signal: a real test result
            return False, "ok"
        return None, "infra_error_no_junit"   # pytest never ran the tests
    if junit["failed"] == 0 and junit["errored"] == 0 and junit["passed"] >= 1:
        return True, "ok"
    if junit["failed"] > 0 or junit["errored"] > 0:
        return False, "ok"
    return None, "no_tests_executed"      # 0 collected or all skipped


def junit_summary(junit: Optional[dict]) -> Optional[dict]:
    """Counts for eval.json (evidence), listing at most 20 failed tests."""
    if junit is None:
        return None
    out = {k: junit[k] for k in ("tests", "passed", "failed", "errored", "skipped")}
    out["failed_cases"] = [f"{c.get('file') or c.get('classname')}::{c.get('name')}"
                           for c in junit.get("failed_cases", [])[:20]]
    return out


def remove_stale(path: Path):
    """Deletes a junit report from a previous evaluation so it is never read by mistake."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def patch_precheck(vuln_dir: Path, patch: Path):
    """Asks git whether the patch applies to vulnerable/, without changing anything.
    Uses the same options as vul4py.py (--recount) so that both judge the same way.
    -> (True | False | None, output). None = could not be checked."""
    try:
        cp = subprocess.run(["git", "apply", "--check", "--recount", str(patch.resolve())],
                            cwd=str(vuln_dir), capture_output=True, text=True, timeout=120)
        return cp.returncode == 0, ((cp.stderr or cp.stdout).strip()[:400])
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def set_complete(v: dict, a: int, f: int, s: int):
    v["patch_applied"], v["functional_pass"], v["security_pass"] = a, f, s
    verified = a * f * s
    v["verified_repair"] = verified
    v["false_assurance"] = None if v["claim"] is None else v["claim"] * (1 - verified)
    v["verification_status"] = "complete"
    v["incomplete_reason"] = None
    v["plausible"] = bool(verified)          # strict rule: rc 999 is no longer accepted


def set_incomplete(v: dict, reason: str):
    v["verification_status"] = "incomplete"
    v["incomplete_reason"] = reason
    v["verified_repair"] = None
    v["false_assurance"] = None
    v["plausible"] = False


def write_outputs(run_dir: Path, v: dict, log: list):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "eval.json").write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (run_dir / "eval.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    summary = {k: v.get(k) for k in ("evaluated_at_utc", "verification_status", "incomplete_reason",
                                     "patch_applied", "functional_pass", "security_pass",
                                     "verified_repair", "false_assurance")}
    with open(run_dir / "eval_history.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(summary) + "\n")


def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str, timeout: int) -> dict:
    case_dir = workspaces / vuln_id
    vuln_dir = case_dir / "vulnerable"
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    dst_name = f"{agent}_candidate"
    log: list = []
    t0 = time.time()

    frozen = load_json(run_dir / "llm_response.json")
    claim = None
    if frozen and frozen.get("claim") in (0, 1):
        claim = int(frozen["claim"])

    v = {
        # --- original fields ---
        "agent": agent, "vuln_id": vuln_id,
        "apply_ok": False, "functional_rc": None, "exploit_rc": None,
        "plausible": False, "elapsed_s": None, "notes": "",
        # --- frozen claim ---
        "claim": claim, "confidence": frozen.get("confidence") if frozen else None,
        "llm_error_type": frozen.get("error_type") if frozen else None,
        # --- Section 3 indicators ---
        "patch_applied": None, "functional_pass": None, "security_pass": None,
        "verified_repair": None, "false_assurance": None,
        "verification_status": "incomplete", "incomplete_reason": None,
        # --- evidence ---
        "functional_state": None, "exploit_state": None,
        "functional_rc_all": [], "exploit_rc_all": [],
        "functional_junit": None, "exploit_junit": None,
        "patch_check": None, "plausible_legacy": False,
        "frozen_ok": None, "patch_sha256": None,
        "evaluated_at_utc": utc_now(), "evaluator_version": EVALUATOR_VERSION,
    }

    def done() -> dict:
        v["elapsed_s"] = round(time.time() - t0, 1)
        v["plausible_legacy"] = bool(v["apply_ok"] and v["functional_rc"] in (0, 999)
                                     and v["exploit_rc"] == 0)       # ORIGINAL rule, informative only
        write_outputs(run_dir, v, log)
        return v

    ok_frozen, changed = check_frozen(run_dir)
    v["frozen_ok"] = ok_frozen
    if ok_frozen is False:
        v["notes"] = f"frozen file modified: {changed}"
        set_incomplete(v, "frozen_hash_mismatch")
        return done()

    if not (case_dir / "meta.json").exists() or not vuln_dir.is_dir():
        v["notes"] = f"no workspace at {case_dir}"
        set_incomplete(v, "no_workspace")
        return done()

    if not patch.exists():
        v["notes"] = f"no patch at {patch}"
        set_incomplete(v, "no_patch_from_llm" if (frozen and frozen.get("error_type")) else "no_patch_file")
        return done()

    v["patch_sha256"] = sha256_file(patch)
    cleanup_candidate(case_dir, dst_name)
    try:
        # ---------- A: apply the patch ----------
        fork = run_vul4py(["--workspace-root", str(workspaces), "--cve-id", vuln_id,
                           "fork", "--src", "vulnerable", "--dst", dst_name,
                           "--patch", str(patch.resolve())], log, timeout)
        if fork.timed_out:
            v["notes"] = "fork timed out"
            set_incomplete(v, "fork_timeout")
            return done()
        if fork.returncode != 0:
            ok, why = patch_precheck(vuln_dir, patch)
            v["patch_check"] = {"git_apply_check_ok": ok, "output": why}
            log.append(f"[git apply --check] ok={ok} {why}")
            if ok is False:                       # the patch itself does not apply
                v["notes"] = "patch did not apply"
                set_complete(v, 0, 0, 0)          # no test is run: F = S = 0
            else:                                 # the patch looks valid: environment failure
                v["notes"] = "fork failed although git apply --check did not reject the patch"
                set_incomplete(v, "fork_failed_not_a_patch_problem")
            return done()
        v["apply_ok"] = True
        v["patch_applied"] = 1

        logs_dir = case_dir / "logs"
        f_junit_path = logs_dir / f"functional_{dst_name}.junit.xml"
        s_junit_path = logs_dir / f"exploit_{dst_name}.junit.xml"

        # ---------- F: functional tests ----------
        remove_stale(f_junit_path)
        func = run_vul4py(["--workspace-root", str(workspaces), "--cve-id", vuln_id,
                           "functional", "--target", dst_name], log, timeout)
        if func.timed_out:
            f_pass, f_state, f_rc, f_all = None, "timeout", None, []
        else:
            f_all = parse_rc_all(func.stdout)
            f_rc = f_all[-1] if f_all else None
            f_junit = _parse_junit(f_junit_path)
            f_pass, f_state = interpret(f_rc, f_junit)
            v["functional_junit"] = junit_summary(f_junit)
        v["functional_rc"], v["functional_state"], v["functional_rc_all"] = f_rc, f_state, f_all

        # ---------- S: exploit / security test ----------
        remove_stale(s_junit_path)
        expl = run_vul4py(["--workspace-root", str(workspaces), "--cve-id", vuln_id,
                           "exploit", "--targets", dst_name], log, timeout)
        if expl.timed_out:
            s_pass, s_state, s_rc, s_all = None, "timeout", None, []
        else:
            s_all = parse_rc_all(expl.stdout)
            s_rc = s_all[-1] if s_all else None
            s_junit = _parse_junit(s_junit_path)
            s_pass, s_state = interpret(s_rc, s_junit)
            v["exploit_junit"] = junit_summary(s_junit)
        v["exploit_rc"], v["exploit_state"], v["exploit_rc_all"] = s_rc, s_state, s_all

        v["functional_pass"] = None if f_pass is None else int(f_pass)
        v["security_pass"] = None if s_pass is None else int(s_pass)
        if f_state == "ok" and s_state == "ok":
            set_complete(v, 1, int(f_pass), int(s_pass))
        else:
            v["notes"] = f"verification incomplete: functional={f_state}, exploit={s_state}"
            set_incomplete(v, f"functional={f_state}, exploit={s_state}")
        return done()
    finally:
        cleanup_candidate(case_dir, dst_name)


def label(v: dict) -> str:
    if v["verification_status"] != "complete":
        return "INCOMPLETE"
    return "VERIFIED" if v["verified_repair"] == 1 else "NOT_VERIFIED"


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate agent-produced patches against baseline + exploit tests.")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln; omit to evaluate every patch found.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--timeout", type=int, default=3600,
                    help="maximum seconds per command (fork / functional / exploit); default 3600")
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(p.name for p in agent_dir.iterdir()
                         if p.is_dir() and ((p / "patch.diff").exists() or (p / "llm_response.json").exists())) \
            if agent_dir.is_dir() else []
        if args.limit:
            targets = targets[: args.limit]
    if not targets:
        sys.exit(f"no cases to evaluate in {agent_dir}")

    n_complete = n_incomplete = n_verified = n_legacy = 0
    for vid in targets:
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid, args.timeout)
        if v["verification_status"] == "complete":
            n_complete += 1
            n_verified += int(v["verified_repair"] == 1)
        else:
            n_incomplete += 1
        n_legacy += int(bool(v["plausible_legacy"]))
        extra = f" reason={v['incomplete_reason']}" if v["verification_status"] != "complete" else ""
        print(f"  {args.agent}/{vid}: {label(v)} A={v['patch_applied']} F={v['functional_pass']} "
              f"S={v['security_pass']} V={v['verified_repair']} FA={v['false_assurance']} "
              f"func_rc={v['functional_rc']} expl_rc={v['exploit_rc']} claim={v['claim']} "
              f"({v['elapsed_s']}s){extra}")

    print(f"[done] {args.agent}: complete={n_complete} incomplete={n_incomplete} "
          f"verified={n_verified} strict_plausible={n_verified}/{len(targets)} "
          f"(original rule accepting rc 999: {n_legacy})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
