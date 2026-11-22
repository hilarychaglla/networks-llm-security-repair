"""VRR and FAR of scripts/aggregate_results.py against the example in Section 3 of the assignment.

    python -m pytest tests/ -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from aggregate_results import compute_metrics  # noqa: E402


def rec(case, c, v, status="complete"):
    fa = "" if status != "complete" else c * (1 - v)
    return {"case_id": case, "prompt_version": "v2", "claim": c,
            "verified_repair": v if status == "complete" else "", "false_assurance": fa,
            "verification_status": status,
            "incomplete_reason": "" if status == "complete" else "functional=timeout, exploit=timeout"}


# Assignment table: (C, V) per case -> VRR = 2/5 = 40 %, FAR = 2/4 = 50 %
EXAMPLE = [rec(1, 1, 1), rec(2, 1, 0), rec(3, 1, 0), rec(4, 0, 0), rec(5, 1, 1)]


def test_assignment_example():
    m = compute_metrics(EXAMPLE)
    assert (m["N"], m["claims"], m["verified"], m["false_assurances"]) == (5, 4, 2, 2)
    assert m["VRR"] == pytest.approx(0.40)
    assert m["FAR"] == pytest.approx(0.50)


def test_incomplete_records_are_excluded_from_N_and_listed():
    records = EXAMPLE[:4] + [rec(5, 1, 1, status="incomplete")]
    m = compute_metrics(records)
    assert (m["N_total"], m["N"], m["n_incomplete"]) == (5, 4, 1)
    assert m["incomplete"][0]["case_id"] == 5
    assert m["VRR"] == pytest.approx(1 / 4)        # 25 %
    assert m["FAR"] == pytest.approx(2 / 3)        # 66.7 %


def test_far_undefined_without_positive_claims():
    m = compute_metrics([rec(1, 0, 0), rec(2, 0, 0)])
    assert m["FAR"] is None                        # "undefined", never 0 %
    assert m["VRR"] == 0


def test_all_false_assurance_like_v1():
    m = compute_metrics([rec(i, 1, 0) for i in range(5)])
    assert (m["VRR"], m["FAR"]) == (0, 1)
