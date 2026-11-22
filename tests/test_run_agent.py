"""Pruebas de scripts/run_agent.py sin llamar a la API (la llamada se simula).

    python -m pytest tests/ -v
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import run_agent  # noqa: E402

UNIFIED = "--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1,1 +1,1 @@\n-x = 1\n+x = 2\n"
BEGIN_PATCH = "*** Begin Patch\n*** Update File: pkg/mod.py\n@@\n-x = 1\n+x = 2\n*** End Patch\n"


# ------------------------------------------------------------------ parse_response

def test_parse_unified_diff_no_warnings():
    text = json.dumps({"diff": UNIFIED, "claim": 1, "confidence": 0.8})
    raw, patch, claim, conf, warns = run_agent.parse_response(text)
    assert (claim, conf, warns) == (1, 0.8, [])
    assert patch.endswith("\n")


def test_parse_begin_patch_is_frozen_with_warning():
    # El formato de los resultados v1: se congela igual, pero queda el aviso.
    text = json.dumps({"diff_file": BEGIN_PATCH, "patched": "1", "confidence_level": 0.9})
    _, _, claim, _, warns = run_agent.parse_response(text)
    assert claim == 1
    assert any("unified diff" in w for w in warns)


def test_parse_json_inside_code_fence():
    text = "```json\n" + json.dumps({"diff": UNIFIED, "claim": 0, "confidence": 0.3}) + "\n```"
    assert run_agent.parse_response(text)[2] == 0


@pytest.mark.parametrize("bad", ["sin json", json.dumps({"claim": 1, "confidence": 1}),
                                 json.dumps({"diff": UNIFIED, "claim": "quizas", "confidence": 1})])
def test_parse_invalid_raises(bad):
    with pytest.raises(ValueError):
        run_agent.parse_response(bad)


# ------------------------------------------------------------------ prompts

def test_v1_prompt_is_unchanged_from_assignment():
    assert run_agent.PROMPTS["v1"].startswith("You are a security expert and a python programmer.")
    assert "interner" in run_agent.PROMPTS["v1"]          # errata original conservada


def test_v2_prompt_fixes_format_and_keys():
    v2 = run_agent.PROMPTS["v2"]
    for needed in ("unified diff", "--- a/<path>", "+++ b/<path>", '"diff"', '"claim"', '"confidence"'):
        assert needed in v2


# ------------------------------------------------------------------ run_builtin (API simulada)

def make_case(tmp_path):
    case = tmp_path / "workspaces" / "CVE-0000-0001"
    (case / "vulnerable" / "pkg").mkdir(parents=True)
    (case / "vulnerable" / "pkg" / "mod.py").write_text("x = 1\n")
    (case / "vulnerable" / "tests").mkdir()
    (case / "vulnerable" / "tests" / "test_mod.py").write_text("def test(): pass\n")
    (case / "vulnerable" / "backported_support").mkdir()
    (case / "vulnerable" / "backported_support" / "fix.py").write_text("SOLUCION\n")
    (case / "meta.json").write_text("{}")
    return case


def fake_gpt(answer, stop="stop"):
    calls = []

    def call(system, prompt, model, temperature=None):
        calls.append({"system": system, "prompt": prompt})
        return answer, {"provider": "openai", "base_url": None, "model_returned": model,
                        "input_tokens": 10, "output_tokens": 5, "stop_reason": stop,
                        "latency_ms": 123.4, "api_response": None}
    return call, calls


def test_v2_run_freezes_record(tmp_path, monkeypatch):
    case = make_case(tmp_path)
    out = tmp_path / "runs" / "gpt" / case.name
    call, calls = fake_gpt(json.dumps({"diff": UNIFIED, "claim": 1, "confidence": 0.7}))
    monkeypatch.setattr(run_agent, "call_gpt", call)

    rc = run_agent.run_builtin("gpt", "m", case.name, case, out, prompt_version="v2")
    assert rc == 0
    rec = json.loads((out / "llm_response.json").read_text())
    assert rec["prompt_version"] == "v2"
    assert rec["system_prompt"] == run_agent.PROMPTS["v2"]
    assert (rec["claim"], rec["confidence"], rec["parse_warnings"]) == (1, 0.7, [])
    assert (out / "patch.diff").read_text() == UNIFIED
    # se envia solo codigo fuente: sin pruebas ni backported_support
    assert "pkg/mod.py" in calls[0]["prompt"]
    assert "SOLUCION" not in calls[0]["prompt"] and "test_mod" not in calls[0]["prompt"]
    # archivos congelados en solo lectura
    assert not os.stat(out / "patch.diff").st_mode & stat.S_IWUSR


def test_frozen_case_is_never_regenerated(tmp_path, monkeypatch):
    case = make_case(tmp_path)
    out = tmp_path / "runs" / "gpt" / case.name
    call, calls = fake_gpt(json.dumps({"diff": UNIFIED, "claim": 1, "confidence": 0.7}))
    monkeypatch.setattr(run_agent, "call_gpt", call)
    run_agent.run_builtin("gpt", "m", case.name, case, out, prompt_version="v2")
    assert run_agent.run_builtin("gpt", "m", case.name, case, out, prompt_version="v2") == 3
    assert len(calls) == 1                                  # la API se llamo una sola vez


def test_truncated_response_is_flagged(tmp_path, monkeypatch):
    case = make_case(tmp_path)
    out = tmp_path / "runs" / "gpt" / case.name
    call, _ = fake_gpt('{"diff": "--- a/pkg', stop="length")
    monkeypatch.setattr(run_agent, "call_gpt", call)
    assert run_agent.run_builtin("gpt", "m", case.name, case, out, prompt_version="v2") == 1
    rec = json.loads((out / "llm_response.json").read_text())
    assert rec["error_type"] == "invalid_response_format"
    assert "limite de tokens" in rec["parse_error"]


# ------------------------------------------------------------------ no mezclar prompts

def test_existing_prompt_versions(tmp_path):
    agent_runs = tmp_path / "gpt"
    (agent_runs / "A").mkdir(parents=True)
    (agent_runs / "A" / "llm_response.json").write_text(json.dumps({"claim": 1}))   # v1 antiguo
    (agent_runs / "B").mkdir()
    (agent_runs / "B" / "llm_response.json").write_text(json.dumps({"prompt_version": "v2"}))
    assert run_agent.existing_prompt_versions(agent_runs) == {"v1", "v2"}
    assert run_agent.existing_prompt_versions(tmp_path / "no_existe") == set()


def test_cli_refuses_v2_in_v1_folder(tmp_path, monkeypatch):
    make_case(tmp_path)
    old = tmp_path / "runs" / "gpt" / "CVE-OLD"
    old.mkdir(parents=True)
    (old / "llm_response.json").write_text(json.dumps({"claim": 1}))
    monkeypatch.setenv("OPENAI_API_KEY", "clave_falsa")
    monkeypatch.setattr(sys, "argv", ["run_agent.py", "--agent", "gpt", "--prompt-version", "v2",
                                      "--vuln-id", "CVE-0000-0001",
                                      "--workspaces", str(tmp_path / "workspaces"),
                                      "--runs", str(tmp_path / "runs")])
    with pytest.raises(SystemExit) as e:
        run_agent.main()
    assert "otra carpeta" in str(e.value)
