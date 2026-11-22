#!/usr/bin/env python3
"""
run_agent.py  (midterm version, "Extend Vul4Py")

Generates patches with an LLM and FREEZES the attempt: claim, confidence and patch.

Layout it produces (one folder per (agent, vuln_id)):
    runs/<agent>/<vuln_id>/
        prompt.txt          -- user message sent (vulnerable source code only)
        patch.diff          -- patch (unified diff against vulnerable/)
        generation.json     -- metadata (model, tokens, timing, error); compatible with the original
        llm_response.json   -- full record: original response, claim, confidence, patch,
                               model, tokens, latency, timestamp and errors
        frozen.sha256       -- hashes; check them with:  sha256sum -c frozen.sha256
The files are left READ-ONLY. A frozen case is NEVER regenerated.

Fixed prompts (--prompt-version):
    v1  the assignment's prompt, copied verbatim (official midterm result, runs/midterm)
    v2  the same request, but it fixes the output format: a JSON object with the keys
        diff / claim / confidence and the patch as a unified diff with paths relative to the
        project root. Second experimental condition approved by the instructor (runs/midterm_v2).
Each condition goes in its own --runs folder; a folder never mixes prompt versions.

Built-in agents (direct LLM call): claude, gpt
External agents (not run by this script): openhands, trae, swe
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"

BUILTIN = {"claude", "gpt"}
EXTERNAL = {"openhands", "trae", "swe"}
SCRIPT_VERSION = "midterm-v2"
FENCE = chr(96) * 3          # three backticks, without writing them literally

# --------------------------------- FIXED SETTINGS ---------------------------------
# v1: the assignment's fixed prompt, copied verbatim (including its typo "interner").
SYSTEM_PROMPT = (
    "You are a security expert and a python programmer. I will provide you with a "
    "vulnerable Python project, and you will respond with a json file that includes the diff file, "
    "your claim if the code was patched (1) or not (0), and the confidence level of your claim (0-1). "
    "You don't have access to the interner nor external tools."
)

# v2: the same request, with the output format specified. v1 did not say the diff had to be a
# unified diff, and the model answered in "*** Begin Patch" format, which git apply rejects.
SYSTEM_PROMPT_V2 = (
    "You are a security expert and a python programmer. I will provide you with a vulnerable "
    "Python project; each file starts with a line '=== FILE: <path> ===' where <path> is relative "
    "to the project root. Respond ONLY with a JSON object, with no other text, with exactly these keys: "
    "\"diff\": a patch in unified diff format, as produced by `git diff`, with headers "
    "'--- a/<path>' and '+++ b/<path>' using the same paths, and hunk headers '@@ -l,s +l,s @@'; "
    "\"claim\": 1 if your patch fixes the vulnerability, 0 otherwise; "
    "\"confidence\": the confidence level of your claim, a number between 0 and 1. "
    "You don't have access to the internet nor external tools."
)

PROMPTS = {"v1": SYSTEM_PROMPT, "v2": SYSTEM_PROMPT_V2}

EXCLUDE_DIRS = {"backported_support", ".git", ".venv", "venv", "env", ".tox", "site-packages", "node_modules",
                "build", "dist", "docs", ".eggs", "__pycache__", ".pytest_cache", ".github"}
MAX_FILES = 60
MAX_BYTES = 150_000
API_TIMEOUT_S = 300

# True : if NO response arrives from the model (network, key, rate limit), the error is logged in
#        api_errors.jsonl and the case can be run again, because no patch was ever delivered.
# False: that failure is also frozen as an incomplete case and cannot be repeated.
ALLOW_RERUN_AFTER_NO_RESPONSE = True
# ----------------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------- selection of the vulnerable code (no information about the fix) ----------

def is_test_path(rel: Path) -> bool:
    parts = [p.lower() for p in rel.parts]
    name = rel.name.lower()
    in_test_dir = any(p in ("tests", "test", "testing") or p.startswith("test") for p in parts[:-1])
    return in_test_dir or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def collect_context_files(case_dir: Path):
    """Only source code of the vulnerable project: no tests, environments, dependencies,
    meta.json or fixed/. Returns ([(path, content)], [omitted_paths])."""
    root = case_dir / "vulnerable"
    sent, omitted, total = [], [], 0
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in EXCLUDE_DIRS for part in rel.parts) or is_test_path(rel):
            continue
        data = p.read_text(encoding="utf-8", errors="ignore")
        if len(sent) >= MAX_FILES or total + len(data) > MAX_BYTES:
            omitted.append(str(rel))
            continue
        sent.append((str(rel), data))
        total += len(data)
    return sent, omitted


def build_user_prompt(files) -> str:
    # Code only: no CVE ID, no fix commit, no description, no tests.
    return "\n\n".join(f"=== FILE: {rel} ===\n{data}" for rel, data in files)


# ---------- parsing the response ----------

def extract_diff(text: str) -> str:
    """If the model wrapped the diff in a code block, removes the fences; ensures a final newline.
    Nothing else in the content is changed."""
    t = text
    s = t.strip()
    if s.startswith(FENCE):
        lines = s.splitlines()
        if lines and lines[0].startswith(FENCE):
            lines = lines[1:]
        if lines and lines[-1].strip() == FENCE:
            lines = lines[:-1]
        t = "\n".join(lines)
    return t if t.endswith("\n") else t + "\n"


def _to_claim(v) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)) and v in (0, 1):
        return int(v)
    if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes"):
        return 1
    if isinstance(v, str) and v.strip().lower() in ("0", "false", "no"):
        return 0
    raise ValueError(f"claim cannot be interpreted: {v!r}")


def parse_response(text: str):
    """Returns (patch_as_returned, patch_ready, claim, confidence, warnings) or raises ValueError.
    The v1 prompt does not name the JSON keys, so several names are accepted."""
    warnings = []
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object found in the response")
    data = json.loads(m.group(0), strict=False)
    if not isinstance(data, dict):
        raise ValueError("the JSON is not an object")

    def pick(*keys):
        for k in keys:
            if k in data:
                return data[k]
        return None

    diff = pick("diff", "patch", "diff_file")
    claim = pick("claim", "claimed_success", "patched")
    conf = pick("confidence", "confidence_level")
    if not isinstance(diff, str) or not diff.strip():
        raise ValueError("the patch (diff) is missing or is not text")
    if claim is None or conf is None:
        raise ValueError("claim or confidence is missing")
    claim = _to_claim(claim)
    conf = float(conf)
    if not 0.0 <= conf <= 1.0:
        warnings.append(f"confidence outside [0,1]: {conf}")
    patch = extract_diff(diff)
    if "@@" not in patch or "---" not in patch:
        warnings.append("the patch does not look like a unified diff (frozen anyway)")
    return diff, patch, claim, conf, warnings


# ---------- errors and LLM calls ----------

class NoResponse(Exception):
    def __init__(self, error_type: str, message: str):
        super().__init__(message)
        self.error_type = error_type
        self.message = message


def classify_error(e: Exception) -> str:
    status = getattr(e, "status_code", None)
    if status is not None:
        return f"http_{status}"          # 401, 429, 5xx...
    name = type(e).__name__
    if "Timeout" in name:
        return "timeout"
    if "Connection" in name:
        return "connection_error"
    return name


def safe_message(e: Exception, etype: str) -> str:
    if etype == "http_401":
        return "authentication failed (message omitted)"
    return re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "sk-***", str(e))[:500]


def _dump(obj):
    try:
        return obj.model_dump()
    except Exception:
        return None


def call_claude(system: str, prompt: str, model: str):
    from anthropic import Anthropic  # deferred import
    client = Anthropic()
    t0 = time.perf_counter()
    try:
        resp = client.messages.create(
            model=model, max_tokens=8192, system=system,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        et = classify_error(e)
        raise NoResponse(et, safe_message(e, et))
    latency_ms = (time.perf_counter() - t0) * 1000
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    info = {
        "provider": "anthropic", "base_url": None,
        "model_returned": getattr(resp, "model", None),
        "input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens,
        "stop_reason": resp.stop_reason, "latency_ms": round(latency_ms, 1),
        "api_response": _dump(resp),
    }
    return text, info


def call_gpt(system: str, prompt: str, model: str, temperature=None):
    from openai import OpenAI  # deferred import
    # If OPENROUTER_API_KEY is set, the original script routes through OpenRouter. This is kept,
    # but recorded (provider/base_url). The midterm uses the OpenAI API: do not set
    # OPENROUTER_API_KEY or OPENAI_BASE_URL.
    or_key = os.environ.get("OPENROUTER_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL") or ("https://openrouter.ai/api/v1" if or_key else None)
    api_key = or_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise NoResponse("missing_api_key", "no API key in the environment")
    kwargs = {"api_key": api_key, "timeout": API_TIMEOUT_S, "max_retries": 0}  # no retries
    if base_url:
        kwargs["base_url"] = base_url
    client = OpenAI(**kwargs)

    params = {"model": model,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": prompt}]}
    if temperature is not None:
        params["temperature"] = temperature

    t0 = time.perf_counter()                      # latency is measured ONLY around the request
    try:
        resp = client.chat.completions.create(**params)
    except Exception as e:
        et = classify_error(e)
        raise NoResponse(et, safe_message(e, et))
    latency_ms = (time.perf_counter() - t0) * 1000

    choice = resp.choices[0] if resp.choices else None
    usage = getattr(resp, "usage", None)
    info = {
        "provider": "openrouter" if base_url and "openrouter" in base_url else "openai",
        "base_url": base_url,
        "model_returned": getattr(resp, "model", None),
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "stop_reason": getattr(choice, "finish_reason", None),
        "latency_ms": round(latency_ms, 1),
        "api_response": _dump(resp),
    }
    text = (choice.message.content or "") if choice else ""
    return text, info


# ---------- freezing ----------

def write_frozen(out_dir: Path, record: dict, generation: dict, patch_text) -> None:
    """Saves everything, writes the hashes and makes the files read-only."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "llm_response.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "generation.json").write_text(
        json.dumps(generation, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    names = ["llm_response.json", "generation.json"]
    if (out_dir / "prompt.txt").exists():
        names.append("prompt.txt")
    if patch_text is not None:
        (out_dir / "patch.diff").write_text(patch_text, encoding="utf-8")
        names.append("patch.diff")
    lines = [f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in names]
    (out_dir / "frozen.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for n in names + ["frozen.sha256"]:
        os.chmod(out_dir / n, 0o444)


# ---------- execution ----------

def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature=None, dry_run: bool = False, prompt_version: str = "v1") -> int:
    """Returns 0 = ok, 1 = error, 2 = cannot run, 3 = already frozen."""
    vuln_dir = case_dir / "vulnerable"
    if not vuln_dir.is_dir():
        print(f"[!] {vuln_id}: {vuln_dir} does not exist", file=sys.stderr)
        return 2

    files, omitted = collect_context_files(case_dir)
    if not files:
        print(f"[!] {vuln_id}: no source code found to send", file=sys.stderr)
        return 2
    system = PROMPTS[prompt_version]
    user = build_user_prompt(files)
    print(f"[{vuln_id}] prompt {prompt_version} | files to send: {len(files)} | characters: {len(user)}")
    for rel, _ in files:
        print("    -", rel)
    if omitted:
        print(f"[warning] omitted because of the size cap: {omitted}")

    if dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "prompt_preview.txt").write_text(
            "SYSTEM:\n" + system + "\n\nUSER:\n" + user, encoding="utf-8")
        print(f"[dry-run] the API was NOT called. Preview: {out_dir / 'prompt_preview.txt'}")
        return 0

    # One attempt per case: if a record or a patch already exists, it is not regenerated.
    if (out_dir / "llm_response.json").exists() or (out_dir / "patch.diff").exists():
        print(f"[{vuln_id}] a frozen attempt or a previous patch already exists in {out_dir}. Not regenerated.")
        return 3

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    timestamp = utc_now()
    try:
        if agent == "claude":
            text, info = call_claude(system, user, model)
        else:
            text, info = call_gpt(system, user, model, temperature=temperature)
    except NoResponse as e:
        err = {"case_id": vuln_id, "agent": agent, "model_requested": model,
               "prompt_version": prompt_version,
               "timestamp_utc": timestamp, "error_type": e.error_type, "error_message": e.message}
        if ALLOW_RERUN_AFTER_NO_RESPONSE:
            with open(out_dir / "api_errors.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(err, ensure_ascii=False) + "\n")
            (out_dir / "generation.json").write_text(      # compatible with the original
                json.dumps({"agent": agent, "model": model, "error": e.error_type}, indent=2),
                encoding="utf-8")
            print(f"[!] {vuln_id}: no response from the API ({e.error_type}). "
                  "No patch was frozen; you can run it again.", file=sys.stderr)
        else:
            record = dict(err, claim=None, confidence=None, patch=None, raw_response=None,
                          script_version=SCRIPT_VERSION)
            write_frozen(out_dir, record,
                         {"agent": agent, "model": model, "error": e.error_type}, None)
            print(f"[!] {vuln_id}: API error ({e.error_type}). Frozen as incomplete.",
                  file=sys.stderr)
        return 1

    record = {
        "case_id": vuln_id, "agent": agent,
        "model_requested": model, "model_returned": info["model_returned"],
        "provider": info["provider"], "base_url": info["base_url"],
        "temperature": temperature,
        "timestamp_utc": timestamp,
        "latency_ms": info["latency_ms"],
        "input_tokens": info["input_tokens"], "output_tokens": info["output_tokens"],
        "stop_reason": info["stop_reason"],
        "prompt_version": prompt_version,
        "system_prompt": system, "system_prompt_sha256": sha256_text(system),
        "user_prompt_sha256": sha256_text(user),
        "context_files": [{"path": r, "chars": len(d)} for r, d in files],
        "context_omitted": omitted,
        "raw_response": text,
        "api_response": info["api_response"],
        "claim": None, "confidence": None, "patch": None, "patch_as_returned": None,
        "parse_error": None, "parse_warnings": [],
        "error_type": None, "error_message": None,
        "script_version": SCRIPT_VERSION,
    }
    patch_text = None
    try:
        raw_patch, patch_text, claim, conf, warns = parse_response(text)
        if info["stop_reason"] == "length":
            warns.append("response truncated by the token limit (stop_reason=length)")
        record.update(claim=claim, confidence=conf, patch=patch_text,
                      patch_as_returned=raw_patch, parse_warnings=warns)
    except (ValueError, TypeError, KeyError) as e:
        if info["stop_reason"] == "length":
            e = ValueError(f"{e} (response truncated by the token limit)")
        record.update(parse_error=str(e)[:300], error_type="invalid_response_format",
                      error_message=str(e)[:300])
        patch_text = None

    generation = {                                  # same keys as the original, plus the new ones
        "model": model, "model_returned": info["model_returned"], "provider": info["provider"],
        "input_tokens": info["input_tokens"], "output_tokens": info["output_tokens"],
        "stop_reason": info["stop_reason"], "elapsed_s": info["latency_ms"] / 1000.0,
        "latency_ms": info["latency_ms"], "agent": agent, "vuln_id": vuln_id,
        "prompt_version": prompt_version,
        "context_files": [r for r, _ in files],
        "claim": record["claim"], "confidence": record["confidence"],
        "error_type": record["error_type"],
    }
    write_frozen(out_dir, record, generation, patch_text)

    if record["error_type"]:
        print(f"[!] {vuln_id}: response received but could not be parsed ({record['parse_error']}). "
              "Frozen as incomplete; it is not regenerated.", file=sys.stderr)
        return 1
    print(f"[{vuln_id}] frozen: claim={record['claim']} confidence={record['confidence']} "
          f"latency={record['latency_ms']} ms tokens={record['input_tokens']}/{record['output_tokens']}")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(f"[external] expected {patch} produced by agent {agent}; not found.",
              file=sys.stderr)
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8")
    return 0


def existing_prompt_versions(agent_runs: Path) -> set:
    """Prompt versions already frozen in a folder (records without the field are v1)."""
    found = set()
    if agent_runs.is_dir():
        for f in agent_runs.glob("*/llm_response.json"):
            try:
                found.add(json.loads(f.read_text(encoding="utf-8")).get("prompt_version") or "v1")
            except (OSError, ValueError):
                continue
    return found


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generates patches with an LLM and freezes claim, confidence and patch.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Model (built-in agents only). "
                                    "Default: claude=claude-opus-4-7, gpt=gpt-6-luna")
    ap.add_argument("--vuln-id", help="A single vulnerability")
    ap.add_argument("--ids-file", type=Path,
                    help="File with one vuln_id per line (lines starting with # are ignored)")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Maximum number of cases to process")
    ap.add_argument("--temperature", type=float, default=None,
                    help="Temperature (NOT sent by default; use 0 to reproduce the original script)")
    ap.add_argument("--prompt-version", choices=sorted(PROMPTS), default="v1",
                    help="Fixed prompt: v1 = assignment (official), v2 = unified diff format specified")
    ap.add_argument("--dry-run", action="store_true",
                    help="Builds and saves the message WITHOUT calling the API")
    ap.add_argument("--yes-all", action="store_true",
                    help="Confirms that you want to process ALL cases in workspaces/")
    args = ap.parse_args()

    model = args.model
    if args.agent == "claude" and not model:
        model = "claude-opus-4-7"
    elif args.agent == "gpt" and not model:
        model = "gpt-6-luna"

    if args.vuln_id:
        targets = [args.vuln_id]
    elif args.ids_file:
        targets = [ln.strip() for ln in args.ids_file.read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
    else:
        if args.agent in BUILTIN and not args.dry_run and not args.yes_all:
            sys.exit("Without --vuln-id or --ids-file ALL cases would be processed (each one is a "
                     "paid API call). If that is what you want, add --yes-all.")
        targets = sorted(p.name for p in args.workspaces.iterdir()
                         if p.is_dir() and (p / "meta.json").exists())
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        sys.exit(f"no cases found in {args.workspaces}")

    if args.agent in BUILTIN and not args.dry_run:
        key_var = "ANTHROPIC_API_KEY" if args.agent == "claude" else "OPENAI_API_KEY"
        if args.agent == "gpt":
            has_key = bool(os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        else:
            has_key = bool(os.environ.get(key_var))
        if not has_key:
            sys.exit(f"{key_var} is missing from the environment. No attempt was used.")
        if args.agent == "gpt" and os.environ.get("OPENROUTER_API_KEY"):
            print("[warning] OPENROUTER_API_KEY is set: calls will go through OpenRouter, "
                  "not api.openai.com.", file=sys.stderr)

    if args.agent in BUILTIN and not args.dry_run:
        mixed = existing_prompt_versions(args.runs / args.agent) - {args.prompt_version}
        if mixed:
            sys.exit(f"{args.runs / args.agent} already contains attempts with prompt {sorted(mixed)}; "
                     f"use another --runs folder for prompt {args.prompt_version}.")

    n_ok = n_err = n_skip = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: {case_dir} does not exist; skipped", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir,
                             temperature=args.temperature, dry_run=args.dry_run,
                             prompt_version=args.prompt_version)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        elif rc == 3:
            n_skip += 1
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, already_frozen={n_skip}, total={len(targets)}")
    return 0 if n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
