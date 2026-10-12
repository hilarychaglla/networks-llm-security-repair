#!/usr/bin/env python3

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
SCRIPT_VERSION = "midterm-v1"
FENCE = chr(96) * 3          # tres acentos graves, sin escribirlos literalmente

# ------------------------------- CONFIGURACION FIJA -------------------------------
# Prompt fijo del enunciado, copiado tal cual (incluida la errata "interner").
SYSTEM_PROMPT = (
    "You are a security expert and a python programmer. I will provide you with a "
    "vulnerable Python project, and you will respond with a json file that includes the diff file, "
    "your claim if the code was patched (1) or not (0), and the confidence level of your claim (0-1). "
    "You don't have access to the interner nor external tools."
)

EXCLUDE_DIRS = {"backported_support", ".git", ".venv", "venv", "env", ".tox", "site-packages", "node_modules",
                "build", "dist", "docs", ".eggs", "__pycache__", ".pytest_cache", ".github"}
MAX_FILES = 60
MAX_BYTES = 150_000
API_TIMEOUT_S = 300

# True : si NO llega ninguna respuesta del modelo (red, clave, limite de uso) se anota el error
#        en api_errors.jsonl y se puede volver a ejecutar, porque no existe ningun parche entregado.
# False: ese fallo tambien se congela como caso incompleto y no se puede repetir.
ALLOW_RERUN_AFTER_NO_RESPONSE = True
# ----------------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------- seleccion del codigo vulnerable (sin informacion del arreglo) ----------

def is_test_path(rel: Path) -> bool:
    parts = [p.lower() for p in rel.parts]
    name = rel.name.lower()
    in_test_dir = any(p in ("tests", "test", "testing") or p.startswith("test") for p in parts[:-1])
    return in_test_dir or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def collect_context_files(case_dir: Path):
    """Solo codigo fuente del proyecto vulnerable: sin tests, entornos, dependencias,
    meta.json ni fixed/. Devuelve ([(ruta, contenido)], [rutas_omitidas])."""
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
    # Solo codigo: sin id del CVE, sin commit de correccion, sin descripcion, sin pruebas.
    return "\n\n".join(f"=== FILE: {rel} ===\n{data}" for rel, data in files)


# ---------- interpretacion de la respuesta ----------

def extract_diff(text: str) -> str:
    """Si el modelo envolvio el diff en bloques de codigo, los quita; garantiza salto de linea final.
    No toca nada mas del contenido."""
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
    raise ValueError(f"claim no interpretable: {v!r}")


def parse_response(text: str):
    """Devuelve (parche_tal_como_vino, parche_listo, claim, confianza, avisos) o lanza ValueError.
    El prompt fijo no define los nombres de las claves del JSON, por eso se aceptan varios."""
    warnings = []
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no se encontro un objeto JSON en la respuesta")
    data = json.loads(m.group(0), strict=False)
    if not isinstance(data, dict):
        raise ValueError("el JSON no es un objeto")

    def pick(*keys):
        for k in keys:
            if k in data:
                return data[k]
        return None

    diff = pick("diff", "patch", "diff_file")
    claim = pick("claim", "claimed_success", "patched")
    conf = pick("confidence", "confidence_level")
    if not isinstance(diff, str) or not diff.strip():
        raise ValueError("falta el parche (diff) o no es texto")
    if claim is None or conf is None:
        raise ValueError("falta claim o confianza")
    claim = _to_claim(claim)
    conf = float(conf)
    if not 0.0 <= conf <= 1.0:
        warnings.append(f"confianza fuera de [0,1]: {conf}")
    patch = extract_diff(diff)
    if "@@" not in patch or "---" not in patch:
        warnings.append("el parche no parece un unified diff (se congela igualmente)")
    return diff, patch, claim, conf, warnings


# ---------- errores y llamadas al LLM ----------

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
    from anthropic import Anthropic  # importacion diferida
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
    from openai import OpenAI  # importacion diferida
    # Si OPENROUTER_API_KEY esta definida, el original enruta por OpenRouter. Se conserva,
    # pero queda registrado (provider/base_url). Para el midterm usa la API de OpenAI:
    # no definas OPENROUTER_API_KEY ni OPENAI_BASE_URL.
    or_key = os.environ.get("OPENROUTER_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL") or ("https://openrouter.ai/api/v1" if or_key else None)
    api_key = or_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise NoResponse("missing_api_key", "no hay clave de API en el entorno")
    kwargs = {"api_key": api_key, "timeout": API_TIMEOUT_S, "max_retries": 0}  # sin reintentos
    if base_url:
        kwargs["base_url"] = base_url
    client = OpenAI(**kwargs)

    params = {"model": model,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": prompt}]}
    if temperature is not None:
        params["temperature"] = temperature

    t0 = time.perf_counter()                      # la latencia se mide SOLO alrededor de la peticion
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


# ---------- congelado ----------

def write_frozen(out_dir: Path, record: dict, generation: dict, patch_text) -> None:
    """Guarda todo, escribe los hashes y deja los archivos en solo lectura."""
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


# ---------- ejecucion ----------

def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature=None, dry_run: bool = False) -> int:
    """Devuelve 0 = ok, 1 = error, 2 = no se puede ejecutar, 3 = ya estaba congelado."""
    vuln_dir = case_dir / "vulnerable"
    if not vuln_dir.is_dir():
        print(f"[!] {vuln_id}: no existe {vuln_dir}", file=sys.stderr)
        return 2

    files, omitted = collect_context_files(case_dir)
    if not files:
        print(f"[!] {vuln_id}: no se encontro codigo para enviar", file=sys.stderr)
        return 2
    user = build_user_prompt(files)
    print(f"[{vuln_id}] archivos a enviar: {len(files)} | caracteres: {len(user)}")
    for rel, _ in files:
        print("    -", rel)
    if omitted:
        print(f"[aviso] omitidos por tope de tamano: {omitted}")

    if dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "prompt_preview.txt").write_text(
            "SYSTEM:\n" + SYSTEM_PROMPT + "\n\nUSER:\n" + user, encoding="utf-8")
        print(f"[dry-run] NO se llamo a la API. Vista previa: {out_dir / 'prompt_preview.txt'}")
        return 0

    # Un solo intento por caso: si ya hay un registro o un parche, no se regenera.
    if (out_dir / "llm_response.json").exists() or (out_dir / "patch.diff").exists():
        print(f"[{vuln_id}] ya hay un intento congelado o un parche previo en {out_dir}. No se regenera.")
        return 3

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    timestamp = utc_now()
    try:
        if agent == "claude":
            text, info = call_claude(SYSTEM_PROMPT, user, model)
        else:
            text, info = call_gpt(SYSTEM_PROMPT, user, model, temperature=temperature)
    except NoResponse as e:
        err = {"case_id": vuln_id, "agent": agent, "model_requested": model,
               "timestamp_utc": timestamp, "error_type": e.error_type, "error_message": e.message}
        if ALLOW_RERUN_AFTER_NO_RESPONSE:
            with open(out_dir / "api_errors.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(err, ensure_ascii=False) + "\n")
            (out_dir / "generation.json").write_text(      # compatible con el original
                json.dumps({"agent": agent, "model": model, "error": e.error_type}, indent=2),
                encoding="utf-8")
            print(f"[!] {vuln_id}: sin respuesta de la API ({e.error_type}). "
                  "No hay parche congelado; puedes volver a ejecutar.", file=sys.stderr)
        else:
            record = dict(err, claim=None, confidence=None, patch=None, raw_response=None,
                          script_version=SCRIPT_VERSION)
            write_frozen(out_dir, record,
                         {"agent": agent, "model": model, "error": e.error_type}, None)
            print(f"[!] {vuln_id}: error de API ({e.error_type}). Congelado como incompleto.",
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
        "system_prompt": SYSTEM_PROMPT, "system_prompt_sha256": sha256_text(SYSTEM_PROMPT),
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
        record.update(claim=claim, confidence=conf, patch=patch_text,
                      patch_as_returned=raw_patch, parse_warnings=warns)
    except (ValueError, TypeError, KeyError) as e:
        record.update(parse_error=str(e)[:300], error_type="invalid_response_format",
                      error_message=str(e)[:300])
        patch_text = None

    generation = {                                  # mismas claves que el original, mas las nuevas
        "model": model, "model_returned": info["model_returned"], "provider": info["provider"],
        "input_tokens": info["input_tokens"], "output_tokens": info["output_tokens"],
        "stop_reason": info["stop_reason"], "elapsed_s": info["latency_ms"] / 1000.0,
        "latency_ms": info["latency_ms"], "agent": agent, "vuln_id": vuln_id,
        "context_files": [r for r, _ in files],
        "claim": record["claim"], "confidence": record["confidence"],
        "error_type": record["error_type"],
    }
    write_frozen(out_dir, record, generation, patch_text)

    if record["error_type"]:
        print(f"[!] {vuln_id}: respuesta recibida pero no interpretable ({record['parse_error']}). "
              "Congelada como incompleta; no se regenera.", file=sys.stderr)
        return 1
    print(f"[{vuln_id}] congelado: claim={record['claim']} confianza={record['confidence']} "
          f"latencia={record['latency_ms']} ms tokens={record['input_tokens']}/{record['output_tokens']}")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(f"[external] se esperaba {patch} producido por el agente {agent}; no se encontro.",
              file=sys.stderr)
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Genera parches con un LLM y congela claim, confianza y parche.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Modelo (solo agentes integrados). "
                                    "Por defecto: claude=claude-opus-4-7, gpt=gpt-6-luna")
    ap.add_argument("--vuln-id", help="Una vulnerabilidad concreta")
    ap.add_argument("--ids-file", type=Path,
                    help="Archivo con un vuln_id por linea (las lineas con # se ignoran)")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Tope de casos a procesar")
    ap.add_argument("--temperature", type=float, default=None,
                    help="Temperatura (por defecto NO se envia; usa 0 para reproducir el original)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Construye el mensaje y lo guarda, SIN llamar a la API")
    ap.add_argument("--yes-all", action="store_true",
                    help="Confirma que quieres recorrer TODOS los casos de workspaces/")
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
            sys.exit("Sin --vuln-id ni --ids-file se recorreria TODOS los casos (cada uno es una "
                     "llamada de pago a la API). Si es lo que quieres, agrega --yes-all.")
        targets = sorted(p.name for p in args.workspaces.iterdir()
                         if p.is_dir() and (p / "meta.json").exists())
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        sys.exit(f"no se encontraron casos en {args.workspaces}")

    if args.agent in BUILTIN and not args.dry_run:
        key_var = "ANTHROPIC_API_KEY" if args.agent == "claude" else "OPENAI_API_KEY"
        if args.agent == "gpt":
            has_key = bool(os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        else:
            has_key = bool(os.environ.get(key_var))
        if not has_key:
            sys.exit(f"Falta {key_var} en el entorno. No se ha consumido ningun intento.")
        if args.agent == "gpt" and os.environ.get("OPENROUTER_API_KEY"):
            print("[aviso] OPENROUTER_API_KEY esta definida: las llamadas iran por OpenRouter, "
                  "no por api.openai.com.", file=sys.stderr)

    n_ok = n_err = n_skip = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: no existe {case_dir}; se omite", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir,
                             temperature=args.temperature, dry_run=args.dry_run)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        elif rc == 3:
            n_skip += 1
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, ya_congelados={n_skip}, total={len(targets)}")
    return 0 if n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
