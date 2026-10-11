#!/usr/bin/env python3
"""aggregate_results.py  (version del midterm "Extend Vul4Py")

Reune, para los casos indicados, el registro congelado del LLM (llm_response.json) y el resultado
de la verificacion (eval.json), y calcula VRR y FAR exactamente como la Seccion 3 del enunciado:

    V_i  = A_i * F_i * S_i                  (reparacion verificada)
    FA_i = C_i * (1 - V_i)                  (falsa seguridad)
    VRR  = sum(V_i) / N
    FAR  = sum(FA_i) / sum(C_i)             si sum(C_i) > 0; si no: "undefined (no positive repair claims)"

N = observaciones COMPLETAS. Los registros incompletos NO entran en N: se listan aparte, con su motivo.
Los intentos fallidos (parche que no aplica, pruebas que fallan) se CONSERVAN: son observaciones completas.

Salidas (en --out-dir): results.csv, results_table.md, metrics.json

Uso:
  python scripts/aggregate_results.py --runs runs/midterm --agents gpt --ids-file submission/selected_ids.txt
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

COLS = ["case_id", "agent", "model", "timestamp_utc",
        "claim", "confidence", "patch_applied", "functional_pass", "security_pass",
        "verified_repair", "false_assurance", "latency_ms", "input_tokens", "output_tokens",
        "verification_status", "incomplete_reason", "error_type",
        "functional_rc", "exploit_rc", "patch_sha256"]


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record_for(runs: Path, agent: str, vid: str) -> dict:
    run_dir = runs / agent / vid
    gen = load_json(run_dir / "llm_response.json") or {}
    ev = load_json(run_dir / "eval.json")

    rec = {c: "" for c in COLS}
    rec.update(case_id=vid, agent=agent,
               model=gen.get("model_requested", ""), timestamp_utc=gen.get("timestamp_utc", ""),
               latency_ms=gen.get("latency_ms", ""), input_tokens=gen.get("input_tokens", ""),
               output_tokens=gen.get("output_tokens", ""),
               error_type=gen.get("error_type") or "")

    if ev is None:
        rec["verification_status"] = "incomplete"
        if not gen and (run_dir / "api_errors.jsonl").exists():
            rec["incomplete_reason"] = "api_error_no_response"
        elif not gen:
            rec["incomplete_reason"] = "no_llm_response"
        else:
            rec["incomplete_reason"] = "not_evaluated"
        return rec

    claim = ev.get("claim")
    if claim not in (0, 1):
        claim = gen.get("claim") if gen.get("claim") in (0, 1) else None
    rec.update(claim="" if claim is None else claim,
               confidence=ev.get("confidence", gen.get("confidence", "")),
               patch_applied=_s(ev.get("patch_applied")), functional_pass=_s(ev.get("functional_pass")),
               security_pass=_s(ev.get("security_pass")), verified_repair=_s(ev.get("verified_repair")),
               false_assurance=_s(ev.get("false_assurance")),
               verification_status=ev.get("verification_status", "incomplete"),
               incomplete_reason=ev.get("incomplete_reason") or "",
               functional_rc=_s(ev.get("functional_rc")), exploit_rc=_s(ev.get("exploit_rc")),
               patch_sha256=ev.get("patch_sha256") or "")

    patch = run_dir / "patch.diff"
    # El eval.json debe corresponder al parche congelado actual.
    if patch.exists() and ev.get("patch_sha256") and sha256_file(patch) != ev["patch_sha256"]:
        _mark_incomplete(rec, "stale_eval_patch_changed")
    elif rec["verification_status"] == "complete":
        if rec["claim"] == "":
            _mark_incomplete(rec, "missing_claim")
        elif rec["verified_repair"] == "":
            _mark_incomplete(rec, "missing_verified")
    return rec


def _s(x):
    return "" if x is None else x


def _mark_incomplete(rec: dict, reason: str):
    rec["verification_status"] = "incomplete"
    rec["incomplete_reason"] = reason
    rec["verified_repair"] = ""
    rec["false_assurance"] = ""


def compute_metrics(records: list) -> dict:
    done = [r for r in records if r["verification_status"] == "complete"]
    incomplete = [r for r in records if r["verification_status"] != "complete"]
    n = len(done)
    claims = sum(int(r["claim"]) for r in done)
    verified = sum(int(r["verified_repair"]) for r in done)
    false_assur = sum(int(r["false_assurance"]) for r in done)
    return {
        "N_total": len(records), "N": n, "n_incomplete": len(incomplete),
        "incomplete": [{"case_id": r["case_id"], "reason": r["incomplete_reason"]} for r in incomplete],
        "claims": claims, "verified": verified, "false_assurances": false_assur,
        "VRR": (verified / n) if n else None,
        "FAR": (false_assur / claims) if claims else None,
    }


def report(m: dict) -> str:
    vrr = "undefined (no completed observations)" if m["VRR"] is None else f"{100 * m['VRR']:.1f}%"
    far = ("undefined (no positive repair claims)" if m["FAR"] is None
           else f"{100 * m['FAR']:.1f}%")
    lines = [f"Completed observations used as N: {m['N']} of {m['N_total']}",
             f"Incomplete observations: {m['n_incomplete']}"]
    for it in m["incomplete"]:
        lines.append(f"  - {it['case_id']}: {it['reason']}")
    lines += [f"Positive claims (sum C): {m['claims']}",
              f"Verified repairs (sum V): {m['verified']}",
              f"False assurances (sum FA): {m['false_assurances']}",
              f"VRR = {vrr}",
              f"FAR = {far}"]
    if m["n_incomplete"]:
        lines.append(f"AVISO: ejecucion incompleta; las metricas usan N = {m['N']}, no {m['N_total']}.")
    return "\n".join(lines)


def md_table(records: list) -> str:
    head = ["case_id", "claim C", "conf P", "A", "F", "S", "V", "FA", "latency_ms",
            "in_tok", "out_tok", "status"]
    out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in records:
        status = r["verification_status"] + (f" ({r['incomplete_reason']})" if r["incomplete_reason"] else "")
        vals = [r["case_id"], r["claim"], r["confidence"], r["patch_applied"], r["functional_pass"],
                r["security_pass"], r["verified_repair"], r["false_assurance"], r["latency_ms"],
                r["input_tokens"], r["output_tokens"], status]
        out.append("| " + " | ".join("-" if v == "" or v is None else str(v) for v in vals) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Agrega resultados y calcula VRR y FAR.")
    ap.add_argument("--runs", type=Path, default=HERE.parent / "runs")
    ap.add_argument("--agents", default="gpt")
    ap.add_argument("--ids-file", type=Path, help="vuln_id por linea (# = comentario)")
    ap.add_argument("--ids", help="vuln_id separados por coma")
    ap.add_argument("--out-dir", type=Path, default=HERE.parent / "submission")
    args = ap.parse_args()

    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    if args.ids_file:
        ids = [ln.strip() for ln in args.ids_file.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    elif args.ids:
        ids = [x.strip() for x in args.ids.split(",") if x.strip()]
    else:
        ids = sorted({d.name for a in agents if (args.runs / a).is_dir()
                      for d in (args.runs / a).iterdir()
                      if d.is_dir() and ((d / "llm_response.json").exists() or (d / "eval.json").exists())})
    if not ids:
        sys.exit("no hay casos: usa --ids-file, --ids o revisa --runs")

    records = [record_for(args.runs, a, vid) for a in agents for vid in ids]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(records)
    (args.out_dir / "results_table.md").write_text(md_table(records), encoding="utf-8")

    m = compute_metrics(records)
    (args.out_dir / "metrics.json").write_text(json.dumps(m, indent=2), encoding="utf-8")

    print(md_table(records))
    print(report(m))
    print(f"\n[+] escrito en {args.out_dir}: results.csv, results_table.md, metrics.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
