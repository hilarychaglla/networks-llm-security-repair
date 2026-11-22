#!/usr/bin/env bash
# Demonstration script (v4).  Run from anywhere:  bash demo.sh
# No step calls the API with a real key: steps 6 and 12 use a fake key on purpose.
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
source .venv/bin/activate
unset OPENAI_API_KEY OPENROUTER_API_KEY OPENAI_BASE_URL
step()  { echo; echo "=========================================================="; echo "$1"; echo "=========================================================="; }
pause() { echo; read -r -p ">>> [Press Enter to continue] " _; }

step "1/12 REPOSITORY: commits, changes to Vul4Py and where the evidence is"
git log --format='%h %an | %s' -20
git diff --stat 2649d7b HEAD -- scripts
echo "--- evidence:"; ls submission; ls runs/midterm/gpt; ls runs/midterm_v2/gpt 2>/dev/null
pause

step "2/12 AUTOMATED TESTS of the rules (no API, no Vul4Py)"
python -m pytest tests/ -q
pause

step "3/12 FIXED PROMPTS: v1 (assignment, official) and v2 (output format specified)"
python -c "import sys; sys.path.insert(0,'scripts'); import run_agent as r; [print(f'--- {k}:\n{v}\n') for k,v in r.PROMPTS.items()]"
pause

step "4/12 WHAT IS SENT TO THE MODEL (without calling the API)"
rm -rf runs/demo_dry
python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-47163 --runs runs/demo_dry --prompt-version v2 --dry-run
echo "mentions of backported_support in the prompt:"; grep -c -i "backported" runs/demo_dry/gpt/CVE-2023-47163/prompt_preview.txt
rm -rf runs/demo_dry
pause

step "5/12 FROZEN ATTEMPT: the model's response (v2, CVE-2025-43859)"
d=runs/midterm_v2/gpt/CVE-2025-43859
ls -l $d
cat $d/frozen.sha256
(cd $d && sha256sum -c frozen.sha256)
python -c "import json;r=json.load(open('$d/llm_response.json'));print({k:r[k] for k in ('prompt_version','model_returned','timestamp_utc','latency_ms','input_tokens','output_tokens','claim','confidence')})"
head -8 $d/patch.diff
pause

step "6/12 ONE ATTEMPT ONLY: the script refuses to regenerate (no API call)"
OPENAI_API_KEY=fake_key python scripts/run_agent.py --agent gpt --model gpt-6-luna --prompt-version v2 --vuln-id CVE-2025-43859 --runs runs/midterm_v2 | tail -3
pause

step "7/12 WHY A=0 IN v1: git apply rejects the format, and evaluate.py measures it"
(cd workspaces/CVE-2025-43859/vulnerable && git apply --check --recount "$ROOT/runs/midterm/gpt/CVE-2025-43859/patch.diff"; echo "exit code: $?")
rm -rf /tmp/demo_runs && cp -r runs/midterm /tmp/demo_runs
python scripts/evaluate.py --agent gpt --runs /tmp/demo_runs
pause

step "8/12 v2: why each applied patch failed (junit counts and failing tests)"
python - <<'PY'
import json, pathlib
for d in sorted(pathlib.Path("runs/midterm_v2/gpt").iterdir()):
    e = json.loads((d / "eval.json").read_text())
    print(f"{d.name}: A={e['patch_applied']} F={e['functional_pass']} S={e['security_pass']} "
          f"V={e['verified_repair']} FA={e['false_assurance']} | {e['notes'] or ''}")
    for k in ("functional_junit", "exploit_junit"):
        j = e.get(k)
        if j:
            print(f"    {k}: passed={j['passed']} failed={j['failed']} -> {j['failed_cases']}")
PY
pause

step "9/12 REFERENCE CONTROL: the official fix through the same evaluator"
for d in submission/v2/reference_control/*/; do
  python -c "import json;e=json.load(open('$d/eval.json'));print('$(basename $d)', 'A=%s F=%s S=%s V=%s' % (e['patch_applied'],e['functional_pass'],e['security_pass'],e['verified_repair']), '|', [c for k in ('functional_junit','exploit_junit') if e.get(k) for c in e[k]['failed_cases']])"
done
echo "--- positive control used before the experiment (takes about 25 s):"
rm -rf /tmp/sanity && mkdir -p /tmp/sanity/gpt/CVE-2023-30608
cp submission/validation/positive_control/patch.diff /tmp/sanity/gpt/CVE-2023-30608/
python scripts/evaluate.py --agent gpt --vuln-id CVE-2023-30608 --runs /tmp/sanity
pause

step "10/12 METRICS: VRR and FAR of each condition"
echo "=== v1 (official) ==="
python scripts/aggregate_results.py --runs runs/midterm --agents gpt --ids-file submission/selected_ids.txt --out-dir /tmp/demo_agg_v1
echo; echo "=== v2 ==="
python scripts/aggregate_results.py --runs runs/midterm_v2 --agents gpt --ids-file submission/selected_ids.txt --out-dir /tmp/demo_agg_v2
pause

step "11/12 NETWORK: DNS, TCP, TLS and HTTPS to api.openai.com"
echo "--- the instance's DNS server:"; grep -v '^#' /etc/resolv.conf | head -4
echo "--- IPv4 address of api.openai.com:"; getent ahostsv4 api.openai.com | head -1
curl -s -o /dev/null -w "dns=%{time_namelookup}s tcp_cumulative=%{time_connect}s tls_cumulative=%{time_appconnect}s total=%{time_total}s http=%{http_code}\n" https://api.openai.com/v1/models
curl -sv -o /dev/null https://api.openai.com/v1/models 2>&1 | grep -E "Connected to|SSL connection|subject:|issuer:|ALPN|< HTTP"
echo "--- if DNS fails:"; curl -sS https://api.openai.invalid 2>&1 | head -2
pause

step "12/12 DIAGNOSING API ERRORS (no cost; a case outside the sample)"
rm -rf runs/demo
echo "--- invalid key (HTTP 401):"
OPENAI_API_KEY=fake_key python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-6681 --runs runs/demo | tail -2
echo "--- DNS name that does not resolve (connection_error):"
OPENAI_BASE_URL=https://api.openai.invalid OPENAI_API_KEY=fake_key python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-6681 --runs runs/demo | tail -2
echo "--- error log:"; cut -c1-230 runs/demo/gpt/CVE-2023-6681/api_errors.jsonl
rm -rf runs/demo
echo; echo "END OF THE DEMONSTRATION"
