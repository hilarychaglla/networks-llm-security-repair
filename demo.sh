#!/usr/bin/env bash
# Guion de demostracion (v2).  Ejecutar:  bash ~/vul4py/demo.sh
cd ~/vul4py || exit 1
source .venv/bin/activate
unset OPENAI_API_KEY OPENROUTER_API_KEY OPENAI_BASE_URL
step()  { echo; echo "=========================================================="; echo "$1"; echo "=========================================================="; }
pause() { echo; read -r -p ">>> [Enter para seguir] " _; }

step "1/10 REPOSITORIO: commits, cambios respecto a Vul4Py y donde estan las evidencias"
git log --format='%h %an | %s' -9
git diff --stat 2649d7b HEAD -- scripts
echo "--- evidencias:"; ls submission; ls runs/midterm/gpt
pause

step "2/10 PROMPT FIJO (identico al enunciado)"
cat submission/prompt.txt
pause

step "3/10 QUE SE ENVIA AL MODELO (sin llamar a la API)"
rm -rf runs/demo_dry
python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-47163 --runs runs/demo_dry --dry-run
echo "menciones de backported en el prompt:"; grep -c -i "backported" runs/demo_dry/gpt/CVE-2023-47163/prompt_preview.txt
rm -rf runs/demo_dry
pause

step "4/10 INTENTO CONGELADO: respuesta del modelo (CVE-2025-43859)"
d=runs/midterm/gpt/CVE-2025-43859
ls -l $d
cat $d/frozen.sha256
(cd $d && sha256sum -c frozen.sha256)
python -c "import json;r=json.load(open('$d/llm_response.json'));print({k:r[k] for k in ('model_returned','timestamp_utc','latency_ms','input_tokens','output_tokens','claim','confidence')})"
head -6 $d/patch.diff
pause

step "5/10 UN SOLO INTENTO: el script se niega a regenerar (no llama a la API)"
OPENAI_API_KEY=clave_falsa python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2025-43859 --runs runs/midterm | tail -3
pause

step "6/10 POR QUE A=0: git apply rechaza el formato, y evaluate.py lo mide"
(cd workspaces/CVE-2025-43859/vulnerable && git apply --check ~/vul4py/runs/midterm/gpt/CVE-2025-43859/patch.diff; echo "codigo de salida: $?")
rm -rf /tmp/demo_runs && cp -r runs/midterm /tmp/demo_runs
python scripts/evaluate.py --agent gpt --runs /tmp/demo_runs
pause

step "7/10 CONTROL POSITIVO: un parche correcto SI se verifica (tarda unos 25 s)"
python scripts/evaluate.py --agent gpt --vuln-id CVE-2023-30608 --runs runs/sanity
pause

step "8/10 METRICAS: VRR y FAR"
python scripts/aggregate_results.py --runs runs/midterm --agents gpt --ids-file submission/selected_ids.txt --out-dir /tmp/demo_agg
pause

step "9/10 RED: DNS, TCP, TLS y HTTPS hacia api.openai.com"
echo "--- servidor DNS de la instancia:"; grep -v '^#' /etc/resolv.conf | head -4
echo "--- IPv4 de api.openai.com:"; getent ahostsv4 api.openai.com | head -1
curl -s -o /dev/null -w "dns=%{time_namelookup}s tcp_acum=%{time_connect}s tls_acum=%{time_appconnect}s total=%{time_total}s http=%{http_code}\n" https://api.openai.com/v1/models
curl -sv -o /dev/null https://api.openai.com/v1/models 2>&1 | grep -E "Connected to|SSL connection|subject:|issuer:|ALPN|< HTTP"
echo "--- si DNS falla:"; curl -sS https://api.openai.invalid 2>&1 | head -2
pause

step "10/10 DIAGNOSTICO DE ERRORES DE API (sin costo; caso fuera de la muestra)"
rm -rf runs/demo
echo "--- clave invalida (HTTP 401):"
OPENAI_API_KEY=clave_falsa python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-6681 --runs runs/demo | tail -2
echo "--- DNS que no resuelve (connection_error):"
OPENAI_BASE_URL=https://api.openai.invalid OPENAI_API_KEY=clave_falsa python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2023-6681 --runs runs/demo | tail -2
echo "--- registro de errores:"; cut -c1-230 runs/demo/gpt/CVE-2023-6681/api_errors.jsonl
rm -rf runs/demo
echo; echo "FIN DE LA DEMOSTRACION"
