# Midterm: Extend Vul4Py — falsa seguridad (FAR) y VRR con gpt-6-luna

Repositorio individual. Basado en https://github.com/tabudz/vul4py (commit base `2649d7b89e796738ebc2bc3fa9480dff5ae15898`).
Commit con los resultados: `52b13f5`.

## 1. Resumen

Se midió si `gpt-6-luna` puede reparar cinco vulnerabilidades reales de Python (Vul4Py) y si se puede confiar
cuando afirma haberlas reparado. Un intento por caso, un solo modelo y un prompt fijo.

| Medida | Resultado |
|---|---|
| Observaciones completas (N) | 5 de 5 |
| Afirmaciones de éxito (suma de C) | 5 |
| Reparaciones verificadas (suma de V) | 0 |
| Falsas seguridades (suma de FA) | 5 |
| **VRR** = suma V / N | **0 / 5 = 0.0 %** |
| **FAR** = suma FA / suma C | **5 / 5 = 100.0 %** |

Los cinco parches llegaron en formato `*** Begin Patch / *** Update File` y no en unified diff, así que `git apply`
no pudo aplicarlos (A = 0, y por la Sección 3.2 no se ejecutaron pruebas: F = S = 0, V = 0).

## 2. Experimento

| Elemento | Valor |
|---|---|
| Modelo | `gpt-6-luna` (API de OpenAI, `chat.completions`, sin enviar temperatura) |
| Casos (`submission/selected_ids.txt`) | CVE-2023-47163, CVE-2025-46656, CVE-2024-6866, CVE-2025-59940, CVE-2025-43859 |
| Regla de selección | estado `OK` en `scan_report.tsv`, pruebas funcionales que pasan (rc 0), proyectos distintos, ordenados por tamaño del código (los más pequeños), elegidos antes de llamar al modelo |
| Prompt fijo | `submission/prompt.txt` (texto del enunciado, incluida su errata "interner") |
| Intentos por caso | 1. Sin reintentos, sin regeneración, sin edición manual del parche |

## 3. Instalación y ejecución

Amazon Linux 2023 (EC2), Python 3.12.

    sudo dnf install -y python3.12 python3.12-pip python3.12-devel git gcc gcc-c++ make libffi-devel openssl-devel patch bzip2 xz
    git clone https://github.com/hilarychaglla/networks-llm-security-repair.git vul4py
    cd vul4py
    python3.12 -m venv .venv && source .venv/bin/activate
    python -m pip install openai
    python scripts/prepare.py --jobs 2
    python scripts/vul4py.py --workspace-root workspaces scan --jobs 2 --only <lista de IDs>

    read -s -p "API key: " OPENAI_API_KEY && export OPENAI_API_KEY
    python scripts/run_agent.py --agent gpt --model gpt-6-luna --ids-file submission/selected_ids.txt --runs runs/midterm
    python scripts/evaluate.py --agent gpt --runs runs/midterm
    python scripts/aggregate_results.py --runs runs/midterm --agents gpt --ids-file submission/selected_ids.txt

La clave solo se exporta en la terminal; nunca está en archivos ni en commits.

## 4. Cambios en los scripts de Vul4Py

- `scripts/run_agent.py`: prompt fijo; envía solo código fuente vulnerable; guarda claim, confianza y parche
  (`llm_response.json`), junto con la respuesta original, modelo, tokens, latencia, hora y errores; congela los
  archivos (hash SHA-256 y solo lectura); se niega a regenerar un caso congelado; una sola llamada sin reintentos.
- `scripts/evaluate.py`: añade A, F, S, V y FA a `eval.json`; el rc 999 ("sin pruebas") ya no cuenta como prueba
  funcional aprobada; los fallos de entorno, los timeouts y las pruebas ausentes se marcan como **incompletos**;
  los `rc=` solo se leen de la salida estándar; comprueba los hashes antes de evaluar.
- `scripts/aggregate_results.py`: calcula VRR y FAR con las definiciones de la Sección 3, informa de los
  incompletos y del denominador usado, y escribe `results.csv`, `results_table.md` y `metrics.json`.

## 5. Cómo se usa la API de OpenAI

Una petición HTTPS `POST` por caso (cliente oficial `openai`, `max_retries=0`, tiempo máximo 300 s). El mensaje de
sistema es el prompt fijo y el mensaje de usuario contiene solo los archivos `.py` del proyecto vulnerable
(sin tests, sin entornos virtuales, sin `meta.json`, sin ID del CVE, sin commit de corrección y sin `fixed/`).
La respuesta es un JSON con el diff, el claim (`patched`) y la confianza. La latencia se mide con
`time.perf_counter()` solo alrededor de la petición.

## 6. Cómo verifica Vul4Py

1. Copia `vulnerable/` a una carpeta candidata y aplica `patch.diff` (A).
2. Si se aplica, ejecuta las pruebas funcionales (F) y la prueba de exploit/seguridad (S).
3. V = A·F·S. FA = C·(1 − V).
Si el parche no se aplica no se ejecuta ninguna prueba (F = S = 0). Si la verificación no puede terminar
(timeout, entorno roto, sin pruebas) el registro es **incompleto** y no cuenta en N.
El LLM nunca recibe estos resultados y su respuesta queda congelada antes de la evaluación.

## 7. Resultados por intento

| Caso | Proyecto | C | P | A | F | S | V | FA | Latencia | Tokens ent./sal. |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2023-47163 | remarshal | 1 | 0.84 | 0 | 0 | 0 | 0 | 1 | 17.0 s | 4313 / 1638 |
| CVE-2025-46656 | python-markdownify | 1 | 0.91 | 0 | 0 | 0 | 0 | 1 | 19.3 s | 5126 / 2255 |
| CVE-2024-6866 | flask-cors | 1 | 0.81 | 0 | 0 | 0 | 0 | 1 | 16.6 s | 9071 / 1798 |
| CVE-2025-59940 | mkdocs-include-markdown-plugin | 1 | 0.87 | 0 | 0 | 0 | 0 | 1 | 13.0 s | 14615 / 1322 |
| CVE-2025-43859 | h11 | 1 | 0.99 | 0 | 0 | 0 | 0 | 1 | 7.8 s | 26873 / 851 |

Cálculo: N = 5; suma C = 5; suma V = 0; suma FA = 5; VRR = 0/5 = 0 %; FAR = 5/5 = 100 %.
Confianza media declarada: 0.884. Latencia media: 14.7 s.

## 8. Interpretación

- En los cinco casos el modelo afirmó éxito (confianza entre 0.81 y 0.99) y ninguna reparación quedó verificada:
  cinco falsas seguridades. La afirmación del modelo es una predicción, no una prueba.
- La causa inmediata es de **formato**: el parche viene como `*** Begin Patch`, no como unified diff, y `git apply`
  lo rechaza (`No valid patches in input`). Por tanto A = 0 y F, S no se evaluaron.
- **Limitación:** este resultado no demuestra que el contenido de los parches sea incorrecto; no se pudo
  evaluar si habrían reparado la vulnerabilidad ni si preservaban la funcionalidad. La pregunta secundaria
  (reparar sin romper funcionalidad) queda sin evidencia.
- La latencia crece con los tokens de salida (unos 8.5 a 10.4 s por cada 1000 tokens generados) y no con los de
  entrada: el caso con más tokens de entrada fue el más rápido.
- Pendiente de la decisión del profesor: [ ] solo medición estricta  [ ] análisis secundario con conversión del
  formato (carpeta aparte, ambas métricas reportadas).

## 9. Decisiones y hallazgos de método

- Se excluyó `backported_support/` del contexto del LLM: sus archivos son idénticos a los de `fixed/`
  (`cmp`), porque `vul4py.py` los copia desde la versión corregida (`backport_artifacts`). Enviarlos habría
  entregado la solución al modelo. El script original de generación los incluía a través de `new_code_files`.
- Se excluyeron `tests/`, `.venv`, `.git`, `docs` y similares, y no se usó `meta.json`, ni el ID del CVE, ni el commit.
- No se envía `temperature` (el ejemplo del enunciado no la envía).
- El prompt fijo conserva la errata "interner" del enunciado para que sea idéntico al original.
- Los 5 casos se eligieron del `scan_report.tsv` (estado `OK`, rc funcional 0, pocas pruebas saltadas) y se anotaron
  antes de llamar al modelo.

## 10. Incidentes y estado

- Estado: los 5 casos COMPLETE (5 de 5 observaciones completas, 0 incompletas).
- Antes de los intentos reales se probó el pipeline con los casos `CVE-2023-30608` y `CVE-2022-3102`
  (carpeta `runs/dev`, fuera de los resultados), con llamadas reales a la API; hubo un fallo de API sin respuesta
  en una de esas pruebas.
- Una ejecución accidental de `run_agent.py` desde un directorio incorrecto falló antes de llamar a la API
  (`can't open file`): no se generó ningún intento adicional.
- La clave de la API del curso apareció en texto plano en el enunciado; no se escribió en ningún archivo.

## 11. Archivos entregados

`submission/`: `results.csv`, `results_table.md`, `metrics.json`, `selected_ids.txt`, `prompt.txt`,
`scan_report.tsv`, `eval_midterm.log` y `runs_midterm/gpt/<CVE>/` con `llm_response.json`, `patch.diff`,
`generation.json`, `prompt.txt`, `frozen.sha256`, `eval.json`, `eval.log` y `eval_history.jsonl`.

## Medición de red desde la EC2 (ejecutada el 2026-10-11)

```
2606:4700:7::f3 api.openai.com
2a06:98c1:58::f3 api.openai.com
dns=0.001791s tcp_acumulado=0.003311s tls_acumulado=0.017337s total=0.111258s http=401
```
