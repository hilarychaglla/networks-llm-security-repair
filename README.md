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
La respuesta es un JSON con el diff, el claim (campo `patched` o `claim`, según la respuesta) y la confianza. La latencia se mide con
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
  entregado la solución al modelo. Mi primera versión del selector (que recorre todos los `.py` de `vulnerable/`) los habría incluido, como mostró el `--dry-run`; se detectó antes de generar los intentos reales. El script original elegía los archivos a partir de `new_code_files` de `meta.json` (los archivos que cambia el arreglo), lo que también revela dónde está la corrección; esa información no se usa.
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

## 12. Análisis a posteriori: archivos que tocó el modelo frente al arreglo oficial

Comparación descriptiva hecha DESPUÉS de congelar las respuestas (el modelo nunca recibió `fixed/`). Coincidir en el
archivo no implica que el parche sea correcto; los parches no se pudieron aplicar, así que no se evaluó su contenido.

| Caso | Archivo que toca el parche del modelo | Archivos de código del arreglo oficial | Coincidencia |
|---|---|---|---|
| CVE-2023-47163 | remarshal.py | remarshal.py (y pyproject.toml) | mismo archivo de código |
| CVE-2025-46656 | markdownify/__init__.py | markdownify/__init__.py | mismo archivo |
| CVE-2024-6866 | flask_cors/extension.py | flask_cors/core.py y flask_cors/extension.py | parcial (1 de 2) |
| CVE-2025-59940 | src/mkdocs_include_markdown_plugin/process.py | event.py (modificado) y placeholders.py (archivo nuevo) | distinto |
| CVE-2025-43859 | h11/_readers.py | h11/_readers.py | mismo archivo |

## 13. Interpretación de la medición de red

Dos mediciones con curl desde la EC2 (HTTP/2, sin clave, respuesta 401). Los tiempos de curl son acumulativos; las
fases se obtienen restando:

| Fase | Medición 1 | Medición 2 |
|---|---|---|
| DNS | 1.8 ms | 1.5 ms |
| Handshake TCP (connect - DNS) | 1.5 ms | 1.9 ms |
| Handshake TLS (appconnect - connect) | 14.0 ms | 12.8 ms |
| Resto hasta completar la respuesta | 93.9 ms | 63.4 ms |
| Total | 111.3 ms | 79.5 ms |

Conexión observada: IPv4 162.159.140.245 (por el rango parece una dirección de Cloudflare), puerto 443, TLS 1.3
(TLS_AES_256_GCM_SHA384, intercambio de claves x25519), certificado de api.openai.com emitido por Google Trust Services
y HTTP/2 negociado por ALPN. El cliente de Python (httpx) usa HTTP/1.1 por defecto y crea una conexión nueva por caso.

Abrir la conexión (DNS + TCP + TLS) cuesta unos 16 a 17 ms, es decir entre el 0.08 % y el 0.22 % de la latencia de una
llamada real (7.8 a 19.3 s). El tiempo lo domina la generación del modelo, no la red.

## 14. Estado de los casos (Sección 8 del enunciado)

Los cinco casos se completaron de principio a fin (generación, congelado, evaluación y agregación). No hubo errores de
dependencias ni casos sin completar, y no se fabricó ningún resultado.

    CVE-2023-47163: COMPLETE  (claim=1, P=0.84, A=0: parche en formato no aplicable)
    CVE-2025-46656: COMPLETE  (claim=1, P=0.91, A=0: parche en formato no aplicable)
    CVE-2024-6866:  COMPLETE  (claim=1, P=0.81, A=0: parche en formato no aplicable)
    CVE-2025-59940: COMPLETE  (claim=1, P=0.87, A=0: parche en formato no aplicable)
    CVE-2025-43859: COMPLETE  (claim=1, P=0.99, A=0: parche en formato no aplicable)

"COMPLETE" significa que el caso recorrió todo el pipeline y que su verificación terminó (`verification_status = complete`).
Que A = 0 no es un caso incompleto: la Sección 3.2 define F = S = 0 cuando el parche no se aplica.

Incidentes adicionales (sin efecto sobre los resultados):
- Una ejecución de `run_agent.py` desde un directorio incorrecto falló antes de llamar a la API (no se generó ningún intento).
- Se ejecutaron una vez los comandos del enunciado con los marcadores sin reemplazar (`MODEL_ID`, `SELECTED_ID`): el caso no
  existe, no se llamó a la API y la carpeta residual que creó el evaluador se eliminó.

## 15. Controles de validación (fuera de la muestra de 5; no forman parte de los resultados)

Antes de generar los cinco intentos se validó cada pieza con casos de prueba (copias en `submission/validation/`):

- Parche inválido: la respuesta real del modelo para `CVE-2023-30608` (formato `*** Begin Patch`) dio A = 0, F = S = 0,
  V = 0 y FA = 1.
- Control positivo: para comprobar que el evaluador reconoce una reparación correcta, se construyó un parche a partir del
  arreglo oficial de `CVE-2023-30608` SOLO para validar el evaluador (nunca se dio al modelo). Resultado: A = 1, F = 1,
  S = 1, V = 1.
- Verificación incompleta: con `--timeout 1` el evaluador marcó el caso como `incomplete` (`functional=timeout,
  exploit=timeout`), sin contarlo como éxito ni como fallo.
- Ejemplo de la Sección 3 del enunciado con datos sintéticos: VRR = 40.0 % y FAR = 50.0 %; con un caso sin evaluar:
  N = 4 de 5, VRR = 25.0 % y FAR = 66.7 %.
- Los `rc=` se leen solo de la salida estándar: un mensaje `Command failed (rc=1)` ya no se confunde con una prueba fallida.
- Un caso congelado no se puede regenerar: el script se niega sin llamar a la API.
- Caso de desarrollo CVE-2022-3102 (parche en unified diff válido, fuera de la muestra): A=0, F=0, S=0, V=0, FA=1, estado=complete.

## 16. Integridad académica y uso de IA (Sección 9 del enunciado)

Se usó Claude (Anthropic), herramienta permitida por el enunciado, para entender la documentación de Vul4Py y de la API,
depurar errores y mejorar la implementación. Ejecuté, probé y revisé cada script y cada resultado, y soy responsable de
entender el sistema entregado: puedo explicar el código, modificar una parte, diagnosticar un error de la API, calcular
VRR y FAR, explicar un caso de falsa seguridad, explicar DNS, TCP, TLS y HTTPS, explicar por qué el LLM no ve los
resultados de Vul4Py y por qué `patch.diff` se congela antes de evaluar.

## 17. Seguridad y ética (Sección 10 del enunciado)

- Solo se usó el benchmark Vul4Py y recursos autorizados (la instancia EC2 del curso y la clave de API del curso).
- No se atacó ningún sistema externo. Las pruebas funcionales y de exploit de Vul4Py se ejecutaron únicamente de forma
  local, dentro de la EC2, y no se desplegó ninguna aplicación vulnerable de forma pública.
- Credenciales: la clave de la API no está en ningún archivo ni commit (búsqueda del patrón `sk-...` en el repositorio:
  sin resultados) y se exporta en la terminal con `read -s`. Incidente: antes de adoptar `read -s`, la clave se escribió
  una vez directamente en una terminal de la EC2; el historial de Bash se borró después. La clave del curso aparece además
  en texto plano en el enunciado, por lo que se recomienda rotarla.

## 18. Escalado (Sección 11 del enunciado)

N_experimentos = N_casos x N_modelos x N_ejecuciones. Este trabajo: 5 x 1 x 1 = 5. Ejemplo del enunciado: 100 x 2 x 3 = 600.
El pipeline no necesita rediseñarse; solo se repite con otros parámetros:

    for modelo in MODELO_A MODELO_B; do
      for k in 1 2 3; do
        python scripts/run_agent.py --agent gpt --model $modelo --ids-file ids.txt --runs runs/${modelo}_run${k}
        python scripts/evaluate.py --agent gpt --runs runs/${modelo}_run${k}
        python scripts/aggregate_results.py --runs runs/${modelo}_run${k} --agents gpt --ids-file ids.txt --out-dir resultados/${modelo}_run${k}
      done
    done

Cada combinación (modelo, ejecución) usa su propia carpeta de `runs/`, porque un caso congelado no se regenera.
Consideraciones para escalar, a partir de lo observado:
- Casos válidos: en mi entorno solo 12 de unos 100 casos quedaron en estado `OK` en `scan_report.tsv`; el resto estaba
  `INFRA_BROKEN`, `UNEXPECTED`, `NON_ORACLE` o `TIMEOUT`. N_casos real sería como máximo 12 salvo que se reparen esos entornos.
- Coste: con proyectos pequeños, unos 12 000 tokens de entrada y 1 600 de salida por llamada; 600 llamadas serían del
  orden de 7.2 millones de tokens de entrada y 0.9 millones de salida.
- Tiempo: con 14.7 s de latencia media por llamada, 600 llamadas en serie son unas 2.5 horas, más la evaluación.
- Límites de uso (HTTP 429): haría falta espera con reintento controlado; hoy el script no reintenta, y un fallo sin
  respuesta se anota en `api_errors.jsonl`.
- El formato del parche puede dominar los resultados (A = 0); conviene decidir cómo tratarlo antes de escalar.
- Sin temperatura fijada, las ejecuciones repetidas pueden diferir: eso es justo lo que mide N_ejecuciones.

## 19. Dónde está cada cosa

| Qué | Dónde |
|---|---|
| Salida original de los scripts | `runs/midterm/gpt/<CVE>/` (subida con `git add -f`, porque `runs/` está en el `.gitignore` de Vul4Py) |
| Copia de entrega, idéntica a la anterior | `submission/runs_midterm/gpt/<CVE>/` |
| Tabla por intento, métricas | `submission/results.csv`, `results_table.md`, `metrics.json` |
| Prompt fijo, IDs, reporte del escaneo | `submission/prompt.txt`, `selected_ids.txt`, `scan_report.tsv` |
| Medición de red | `submission/red_medicion.md` y la sección 13 |
| Controles de validación | `submission/validation/` |
| Guion de la demostración | `demo.sh` |
| README original de Vul4Py | `README_VUL4PY.md` |
