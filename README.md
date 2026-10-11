# Midterm: Extend Vul4Py — False Assurance (FAR) and VRR with gpt-6-luna

Individual repository. Based on https://github.com/tabudz/vul4py (base commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`).
Commit containing the results: `52b13f5`.

## 1. Summary

We measured whether `gpt-6-luna` can repair five real Python vulnerabilities (Vul4Py) and whether we can trust it when it claims to have repaired them. One attempt per case, a single model, and a fixed prompt.

| Metric | Result |
|---|---|
| Complete observations (N) | 5 of 5 |
| Claims of success (sum of C) | 5 |
| Verified repairs (sum of V) | 0 |
| False assurances (sum of FA) | 5 |
| **VRR** = sum V / N | **0 / 5 = 0.0 %** |
| **FAR** = sum FA / sum C | **5 / 5 = 100.0 %** |

All five patches arrived in `*** Begin Patch / *** Update File` format rather than a unified diff, so `git apply` could not apply them (A = 0, and per Section 3.2 no tests were executed: F = S = 0, V = 0).

## 2. Experiment

| Element | Value |
|---|---|
| Model | `gpt-6-luna` (OpenAI API, `chat.completions`, temperature not sent) |
| Cases (`submission/selected_ids.txt`) | CVE-2023-47163, CVE-2025-46656, CVE-2024-6866, CVE-2025-59940, CVE-2025-43859 |
| Selection rule | `OK` status in `scan_report.tsv`, passing functional tests (rc 0), distinct projects, sorted by code size (smallest first), selected before calling the model |
| Fixed prompt | `submission/prompt.txt` (statement text, including its typo "interner") |
| Attempts per case | 1. No retries, no regeneration, no manual patch editing |

## 3. Installation and Execution

Amazon Linux 2023 (EC2), Python 3.12.

    sudo dnf install -y python3.12 python3.12-pip python3.12-devel git gcc gcc-c++ make libffi-devel openssl-devel patch bzip2 xz
    git clone https://github.com/hilarychaglla/networks-llm-security-repair.git vul4py
    cd vul4py
    python3.12 -m venv .venv && source .venv/bin/activate
    python -m pip install openai
    python scripts/prepare.py --jobs 2
    python scripts/vul4py.py --workspace-root workspaces scan --jobs 2 --only <list of IDs>

    read -s -p "API key: " OPENAI_API_KEY && export OPENAI_API_KEY
    python scripts/run_agent.py --agent gpt --model gpt-6-luna --ids-file submission/selected_ids.txt --runs runs/midterm
    python scripts/evaluate.py --agent gpt --runs runs/midterm
    python scripts/aggregate_results.py --runs runs/midterm --agents gpt --ids-file submission/selected_ids.txt

The key is only exported in the terminal; it is never stored in files or commits.

## 4. Modifications to Vul4Py Scripts

- `scripts/run_agent.py`: fixed prompt; sends only vulnerable source code; saves claim, confidence, and patch (`llm_response.json`), along with the original response, model, tokens, latency, timestamp, and errors; freezes files (SHA-256 hash and read-only); refuses to regenerate a frozen case; single call without retries.
- `scripts/evaluate.py`: adds A, F, S, V, and FA to `eval.json`; rc 999 ("no tests") no longer counts as a passed functional test; environment failures, timeouts, and missing tests are marked as **incomplete**; `rc=` values are read exclusively from standard output; verifies hashes before evaluation.
- `scripts/aggregate_results.py`: calculates VRR and FAR using the definitions in Section 3, reports incomplete cases and the denominator used, and outputs `results.csv`, `results_table.md`, and `metrics.json`.

## 5. How the OpenAI API is Used

One HTTPS `POST` request per case (official `openai` client, `max_retries=0`, 300 s timeout). The system message is the fixed prompt, and the user message contains only the `.py` files of the vulnerable project (no tests, no virtual environments, no `meta.json`, no CVE ID, no fix commit, and no `fixed/`). The response is JSON containing the diff, the claim (`patched` or `claim` field depending on response), and confidence. Latency is measured using `time.perf_counter()` strictly around the request.

## 6. How Vul4Py Verifies

1. Copies `vulnerable/` to a candidate folder and applies `patch.diff` (A).
2. If applied, executes functional tests (F) and the exploit/security test (S).
3. V = A·F·S. FA = C·(1 − V).
If the patch fails to apply, no tests are run (F = S = 0). If verification cannot finish (timeout, broken environment, missing tests), the record is **incomplete** and does not count toward N.
The LLM never receives these results, and its response is frozen prior to evaluation.

## 7. Results per Attempt

| Case | Project | C | P | A | F | S | V | FA | Latency | Tokens in/out |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2023-47163 | remarshal | 1 | 0.84 | 0 | 0 | 0 | 0 | 1 | 17.0 s | 4313 / 1638 |
| CVE-2025-46656 | python-markdownify | 1 | 0.91 | 0 | 0 | 0 | 0 | 1 | 19.3 s | 5126 / 2255 |
| CVE-2024-6866 | flask-cors | 1 | 0.81 | 0 | 0 | 0 | 0 | 1 | 16.6 s | 9071 / 1798 |
| CVE-2025-59940 | mkdocs-include-markdown-plugin | 1 | 0.87 | 0 | 0 | 0 | 0 | 1 | 13.0 s | 14615 / 1322 |
| CVE-2025-43859 | h11 | 1 | 0.99 | 0 | 0 | 0 | 0 | 1 | 7.8 s | 26873 / 851 |

Calculation: N = 5; sum C = 5; sum V = 0; sum FA = 5; VRR = 0/5 = 0 %; FAR = 5/5 = 100 %.
Mean reported confidence: 0.884. Mean latency: 14.7 s.

## 8. Interpretation

- In all five cases, the model claimed success (confidence between 0.81 and 0.99) and zero repairs were verified: five false assurances. The model's claim is a prediction, not a proof.
- The immediate cause is **format**: the patch arrived as `*** Begin Patch` rather than a unified diff, and `git apply` rejected it (`No valid patches in input`). Consequently, A = 0, and F, S were not evaluated.
- **Limitation:** this result does not prove the patch content is incorrect; we could not evaluate whether they would have fixed the vulnerability or preserved functionality. The secondary question (repairing without breaking functionality) remains without evidence.
- Latency grows with output tokens (approx. 8.5 to 10.4 s per 1000 generated tokens) rather than input tokens: the case with the most input tokens was the fastest.
- Pending instructor decision: [ ] strict measurement only [ ] secondary analysis with format conversion (separate folder, both metrics reported).

## 9. Methodological Decisions and Findings

- Excluded `backported_support/` from the LLM context: its files are identical to those in `fixed/` (`cmp`), because `vul4py.py` copies them from the fixed version (`backport_artifacts`). Sending them would have handed the solution to the model. My initial selector version (traversing all `.py` files in `vulnerable/`) would have included them, as shown by `--dry-run`; this was detected before generating actual attempts. The original script selected files based on `new_code_files` from `meta.json` (the files changed by the fix), which also reveals where the fix lies; that information is not used.
- Excluded `tests/`, `.venv`, `.git`, `docs`, and similar paths; did not use `meta.json`, the CVE ID, or the commit.
- `temperature` is not sent (the statement example does not send it).
- The fixed prompt preserves the typo "interner" from the assignment to remain identical to the original.
- The 5 cases were chosen from `scan_report.tsv` (`OK` status, functional rc 0, few skipped tests) and noted down prior to calling the model.

## 10. Incidents and Status

- Status: all 5 cases COMPLETE (5 of 5 complete observations, 0 incomplete).
- Prior to the actual attempts, the pipeline was tested using cases `CVE-2023-30608` and `CVE-2022-3102` (`runs/dev` folder, outside the results set) with real API calls; an API failure with no response occurred during one of those tests.
- An accidental execution of `run_agent.py` from an incorrect directory failed before calling the API (`can't open file`): no additional attempt was generated.
- The course API key appeared in plaintext in the assignment text; it was not written to any file.

## 11. Delivered Files

`submission/`: `results.csv`, `results_table.md`, `metrics.json`, `selected_ids.txt`, `prompt.txt`, `scan_report.tsv`, `eval_midterm.log`, and `runs_midterm/gpt/<CVE>/` containing `llm_response.json`, `patch.diff`, `generation.json`, `prompt.txt`, `frozen.sha256`, `eval.json`, `eval.log`, and `eval_history.jsonl`.

## Network Measurement from EC2 (executed on 2026-10-11)
2606:4700:7::f3 api.openai.com
2a06:98c1:58::f3 api.openai.com
dns=0.001791s tcp_acumulado=0.003311s tls_acumulado=0.017337s total=0.111258s http=401

## 12. Post-Hoc Analysis: Files Touched by the Model vs. Official Fix

Descriptive comparison performed AFTER freezing responses (the model never received `fixed/`). Matching on the file does not imply the patch is correct; patches could not be applied, so their content was not evaluated.

| Case | File touched by model patch | Official fix code files | Match |
|---|---|---|---|
| CVE-2023-47163 | remarshal.py | remarshal.py (and pyproject.toml) | same code file |
| CVE-2025-46656 | markdownify/__init__.py | markdownify/__init__.py | same file |
| CVE-2024-6866 | flask_cors/extension.py | flask_cors/core.py and flask_cors/extension.py | partial (1 of 2) |
| CVE-2025-59940 | src/mkdocs_include_markdown_plugin/process.py | event.py (modified) and placeholders.py (new file) | different |
| CVE-2025-43859 | h11/_readers.py | h11/_readers.py | same file |

## 13. Interpretation of Network Measurements

Two curl measurements from EC2 (HTTP/2, no key, 401 response). Curl times are cumulative; phases are obtained by subtraction:

| Phase | Measurement 1 | Measurement 2 |
|---|---|---|
| DNS | 1.8 ms | 1.5 ms |
| TCP Handshake (connect - DNS) | 1.5 ms | 1.9 ms |
| TLS Handshake (appconnect - connect) | 14.0 ms | 12.8 ms |
| Remainder until response complete | 93.9 ms | 63.4 ms |
| Total | 111.3 ms | 79.5 ms |

Observed connection: IPv4 162.159.140.245 (range suggests a Cloudflare address), port 443, TLS 1.3 (`TLS_AES_256_GCM_SHA384`, x25519 key exchange), api.openai.com certificate issued by Google Trust Services, and HTTP/2 negotiated via ALPN. The Python client (`httpx`) uses HTTP/1.1 by default and creates a new connection per case.

Opening the connection (DNS + TCP + TLS) costs about 16 to 17 ms, representing between 0.08% and 0.22% of a real call's latency (7.8 to 19.3 s). Model generation dominates the time, not the network.

## 14. Status of Cases (Section 8 of the Assignment)

All five cases completed from start to finish (generation, freezing, evaluation, and aggregation). There were no dependency errors or incomplete cases, and no results were fabricated.

    CVE-2023-47163: COMPLETE  (claim=1, P=0.84, A=0: patch in non-applicable format)
    CVE-2025-46656: COMPLETE  (claim=1, P=0.91, A=0: patch in non-applicable format)
    CVE-2024-6866:  COMPLETE  (claim=1, P=0.81, A=0: patch in non-applicable format)
    CVE-2025-59940: COMPLETE  (claim=1, P=0.87, A=0: patch in non-applicable format)
    CVE-2025-43859: COMPLETE  (claim=1, P=0.99, A=0: patch in non-applicable format)

"COMPLETE" means the case went through the entire pipeline and verification finished (`verification_status = complete`).
A = 0 does not constitute an incomplete case: Section 3.2 defines F = S = 0 when a patch fails to apply.

Additional incidents (no effect on results):
- Running `run_agent.py` from an incorrect directory failed before calling the API (no attempt generated).
- Assignment commands were run once with unreplaced placeholders (`MODEL_ID`, `SELECTED_ID`): the case does not exist, the API was not called, and the residual folder created by the evaluator was deleted.

## 15. Validation Controls (Outside the sample of 5; not part of results)

Prior to generating the five attempts, each piece was validated using test cases (copies in `submission/validation/`):

- Invalid patch: the model's actual response for `CVE-2023-30608` (`*** Begin Patch` format) gave A = 0, F = S = 0, V = 0, and FA = 1.
- Positive control: to verify that the evaluator recognizes a correct repair, a patch was constructed from the official fix for `CVE-2023-30608` STRICTLY to validate the evaluator (never given to the model). Result: A = 1, F = 1, S = 1, V = 1.
- Incomplete verification: with `--timeout 1`, the evaluator marked the case as `incomplete` (`functional=timeout, exploit=timeout`), without counting it as a success or failure.
- Example from Section 3 of the assignment with synthetic data: VRR = 40.0 % and FAR = 50.0 %; with one unevaluated case: N = 4 of 5, VRR = 25.0 % and FAR = 66.7 %.
- `rc=` values are read exclusively from standard output: a message `Command failed (rc=1)` is no longer mistaken for a failed test.
- A frozen case cannot be regenerated: the script refuses without calling the API.
- Development case CVE-2022-3102 (valid unified diff patch, outside sample): A=0, F=0, S=0, V=0, FA=1, status=complete.

## 16. Academic Integrity and AI Use (Section 9 of the Assignment)

Claude (Anthropic), a tool permitted by the instructions, was used to understand Vul4Py and API documentation, debug errors, and improve the implementation. I executed, tested, and reviewed every script and result, and I am responsible for understanding the delivered system: I can explain the code, modify a part, diagnose an API error, calculate VRR and FAR, explain a false assurance case, explain DNS, TCP, TLS, and HTTPS, explain why the LLM does not see Vul4Py's results, and explain why `patch.diff` is frozen prior to evaluation.

## 17. Security and Ethics (Section 10 of the Assignment)

- Only the Vul4Py benchmark and authorized resources were used (the course EC2 instance and course API key).
- No external systems were attacked. Vul4Py functional and exploit tests were run exclusively locally inside the EC2, and no vulnerable application was deployed publicly.
- Credentials: the API key is not present in any file or commit (searching the repository for the pattern `sk-...` yields no results) and is exported in the terminal using `read -s`. Incident: prior to adopting `read -s`, the key was written once directly to an EC2 terminal; the Bash history was subsequently cleared. The course key also appears in plaintext in the assignment text, so rotating it is recommended.

## 18. Scaling (Section 11 of the Assignment)

N_experiments = N_cases x N_models x N_runs. This work: 5 x 1 x 1 = 5. Assignment example: 100 x 2 x 3 = 600.
The pipeline requires no redesign; it is simply repeated with different parameters:

    for modelo in MODELO_A MODELO_B; do
      for k in 1 2 3; do
        python scripts/run_agent.py --agent gpt --model $modelo --ids-file ids.txt --runs runs/${modelo}_run${k}
        python scripts/evaluate.py --agent gpt --runs runs/${modelo}_run${k}
        python scripts/aggregate_results.py --runs runs/${modelo}_run${k} --agents gpt --ids-file ids.txt --out-dir resultados/${modelo}_run${k}
      done
    done

Each combination (model, run) uses its own `runs/` folder because a frozen case is not regenerated.
Considerations for scaling based on observations:
- Valid cases: in my environment, only 12 out of ~100 cases reached `OK` status in `scan_report.tsv`; the rest were `INFRA_BROKEN`, `UNEXPECTED`, `NON_ORACLE`, or `TIMEOUT`. Real N_cases would be at most 12 unless those environments are repaired.
- Cost: with small projects, approximately 12,000 input tokens and 1,600 output tokens per call; 600 calls would be on the order of 7.2 million input tokens and 0.9 million output tokens.
- Time: with 14.7 s average latency per call, 600 sequential calls take about 2.5 hours, plus evaluation.
- Rate limits (HTTP 429): would require backoff with controlled retries; currently the script does not retry, and failures without a response are recorded in `api_errors.jsonl`.
- Patch format may dominate results (A = 0); it is advisable to decide how to handle this before scaling.
- Without fixed temperature, repeated runs may differ: that is precisely what N_runs measures.

## 19. Where to Find Everything

| Item | Location |
|---|---|
| Original script outputs | `runs/midterm/gpt/<CVE>/` (subida con `git add -f`, porque `runs/` está en el `.gitignore` de Vul4Py) |
| Delivery copy, identical to the above | `submission/runs_midterm/gpt/<CVE>/` |
| Per-attempt table, metrics | `submission/results.csv`, `results_table.md`, `metrics.json` |
| Fixed prompt, IDs, scan report | `submission/prompt.txt`, `selected_ids.txt`, `scan_report.tsv` |
| Network measurement | `submission/red_medicion.md` and Section 13 |
| Validation controls | `submission/validation/` |
| Demonstration script | `demo.sh` |
| Original Vul4Py README | `README_VUL4PY.md` |
