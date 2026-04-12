# Research: LLM-Powered Android Bridge Security Analyzer

## Project Overview

**"Trust, but Verify"** — A multi-agent framework for auditing LLM-guided Android security analysis.

The tool is a research prototype that runs a three-agent LLM pipeline against Android hybrid applications. Its domain is the JavaScript-to-Java WebView bridge (`addJavascriptInterface`) — a cross-language attack surface that traditional static analysis tools struggle with. The research goal is to measure how trustworthy LLM-generated security findings are, and whether a second LLM can reliably catch hallucinations in the first LLM's output.

---

## Architecture: Three-Agent Pipeline

```
DataExtractor (SQLite)
        │
        ▼ context: { app_name, bridges, js_snippets }
        │
        ├──► Agent A (AnalysisOrchestrator)
        │         └── report.md  (defensive security report)
        │                  │
        │                  ├──► Agent B (AuditorOrchestrator) ──► audit.json + trust.json
        │
        └──► Agent C (CrossCheckerOrchestrator)  [never sees Agent A's report]
                  └── checker.md  (offensive attack-surface report)
                           │
                           └──► Agent B (AuditorOrchestrator) ──► checker_audit.json + checker_trust.json
                                                                           │
                                                                           └──► comparison.json

All apps ──► build_aggregate() ──► aggregate_scores.json + aggregate_report.md
```

---

## Data Input

### Source Database

The tool reads from an SQLite file at `analyzer/data/Intent.sqlite`, produced by the external tool [iWanDroid](https://github.com/s2-lab/iWandroid).

### `DataExtractor` (`extractor.py`)

Two tables are queried per app:

**`webview_new`** — Java bridge interfaces:
- `bridgeClass` — the Java class registered as a bridge
- `intefaceObject` — the JS-side name (the object `window.<name>` in JavaScript)
- `bridgeMethods` — methods exposed on that interface
- `initiatingMethod` — Java method that called `addJavascriptInterface`

**`jsdetails`** — JavaScript snippets:
- `PASS_STRING` — the actual JS code snippet
- `confidence` — extraction confidence
- `resolution_type` — how the snippet was resolved/classified

`get_all_apps()` returns a list of all distinct `appName` values. `get_app_context(app_name)` returns a dict `{ app_name, bridges: [...], js_snippets: [...] }` for a single app.

---

## Agent A: Analyzer (`orchestrator.py` — `AnalysisOrchestrator`)

### Role

Primary security analyzer. Takes a defensive perspective — classify vulnerabilities, trace data flows, assess risk.

### Prompt Design

The prompt frames the LLM as a "Principal Android Security Architect & Vulnerability Researcher". It provides:

1. The bridge inventory formatted as:
   `- Interface Object: '<name>' exposes <methods> via <class>`

2. Up to 10 JS snippets formatted as:
   `// Snippet (<resolution_type>)\n<code>`

The LLM is instructed to evaluate across four criteria:

- **A. Data Flow & Sink Analysis** — trace JS calls to Java sinks (SQL, file paths, intents, RCE)
- **B. PII & Permission Leakage** — identify methods returning sensitive data (device ID, accounts, location); check if JS caches or exfiltrates it
- **C. Semantic Mismatch & Over-Privilege** — name obfuscation, exposed methods never called in JS
- **D. Protocol & Origin Security** — `http://` loading, missing `message.origin` validation

### Output Format (Markdown)

1. Executive Summary (total attack surface, risk posture)
2. Critical Vulnerability Findings (title, risk level, data flow path, technical description, evidence)
3. Remediation Steps
4. Confidence Score (1–10)

### LLM Integration

Supports two backends, selected at construction time:

- **Gemini** (`google-genai` SDK): `genai.Client.models.generate_content()`. Default model: `gemini-2.0-flash-lite`.
- **Ollama** (`ollama` SDK): `OllamaIntegration.generate_response()`. Default model: `llama3.1:8b`.

Rate limiting is handled for Gemini with exponential back-off (up to 5 retries). The retry delay is parsed from the `retryDelay` field in the 429 error string; otherwise it doubles from 60 s.

---

## Agent B: Auditor (`auditor.py` — `AuditorOrchestrator`)

### Role

Quality-control agent. Reads an analyzer report alongside the raw evidence and checks whether each finding is traceable.

### Prompt Design

Framed as a "Security Analysis Auditor". Given:
1. The same raw context (bridge interfaces + JS snippets, up to 10)
2. The full text of the report under review (either Agent A's or Agent C's)

Instructed to check:
- Is each data flow path traceable in the evidence?
- Do quoted identifiers actually appear?
- Is severity proportionate to evidence?

### Verdict Schema

Per finding:
```json
{
  "finding_title": "string",
  "verdict": "SUPPORTED | PARTIALLY_SUPPORTED | UNSUPPORTED | HALLUCINATED",
  "reasoning": "cite evidence or note its absence",
  "evidence_found_in_context": "true | false",
  "consistency_score": "1–10"
}
```

Top-level:
```json
{
  "findings_audit": [...],
  "unsupported_claims": ["..."],
  "missing_findings": ["risks not flagged by the analyzer"],
  "overall_consistency_score": "1–10",
  "auditor_notes": "string"
}
```

The prompt explicitly requires **only** valid JSON in the response (no markdown fences).

### Verdict Definitions

| Verdict | Meaning |
|---|---|
| `SUPPORTED` | Data flow path and cited evidence are traceable in the raw context |
| `PARTIALLY_SUPPORTED` | Risk category is plausible but specific evidence is absent or misquoted |
| `UNSUPPORTED` | Finding is not traceable to any bridge or JS snippet entry |
| `HALLUCINATED` | References methods, objects, or snippets that do not exist in the context at all |

### JSON Extraction (`utils.py`)

`extract_json(text)` strips optional markdown code fences (` ```json ... ``` `) then calls `json.loads()`. If parsing fails, the exception propagates to `_run_audit()` in `main.py`, which saves `{"error": str(e)}` to the audit file and returns `None`.

---

## Agent C: Cross-Checker (`cross_checker.py` — `CrossCheckerOrchestrator`)

### Role

Independent analyzer. Takes an offensive perspective — enumerate attack vectors, think like an attacker. **Critically, it never sees Agent A's report.** This independence ensures Agent B audits two analyses that arrived at findings separately, enabling a fair comparison.

### Prompt Design

Framed as an "Offensive Security Researcher — Attack Surface Enumeration". Same input structure as Agent A (bridge inventory + JS snippets, up to 10). Evaluation criteria differ:

- **A. Reachability & Control** — which methods can attacker-controlled JS reach, how much input is attacker-controlled
- **B. Impact Chain** — worst-case outcome per method, chaining of calls
- **C. Privilege & Scope Escalation** — methods granting access beyond WebView's origin, read+send combinations
- **D. Trust Boundary Violations** — content from untrusted origins (`http://`), missing origin checks

### Output Format

Same markdown structure as Agent A (Executive Summary, Findings, Remediation, Confidence Score), but findings are phrased from an attacker's perspective.

---

## Trustworthiness Scoring (`trustworthiness.py`)

### `compute_trustworthiness(audit)`

Given an audit dict, computes three metrics from the `findings_audit` list:

| Metric | Formula |
|---|---|
| `semantic_precision` | `supported_count / total_findings` |
| `hallucination_rate` | `hallucinated_count / total_findings` |
| `argumentative_consistency` | `avg(consistency_score) / 10` |
| **`trustworthiness_score`** | `(semantic_precision + argumentative_consistency) / 2 − hallucination_rate` |

Score range: approximately **-1.0 to 1.0**.

Interpretation:
- **0.7 – 1.0** — well-evidenced and consistent
- **0.4 – 0.7** — mostly sound, some unsupported claims
- **0.0 – 0.4** — significant unsupported findings, treat with caution
- **below 0.0** — hallucination rate dominates; report likely unreliable

### `compute_comparison(trust_a, trust_c)`

Computes a head-to-head comparison between Agent A and Agent C scores:

```json
{
  "delta_trustworthiness": "score_a − score_c",
  "delta_hallucination_rate": "halluc_a − halluc_c",
  "delta_semantic_precision": "precision_a − precision_c",
  "more_trustworthy_agent": "A | C | tie",
  "agreement_note": "human-readable summary"
}
```

A tie is declared when `|delta| < 0.01`.

---

## Aggregation (`aggregate.py`)

`build_aggregate(reports_dir, run_metadata)` runs after all apps are processed.

It scans all subdirectories in `reports/`, loading `trust.json`, `checker_trust.json`, and `comparison.json` for each app. Apps with no `trust.json` (e.g., Agent A failed) are skipped.

### `aggregate_scores.json`

Machine-readable summary:
```json
{
  "run_metadata": { "agent_a_model", "agent_b_model", "agent_c_model", "apps_analyzed", "timestamp" },
  "per_app": [ { "app", "trust_a", "trust_c", "comparison" }, ... ],
  "totals": {
    "apps_with_full_comparison": N,
    "avg_trustworthiness_a": float,
    "avg_trustworthiness_c": float,
    "avg_hallucination_rate_a": float,
    "avg_hallucination_rate_c": float,
    "agent_a_wins": int,
    "agent_c_wins": int,
    "ties": int
  }
}
```

### `aggregate_report.md`

Human-readable markdown table with per-app rows (Trust A, Trust C, delta, winner, hallucination rates) plus overall averages and win counts.

---

## Ollama Integration (`integrations/ollama_int.py`)

`OllamaIntegration` wraps the `ollama` Python SDK. Notable methods:

- `get_available_models()` — lists locally pulled models; handles both dict-style and object-style SDK responses (SDK version compatibility)
- `set_model(name)` — validates model name against available list before setting
- `get_current_model_metadata()` — returns context window size, model family, parameter size, quantization level (useful for research documentation)
- `generate_response(prompt)` — calls `client.generate()` and extracts the response string from multiple possible response shapes

Context window extraction (`_extract_context_window`) checks `model_info` keys containing `context_length`, then falls back to parsing the `parameters` string with a regex.

---

## Entry Point and CLI (`main.py`)

### Arguments

| Flag | Agent | Default |
|---|---|---|
| `--provider` | A | `gemini` (or `$LLM_PROVIDER`) |
| `--model` | A | provider default |
| `--auditor-provider` | B | same as `--provider` |
| `--auditor-model` | B | same as `--model` |
| `--checker-provider` | C | same as `--provider` |
| `--checker-model` | C | same as `--model` |
| `--limit N` | all | unlimited |
| `--skip-audit` | — | run Agent A only |
| `--skip-checker` | — | run A + B only |

When `--provider ollama` is used without `--model`, an interactive numbered selector is shown listing all locally available models.

### Per-App Execution Flow

```
for app in apps:
    1. extractor.get_app_context(app)          → context dict
    2. orchestrator.get_analysis(context)      → report_a (markdown)
       save to reports/<app>/report.md
    3. _run_audit(auditor, context, report_a)  → trust_a scores
       save audit.json, trust.json
    4. checker.get_analysis(context)           → report_c (markdown)
       save to reports/<app>/checker.md
    5. _run_audit(auditor, context, report_c)  → trust_c scores
       save checker_audit.json, checker_trust.json
    6. compute_comparison(trust_a, trust_c)    → comparison dict
       save comparison.json
```

Steps 3–6 are skipped if `--skip-audit` / `--skip-checker` flags are set.

### Error Handling

- Gemini 429 rate limits: exponential back-off with delay parsed from the error response
- Audit JSON parse failures: saved as `{"error": "..."}`, pipeline continues
- Agent C failures: logged, `checker.md` written with the error, remainder of per-app processing skipped

---

## Output File Structure

```
analyzer/
  data/
    Intent.sqlite              Input: iWanDroid database
  reports/
    <package_name>/
      report.md                Agent A's markdown security report
      audit.json               Agent B's per-finding verdicts on Agent A
      trust.json               Trustworthiness scores for Agent A
      checker.md               Agent C's markdown security report (independent)
      checker_audit.json       Agent B's per-finding verdicts on Agent C
      checker_trust.json       Trustworthiness scores for Agent C
      comparison.json          Head-to-head score comparison A vs C
    aggregate_scores.json      Machine-readable summary across all apps
    aggregate_report.md        Human-readable markdown summary table
```

---

## Environment Configuration

`.env` file in `analyzer/`:

```
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-2.0-flash-lite          # optional override for Agent A
AUDITOR_GEMINI_MODEL=gemini-2.0-flash-lite  # optional override for Agent B
CHECKER_GEMINI_MODEL=gemini-2.0-flash-lite  # optional override for Agent C
LLM_PROVIDER=gemini                         # optional, sets --provider default
```

---

## Dependencies (`requirements.txt`)

| Package | Purpose |
|---|---|
| `pandas` | SQL query results to dicts via `read_sql_query` |
| `python-dotenv` | `.env` file loading |
| `google-genai` | Gemini API client |
| `ollama` | Ollama local inference client |
| `pydantic` | (declared, not visibly used in current source) |
| `openai` | (declared, not visibly used in current source) |
| `tabulate` | (declared, not visibly used in current source) |

---

## Research Questions the Tool Is Designed to Answer

**RQ A — What metrics best capture trustworthiness?**
Run the full pipeline across all apps. The `trust.json` files provide `semantic_precision`, `hallucination_rate`, and `argumentative_consistency`. Load `aggregate_scores.json` into a notebook. A Gold Standard (manually verified subset) is needed to validate that the composite score correlates with actual finding quality.

**RQ B — How do different model architectures compare?**
Run twice with Agent A and Agent C assigned to different models (e.g., Gemini vs. Ollama/llama3.1). The `comparison.json` files give per-app paired data suitable for Wilcoxon signed-rank or paired t-tests.

**RQ C — Where does the auditor struggle?**
Aggregate `verdict` fields across all `audit.json` files. Look for which vulnerability categories get `HALLUCINATED` most often, what `missing_findings` consistently flags, and whether failure rate correlates with app complexity (bridge method count, JS snippet count).

**Hypothesis test**
H₀: auditor error-detection rate is no better than random (p = 0.05). Test with a one-sample binomial test against the 0.5 baseline using manually verified Gold Standard labels.
