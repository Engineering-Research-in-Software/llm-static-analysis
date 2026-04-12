# Pivot Research: Callsite-Level Multi-Model Inspector Evaluation

## Executive Summary

The current tool runs a single A+B+C pipeline per **app** with fixed model assignments. The research pivot changes two fundamental things:

1. **Unit of analysis**: from app-level to **callsite-level** (one row in `webview_new`).
2. **Evaluation model**: from a trustworthiness scoring system comparing Agent A vs. C, to a **multi-pair inspector evaluation** across defined model permutations, with richer auditor metrics and a manual researcher verification layer.

---

## Current Architecture Recap

```
per app:
  Inspector A  (defensive prompt)  →  report.md
  Inspector B  (audit A's report)  →  audit.json, trust.json
  Inspector C  (offensive prompt)  →  checker.md
  Inspector B  (audit C's report)  →  checker_audit.json, checker_trust.json
  compute_comparison(A, C)         →  comparison.json
build_aggregate()                  →  aggregate_scores.json, aggregate_report.md
```

Key constraints of current design:
- A and C use **different prompts** (defensive vs. offensive framing).
- Only one model pair runs per execution.
- No concept of a callsite ID — analysis is per `appName`.
- Auditor metrics: SUPPORTED / PARTIALLY_SUPPORTED / UNSUPPORTED / HALLUCINATED verdicts + consistency score.
- No researcher manual-verification layer in the output schema.

---

## Target Architecture

### Unit of Analysis: Callsite

A **callsite** = one row in `webview_new`, identified as:
```
<databaseFileStem>-<tableName>-<rowID>
```
Example: `Intent-webview_new-42`

The `id` column in `webview_new` is the primary key (`INTEGER PRIMARY KEY AUTOINCREMENT`). The database filename stem is `Intent` (from `data/Intent.sqlite`).

Each callsite context contains:
- The specific bridge row: `bridgeClass`, `intefaceObject`, `bridgeMethods`, `initiatingMethod`
- All JS snippets from `jsdetails` matching the same `appName` / `PACKAGE_NAME` (as today, capped at 10)

### Inspector Agents (A and C)

Both agents must share the **same prompt** — a "security researcher" perspective that is neither purely defensive nor purely offensive, but enumerates findings objectively. This is a direct break from the current design where A is framed as an "Android Security Architect" and C as an "Offensive Security Researcher."

A single `InspectorOrchestrator` class replaces the separate `AnalysisOrchestrator` and `CrossCheckerOrchestrator` classes.

### Model Pairs: `analysis_configuration.json`

All model permutations to test are declared in a single config file:

```json
{
  "auditor": {
    "provider": "gemini",
    "model": "gemini-2.0-flash"
  },
  "inspector_pairs": [
    {
      "inspector_a": { "provider": "gemini", "model": "gemini-2.0-flash-lite" },
      "inspector_c": { "provider": "gemini", "model": "gemini-2.0-flash-lite" }
    },
    {
      "inspector_a": { "provider": "ollama", "model": "llama3.1:8b" },
      "inspector_c": { "provider": "gemini", "model": "gemini-2.0-flash-lite" }
    }
  ]
}
```

A single `auditor` is defined globally; it evaluates all inspector pairs. There is one auditor verdict per inspector per permutation.

### Auditor Evaluation Metrics

The auditor evaluates each inspector's findings against the callsite context using four metrics:

| Metric | Type | Description |
|---|---|---|
| `hallucinationFrequency` | float [0..1] | Fraction of the inspector's findings that were hallucinated (reference: non-existent methods, objects, or code), normalised by the inspector with the highest hallucination count in this permutation |
| `technicalAccuracy` | int [1..10] | How technically correct the inspector's description of each fault is |
| `effectChainAwareness` | int [1..10] | How well the inspector traces the downstream chain of effects made possible by the vulnerability |
| `attackSurfaceCoverage` | float [0..1] | Fraction of vulnerabilities identified by the inspector compared to the researcher's reference (left 0 until researcher manually fills `researcherConclusion`) |

**Definition of hallucination** for this context: an inspector hallucination is a finding that references a method name, class name, object name, or JS code segment that **does not appear** in the provided callsite context (bridge row + JS snippets). This aligns with the existing `HALLUCINATED` verdict in the auditor but operationalised as a frequency rather than a per-finding label.

### Output Schema

The output is a JSON file (e.g., `results/callsite_results.json`) containing an array of:

```typescript
type ModelID = string; // e.g. "gemini/gemini-2.0-flash-lite" or "ollama/llama3.1:8b"

interface EvaluationMetricsResult {
  hallucinationFrequency: number;   // 0.0–1.0
  technicalAccuracy: number;        // 1–10
  effectChainAwareness: number;     // 1–10
  attackSurfaceCoverage: number;    // 0.0–1.0
}

interface CallsiteResult {
  identifiedCallsiteID: string;     // "<dbStem>-<tableName>-<rowID>"
  context: string;                  // formatted JS + Java/Kotlin bridge context sent to inspectors

  permutations: {
    researcher: number;             // uint8, manually filled after review (0 = not yet reviewed)
    inspectors: ModelID[];          // [inspector_a_model_id, inspector_c_model_id]
    auditor: ModelID;

    results: {
      inspector: ModelID;
      findings: string[];           // raw findings text from this inspector
    }[];

    auditorVerdict: {
      [inspectorModelID: ModelID]: EvaluationMetricsResult;
    };

    researcherConclusion: EvaluationMetricsResult; // manually filled, empty/zero by default
  }[];
}
```

**Notes on `researcher`**: The `researcher` field is a `uint8` counter; it is intended to be incremented by 1 each time a researcher reviews this callsite entry. It starts at `0`. The `researcherConclusion` field is an `EvaluationMetricsResult` filled manually by the researcher after reviewing all auditor verdicts for the permutation.

---

## Gap Analysis: What Needs to Change

### 1. `extractor.py` — Add Callsite-Level Queries

**Currently:** `get_app_context(app_name)` aggregates all bridge rows for an app.  
**Needed:** Two new methods:

```python
def get_all_callsites() -> list[dict]:
    # Returns all rows from webview_new with their id, appName, and bridge fields
    # SELECT id, appName, bridgeClass, intefaceObject, bridgeMethods, initiatingMethod FROM webview_new

def get_callsite_context(callsite_id: int) -> dict:
    # Fetches one webview_new row by id
    # Fetches all jsdetails rows for that row's appName
    # Returns { "callsite_id": id, "db_stem": "Intent", "app_name": ..., "bridge": {...}, "js_snippets": [...] }
```

The `identifiedCallsiteID` is then built as:
```python
f"{db_stem}-webview_new-{callsite_id}"
```

### 2. New `InspectorOrchestrator` — Unified Inspector Prompt

Replace `AnalysisOrchestrator` (`orchestrator.py`) and `CrossCheckerOrchestrator` (`cross_checker.py`) with a single `InspectorOrchestrator`.

The new prompt frames the LLM as a "Security Researcher" evaluating a specific bridge callsite. It should include both the defensive (data flow / sink analysis, PII leakage) and offensive (reachability, impact chain) criteria from the current two prompts, unified into one analysis frame.

Key change: the prompt receives a **single bridge row** as context (not all bridges for the app), plus the app's JS snippets. This focuses the analysis on one callsite at a time.

Output format stays as Markdown findings (a list of vulnerabilities with title, risk, data flow, description, evidence), because the auditor needs to parse them.

The `InspectorOrchestrator` constructor takes `provider` and `model_name` — same as today.

### 3. Revised `AuditorOrchestrator` — New Metrics Schema

**Currently:** The auditor produces per-finding `SUPPORTED/HALLUCINATED` verdicts + an `overall_consistency_score`.  
**Needed:** The auditor produces an `EvaluationMetricsResult` per inspector (not per finding).

The new auditor prompt:
1. Receives the callsite context (the single bridge row + JS snippets).
2. Receives both inspectors' findings (labelled by model ID).
3. Produces a JSON object keyed by model ID with the four metrics.

For `hallucinationFrequency`: the auditor should count hallucinated findings per inspector and then normalise relative to whichever inspector hallucinated more (the one with higher count gets 1.0; the other gets `its_count / max_count`). If both have zero hallucinations, both get 0.0.

For `attackSurfaceCoverage`: at audit time, the auditor has no researcher reference yet, so this should be set to the auditor's best estimate — it will be overridden by the researcher. The auditor can use its own assessment of the "true" vulnerability set from the context as the denominator.

Output schema for the auditor response:
```json
{
  "<modelID_A>": {
    "hallucinationFrequency": 0.0,
    "technicalAccuracy": 7,
    "effectChainAwareness": 6,
    "attackSurfaceCoverage": 0.8
  },
  "<modelID_C>": {
    "hallucinationFrequency": 0.33,
    "technicalAccuracy": 5,
    "effectChainAwareness": 4,
    "attackSurfaceCoverage": 0.5
  }
}
```

### 4. New `analysis_configuration.json` — Multi-Pair Config

New file: `analyzer/analysis_configuration.json`

Loaded at startup in `main.py`. Replaces CLI flags for model selection (though CLI flags could still override for quick testing).

### 5. Revised `main.py` — Multi-Pair Loop

The new execution loop:

```
load analysis_configuration.json  →  { auditor, inspector_pairs }
build auditor instance (single, shared)
for each callsite in db:
    callsite_context = extractor.get_callsite_context(callsite.id)
    permutations = []
    for each pair in inspector_pairs:
        build inspector_a (pair.inspector_a)
        build inspector_c (pair.inspector_c)
        findings_a = inspector_a.get_analysis(callsite_context)
        findings_c = inspector_c.get_analysis(callsite_context)
        audit = auditor.get_audit(callsite_context, findings_a, findings_c, pair)
        permutations.append({
            "researcher": 0,
            "inspectors": [pair.inspector_a.model_id, pair.inspector_c.model_id],
            "auditor": auditor.model_id,
            "results": [
                { "inspector": pair.inspector_a.model_id, "findings": findings_a_list },
                { "inspector": pair.inspector_c.model_id, "findings": findings_c_list }
            ],
            "auditorVerdict": audit,
            "researcherConclusion": empty_metrics()
        })
    output_record = {
        "identifiedCallsiteID": callsite_id_string,
        "context": formatted_context_string,
        "permutations": permutations
    }
    append output_record to results list
write results to results/callsite_results.json
```

### 6. `findings` Extraction

The `findings` field in the output schema (`results[].findings: string[]`) should be a list of individual findings extracted from the inspector's Markdown report. Each finding corresponds to one "CRITICAL VULNERABILITY FINDING" block. An extraction utility (extending `utils.py`) can parse these from the Markdown by splitting on finding heading markers.

### 7. Remove / Deprecate

- `trustworthiness.py` — `compute_trustworthiness` and `compute_comparison` are no longer used in the new pipeline. Keep the file or archive it; do not delete until new pipeline is validated.
- `aggregate.py` — the aggregation concept is replaced by the single `callsite_results.json` output; per-run stats can be computed from it. Keep or archive.
- `cross_checker.py` — replaced by `InspectorOrchestrator`.
- `orchestrator.py` — replaced by `InspectorOrchestrator`.

---

## File Structure After Pivot

```
analyzer/
  analysis_configuration.json     New: defines inspector pairs + auditor model
  data/
    Intent.sqlite                  Unchanged
  results/
    callsite_results.json          New output: array of CallsiteResult objects
  src/
    extractor.py                   Modified: add get_all_callsites(), get_callsite_context()
    inspector.py                   New: unified InspectorOrchestrator (replaces orchestrator.py + cross_checker.py)
    auditor.py                     Modified: new metrics schema, accepts two findings inputs
    main.py                        Rewritten: config-driven multi-pair loop
    utils.py                       Extended: add extract_findings_from_markdown()
    trustworthiness.py             Archived (not used in new pipeline)
    aggregate.py                   Archived (not used in new pipeline)
    orchestrator.py                Archived
    cross_checker.py               Archived
    integrations/
      ollama_int.py                Unchanged
```

---

## What Is Preserved

- **LLM provider abstraction** (`OllamaIntegration` + Gemini client pattern): no changes needed.
- **Rate-limit retry logic**: identical pattern, reused in `InspectorOrchestrator` and `AuditorOrchestrator`.
- **`extract_json()`** in `utils.py`: still used for auditor JSON parsing.
- **Prompt context formatting** (bridge row + JS snippets): the formatting logic is carried over, scoped to one bridge row instead of all rows for an app.
- **`.env` config** for API keys: unchanged.

---

## Open Questions for Researchers

1. **Inspector prompt direction**: The new unified inspector prompt must balance the defensive criteria (data flow/sink analysis, PII leakage) and offensive criteria (reachability, impact chain) from the current two prompts. A draft should be reviewed by both researchers before implementation.

2. **`attackSurfaceCoverage` baseline**: At audit time, the auditor self-estimates the "true" vulnerability set. Should the auditor be given an explicit task to enumerate its own ground truth first, then evaluate coverage against that? Or should coverage always be `0.0` at audit time and filled entirely by the researcher? This is a research design choice.

3. **`hallucinationFrequency` normalisation**: Normalising relative to the most-hallucinating inspector in a pair means each run of two inspectors produces one frequency of 1.0 and one ≤ 1.0 (unless both have zero). Consider whether an absolute frequency (hallucinated_count / total_findings) is more useful for inter-run comparison.

4. **Callsite scope vs. app scope**: The current JS snippet query is `WHERE PACKAGE_NAME = ?` which returns all snippets for the app. Since a callsite is one bridge row, the JS snippets remain app-level context. This is accurate to how the data is structured in `jsdetails` (no per-callsite JS linkage). Confirm this is the intended design.

5. **`findings: string[]` granularity**: Individual finding strings could be the full finding block (title + description + evidence) or just the title. The auditor needs enough detail to evaluate `technicalAccuracy` and `effectChainAwareness`, so the full block is preferable.

6. **Output append vs. overwrite**: Should `callsite_results.json` be written incrementally (append per callsite) or built in memory and written at the end? Incremental is safer for long runs that might be interrupted.

7. **`--limit` behaviour**: In the new design, `--limit N` should limit the number of callsites (rows from `webview_new`), not apps.
