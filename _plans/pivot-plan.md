# Implementation Plan: Callsite-Level Multi-Model Inspector Evaluation

> Answers incorporated:
> - Inspectors A and C receive the **exact same prompt string** — the only variable is the model.
> - Auditor **self-estimates** `attackSurfaceCoverage`; researcher fills their own in `researcherConclusion`.
> - `hallucinationFrequency` is normalised **relative to the most-hallucinating inspector** in the pair.
> - `callsite_results.json` is written **incrementally** (appended after each callsite).

---

## Phase 1 — Config & Scaffolding

- [x] **1.1** Create `_plans/` directory (done) and `analyzer/analysis_configuration.json` with the following structure:
  ```json
  {
    "auditor": { "provider": "gemini", "model": "gemini-2.0-flash" },
    "inspector_pairs": [
      {
        "inspector_a": { "provider": "gemini", "model": "gemini-2.0-flash-lite" },
        "inspector_c": { "provider": "gemini", "model": "gemini-2.0-flash-lite" }
      }
    ]
  }
  ```
  This file is the sole place to declare which model pairs and auditor to use per run.

- [x] **1.2** Create `analyzer/results/` directory (the new output location). Add a `.gitkeep` so it is tracked but its contents are not — add `analyzer/results/*.json` to `.gitignore`.

---

## Phase 2 — Extractor: Callsite-Level Queries (`extractor.py`)

- [x] **2.1** Add method `get_all_callsites() -> list[dict]`:
  - Query: `SELECT id, appName, bridgeClass, intefaceObject, bridgeMethods, initiatingMethod FROM webview_new`
  - Returns a list of dicts, one per row.

- [x] **2.2** Add method `get_callsite_context(callsite_id: int) -> dict`:
  - Fetch the single `webview_new` row `WHERE id = ?`.
  - Fetch all `jsdetails` rows `WHERE PACKAGE_NAME = ?` using the row's `appName`.
  - Return:
    ```python
    {
        "callsite_id": int,
        "db_stem": "Intent",          # derived from the db filename, stripped of path and extension
        "app_name": str,
        "bridge": {                   # the single webview_new row as a dict
            "bridgeClass": ...,
            "intefaceObject": ...,
            "bridgeMethods": ...,
            "initiatingMethod": ...
        },
        "js_snippets": [...]          # list of jsdetails dicts for this app, capped at 10
    }
    ```

- [x] **2.3** Add helper `build_callsite_id(db_stem: str, row_id: int) -> str`:
  - Returns `f"{db_stem}-webview_new-{row_id}"`.
  - Place in `extractor.py` or `utils.py` (whichever feels cleaner — `utils.py` is preferred to keep extractor focused on DB access).

---

## Phase 3 — Inspector: Unified Inspector Orchestrator (`inspector.py`)

- [x] **3.1** Create `analyzer/src/inspector.py` with class `InspectorOrchestrator`.
  - Constructor: `__init__(self, provider: str, model_name: str | None = None)` — same provider/model pattern as existing orchestrators (Gemini client or `OllamaIntegration`).
  - Expose `self.model_id: str` as `f"{provider}/{model_name}"` for use in output keys.

- [x] **3.2** Write `_format_prompt(self, context: dict) -> str`:
  - Context contains one `bridge` row + `js_snippets`.
  - Prompt framing: **"Security Researcher — Bridge Callsite Vulnerability Assessment"** — neither purely defensive nor offensive. Cover all four domains from the current two prompts:
    - Data flow & sink analysis (SQL injection, path traversal, intent redirection, RCE)
    - PII & permission leakage (device ID, accounts, location)
    - Reachability & attacker control (which methods are reachable, how much input is controlled)
    - Impact chain & privilege escalation (worst-case outcome, chaining of calls)
    - Protocol & origin security (http://, missing origin checks)
  - Output format: Markdown list of findings. Each finding must follow:
    ```
    ### Finding: <title>
    **Risk Level**: Critical/High/Medium/Low
    **Data Flow Path**: [JS Source] -> [Bridge Object] -> [Java Sink]
    **Technical Description**: ...
    **Evidence**: <quoted JS line or method name>
    ```
  - This structure is required for the `extract_findings_from_markdown()` parser in Phase 5.

- [x] **3.3** Implement `get_analysis(self, context: dict) -> str`:
  - Identical retry/rate-limit logic as in the current orchestrators (max 5 retries, exponential backoff, parses `retryDelay` from Gemini 429 errors).
  - Returns the raw Markdown string.

---

## Phase 4 — Auditor: New Metrics Schema (`auditor.py`)

- [x] **4.1** Replace `_OUTPUT_SCHEMA` and `_VERDICT_DEFINITIONS` constants with the new metrics schema:
  ```json
  {
    "<modelID_inspector_a>": {
      "hallucinationFrequency": "0.0–1.0, normalised relative to the inspector with the highest hallucination count in this pair",
      "technicalAccuracy": "integer 1–10",
      "effectChainAwareness": "integer 1–10",
      "attackSurfaceCoverage": "0.0–1.0, your estimate of vulnerabilities found vs all visible in the context"
    },
    "<modelID_inspector_c>": { "...same keys..." }
  }
  ```

- [x] **4.2** Rewrite `_format_prompt(self, context: dict, findings_a: list[str], findings_c: list[str], model_id_a: str, model_id_c: str) -> str`:
  - Ground truth section: single bridge row + JS snippets (same as today).
  - Inspector findings section: two labelled blocks — one per inspector, keyed by their `model_id`.
  - Hallucination definition: explicitly state that a hallucination is any finding referencing a method, class, object, or code segment that **does not appear** in the provided context.
  - Normalisation instruction: for `hallucinationFrequency`, count hallucinated findings per inspector, then assign `1.0` to whichever inspector has more hallucinations and `their_count / max_count` to the other. If both have zero, both get `0.0`.
  - `attackSurfaceCoverage` instruction: assess which vulnerabilities are genuinely present in the context, then score each inspector as `found / total_in_context`.
  - Output: ONLY valid JSON matching the schema above — no markdown fences.

- [x] **4.3** Rewrite `get_audit(self, context: dict, findings_a: list[str], findings_c: list[str], model_id_a: str, model_id_c: str) -> str`:
  - Same provider dispatch + retry logic as current.
  - Returns raw JSON string (parsed by caller with `extract_json()`).

- [x] **4.4** Remove `_run_audit()` helper from `main.py` (it will be inlined into the new main loop).

---

## Phase 5 — Utils: Findings Extractor (`utils.py`)

- [x] **5.1** Add `extract_findings_from_markdown(report: str) -> list[str]`:
  - Split the Markdown on `### Finding:` headings.
  - Each chunk from a heading to the next heading (or end of string) is one finding string — include the heading itself.
  - Strip leading/trailing whitespace from each chunk.
  - Return an empty list if no headings found (graceful degradation if the model didn't follow the format).

- [x] **5.2** Add `build_callsite_id(db_stem: str, row_id: int) -> str` here if not placed in `extractor.py` (see step 2.3).

- [x] **5.3** Add `empty_metrics() -> dict`:
  - Returns `{ "hallucinationFrequency": 0.0, "technicalAccuracy": 0, "effectChainAwareness": 0, "attackSurfaceCoverage": 0.0 }`.
  - Used to initialise `researcherConclusion` fields in the output.

---

## Phase 6 — Main: Config-Driven Multi-Pair Loop (`main.py`)

- [x] **6.1** Add `load_config(path: str) -> dict`:
  - Reads and parses `analysis_configuration.json`.
  - Validates that `auditor` and `inspector_pairs` keys exist and that each pair has `inspector_a` and `inspector_c` with `provider` and `model`.
  - Raises a clear error with the missing key if validation fails.

- [x] **6.2** Add `_build_inspector(spec: dict) -> InspectorOrchestrator`:
  - `spec` is one of `{ "provider": ..., "model": ... }`.
  - Mirrors current `_build_orchestrator` / `_build_checker` logic; calls the Ollama interactive selector if `provider == "ollama"` and model is absent.

- [x] **6.3** Rewrite `run()`:
  - Load config with `load_config("analysis_configuration.json")`.
  - Build auditor from `config["auditor"]`.
  - Retain `--limit N` flag (now limits callsites, not apps). Remove `--provider`, `--model`, `--auditor-*`, `--checker-*`, `--skip-audit`, `--skip-checker` flags (these are replaced by the config file). Keep `--config` flag (path override for the config file, default `analysis_configuration.json`).
  - Open `results/callsite_results.json` for **incremental writing**: write `[` at start, append each serialised `CallsiteResult` object followed by `,\n`, close with `]` at end. Handle the trailing comma issue (write separator before each item after the first, not after each item).
  - Main loop:
    ```
    for callsite_row in extractor.get_all_callsites()[:limit]:
        context = extractor.get_callsite_context(callsite_row["id"])
        callsite_id_str = build_callsite_id(context["db_stem"], context["callsite_id"])
        context_str = format_context_for_output(context)  # human-readable string for the "context" field
        permutations = []
        for pair in config["inspector_pairs"]:
            inspector_a = _build_inspector(pair["inspector_a"])
            inspector_c = _build_inspector(pair["inspector_c"])
            report_a = inspector_a.get_analysis(context)
            report_c = inspector_c.get_analysis(context)
            findings_a = extract_findings_from_markdown(report_a)
            findings_c = extract_findings_from_markdown(report_c)
            raw_verdict = auditor.get_audit(context, findings_a, findings_c, inspector_a.model_id, inspector_c.model_id)
            verdict = extract_json(raw_verdict)
            permutations.append({
                "researcher": 0,
                "inspectors": [inspector_a.model_id, inspector_c.model_id],
                "auditor": auditor.model_id,
                "results": [
                    { "inspector": inspector_a.model_id, "findings": findings_a },
                    { "inspector": inspector_c.model_id, "findings": findings_c }
                ],
                "auditorVerdict": verdict,
                "researcherConclusion": empty_metrics()
            })
        record = {
            "identifiedCallsiteID": callsite_id_str,
            "context": context_str,
            "permutations": permutations
        }
        write record to results/callsite_results.json incrementally
    ```

- [x] **6.4** Add `format_context_for_output(context: dict) -> str`:
  - Produces the human-readable string stored in the `"context"` field of each output record.
  - Format: bridge row details + JS snippets, same style as the current prompt formatters.

---

## Phase 7 — Archive Old Files

- [x] **7.1** Move `analyzer/src/orchestrator.py` → `analyzer/src/_archive/orchestrator.py`.
- [x] **7.2** Move `analyzer/src/cross_checker.py` → `analyzer/src/_archive/cross_checker.py`.
- [x] **7.3** Move `analyzer/src/trustworthiness.py` → `analyzer/src/_archive/trustworthiness.py`.
- [x] **7.4** Move `analyzer/src/aggregate.py` → `analyzer/src/_archive/aggregate.py`.
- [x] **7.5** Remove all imports of archived modules from `main.py`.

---

## Phase 8 — Validation

Pre-run checklist:
- [ ] Configure models so for one pair tests:
    - Auditor is gemma3:12b
    - Inspector A is gemma3:4b
    - Inspector B is llama3.2:3b
- [ ] Ask user to have ollama engine running and get confirmation that it is

- [ ] **8.1** Run the pipeline with `--limit 1` on a single callsite across one inspector pair and inspect the output JSON manually:
  - Confirm `identifiedCallsiteID` format is `Intent-webview_new-<id>`.
  - Confirm both inspectors' findings are non-empty lists.
  - Confirm `auditorVerdict` contains both model IDs as keys with all four metrics populated.
  - Confirm `researcherConclusion` is all zeros/empty.
  - Confirm the JSON file is valid (parseable with `json.loads`).

- Configure second pair of inspectors as Inspector A being codellama:7b and Inspector B being mistral:7b
- [ ] **8.2** Run with `--limit 3` across two inspector pairs and confirm:
 
  - Output has 3 top-level records.
  - Each record has 2 permutations.
  - File was written incrementally (check file size grows after each callsite by observing log output).

- [ ] **8.3** Simulate an interrupted run (kill mid-way), then inspect the partial file to confirm it is still parseable up to the last complete record. Adjust the incremental write strategy if not (e.g., write complete valid JSON on each flush by rewriting the closing bracket).

- [ ] **8.4** Confirm Ollama path: if an `inspector_pairs` entry uses `provider: "ollama"` with no model, the interactive model selector is presented before the loop begins (not once per callsite).

---

## Dependency / Order Summary

```
Phase 1 (config files)
  └─► Phase 2 (extractor callsite queries)
        └─► Phase 3 (inspector prompt + orchestrator)
              └─► Phase 5 (utils: findings extractor, callsite ID, empty_metrics)
                    └─► Phase 4 (auditor: new schema)
                          └─► Phase 6 (main rewrite)
                                └─► Phase 7 (archive)
                                      └─► Phase 8 (validation)
```

Phases 3 and 5 can be worked on in parallel. Phase 4 depends on Phase 5 only for `empty_metrics`. Phases 7 and 8 are sequential at the end.
