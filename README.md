# Trust, but Verify
### A Multi-Agent Framework for Auditing LLM-Guided Android Security Analysis

This tool runs a three-agent LLM pipeline against Android hybrid applications to identify security vulnerabilities in the JavaScript-to-Java WebView bridge and measure how much the analysis output can be trusted. It was built as a research prototype for studying the reliability of LLM-generated security findings.

---

## What it does

Android apps that use WebView expose Java methods to JavaScript through `addJavascriptInterface`. This creates a cross-language attack surface that static analysis tools struggle with. This tool uses LLMs to reason about those bridges semantically, then turns a second and third agent loose on the output to catch hallucinations and inconsistencies before the results are trusted.

The three agents are:

- **Agent A** — the main analyzer. Given a set of bridge interfaces and JavaScript snippets extracted from an app, it produces a full security report covering data flows, PII exposure, semantic mismatches, and protocol issues.
- **Agent B** — the auditor. It reads Agent A's report alongside the original raw evidence and checks whether each finding is actually supported by that evidence. Verdicts range from `SUPPORTED` to `HALLUCINATED`.
- **Agent C** — the cross-checker. It independently analyzes the same app from scratch, without ever seeing Agent A's report, from an offensive attack-surface angle. Agent B then audits this output too, giving you two comparable trustworthiness scores from a consistent judge.

At the end of a run, the tool computes a **Trustworthiness Score** for each agent's output and generates a summary report comparing them.

---

## Setup

### Prerequisites

- Python 3.12+
- A Gemini API key (free tier works for small runs), an Ollama installation, or both
- An SQLite database produced by [iWanDroid](https://github.com/s2-lab/iWandroid) containing WebView bridge data for the apps you want to analyze

### Installation

```bash
cd analyzer
python -m venv src/venv
source src/venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the `analyzer/` directory:

```
GEMINI_API_KEY=your_key_here
```

Place your iWanDroid SQLite database at `analyzer/data/Intent.sqlite`.

---

## Running the tool

All commands are run from the `analyzer/` directory.

### Quickstart — Gemini only, all three agents

```bash
python src/main.py
```

This uses Gemini for all three agents with the default model. Reports go into `reports/`.

### Limit to a few apps (useful while testing)

```bash
python src/main.py --limit 5
```

### Use Ollama instead of Gemini

```bash
python src/main.py --provider ollama
```

If you don't pass `--model`, an interactive selector will show all locally available Ollama models.

### Run only Agent A (no auditing)

```bash
python src/main.py --skip-audit
```

### Run Agents A and B but skip Agent C

```bash
python src/main.py --skip-checker
```

### Use different models for each agent

This is the most useful configuration for research purposes — it lets you compare how different models perform as analyzer vs. cross-checker under the same auditor.

```bash
python src/main.py \
  --provider gemini --model gemini-2.0-flash \
  --auditor-provider gemini --auditor-model gemini-2.0-flash \
  --checker-provider ollama --checker-model llama3.1:8b
```

| Flag | Agent | Default |
|---|---|---|
| `--provider` | A | gemini |
| `--model` | A | gemini-2.0-flash-lite |
| `--auditor-provider` | B | same as `--provider` |
| `--auditor-model` | B | same as `--model` |
| `--checker-provider` | C | same as `--provider` |
| `--checker-model` | C | same as `--model` |

---

## Output structure

Each analyzed app gets its own folder inside `reports/`:

```
reports/
  com.example.app/
    report.md               Agent A's security report
    audit.json              Agent B's verdict on Agent A (per-finding)
    trust.json              Trustworthiness scores for Agent A
    checker.md              Agent C's independent security report
    checker_audit.json      Agent B's verdict on Agent C
    checker_trust.json      Trustworthiness scores for Agent C
    comparison.json         Head-to-head A vs C comparison
  aggregate_report.md       Human-readable summary table across all apps
  aggregate_scores.json     Machine-readable data for statistical analysis
```

### Trustworthiness Score

Scores range from **-1.0 to 1.0**:

```
score = (semantic_precision + argumentative_consistency) / 2 - hallucination_rate
```

- **0.7 – 1.0** — findings are well-evidenced and internally consistent
- **0.4 – 0.7** — mostly sound, some unsupported claims
- **0.0 – 0.4** — significant unsupported findings, treat with caution
- **below 0.0** — hallucination rate dominates; the report is likely unreliable

---

## Research process

This tool was designed around four research questions. Here is how to use the output to address each one.

### RQ A — What metrics best capture trustworthiness?

Run the full pipeline across the entire app dataset. The `trust.json` files give you `semantic_precision`, `hallucination_rate`, and `argumentative_consistency` for every app. Load `aggregate_scores.json` into a notebook and analyse the distribution of each metric. To validate that the composite score actually reflects quality, you need a **Gold Standard** — a small manually-verified subset of findings labelled as true or false. Correlate the score against those labels to confirm it is tracking something real.

### RQ B — How do different model architectures compare?

Run the tool at least twice with different model assignments for Agent A and Agent C:

```bash
# Run 1
python src/main.py --provider gemini --checker-provider ollama --checker-model llama3.1:8b --limit 20

# Run 2 — swap the models
python src/main.py --provider ollama --model llama3.1:8b --checker-provider gemini --limit 20
```

Save the `aggregate_scores.json` from each run. Compare `avg_trustworthiness_a` vs `avg_trustworthiness_c` and the win/loss counts. The `comparison.json` files give you per-app paired data suitable for a Wilcoxon signed-rank test or a paired t-test.

### RQ C — Where does the auditor struggle?

The `audit.json` files are the primary source. Aggregate the `verdict` field across all apps and look for patterns:

- Which vulnerability categories (SQL injection, PII, intent) get `HALLUCINATED` most often?
- What does `missing_findings` consistently flag that the analyzer missed?
- Are failures correlated with app complexity (number of bridge methods or JS snippets)?

This produces the failure taxonomy and tells you whether failures are model-specific or structural.

### Hypothesis test

The null hypothesis states that the auditor's error-detection rate is no better than random (p = 0.05). To test this:

1. Manually verify findings for a representative subset of apps — these are your Gold Standard labels.
2. For each finding in the corresponding `audit.json`, check whether Agent B's verdict (`HALLUCINATED` or `UNSUPPORTED` for false findings, `SUPPORTED` for true ones) matches your label.
3. Compute the error-detection rate as the proportion of correctly identified false findings.
4. Run a one-sample binomial test against the random baseline (0.5) at α = 0.05.

If the result is significant, you reject H0 and conclude that the auditor has a real ability to catch unreliable findings.

---

## Notes

- Gemini free tier has a daily quota. For large runs, consider using `--limit` to split across days or switch to Ollama for unlimited local inference.
- If Agent B returns malformed JSON (which happens occasionally with smaller models), the audit is saved as an error and the pipeline continues. Check for `{"error": ...}` entries in audit files after a run.
- The `aggregate_report.md` and `aggregate_scores.json` are regenerated at the end of every run. Running the tool again on the same apps will overwrite existing report folders.
