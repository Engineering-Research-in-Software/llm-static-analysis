import json
import os
import argparse
from extractor import DataExtractor
from auditor import AuditorOrchestrator
from inspector import InspectorOrchestrator
from utils import extract_json, extract_findings_from_markdown, build_callsite_id

from datetime import datetime

_original_print = print

def print(*args, **kwargs):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    _original_print(timestamp, *args, **kwargs)

def _select_ollama_model(label: str) -> str:
    from integrations.ollama_int import OllamaIntegration
    client = OllamaIntegration(model_name="")
    models = client.get_available_models()

    if not models:
        print("[!] No Ollama models found. Pull one first with: ollama pull <model>")
        raise SystemExit(1)

    print(f"\nAvailable Ollama models ({label}):")
    for i, name in enumerate(models, 1):
        print(f"  [{i}] {name}")

    while True:
        raw = input("\nSelect model number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(models):
            chosen = models[int(raw) - 1]
            print(f"[*] Using model: {chosen}")
            return chosen
        print(f"    Invalid choice, enter a number between 1 and {len(models)}.")


def load_config(path: str) -> dict:
    with open(path) as f:
        config = json.load(f)

    if "models" not in config:
        raise KeyError("Config missing required key: 'models'")
    if not isinstance(config["models"], list) or len(config["models"]) == 0:
        raise ValueError("Config 'models' must be a non-empty list")

    for i, spec in enumerate(config["models"]):
        for field in ("provider", "model"):
            if field not in spec:
                raise KeyError(f"models[{i}] missing required key: '{field}'")

    return config


def _build_model(spec: dict, label: str) -> tuple[InspectorOrchestrator, AuditorOrchestrator]:
    provider = spec["provider"].strip().lower()
    model_name: str | None = spec.get("model") or None

    if provider == "ollama" and not model_name:
        model_name = _select_ollama_model(label)

    return (
        InspectorOrchestrator(provider=provider, model_name=model_name),
        AuditorOrchestrator(provider=provider, model_name=model_name),
    )


def _try_unload(orchestrator) -> None:
    """Unload from VRAM if this is an Ollama-backed orchestrator. No-op for Gemini."""
    if getattr(orchestrator, "provider", None) == "ollama":
        ol = getattr(orchestrator, "_ollama", None)
        if ol is not None:
            ol.unload()
            print(f"    [*] Unloaded {orchestrator.model_id} from VRAM.")


def format_context_for_output(context: dict) -> str:
    bridge = context["bridge"]
    bridge_line = (
        f"Interface '{bridge['intefaceObject']}' ({bridge['bridgeClass']}) "
        f"exposes: {bridge['bridgeMethods']} | initiating method: {bridge['initiatingMethod']}"
    )

    js_parts = [
        f"// [{s['resolution_type']}]\n{s['PASS_STRING']}"
        for s in context["js_snippets"][:10]
    ]
    js_summary = "\n---\n".join(js_parts)

    return f"APP: {context['app_name']}\n\nBRIDGE:\n{bridge_line}\n\nJS SNIPPETS:\n{js_summary}"


def run() -> None:
    parser = argparse.ArgumentParser(
        description="LLM-powered Android bridge security analyzer (callsite-level)"
    )
    parser.add_argument(
        "--config",
        default="analysis_configuration.json",
        metavar="PATH",
        help="Path to the analysis configuration JSON (default: analysis_configuration.json)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Only analyze callsites belonging to the first N apps.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"Error: Config file not found at {args.config}")
        raise SystemExit(1)

    config = load_config(args.config)

    db_path = os.path.join("data", "Intent.sqlite")
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        raise SystemExit(1)

    # Pre-build all models before the callsite loop so Ollama model selection
    # (interactive) happens once upfront, not once per callsite.
    built: list[tuple[InspectorOrchestrator, AuditorOrchestrator]] = []
    for i, spec in enumerate(config["models"]):
        inspector, auditor = _build_model(spec, f"Model {i}")
        built.append((inspector, auditor))

    inspectors = [inspector for inspector, _ in built]
    auditors = [auditor for _, auditor in built]

    extractor = DataExtractor(db_path)
    all_callsites = extractor.get_all_callsites()

    if args.limit is not None:
        seen_apps: list[str] = []
        for row in all_callsites:
            app = str(row["appName"])
            if app not in seen_apps:
                seen_apps.append(app)
        apps_to_include = set(seen_apps[: args.limit])
        callsites = [r for r in all_callsites if str(r["appName"]) in apps_to_include]
    else:
        callsites = all_callsites

    app_count = len({str(r["appName"]) for r in callsites})
    os.makedirs("results", exist_ok=True)
    output_path = os.path.join("results", "callsite_results.json")

    # Initialise the output file as a valid empty JSON array.
    with open(output_path, "w") as f:
        f.write("[]")

    print(
        f"\n[*] Analyzing {len(callsites)} callsite(s) across {app_count} app(s) "
        f"with {len(inspectors)} model(s). Starting..."
    )

    # ── Phase 0: Pre-load all callsite contexts (cheap SQLite reads) ──────────
    loaded: list[tuple[dict, dict, str, str]] = []  # (row, context, id_str, ctx_str)
    for idx, callsite_row in enumerate(callsites):
        callsite_id = int(callsite_row["id"])
        print(f"\n[>] Pre-loading context {idx + 1}/{len(callsites)} (db id={callsite_id})...")
        try:
            context = extractor.get_callsite_context(callsite_id)
        except Exception as e:
            print(f"    [!] Skipping callsite {callsite_id}: {e}")
            continue
        callsite_id_str = build_callsite_id(context["db_stem"], context["callsite_id"])
        context_str = format_context_for_output(context)
        loaded.append((callsite_row, context, callsite_id_str, context_str))

    print(f"\n[*] {len(loaded)} callsite(s) pre-loaded.")

    # intermediate[ctx_idx][model_id] = findings: list[str]
    intermediate: list[dict[str, list[str]]] = [{} for _ in loaded]
    # audit_results[ctx_idx][auditor_model_id][inspector_model_id] = metrics: dict
    audit_results: list[dict[str, dict[str, dict]]] = [{} for _ in loaded]

    # ── Phase 1: Inspector passes — one model at a time over all callsites ────
    for inspector in inspectors:
        print(
            f"\n[Phase 1] Inspector={inspector.model_id} — {len(loaded)} callsite(s)"
        )
        for ctx_idx, (_, context, callsite_id_str, _) in enumerate(loaded):
            print(f"  [{ctx_idx + 1}/{len(loaded)}] {callsite_id_str}")
            try:
                report = inspector.get_analysis(context)
            except Exception as e:
                print(f"    [!] Inspector failed: {e}")
                report = ""
            intermediate[ctx_idx][inspector.model_id] = extract_findings_from_markdown(report)

        _try_unload(inspector)

    # ── Phase 2: Cross-audit passes — each auditor evaluates all inspectors ─────
    for auditor in auditors:
        print(
            f"\n[Phase 2] Auditor={auditor.model_id} "
            f"— {len(inspectors)} inspector(s) × {len(loaded)} callsite(s)"
        )
        for ctx_idx, (_, context, callsite_id_str, _) in enumerate(loaded):
            audit_results[ctx_idx].setdefault(auditor.model_id, {})
            for inspector in inspectors:
                inspector_findings = intermediate[ctx_idx].get(inspector.model_id, [])
                print(
                    f"  [{ctx_idx + 1}/{len(loaded)}] {callsite_id_str} "
                    f"auditing {inspector.model_id} — {len(inspector_findings)} finding(s)"
                )
                try:
                    raw = auditor.get_audit(context, inspector_findings, inspector.model_id)
                    metrics = extract_json(raw)
                except Exception as e:
                    print(f"    [!] Auditor failed: {e}")
                    metrics = {}
                audit_results[ctx_idx][auditor.model_id][inspector.model_id] = metrics

        _try_unload(auditor)

    # ── Phase 3: Assemble records + incremental output write ──────────────────
    print(f"\n[Phase 3] Writing {len(loaded)} record(s)...")
    written_count = 0
    model_ids = [inspector.model_id for inspector in inspectors]

    for ctx_idx, (_, context, callsite_id_str, context_str) in enumerate(loaded):
        results = [
            {"inspector": mid, "findings": intermediate[ctx_idx].get(mid, [])}
            for mid in model_ids
        ]
        audits = audit_results[ctx_idx]
        permutation = {
            "researcher": 0,
            "inspectors": model_ids,
            "auditors": model_ids,
            "results": results,
            "audits": audits,
            "researcherConclusion": {},
        }
        record = {
            "identifiedCallsiteID": callsite_id_str,
            "context": context_str,
            "permutations": [permutation],
        }

        record_bytes = json.dumps(record, indent=2).encode()
        with open(output_path, "rb+") as f:
            # Seek back past the closing ']' and write separator + record + ']'.
            f.seek(-1, 2)
            if written_count == 0:
                f.write(b"\n")
            else:
                f.write(b",\n")
            f.write(record_bytes)
            f.write(b"\n]")

        written_count += 1
        print(f"  [+] Written: {callsite_id_str}")

    print(f"\n[!] Done. Results saved to {output_path}")


if __name__ == "__main__":
    run()
