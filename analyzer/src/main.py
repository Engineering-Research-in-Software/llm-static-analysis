import json
import os
import argparse
from extractor import DataExtractor
from auditor import AuditorOrchestrator
from inspector import InspectorOrchestrator
from utils import extract_json, extract_findings_from_markdown, build_callsite_id, empty_metrics


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

    if "auditor" not in config:
        raise KeyError("Config missing required key: 'auditor'")
    if "inspector_pairs" not in config:
        raise KeyError("Config missing required key: 'inspector_pairs'")

    for i, pair in enumerate(config["inspector_pairs"]):
        for role in ("inspector_a", "inspector_c"):
            if role not in pair:
                raise KeyError(f"inspector_pairs[{i}] missing required key: '{role}'")
            for field in ("provider", "model"):
                if field not in pair[role]:
                    raise KeyError(
                        f"inspector_pairs[{i}]['{role}'] missing required key: '{field}'"
                    )

    return config


def _build_inspector(spec: dict, label: str) -> InspectorOrchestrator:
    provider = spec["provider"].strip().lower()
    model_name: str | None = spec.get("model") or None

    if provider == "ollama" and not model_name:
        model_name = _select_ollama_model(label)

    return InspectorOrchestrator(provider=provider, model_name=model_name)


def _build_auditor(spec: dict) -> AuditorOrchestrator:
    provider = spec["provider"].strip().lower()
    model_name: str | None = spec.get("model") or None

    if provider == "ollama" and not model_name:
        model_name = _select_ollama_model("Auditor")

    return AuditorOrchestrator(provider=provider, model_name=model_name)


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

    auditor = _build_auditor(config["auditor"])

    # Pre-build all inspector pairs before the callsite loop so Ollama model
    # selection (interactive) happens once upfront, not once per callsite.
    inspector_pairs_built: list[tuple[InspectorOrchestrator, InspectorOrchestrator]] = []
    for i, pair in enumerate(config["inspector_pairs"]):
        inspector_a = _build_inspector(pair["inspector_a"], f"Pair {i} / Inspector A")
        inspector_c = _build_inspector(pair["inspector_c"], f"Pair {i} / Inspector C")
        inspector_pairs_built.append((inspector_a, inspector_c))

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
        f"\n[*] Analyzing {len(callsites)} callsite(s) across {app_count} app(s) and "
        f"{len(inspector_pairs_built)} inspector pair(s). Starting..."
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

    # intermediate[ctx_idx][pair_idx] = {"findings_a": [...], "findings_c": [...]}
    intermediate: list[dict[int, dict[str, list[str]]]] = [{} for _ in loaded]

    # ── Phase 1: Inspector batches — iterate by model, not by callsite ────────
    for pair_idx, (inspector_a, inspector_c) in enumerate(inspector_pairs_built):
        print(
            f"\n[Phase 1 / Pair {pair_idx}] Inspector A={inspector_a.model_id} "
            f"— {len(loaded)} callsite(s)"
        )
        for ctx_idx, (_, context, callsite_id_str, _) in enumerate(loaded):
            print(f"  [{ctx_idx + 1}/{len(loaded)}] {callsite_id_str} — Inspector A")
            try:
                report_a = inspector_a.get_analysis(context)
            except Exception as e:
                print(f"    [!] Inspector A failed: {e}")
                report_a = ""
            intermediate[ctx_idx].setdefault(pair_idx, {"findings_a": [], "findings_c": []})
            intermediate[ctx_idx][pair_idx]["findings_a"] = extract_findings_from_markdown(report_a)

        _try_unload(inspector_a)

        print(
            f"\n[Phase 1 / Pair {pair_idx}] Inspector C={inspector_c.model_id} "
            f"— {len(loaded)} callsite(s)"
        )
        for ctx_idx, (_, context, callsite_id_str, _) in enumerate(loaded):
            print(f"  [{ctx_idx + 1}/{len(loaded)}] {callsite_id_str} — Inspector C")
            try:
                report_c = inspector_c.get_analysis(context)
            except Exception as e:
                print(f"    [!] Inspector C failed: {e}")
                report_c = ""
            intermediate[ctx_idx].setdefault(pair_idx, {"findings_a": [], "findings_c": []})
            intermediate[ctx_idx][pair_idx]["findings_c"] = extract_findings_from_markdown(report_c)

        _try_unload(inspector_c)

    # ── Phase 2: Auditor pass + incremental output write ─────────────────────
    print(f"\n[Phase 2] Auditing {len(loaded)} callsite(s) with {auditor.model_id}...")
    written_count = 0

    for ctx_idx, (_, context, callsite_id_str, context_str) in enumerate(loaded):
        print(f"\n[>] Callsite {ctx_idx + 1}/{len(loaded)} ({callsite_id_str})...")
        permutations: list[dict] = []

        for pair_idx, (inspector_a, inspector_c) in enumerate(inspector_pairs_built):
            slot = intermediate[ctx_idx].get(pair_idx, {})
            findings_a = slot.get("findings_a", [])
            findings_c = slot.get("findings_c", [])
            print(
                f"    [Pair {pair_idx}] Findings: A={len(findings_a)}, C={len(findings_c)}"
            )
            print(f"    [Pair {pair_idx}] Auditing with {auditor.model_id}...")
            try:
                raw_verdict = auditor.get_audit(
                    context, findings_a, findings_c, inspector_a.model_id, inspector_c.model_id
                )
                verdict = extract_json(raw_verdict)
            except Exception as e:
                print(f"    [!] Auditor failed: {e}")
                verdict = {}

            permutations.append(
                {
                    "researcher": 0,
                    "inspectors": [inspector_a.model_id, inspector_c.model_id],
                    "auditor": auditor.model_id,
                    "results": [
                        {"inspector": inspector_a.model_id, "findings": findings_a},
                        {"inspector": inspector_c.model_id, "findings": findings_c},
                    ],
                    "auditorVerdict": verdict,
                    "researcherConclusion": empty_metrics(),
                }
            )

        record = {
            "identifiedCallsiteID": callsite_id_str,
            "context": context_str,
            "permutations": permutations,
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
        print(f"    [+] Written: {callsite_id_str}")

    _try_unload(auditor)
    print(f"\n[!] Done. Results saved to {output_path}")


if __name__ == "__main__":
    run()
