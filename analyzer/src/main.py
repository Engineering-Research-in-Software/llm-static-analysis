import os
import json
import argparse
from extractor import DataExtractor
from orchestrator import AnalysisOrchestrator
from auditor import AuditorOrchestrator
from cross_checker import CrossCheckerOrchestrator
from utils import extract_json
from trustworthiness import compute_trustworthiness, compute_comparison
from aggregate import build_aggregate


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


def _build_orchestrator(args: argparse.Namespace) -> AnalysisOrchestrator:
    if args.provider == "ollama":
        model_name = args.model or _select_ollama_model("Agent A")
        return AnalysisOrchestrator(provider="ollama", model_name=model_name)
    model_name = args.model or os.getenv("GEMINI_MODEL")
    return AnalysisOrchestrator(provider="gemini", model_name=model_name)


def _build_auditor(args: argparse.Namespace) -> AuditorOrchestrator:
    provider = args.auditor_provider or args.provider
    model_name = args.auditor_model
    if provider == "ollama":
        model_name = model_name or _select_ollama_model("Agent B / Auditor")
        return AuditorOrchestrator(provider="ollama", model_name=model_name)
    return AuditorOrchestrator(provider="gemini", model_name=model_name or os.getenv("AUDITOR_GEMINI_MODEL"))


def _build_checker(args: argparse.Namespace) -> CrossCheckerOrchestrator:
    provider = args.checker_provider or args.provider
    model_name = args.checker_model
    if provider == "ollama":
        model_name = model_name or _select_ollama_model("Agent C / Cross-Checker")
        return CrossCheckerOrchestrator(provider="ollama", model_name=model_name)
    return CrossCheckerOrchestrator(provider="gemini", model_name=model_name or os.getenv("CHECKER_GEMINI_MODEL"))


def _run_audit(
    auditor: AuditorOrchestrator,
    context: dict,
    report: str,
    app_dir: str,
    audit_filename: str,
    trust_filename: str,
    label: str,
) -> dict | None:
    print(f"    [{label}] Auditing...")
    try:
        raw_audit = auditor.get_audit(context, report)
        audit = extract_json(raw_audit)
        scores = compute_trustworthiness(audit)

        with open(os.path.join(app_dir, audit_filename), "w") as f:
            json.dump(audit, f, indent=2)
        with open(os.path.join(app_dir, trust_filename), "w") as f:
            json.dump(scores, f, indent=2)

        halluc_count = round(scores["hallucination_rate"] * len(audit.get("findings_audit", [])))
        print(
            f"    {label}: Consistency {scores['overall_consistency_score']}/10 | "
            f"Trust {scores['trustworthiness_score']} | Halluc {halluc_count}"
        )
        return scores
    except Exception as e:
        print(f"    [!] Audit ({label}) failed: {e}")
        with open(os.path.join(app_dir, audit_filename), "w") as f:
            json.dump({"error": str(e)}, f, indent=2)
        return None


def run() -> None:
    parser = argparse.ArgumentParser(description="LLM-powered Android bridge security analyzer")

    parser.add_argument(
        "--provider",
        choices=["gemini", "ollama"],
        default=os.getenv("LLM_PROVIDER", "gemini").strip().lower(),
        help="LLM backend for Agent A (default: gemini)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model for Agent A. Ollama shows selector if omitted.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Only analyze the first N apps.",
    )
    parser.add_argument(
        "--auditor-provider",
        choices=["gemini", "ollama"],
        default=None,
        dest="auditor_provider",
        help="LLM backend for Agent B. Defaults to --provider.",
    )
    parser.add_argument(
        "--auditor-model",
        default=None,
        dest="auditor_model",
        help="Model for Agent B.",
    )
    parser.add_argument(
        "--checker-provider",
        choices=["gemini", "ollama"],
        default=None,
        dest="checker_provider",
        help="LLM backend for Agent C. Defaults to --provider.",
    )
    parser.add_argument(
        "--checker-model",
        default=None,
        dest="checker_model",
        help="Model for Agent C.",
    )
    parser.add_argument(
        "--skip-audit",
        action="store_true",
        dest="skip_audit",
        help="Run only Agent A, skipping audit and cross-check.",
    )
    parser.add_argument(
        "--skip-checker",
        action="store_true",
        dest="skip_checker",
        help="Run Agent A + Agent B only, skipping Agent C.",
    )
    args = parser.parse_args()

    db_path = os.path.join("data", "Intent.sqlite")
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return

    orchestrator = _build_orchestrator(args)
    auditor = None if args.skip_audit else _build_auditor(args)
    checker = None if (args.skip_audit or args.skip_checker) else _build_checker(args)

    extractor = DataExtractor(db_path)
    apps = extractor.get_all_apps()
    if args.limit is not None:
        apps = apps[:args.limit]

    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    print(f"\n[*] Analyzing {len(apps)} app(s). Starting semantic analysis...")

    for app in apps:
        app_dir = os.path.join(reports_dir, app)
        os.makedirs(app_dir, exist_ok=True)
        print(f"\n[>] Analyzing: {app}...")

        context = extractor.get_app_context(app)

        # Agent A
        report_a = orchestrator.get_analysis(context)
        with open(os.path.join(app_dir, "report.md"), "w") as f:
            f.write(report_a)

        if auditor is None:
            continue

        # Agent B audits Agent A
        trust_a = _run_audit(auditor, context, report_a, app_dir, "audit.json", "trust.json", "B→A")

        if checker is None:
            continue

        # Agent C — independent analysis (never sees Agent A's report)
        print(f"    [C] Cross-checking...")
        try:
            report_c = checker.get_analysis(context)
            with open(os.path.join(app_dir, "checker.md"), "w") as f:
                f.write(report_c)
        except Exception as e:
            print(f"    [!] Agent C failed: {e}")
            with open(os.path.join(app_dir, "checker.md"), "w") as f:
                f.write(f"ERROR: {e}")
            continue

        # Agent B audits Agent C
        trust_c = _run_audit(auditor, context, report_c, app_dir, "checker_audit.json", "checker_trust.json", "B→C")

        # Comparison
        if trust_a and trust_c:
            comp = compute_comparison(trust_a, trust_c)
            with open(os.path.join(app_dir, "comparison.json"), "w") as f:
                json.dump(comp, f, indent=2)
            print(f"    Winner: Agent {comp['more_trustworthy_agent']} (Δ {comp['delta_trustworthiness']:+.3f})")

    # Aggregate
    if auditor is not None:
        print()
        build_aggregate(
            reports_dir,
            run_metadata={
                "agent_a_model": f"{args.provider}/{orchestrator.model_name}",
                "agent_b_model": f"{auditor.provider}/{auditor.model_name}",
                "agent_c_model": f"{checker.provider}/{checker.model_name}" if checker else "N/A",
                "apps_analyzed": len(apps),
            },
        )

    print("\n[!] Done. Check the 'reports' folder.")


if __name__ == "__main__":
    run()
