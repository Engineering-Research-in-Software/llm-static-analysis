import os
from extractor import DataExtractor
from orchestrator import AnalysisOrchestrator
from ollama_orchestrator import OllamaAnalysisOrchestrator


def _build_orchestrator():
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().lower()

    if provider == "ollama":
        model_name = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        return OllamaAnalysisOrchestrator(model_name=model_name)

    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite-preview")
    return AnalysisOrchestrator(model_name=model_name)

def run():
    db_path = os.path.join("data", "Intent.sqlite")
    
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return

    extractor = DataExtractor(db_path)
    orchestrator = _build_orchestrator()
    
    apps = extractor.get_all_apps()
    print(f"[*] Found {len(apps)} apps. Starting semantic analysis...")

    for app in apps:
        print(f"[>] Analyzing: {app}...")
        context = extractor.get_app_context(app)
        report = orchestrator.get_analysis(context)
      
        os.makedirs("reports", exist_ok=True)
        report_path = os.path.join("reports", f"{app.replace('.', '_')}.md")
        with open(report_path, "w") as f:
            f.write(report)
            
    print("[!] Done. Check the 'reports' folder.")

if __name__ == "__main__":
    run()