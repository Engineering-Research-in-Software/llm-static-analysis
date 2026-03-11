import os
from extractor import DataExtractor
from orchestrator import AnalysisOrchestrator

def run():
    db_path = os.path.join("data", "Intent.sqlite")
    
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return

    extractor = DataExtractor(db_path)
    orchestrator = AnalysisOrchestrator()
    
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