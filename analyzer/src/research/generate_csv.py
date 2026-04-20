import json
import csv
import re
import os
from collections import defaultdict


def generate_csvs(results_path: str, output_dir: str) -> None:
    with open(results_path) as f:
        records = json.load(f)

    app_rows = defaultdict(list)

    for record in records:
        callsite_id = record["identifiedCallsiteID"]
        app_match = re.search(r"^APP:\s*(.+)$", record["context"], re.MULTILINE)
        app = app_match.group(1).strip() if app_match else "unknown"

        for permutation in record.get("permutations", []):
            for result in permutation.get("results", []):
                inspector = result["inspector"]
                for finding_text in result.get("findings", []):
                    title_match = re.match(r"###\s*Finding:\s*(.+)", finding_text)
                    finding_title = title_match.group(1).strip() if title_match else finding_text[:80]
                    app_rows[app].append([callsite_id, inspector, finding_title, ""])

    os.makedirs(output_dir, exist_ok=True)
    for app, rows in app_rows.items():
        safe_name = re.sub(r"[^\w\-.]", "_", app)
        out_path = os.path.join(output_dir, f"{safe_name}.csv")
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Callsite", "Inspector", "Finding", "Verdict"])
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rows → {out_path}")


if __name__ == "__main__":
    generate_csvs(
        results_path="/Users/joaocardoso/Documents/SDU/repos/llm-static-analysis/analyzer/results/callsite_results_bina.json",
        output_dir="csv_output",
    )
