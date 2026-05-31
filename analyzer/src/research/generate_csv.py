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

        bridge_match = re.search(r"BRIDGE:\s*\n(.+?)(?=\n\n|\Z)", record["context"], re.DOTALL)
        android_context = bridge_match.group(1).strip() if bridge_match else ""

        js_match = re.search(r"JS SNIPPETS:\s*\n(.+?)(?=\n\n[A-Z]|\Z)", record["context"], re.DOTALL)
        js_call_place = js_match.group(1).strip() if js_match else ""

        for permutation in record.get("permutations", []):
            for result in permutation.get("results", []):
                inspector = result["inspector"]
                for finding_text in result.get("findings", []):
                    app_rows[app].append([callsite_id, inspector, finding_text.strip(), "", js_call_place, android_context])

    os.makedirs(output_dir, exist_ok=True)
    for app, rows in app_rows.items():
        safe_name = re.sub(r"[^\w\-.]", "_", app)
        out_path = os.path.join(output_dir, f"{safe_name}.csv")
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Callsite", "Inspector", "Finding", "Verdict", "JS Call Place", "Android Context"])
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rows → {out_path}")


if __name__ == "__main__":
    generate_csvs(
        results_path="analyzer/src/research/callsite_results_yusuf_filtered_filled.json",
        output_dir="csv_output",
    )
