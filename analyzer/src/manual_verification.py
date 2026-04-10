"""
manual_verification.py - Manual verification tool.

Inspect raw app evidence from the database before annotating findings
produced by the analysis pipeline.

Commands:
    preview <app_name>          print bridge interfaces and JS snippets for an app
    template [--reports-dir]    generate a CSV annotation template from audit files
    evaluate <csv>              compute Agent B accuracy against your annotations

Run from the analyzer/ directory:
    python src/manual_verification.py preview com.cheogram.android_4206304
    python src/manual_verification.py template
    python src/manual_verification.py evaluate annotations.csv
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys


DB_PATH = "data/Intent.sqlite"
REPORTS_DIR = "reports"
OUTPUT_CSV = "annotations.csv"


def cmd_preview(app_name, db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        "SELECT bridgeClass, intefaceObject, bridgeMethods, initiatingMethod "
        "FROM webview_new WHERE appName = ?",
        (app_name,),
    )
    bridges = cur.fetchall()

    if not bridges:
        print(f"App '{app_name}' not found. Available apps:")
        cur.execute("SELECT DISTINCT appName FROM webview_new ORDER BY appName")
        for row in cur.fetchall():
            print(f"  {row[0]}")
        conn.close()
        sys.exit(1)

    js_pkg = re.sub(r'_\d+$', '', app_name)
    cur.execute(
        "SELECT PASS_STRING, confidence, resolution_type FROM jsdetails WHERE PACKAGE_NAME = ?",
        (js_pkg,),
    )
    js_rows = cur.fetchall()
    conn.close()

    print("=" * 70)
    print(f"APP: {app_name}")
    print("=" * 70)

    print(f"\nBridge interfaces ({len(bridges)} row(s))\n")
    for i, (bridge_class, iface_obj, methods, init_method) in enumerate(bridges, 1):
        print(f"  [{i}] {iface_obj} ({bridge_class})")
        print(f"    methods: {methods}")
        print(f"    initiating: {init_method}")
        print()

    if js_rows:
        print(f"JavaScript snippets ({len(js_rows)} row(s))\n")
        for i, (snippet, confidence, res_type) in enumerate(js_rows, 1):
            print(f"  [{i}] {res_type} (confidence: {confidence})")
            print(f"    {snippet[:300]}{'...' if len(snippet) > 300 else ''}")
            print()
    else:
        print("JavaScript snippets: none\n")


def cmd_template(reports_dir, output_csv):
    if not os.path.isdir(reports_dir):
        print(f"Reports directory '{reports_dir}' not found. Run the pipeline first.")
        sys.exit(1)

    rows = []
    for app_name in sorted(os.listdir(reports_dir)):
        app_dir = os.path.join(reports_dir, app_name)
        if not os.path.isdir(app_dir):
            continue

        for audit_file, agent in [("audit.json", "A"), ("checker_audit.json", "C")]:
            path = os.path.join(app_dir, audit_file)
            if not os.path.exists(path):
                continue

            with open(path) as f:
                audit = json.load(f)

            if "error" in audit:
                continue

            for finding in audit.get("findings_audit", []):
                rows.append({
                    "app": app_name,
                    "agent": agent,
                    "finding_title": finding.get("finding_title", ""),
                    "agent_b_verdict": finding.get("verdict", ""),
                    "is_real_vulnerability": "",
                    "notes": "",
                })

    if not rows:
        print("No audit files found. Run the pipeline with Agent B enabled first.")
        sys.exit(1)

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["app", "agent", "finding_title", "agent_b_verdict", "is_real_vulnerability", "notes"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} findings to {output_csv}")
    print("Fill in 'is_real_vulnerability' with YES or NO for each row, then run evaluate.")


def cmd_evaluate(csv_path):
    if not os.path.exists(csv_path):
        print(f"File not found: {csv_path}")
        sys.exit(1)

    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))

    annotated = [r for r in rows if r.get("is_real_vulnerability", "").strip().upper() in ("YES", "NO")]

    if not annotated:
        print("No annotated rows found. Fill in 'is_real_vulnerability' with YES or NO first.")
        sys.exit(1)

    skipped = len(rows) - len(annotated)
    if skipped:
        print(f"Skipping {skipped} unannotated row(s).\n")

    bad_verdicts = {"HALLUCINATED", "UNSUPPORTED"}
    tp, fp, tn, fn = 0, 0, 0, 0

    for row in annotated:
        flagged = row["agent_b_verdict"].strip().upper() in bad_verdicts
        bad = row["is_real_vulnerability"].strip().upper() == "NO"

        if flagged and bad:
            tp += 1
        elif flagged and not bad:
            fp += 1
        elif not flagged and bad:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"Annotated findings: {len(annotated)}")
    print(f"  TP {tp}  FP {fp}  TN {tn}  FN {fn}\n")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1:        {f1:.3f}")


def main():
    parser = argparse.ArgumentParser(description="Manual verification tool")
    sub = parser.add_subparsers(dest="command", required=True)

    preview = sub.add_parser("preview", help="Print raw evidence for one app")
    preview.add_argument("app_name")
    preview.add_argument("--db", default=DB_PATH)

    template = sub.add_parser("template", help="Generate CSV annotation template from audit files")
    template.add_argument("--reports-dir", default=REPORTS_DIR)
    template.add_argument("--output", default=OUTPUT_CSV)

    evaluate = sub.add_parser("evaluate", help="Compute Agent B accuracy against annotations")
    evaluate.add_argument("csv_path")

    args = parser.parse_args()

    if args.command == "preview":
        cmd_preview(args.app_name, args.db)
    elif args.command == "template":
        cmd_template(args.reports_dir, args.output)
    elif args.command == "evaluate":
        cmd_evaluate(args.csv_path)


if __name__ == "__main__":
    main()
