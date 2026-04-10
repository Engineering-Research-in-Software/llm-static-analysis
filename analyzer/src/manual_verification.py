"""
manual_verification.py - Manual verification tool.

Inspect raw app evidence from the database before annotating findings
produced by the analysis pipeline.

Commands:
    preview <app_name>  print bridge interfaces and JS snippets for an app

Run from the analyzer/ directory:
    python src/manual_verification.py preview com.cheogram.android_4206304
"""

import argparse
import re
import sqlite3
import sys


DB_PATH = "data/Intent.sqlite"


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


def main():
    parser = argparse.ArgumentParser(description="Manual verification tool")
    sub = parser.add_subparsers(dest="command", required=True)

    preview = sub.add_parser("preview", help="Print raw evidence for one app")
    preview.add_argument("app_name")
    preview.add_argument("--db", default=DB_PATH)

    args = parser.parse_args()

    if args.command == "preview":
        cmd_preview(args.app_name, args.db)


if __name__ == "__main__":
    main()
