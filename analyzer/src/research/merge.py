#!/usr/bin/env python3
"""
merge_json.py  <folder>

Merges all JSON files found directly inside <folder> into a single JSON array
and writes the result to <folder>/<folder_name>.merged.json.

Each file's content is included as one element of the array:
  - If the file contains a JSON array  → its items are spread into the output.
  - If the file contains a JSON object → it is appended as a single element.

Usage:
    python3 merge_json.py /path/to/folder
"""

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <folder>", file=sys.stderr)
        sys.exit(1)

    folder = Path(sys.argv[1]).resolve()

    if not folder.is_dir():
        print(f"Error: '{folder}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    output_path = folder / f"{folder.name}.merged.json"

    json_files = sorted(
        p for p in folder.iterdir()
        if p.is_file()
        and p.suffix.lower() == ".json"
        and p.name != output_path.name          # skip any previous merge output
    )

    if not json_files:
        print(f"No JSON files found in '{folder}'.", file=sys.stderr)
        sys.exit(1)

    merged: list[Any] = []
    errors: list[str] = []

    for path in json_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"  {path.name}: {exc}")
            continue

        if isinstance(data, list):
            merged.extend(data)
        else:
            merged.append(data)

        print(f"  Merged: {path.name}")

    if errors:
        print("\nThe following files were skipped due to parse errors:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)

    output_path.write_text(
        json.dumps(merged, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\nWrote {len(merged)} item(s) to '{output_path}'.")


if __name__ == "__main__":
    main()