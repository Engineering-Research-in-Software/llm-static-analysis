#!/usr/bin/env python3
"""Fill `researcherConclusion` blocks per callsite per inspector from validated CSV verdicts.

Usage (from analyzer/):
    python src/research/fillResearcherConclusionsFromCsv.py src/research/callsite_results_bina_filtered_filled.json

Writes <input>_researcher.json alongside the input.

Per-callsite per-inspector metrics:
    HF  = INVALID / total                       (0 if total == 0)
    TA  = (10*V + 6*P + 2*I) / total            (0 if total == 0)
    ECA = (8*V  + 5*P + 1*I) / total            (0 if total == 0)
    ASC = (V + P) / max((V_j + P_j) over inspectors at the callsite)   (0 if max == 0)

Inspectors absent from the CSV → all zeros.
Apps with no validated CSV → fall back to averaging the permutation's audits[auditor][inspector] scores.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

csv.field_size_limit(sys.maxsize)

from filterRepeatedFindings import AuditDocument, Callsite, Permutation


METRICS = ("hallucinationFrequency", "technicalAccuracy", "effectChainAwareness", "attackSurfaceCoverage")
ROOT = Path(__file__).resolve().parents[2]
VALIDATED_DIR = ROOT / "validated"


def extract_app(context: str) -> str | None:
    m = re.search(r"APP:\s*([^\n]+)", context)
    return m.group(1).strip() if m else None


def find_validated_dir(app: str) -> Path | None:
    """Return the validated/<dir> path matching this app id, or None."""
    if not VALIDATED_DIR.exists():
        return None
    # Direct match first
    direct = VALIDATED_DIR / app
    if direct.is_dir():
        return direct
    # Longest-prefix match across folders
    best: tuple[int, Path] | None = None
    for entry in VALIDATED_DIR.iterdir():
        if not entry.is_dir():
            continue
        name = entry.name
        if app.startswith(name) or name.startswith(app):
            common = os.path.commonprefix([app, name])
            score = len(common)
            if best is None or score > best[0]:
                best = (score, entry)
    return best[1] if best else None


def load_csv_verdicts(csv_path: Path) -> dict[str, dict[str, Counter]]:
    """Return {callsite_id: {inspector: Counter({verdict: count})}}."""
    out: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = (row.get("Callsite") or "").strip()
            ins = (row.get("Inspector") or "").strip()
            verdict = (row.get("Verdict") or "").strip().upper()
            if not cid or not ins or not verdict:
                continue
            out[cid][ins][verdict] += 1
    return out


def metrics_from_counts(counts: Counter, max_vp_at_callsite: int) -> dict[str, float]:
    v = counts.get("VALID", 0)
    i = counts.get("INVALID", 0)
    p = counts.get("PARTIAL", 0)
    total = v + i + p
    if total == 0:
        return {m: 0 for m in METRICS}
    hf = round(i / total, 2)
    ta = round((10 * v + 6 * p + 2 * i) / total, 1)
    eca = round((8 * v + 5 * p + 1 * i) / total, 1)
    asc = round((v + p) / max_vp_at_callsite, 2) if max_vp_at_callsite > 0 else 0
    return {
        "hallucinationFrequency": hf,
        "technicalAccuracy": ta,
        "effectChainAwareness": eca,
        "attackSurfaceCoverage": asc,
    }


def zeros() -> dict[str, float]:
    return {m: 0 for m in METRICS}


def audit_averages(permutation: Permutation, inspector: str) -> dict[str, float]:
    """Average each metric across all auditors for this inspector. 0 if no data."""
    audits = permutation.get("audits") or {}
    totals: dict[str, float] = {m: 0.0 for m in METRICS}
    counts: dict[str, int] = {m: 0 for m in METRICS}
    for auditor, inspector_scores in audits.items():
        if not isinstance(inspector_scores, dict):
            continue
        scores = inspector_scores.get(inspector)
        if not isinstance(scores, dict):
            continue
        for m in METRICS:
            v = scores.get(m)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                totals[m] += float(v)
                counts[m] += 1
    out: dict[str, float] = {}
    for m in METRICS:
        if counts[m] == 0:
            out[m] = 0
        else:
            avg = totals[m] / counts[m]
            out[m] = round(avg, 2) if m in ("hallucinationFrequency", "attackSurfaceCoverage") else round(avg, 1)
    return out


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Path to input JSON file.")
    args = parser.parse_args()

    in_path = Path(args.input).resolve()
    with open(in_path, "r", encoding="utf-8") as f:
        data: AuditDocument = json.load(f)

    # Cache: app -> {callsite_id -> {inspector -> Counter}}
    csv_cache: dict[str, dict[str, dict[str, Counter]] | None] = {}

    n_callsites = 0
    n_perms_csv = 0
    n_perms_audit_fallback = 0
    apps_with_csv: set[str] = set()
    apps_without_csv: set[str] = set()
    zero_inspector_hits: Counter = Counter()

    for callsite in data:
        n_callsites += 1
        cid = callsite.get("identifiedCallsiteID", "")
        app = extract_app(callsite.get("context", ""))
        if app is None:
            print(f"[WARN] Callsite {cid} has no APP in context — skipping")
            continue

        if app not in csv_cache:
            vdir = find_validated_dir(app)
            if vdir is None:
                csv_cache[app] = None
            else:
                csv_files = list(vdir.glob("*.csv"))
                if not csv_files:
                    csv_cache[app] = None
                else:
                    merged: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
                    for cf in csv_files:
                        sub = load_csv_verdicts(cf)
                        for k, by_ins in sub.items():
                            for ins, cnt in by_ins.items():
                                merged[k][ins].update(cnt)
                    csv_cache[app] = merged

        verdict_table = csv_cache[app]

        for perm in callsite.get("permutations", []):
            inspectors = perm.get("inspectors", []) or []
            conclusion: dict[str, dict[str, float]] = {}

            if verdict_table is not None:
                apps_with_csv.add(app)
                n_perms_csv += 1
                per_inspector = verdict_table.get(cid, {})
                # Precompute max V+P at this callsite across listed inspectors
                vp_per_inspector = {
                    ins: per_inspector.get(ins, Counter()).get("VALID", 0)
                         + per_inspector.get(ins, Counter()).get("PARTIAL", 0)
                    for ins in inspectors
                }
                max_vp = max(vp_per_inspector.values()) if vp_per_inspector else 0
                for ins in inspectors:
                    counts = per_inspector.get(ins, Counter())
                    if sum(counts.values()) == 0:
                        zero_inspector_hits[ins] += 1
                        conclusion[ins] = zeros()
                    else:
                        conclusion[ins] = metrics_from_counts(counts, max_vp)
            else:
                apps_without_csv.add(app)
                n_perms_audit_fallback += 1
                for ins in inspectors:
                    conclusion[ins] = audit_averages(perm, ins)

            perm["researcherConclusion"] = conclusion

    out_path = in_path.with_name(in_path.stem + "_researcher.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    # Summary
    print(f"Wrote: {out_path}")
    print(f"Callsites:                  {n_callsites}")
    print(f"Permutations via CSV:       {n_perms_csv}")
    print(f"Permutations via audits avg:{n_perms_audit_fallback}")
    print(f"Apps with CSV ({len(apps_with_csv)}):")
    for a in sorted(apps_with_csv):
        print(f"  - {a}")
    if apps_without_csv:
        print(f"Apps without CSV ({len(apps_without_csv)}) → audit-average fallback:")
        for a in sorted(apps_without_csv):
            print(f"  - {a}")
    if zero_inspector_hits:
        print("Inspectors with zero findings at some callsite (count of zero-hits):")
        for ins, n in zero_inspector_hits.most_common():
            print(f"  - {ins}: {n}")


if __name__ == "__main__":
    run()
