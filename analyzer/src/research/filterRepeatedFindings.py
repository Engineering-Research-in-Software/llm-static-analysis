#!/usr/bin/env python3
"""Collapse repeating findings (single items, multi-item cycles, fuzzy matches).

Usage:
    python filter_findings.py <input.json> [--fuzz N]

Writes <input>_filtered.<ext> alongside the input.

Markers used:
    [prior repeated N times]                  for runs of identical/near-identical items
    [prior L findings repeated N times]       for cycles of length L >= 2

The --fuzz argument controls the maximum Levenshtein distance for two findings
to be treated as the same. Default 2. Use --fuzz 0 for strict exact matching.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TypedDict, cast


# --- Shape of the JSON we care about ----------------------------------------

class Result(TypedDict, total=False):
    inspector: str
    findings: list[str]


class Permutation(TypedDict, total=False):
    researcher: int
    inspectors: list[str]
    auditors: list[str]
    results: list[Result]
    audits: dict[str, Any]
    researcherConclusion: dict[str, Any]


class Callsite(TypedDict, total=False):
    identifiedCallsiteID: str
    context: str
    permutations: list[Permutation]


AuditDocument = list[Callsite]


# --- Bounded Levenshtein ----------------------------------------------------

def bounded_levenshtein(a: str, b: str, max_dist: int) -> int:
    """Compute Levenshtein distance, capped at max_dist + 1.

    Returns max_dist + 1 as a sentinel meaning "exceeds threshold". Uses a
    band-limited DP: only cells within `max_dist` of the diagonal can
    contribute to a final answer <= max_dist, so each row costs O(2k+1)
    instead of O(m). For short threshold and long strings this is the
    difference between fast and unusable.
    """
    if a == b:
        return 0
    if max_dist <= 0:
        return 1  # not equal, so distance >= 1

    n: int = len(a)
    m: int = len(b)
    if abs(n - m) > max_dist:
        return max_dist + 1

    # Make `a` the longer string so n >= m and the band is centered nicely.
    if n < m:
        a, b = b, a
        n, m = m, n

    INF: int = max_dist + 1

    # prev[j] = D[i-1][j], curr[j] = D[i][j]; cells outside the band stay INF.
    prev: list[int] = [INF] * (m + 1)
    curr: list[int] = [INF] * (m + 1)
    for j in range(min(max_dist, m) + 1):
        prev[j] = j

    for i in range(1, n + 1):
        j_lo: int = max(1, i - max_dist)
        j_hi: int = min(m, i + max_dist)

        # D[i][0] = i, valid only while i <= max_dist.
        curr[0] = i if i <= max_dist else INF
        # Cells just outside the band on either side must be INF for this row,
        # because the previous row's band may have left stale values there.
        if j_lo > 1:
            curr[j_lo - 1] = INF
        if j_hi < m:
            curr[j_hi + 1] = INF

        ai: str = a[i - 1]
        row_min: int = curr[0]
        for j in range(j_lo, j_hi + 1):
            cost: int = 0 if ai == b[j - 1] else 1
            v: int = prev[j - 1] + cost           # substitution / match
            ins: int = curr[j - 1] + 1            # insertion
            if ins < v:
                v = ins
            dlt: int = prev[j] + 1                # deletion
            if dlt < v:
                v = dlt
            curr[j] = v
            if v < row_min:
                row_min = v

        if row_min > max_dist:
            return max_dist + 1
        prev, curr = curr, prev

    result: int = prev[m]
    return result if result <= max_dist else max_dist + 1


# --- Match matrix (precomputed fuzzy equality) ------------------------------

def _build_match_matrix(items: list[str], max_dist: int) -> list[list[bool]]:
    """matches[i][j] is True iff items[i] and items[j] are within max_dist."""
    n: int = len(items)
    matches: list[list[bool]] = [[i == j for j in range(n)] for i in range(n)]
    if n <= 1:
        return matches

    if max_dist == 0:
        # Group by exact string — much faster than O(n^2) for large lists.
        groups: dict[str, list[int]] = {}
        for idx, s in enumerate(items):
            groups.setdefault(s, []).append(idx)
        for indices in groups.values():
            for i in indices:
                for j in indices:
                    matches[i][j] = True
        return matches

    for i in range(n):
        for j in range(i + 1, n):
            if bounded_levenshtein(items[i], items[j], max_dist) <= max_dist:
                matches[i][j] = True
                matches[j][i] = True
    return matches


# --- Cycle detection --------------------------------------------------------

def _best_cycle_at(
    matches: list[list[bool]], n: int, i: int
) -> tuple[int, int]:
    """Find the best repeating cycle starting at index i.

    Returns (cycle_length, repeats) where the block is items[i:i+L] and it
    is followed by `repeats` consecutive blocks each fuzzy-equal element-wise
    to the anchor. Returns (1, 0) if no repetition is found.

    "Best" means maximum total coverage L * (1 + repeats). On ties the smaller
    L wins (preserved by `>` rather than `>=` on the comparison).
    """
    max_L: int = (n - i) // 2
    best_L: int = 1
    best_repeats: int = 0
    best_coverage: int = 1

    for L in range(1, max_L + 1):
        repeats: int = 0
        j: int = i + L
        while j + L <= n:
            ok: bool = True
            for k in range(L):
                if not matches[i + k][j + k]:
                    ok = False
                    break
            if not ok:
                break
            repeats += 1
            j += L
        if repeats > 0:
            coverage: int = L * (1 + repeats)
            if coverage > best_coverage:
                best_L = L
                best_repeats = repeats
                best_coverage = coverage

    return best_L, best_repeats


def collapse_runs(items: list[str], max_dist: int = 0) -> list[str]:
    """Collapse consecutive duplicates and multi-item cycles in a list."""
    if not items:
        return items

    n: int = len(items)
    matches: list[list[bool]] = _build_match_matrix(items, max_dist)

    out: list[str] = []
    i: int = 0
    while i < n:
        L, repeats = _best_cycle_at(matches, n, i)
        if repeats == 0:
            out.append(items[i])
            i += 1
            continue

        out.extend(items[i:i + L])
        if L == 1:
            out.append(f"[prior repeated {repeats} times]")
        else:
            out.append(f"[prior {L} findings repeated {repeats} times]")
        i += L * (1 + repeats)

    return out


def filter_findings(data: AuditDocument, max_dist: int) -> AuditDocument:
    """Walk the audit JSON and dedupe every `findings` list in place."""
    for callsite in data:
        permutations: list[Permutation] = callsite.get("permutations", [])
        for perm in permutations:
            results: list[Result] = perm.get("results", [])
            for result in results:
                findings: list[str] | None = result.get("findings")
                if isinstance(findings, list):
                    result["findings"] = collapse_runs(findings, max_dist)
    return data


# --- I/O --------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collapse repeating findings in an inspector audit JSON file.",
    )
    parser.add_argument("input", help="Path to input JSON file.")
    parser.add_argument(
        "--fuzz",
        type=int,
        default=2,
        help="Max Levenshtein distance for two findings to be treated as the "
             "same (default: 2). Use 0 for strict exact matching.",
    )
    args = parser.parse_args()

    fuzz: int = cast(int, args.fuzz)
    if fuzz < 0:
        print("--fuzz must be non-negative", file=sys.stderr)
        sys.exit(1)

    in_path: Path = Path(cast(str, args.input))
    out_path: Path = in_path.with_name(f"{in_path.stem}_filtered{in_path.suffix}")

    with in_path.open(encoding="utf-8") as f:
        data: AuditDocument = json.load(f)

    filter_findings(data, fuzz)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()