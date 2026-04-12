import json
import os
from datetime import datetime


def _load_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            data = json.load(f)
        if "error" in data:
            return None
        return data
    except Exception:
        return None


def build_aggregate(reports_dir: str, run_metadata: dict) -> None:
    entries: list[dict] = []

    for app_name in sorted(os.listdir(reports_dir)):
        app_dir = os.path.join(reports_dir, app_name)
        if not os.path.isdir(app_dir):
            continue

        trust_a = _load_json(os.path.join(app_dir, "trust.json"))
        trust_c = _load_json(os.path.join(app_dir, "checker_trust.json"))
        comparison = _load_json(os.path.join(app_dir, "comparison.json"))

        if trust_a is None:
            continue

        entries.append({
            "app": app_name,
            "trust_a": trust_a,
            "trust_c": trust_c,
            "comparison": comparison,
        })

    _write_json(reports_dir, run_metadata, entries)
    _write_markdown(reports_dir, run_metadata, entries)


def _write_json(reports_dir: str, run_metadata: dict, entries: list[dict]) -> None:
    complete = [e for e in entries if e["trust_c"] is not None and e["comparison"] is not None]

    def avg(key: str, source: str) -> float:
        vals = [e[source][key] for e in complete if e[source] and key in e[source]]
        return round(sum(vals) / len(vals), 3) if vals else 0.0

    winners = [e["comparison"]["more_trustworthy_agent"] for e in complete if e["comparison"]]
    totals = {
        "apps_with_full_comparison": len(complete),
        "avg_trustworthiness_a": avg("trustworthiness_score", "trust_a"),
        "avg_trustworthiness_c": avg("trustworthiness_score", "trust_c"),
        "avg_hallucination_rate_a": avg("hallucination_rate", "trust_a"),
        "avg_hallucination_rate_c": avg("hallucination_rate", "trust_c"),
        "agent_a_wins": winners.count("A"),
        "agent_c_wins": winners.count("C"),
        "ties": winners.count("tie"),
    }

    output = {
        "run_metadata": {**run_metadata, "timestamp": datetime.utcnow().isoformat() + "Z"},
        "per_app": entries,
        "totals": totals,
    }

    path = os.path.join(reports_dir, "aggregate_scores.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] Aggregate scores saved to {path}")


def _write_markdown(reports_dir: str, run_metadata: dict, entries: list[dict]) -> None:
    lines: list[str] = [
        "# Analysis Run Summary",
        "",
        "## Run Metadata",
        "",
        f"- **Agent A model**: {run_metadata.get('agent_a_model', 'N/A')}",
        f"- **Agent B model**: {run_metadata.get('agent_b_model', 'N/A')}",
        f"- **Agent C model**: {run_metadata.get('agent_c_model', 'N/A')}",
        f"- **Apps analyzed**: {len(entries)}",
        f"- **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Per-App Results",
        "",
        "| App | Trust A | Trust C | Δ | Winner | Halluc. A | Halluc. C |",
        "|-----|---------|---------|---|--------|-----------|-----------|",
    ]

    complete = []
    for e in entries:
        ta = e["trust_a"]
        tc = e["trust_c"]
        comp = e["comparison"]

        trust_a_str = f"{ta['trustworthiness_score']:.3f}" if ta else "—"

        if tc and comp:
            trust_c_str = f"{tc['trustworthiness_score']:.3f}"
            delta_str = f"{comp['delta_trustworthiness']:+.3f}"
            winner_str = comp["more_trustworthy_agent"]
            halluc_c_str = f"{tc['hallucination_rate']:.3f}"
            complete.append(e)
        else:
            trust_c_str = "—"
            delta_str = "—"
            winner_str = "—"
            halluc_c_str = "—"

        halluc_a_str = f"{ta['hallucination_rate']:.3f}" if ta else "—"

        lines.append(
            f"| {e['app']} | {trust_a_str} | {trust_c_str} | {delta_str} | {winner_str} | {halluc_a_str} | {halluc_c_str} |"
        )

    if complete:
        def avg(key: str, source: str) -> float:
            vals = [e[source][key] for e in complete if e[source]]
            return round(sum(vals) / len(vals), 3) if vals else 0.0

        winners = [e["comparison"]["more_trustworthy_agent"] for e in complete if e["comparison"]]

        lines += [
            "",
            "## Overall",
            "",
            f"- **Agent A avg trustworthiness**: {avg('trustworthiness_score', 'trust_a')}",
            f"- **Agent C avg trustworthiness**: {avg('trustworthiness_score', 'trust_c')}",
            f"- **Agent A avg hallucination rate**: {avg('hallucination_rate', 'trust_a')}",
            f"- **Agent C avg hallucination rate**: {avg('hallucination_rate', 'trust_c')}",
            f"- **Agent A won**: {winners.count('A')}/{len(complete)} apps",
            f"- **Agent C won**: {winners.count('C')}/{len(complete)} apps",
            f"- **Ties**: {winners.count('tie')}/{len(complete)} apps",
        ]

    path = os.path.join(reports_dir, "aggregate_report.md")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[*] Aggregate report saved to {path}")
