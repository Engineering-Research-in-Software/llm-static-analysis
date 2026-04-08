def compute_trustworthiness(audit: dict) -> dict:
    findings: list[dict] = audit.get("findings_audit", [])
    total = len(findings)

    if total == 0:
        return {
            "semantic_precision": 0.0,
            "hallucination_rate": 0.0,
            "argumentative_consistency": 0.0,
            "overall_consistency_score": audit.get("overall_consistency_score", 0),
            "trustworthiness_score": 0.0,
        }

    supported = sum(1 for f in findings if f.get("verdict") == "SUPPORTED")
    hallucinated = sum(1 for f in findings if f.get("verdict") == "HALLUCINATED")
    avg_consistency = sum(f.get("consistency_score", 0) for f in findings) / total

    semantic_precision = round(supported / total, 3)
    hallucination_rate = round(hallucinated / total, 3)
    argumentative_consistency = round(avg_consistency / 10, 3)
    trustworthiness_score = round(
        (semantic_precision + argumentative_consistency) / 2 - hallucination_rate, 3
    )

    return {
        "semantic_precision": semantic_precision,
        "hallucination_rate": hallucination_rate,
        "argumentative_consistency": argumentative_consistency,
        "overall_consistency_score": audit.get("overall_consistency_score", 0),
        "trustworthiness_score": trustworthiness_score,
    }


def compute_comparison(trust_a: dict, trust_c: dict) -> dict:
    score_a = trust_a.get("trustworthiness_score", 0.0)
    score_c = trust_c.get("trustworthiness_score", 0.0)
    delta = round(score_a - score_c, 3)

    if abs(delta) < 0.01:
        winner = "tie"
    elif delta > 0:
        winner = "A"
    else:
        winner = "C"

    halluc_delta = round(
        trust_a.get("hallucination_rate", 0.0) - trust_c.get("hallucination_rate", 0.0), 3
    )
    precision_delta = round(
        trust_a.get("semantic_precision", 0.0) - trust_c.get("semantic_precision", 0.0), 3
    )

    if winner == "tie":
        note = "Agents A and C scored within margin — effectively equivalent for this app."
    else:
        loser = "C" if winner == "A" else "A"
        note = (
            f"Agent {winner} outscored Agent {loser} by {abs(delta):.3f} "
            f"(precision Δ {precision_delta:+.3f}, hallucination rate Δ {halluc_delta:+.3f})."
        )

    return {
        "delta_trustworthiness": delta,
        "delta_hallucination_rate": halluc_delta,
        "delta_semantic_precision": precision_delta,
        "more_trustworthy_agent": winner,
        "agreement_note": note,
    }
