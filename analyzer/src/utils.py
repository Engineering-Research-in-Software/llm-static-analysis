import json
import re


def extract_json(text: str) -> dict:
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if match:
        text = match.group(1)
    return json.loads(text)


def extract_findings_from_markdown(report: str) -> list[str]:
    parts = re.split(r"(?=### Finding:)", report)
    findings: list[str] = []
    for part in parts:
        stripped = part.strip()
        if stripped.startswith("### Finding:"):
            findings.append(stripped)
    return findings


def build_callsite_id(db_stem: str, row_id: int) -> str:
    return f"{db_stem}-webview_new-{row_id}"


def empty_metrics() -> dict:
    return {
        "hallucinationFrequency": 0.0,
        "technicalAccuracy": 0,
        "effectChainAwareness": 0,
        "attackSurfaceCoverage": 0.0,
    }
