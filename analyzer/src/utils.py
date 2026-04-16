import json
import re


_METRICS_TYPES: dict[str, type] = {
    "hallucinationFrequency": float,
    "technicalAccuracy": int,
    "effectChainAwareness": int,
    "attackSurfaceCoverage": float,
}


def extract_json(text: str) -> dict:
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if match:
        text = match.group(1)
    raw = json.loads(text)
    return _coerce_metrics(raw)


def _coerce_metrics(data: dict) -> dict:
    return {
        k: _METRICS_TYPES[k](v) if k in _METRICS_TYPES else v
        for k, v in data.items()
    }


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
