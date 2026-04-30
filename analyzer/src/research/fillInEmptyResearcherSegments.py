emptySegment = """{
    "ollama/qwen2.5-coder:7b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    },
    "ollama/deepseek-r1:8b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    },
    "ollama/starcoder2:7b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    },
    "ollama/phi4:14b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    },
    "ollama/llama3.2:3b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    },
    "ollama/gemma3:12b": {
        "hallucinationFrequency": "undefined",
        "technicalAccuracy": "undefined",
        "effectChainAwareness": "undefined",
        "attackSurfaceCoverage": "undefined"
    }
}"""


import argparse
from filterRepeatedFindings import AuditDocument, Permutation
import json

# Traverse the json, paste the empty segment into all keys named "researcherConclusion" that have value "undefined" or is an empty object. Save the modified json to a new file suffixed with "_filled".


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Path to input JSON file.")
    args = parser.parse_args()
    
    with open(args.input, "r", encoding="utf-8") as f:
        data: AuditDocument = json.load(f)

    emptySegmentJson = json.loads(emptySegment)

    for callsite in data:
        permutations: list[Permutation] = callsite.get("permutations", [])
        for permutation in permutations:
            if "researcherConclusion" not in permutation or not permutation["researcherConclusion"]:
                permutation["researcherConclusion"] = emptySegmentJson

    with open(args.input.replace(".json", "_filled.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


if __name__ == "__main__":
    run()



