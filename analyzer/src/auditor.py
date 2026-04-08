import os
import json
import time
import re
from dotenv import load_dotenv

load_dotenv()

_VERDICT_DEFINITIONS = """
- SUPPORTED: The data flow path and any cited evidence are traceable in the raw context.
- PARTIALLY_SUPPORTED: The risk category is plausible but the specific evidence cited is absent or misquoted.
- UNSUPPORTED: The finding is not traceable to any entry in the bridge or JS snippet data.
- HALLUCINATED: The finding references methods, objects, or snippets that do not exist in the context at all.
"""

_OUTPUT_SCHEMA = json.dumps({
    "findings_audit": [
        {
            "finding_title": "string",
            "verdict": "SUPPORTED | PARTIALLY_SUPPORTED | UNSUPPORTED | HALLUCINATED",
            "reasoning": "string - cite specific evidence or note its absence",
            "evidence_found_in_context": "true | false",
            "consistency_score": "integer 1-10"
        }
    ],
    "unsupported_claims": ["list of specific claims made without evidence"],
    "missing_findings": ["risks visible in the raw context that Agent A did not flag"],
    "overall_consistency_score": "integer 1-10",
    "auditor_notes": "string - high-level commentary"
}, indent=2)


class AuditorOrchestrator:
    def __init__(self, provider: str = "gemini", model_name: str | None = None):
        self.provider = provider.strip().lower()

        if self.provider == "ollama":
            from integrations.ollama_int import OllamaIntegration
            self.model_name = model_name or "llama3.1:8b"
            self._client = OllamaIntegration(model_name=self.model_name)
        else:
            from google import genai
            self.model_name = model_name or "gemini-2.0-flash-lite"
            self._client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    def _format_prompt(self, context: dict, agent_a_report: str) -> str:
        bridge_summary = "\n".join([
            f"- Interface '{b['intefaceObject']}' ({b['bridgeClass']}) exposes: {b['bridgeMethods']}"
            for b in context["bridges"]
        ])

        js_summary = "\n---\n".join([
            f"// [{s['resolution_type']}]\n{s['PASS_STRING']}"
            for s in context["js_snippets"][:10]
        ])

        return f"""# ROLE: Security Analysis Auditor
# TASK: Audit the following security report against the raw evidence provided below.

## GROUND TRUTH EVIDENCE
APP PACKAGE: {context['app_name']}

### Bridge Interfaces (Java side)
{bridge_summary}

### JavaScript Snippets (entry points)
{js_summary}

## AGENT A REPORT UNDER REVIEW
{agent_a_report}

## AUDIT INSTRUCTIONS
For each finding in the report:
1. Check whether the data flow path (JS source -> bridge object -> Java method) can be traced in the evidence above.
2. Check whether any quoted JS identifiers, method names, or class names actually appear in the evidence.
3. Assess whether the severity rating is proportionate to what the evidence actually shows.

Verdict definitions:
{_VERDICT_DEFINITIONS}

Also identify:
- unsupported_claims: specific statements in the report that have no basis in the evidence
- missing_findings: risks clearly visible in the raw context that Agent A did not flag

## OUTPUT
Respond with ONLY a valid JSON object. Do not include markdown fences or any other text.
The JSON must match this schema exactly:
{_OUTPUT_SCHEMA}"""

    def get_audit(self, context: dict, agent_a_report: str) -> str:
        prompt = self._format_prompt(context, agent_a_report)

        if self.provider == "ollama":
            return self._client.generate_response(prompt)

        max_retries = 5
        delay = 60

        for attempt in range(max_retries):
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=prompt
                )
                return response.text
            except Exception as e:
                if "429" not in str(e) or attempt == max_retries - 1:
                    raise

                match = re.search(r"retryDelay.*?'(\d+)s'", str(e))
                delay = int(match.group(1)) + 1 if match else delay * 2
                print(f"    [!] Auditor rate limited. Retrying in {delay}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(delay)
