from __future__ import annotations

import json
import os
import re
import time
from typing import TYPE_CHECKING
from dotenv import load_dotenv

if TYPE_CHECKING:
    from integrations.ollama_int import OllamaIntegration
    from google.genai import Client as GeminiClient

load_dotenv()


class AuditorOrchestrator:
    _ollama: OllamaIntegration | None
    _gemini: GeminiClient | None

    def __init__(self, provider: str = "gemini", model_name: str | None = None):
        self.provider = provider.strip().lower()
        self._ollama = None
        self._gemini = None

        if self.provider == "ollama":
            from integrations.ollama_int import OllamaIntegration
            self._model_name = model_name or "llama3.1:8b"
            self._ollama = OllamaIntegration(model_name=self._model_name)
        else:
            from google import genai
            self._model_name = model_name or "gemini-2.0-flash-lite"
            self._gemini = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

        self.model_id = f"{self.provider}/{self._model_name}"

    def _format_prompt(
        self,
        context: dict,
        findings: list[str],
        inspector_model_id: str,
    ) -> str:
        bridge = context["bridge"]
        bridge_line = (
            f"Interface '{bridge['intefaceObject']}' ({bridge['bridgeClass']}) "
            f"exposes: {bridge['bridgeMethods']} | initiating method: {bridge['initiatingMethod']}"
        )

        js_summary = "\n---\n".join(
            f"// [{s['resolution_type']}]\n{s['PASS_STRING']}"
            for s in context["js_snippets"][:10]
        )

        findings_text = "\n\n".join(findings) if findings else "(no findings)"

        schema = json.dumps(
            {
                "hallucinationFrequency": "0.0-1.0",
                "technicalAccuracy": "integer 1-10",
                "effectChainAwareness": "integer 1-10",
                "attackSurfaceCoverage": "0.0-1.0",
            },
            indent=2,
        )

        return f"""# ROLE: Security Audit Judge
# TASK: Evaluate the security analysis of an Android WebView bridge callsite produced by inspector {inspector_model_id}.

## GROUND TRUTH CONTEXT
APP PACKAGE: {context['app_name']}

### Bridge Interface (Java side)
{bridge_line}

### JavaScript Snippets (entry points)
{js_summary}

---

## INSPECTOR FINDINGS

### Inspector {inspector_model_id}
{findings_text}

---

## EVALUATION INSTRUCTIONS

### Hallucination Definition
A hallucination is any finding that references a method, class, object, or code segment that does NOT appear in the provided ground truth context above.

### Metric Definitions
- **hallucinationFrequency**: Float 0.0-1.0. Ratio of hallucinated findings to total findings. If there are no findings, use 0.0.
- **technicalAccuracy**: Integer 1-10. How technically correct and precise are the non-hallucinated findings?
- **effectChainAwareness**: Integer 1-10. How well does the inspector identify chained vulnerabilities and their combined impact?
- **attackSurfaceCoverage**: Float 0.0-1.0. First identify all genuine vulnerabilities visible in the ground truth context. Then score as found/total_in_context.

---

## OUTPUT
Respond with ONLY valid JSON matching this schema. No markdown fences, no other text:
{schema}"""

    def get_audit(
        self,
        context: dict,
        findings: list[str],
        inspector_model_id: str,
    ) -> str:
        prompt = self._format_prompt(context, findings, inspector_model_id)

        if self._ollama is not None:
            return self._ollama.generate_response(prompt)

        assert self._gemini is not None
        max_retries = 5
        delay = 60

        for attempt in range(max_retries):
            try:
                response = self._gemini.models.generate_content(
                    model=self._model_name,
                    contents=prompt,
                )
                if response.text is None:
                    raise ValueError("Empty response from model")
                return response.text
            except Exception as e:
                if "429" not in str(e) or attempt == max_retries - 1:
                    raise

                match = re.search(r"retryDelay.*?'(\d+)s'", str(e))
                delay = int(match.group(1)) + 1 if match else delay * 2
                print(
                    f"    [!] Auditor rate limited. Retrying in {delay}s "
                    f"(attempt {attempt + 1}/{max_retries})..."
                )
                time.sleep(delay)

        raise RuntimeError("Max retries exceeded")
