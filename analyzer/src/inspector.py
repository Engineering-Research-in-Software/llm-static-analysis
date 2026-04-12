from __future__ import annotations

import os
import re
import time
from typing import TYPE_CHECKING
from dotenv import load_dotenv

if TYPE_CHECKING:
    from integrations.ollama_int import OllamaIntegration
    from google.genai import Client as GeminiClient

load_dotenv()


class InspectorOrchestrator:
    _ollama: OllamaIntegration | None
    _gemini: GeminiClient | None

    def __init__(self, provider: str, model_name: str | None = None):
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

    def _format_prompt(self, context: dict) -> str:
        bridge = context["bridge"]
        bridge_line = (
            f"Interface '{bridge['intefaceObject']}' ({bridge['bridgeClass']}) "
            f"exposes: {bridge['bridgeMethods']} | initiating method: {bridge['initiatingMethod']}"
        )

        js_summary = "\n---\n".join(
            f"// [{s['resolution_type']}]\n{s['PASS_STRING']}"
            for s in context["js_snippets"][:10]
        )

        return f"""# ROLE: Security Researcher — Bridge Callsite Vulnerability Assessment
# TASK: Analyse this single Android WebView bridge callsite for security vulnerabilities.

## CONTEXT
APP PACKAGE: {context['app_name']}

### Bridge Interface (Java side)
{bridge_line}

### JavaScript Snippets (entry points)
{js_summary}

---

## EVALUATION CRITERIA

### A. Data Flow & Sink Analysis
- Trace variables from JS calls to their Java sinks.
- Flag methods used in: SQL Queries (SQL Injection), File Paths (Path Traversal), Intent Creation (Intent Redirection), Runtime.exec() or Reflection (RCE).

### B. PII & Permission Leakage
- Identify Java methods returning sensitive data: getDeviceId(), getAccounts(), getLocation(), getSimSerialNumber().
- Check if JS snippets cache PII in localStorage or transmit it externally.

### C. Reachability & Attacker Control
- Which bridge methods can be reached by attacker-controlled JavaScript?
- How much of the input to each reachable method is attacker-controlled?

### D. Impact Chain & Privilege Escalation
- What is the worst-case outcome if an attacker calls each exposed method with arbitrary input?
- Can calls be chained to escalate privileges?

### E. Protocol & Origin Security
- Identify if content is loaded over http://, or if there is no validation of message.origin in event listeners.

---

## OUTPUT FORMAT
Report each vulnerability as a separate finding using EXACTLY this structure:

### Finding: <title>
**Risk Level**: Critical/High/Medium/Low
**Data Flow Path**: [JS Source] -> [Bridge Object] -> [Java Sink]
**Technical Description**: ...
**Evidence**: <quoted JS line or method name>

If no vulnerabilities are found, output:
### Finding: No vulnerabilities identified
**Risk Level**: Low
**Data Flow Path**: N/A
**Technical Description**: No exploitable data flows found in the provided context.
**Evidence**: N/A
"""

    def get_analysis(self, context: dict) -> str:
        prompt = self._format_prompt(context)

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
                    f"    [!] Inspector rate limited. Retrying in {delay}s "
                    f"(attempt {attempt + 1}/{max_retries})..."
                )
                time.sleep(delay)

        raise RuntimeError("Max retries exceeded")
