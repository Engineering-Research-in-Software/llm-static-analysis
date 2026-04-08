import os
import time
import re
from dotenv import load_dotenv

load_dotenv()


class CrossCheckerOrchestrator:
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

    def _format_prompt(self, context: dict) -> str:
        bridge_summary = "\n".join([
            f"- Interface Object: '{b['intefaceObject']}' exposes {b['bridgeMethods']} via {b['bridgeClass']}"
            for b in context["bridges"]
        ])

        js_summary = "\n---\n".join([
            f"// Snippet ({s['resolution_type']})\n{s['PASS_STRING']}"
            for s in context["js_snippets"][:10]
        ])

        return f"""# ROLE: Offensive Security Researcher — Attack Surface Enumeration
# TASK: Enumerate all attack vectors an adversary could exploit in this Android hybrid application.

## CONTEXT
You are performing an independent security assessment. Your goal is not to classify
misconfigurations but to think like an attacker: given this bridge, what can an adversary
actually DO? What is the realistic worst-case impact if a malicious script gains access?

APP PACKAGE: {context['app_name']}

---

## 1. NATIVE INTERFACE INVENTORY
The following Java classes are exposed to the WebView via `addJavascriptInterface`.
{bridge_summary}

## 2. JAVASCRIPT ENTRY POINTS
These snippets represent client-side logic interacting with the native layer.
{js_summary}

---

## ATTACK SURFACE ENUMERATION CRITERIA:

### A. Reachability & Control
- Which bridge methods can be reached by attacker-controlled JavaScript?
- What input does each reachable method accept, and how much of that input is attacker-controlled?

### B. Impact Chain
- What is the worst-case outcome if an attacker calls each exposed method with arbitrary input?
- Can calls be chained? (e.g., read a file path, then exfiltrate its contents)

### C. Privilege & Scope Escalation
- Do any bridge methods grant access beyond what the WebView's origin should have?
- Are there methods that, combined, allow privilege escalation (e.g., read + send)?

### D. Trust Boundary Violations
- Is content loaded from untrusted origins (http://, remote URLs) with access to bridge methods?
- Are there missing origin checks that allow cross-origin JavaScript to invoke the bridge?

---

## OUTPUT STRUCTURE (Markdown Report):

1. **EXECUTIVE SUMMARY**:
   - Total Attack Surface (Number of exposed methods).
   - High-level risk posture from an attacker's perspective.

2. **CRITICAL VULNERABILITY FINDINGS**:
   - **Title**: (e.g., "Arbitrary File Read via Unvalidated Path Parameter")
   - **Risk Level**: (Critical/High/Medium/Low)
   - **Data Flow Path**: [JS Source] -> [Bridge Object] -> [Java Sink]
   - **Technical Description**: How an attacker would exploit this in practice.
   - **Evidence**: Quote the specific JS line and Java method name.

3. **REMEDIATION STEPS**:
   - Specific hardening advice for each identified attack vector.

4. **CONFIDENCE SCORE**: (1-10) Based on the clarity of the provided evidence.
"""

    def get_analysis(self, context: dict) -> str:
        prompt = self._format_prompt(context)

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
                print(f"    [!] Checker rate limited. Retrying in {delay}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(delay)
