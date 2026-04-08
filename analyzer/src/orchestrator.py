import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

class AnalysisOrchestrator:
    def __init__(self, model_name="gemini-3.1-flash-lite-preview"):
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.model_name = model_name

    def format_prompt(self, context):
        bridge_summary = "\n".join([
            f"- Interface Object: '{b['intefaceObject']}' exposes {b['bridgeMethods']} via {b['bridgeClass']}" 
            for b in context['bridges']
        ])
        
        js_summary = "\n---\n".join([
            f"// Snippet ({s['resolution_type']})\n{s['PASS_STRING']}" 
            for s in context['js_snippets'][:10]
        ])

        return f"""
        # ROLE: Principal Android Security Architect & Vulnerability Researcher
        # TASK: Deep-Dive Security Audit of Hybrid Bridge Data Flows (JS <-> Java)

        ## CONTEXT
        You are analyzing a high-risk Android Hybrid Application. Your goal is to identify "Bridge-to-Native" escalation paths where JavaScript (potentially controllable via XSS or compromised Remote URLs) interacts with sensitive Java Methods.

        APP PACKAGE: {context['app_name']}

        ---

        ## 1. NATIVE INTERFACE INVENTORY (The Attack Surface)
        The following Java classes are exposed to the WebView via `addJavascriptInterface`. 
        {bridge_summary}

        ## 2. JAVASCRIPT LOGIC ANALYIS (The Entry Points)
        These snippets represent the client-side logic interacting with the native layer.
        {js_summary}

        ---

        ## MANDATORY EVALUATION CRITERIA:

        ### A. Data Flow & Sink Analysis
        - Trace variables from JS calls (e.g., `window.<interfaceObject>.method(data)`) to their Java sinks. 
        - Flag methods that accept strings which might be used in: 
            - SQL Queries (SQL Injection)
            - File Paths (Path Traversal)
            - Intent Creation (Intent Redirection)
            - Runtime.exec() or Reflection (RCE)

        ### B. PII & Permission Leakage
        - Identify Java methods returning sensitive data: `getDeviceId()`, `getAccounts()`, `getLocation()`, `getSimSerialNumber()`.
        - Check if the JS snippets cache this PII in `localStorage` or transmit it to external `fetch/XMLHttpRequest` endpoints.

        ### C. Semantic Mismatch & Over-Privilege
        - **Name Obfuscation:** Does a method named `log()` actually perform a sensitive action like `uploadFile()`?
        - **Interface Bloat:** Are there methods exposed in `bridgeMethods` that are never called in the JS snippets? (Unnecessary Attack Surface).

        ### D. Protocol & Origin Security
        - Analyze if the JS snippets imply the app is loading content over `http://` or if there is no validation of `message.origin` in event listeners.

        ---

        ## OUTPUT STRUCTURE (Markdown Report):

        1. **EXECUTIVE SUMMARY**: 
        - Total Attack Surface (Number of exposed methods).
        - High-level risk posture.

        2. **CRITICAL VULNERABILITY FINDINGS**:
        - **Title**: (e.g., "Remote PII Exfiltration via Bridge Reflection")
        - **Risk Level**: (Critical/High/Medium/Low)
        - **Data Flow Path**: [JS Source] -> [Bridge Object] -> [Java Sink]
        - **Technical Description**: Detailed explanation of how the vulnerability can be exploited.
        - **Evidence**: Quote the specific JS line and Java method name.

        3. **REMEDIATION STEPS**:
        - Specific coding advice to patch the identified flows (e.g., "Implement `@JavascriptInterface` validation" or "Sanitize input using [X]").

        4. **CONFIDENCE SCORE**: (1-10) Based on the clarity of the provided snippets.
        """

    def get_analysis(self, context):
        prompt = self.format_prompt(context)
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt
        )
        return response.text