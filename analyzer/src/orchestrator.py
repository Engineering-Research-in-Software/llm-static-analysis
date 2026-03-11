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
        # ROLE: Senior Android Security Researcher
        # TASK: Analyze the cross-language data flows in this Hybrid App.
        
        APP PACKAGE: {context['app_name']}

        ## NATIVE JAVA INTERFACES
        {bridge_summary}

        ## DETECTED JAVASCRIPT LOGIC
        {js_summary}

        ## ANALYSIS REQUIREMENTS:
        1. Identify high-risk native methods (e.g., PII access).
        2. Detect data exfiltration in JS snippets.
        3. Flag semantic mismatches between Java names and JS exposure.
        
        OUTPUT FORMAT: Provide a clear Markdown report.
        """

    def get_analysis(self, context):
        prompt = self.format_prompt(context)
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt
        )
        return response.text