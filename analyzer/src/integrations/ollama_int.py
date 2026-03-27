from ollama import Client
import re
from typing import Any, Dict, List, Optional, cast

# c/o liwan21
# since v. 0.0.1
class OllamaIntegration:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.client = Client()

    def get_available_models(self) -> List[str]:
        response = self.client.list()
        models: List[dict[str, Any]] = response.get("models", []) if isinstance(response, dict) else []

        available: List[str] = []
        for model in models:
            if not isinstance(model, dict): # type: ignore
                continue

            # Ollama versions may expose either `model` or `name`.
            model_name = model.get("model") or model.get("name")
            if model_name:
                available.append(model_name)

        return available

    def set_model(self, model_name: str) -> str:
        available_models = self.get_available_models()
        if model_name not in available_models:
            raise ValueError(
                f"Model '{model_name}' is not available. "
                f"Available models: {', '.join(available_models) if available_models else 'none found'}"
            )

        self.model_name = model_name
        return self.model_name

    def _extract_context_window(self, show_response: Dict[str, Any]) -> Optional[int]:
        model_info: Dict[str, Any] = show_response.get("model_info", {})
        if isinstance(model_info, dict): # type: ignore
            for key, value in model_info.items():
                key_lower = str(key).lower()
                if "context_length" in key_lower or key_lower.endswith(".context_length"):
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        pass

        parameters = show_response.get("parameters")
        if isinstance(parameters, str):
            match = re.search(r"(?:num_ctx|context_length)\s+(\d+)", parameters)
            if match:
                return int(match.group(1))

        return None

    def get_current_model_metadata(self) -> Dict[str, Any]:
        show_response = self.client.show(self.model_name)
        if not isinstance(show_response, dict):
            show_response = {"raw": show_response}

        context_window = self._extract_context_window(show_response)

        return {
            "model_name": self.model_name,
            "context_window_tokens": context_window,
            "details": show_response.get("details", {}),
            "family": show_response.get("details", {}).get("family"),
            "parameter_size": show_response.get("details", {}).get("parameter_size"),
            "quantization_level": show_response.get("details", {}).get("quantization_level"),
            "raw": show_response,
        }

    def generate_response(self, prompt: str) -> str:
        response = self.client.generate(model=self.model_name, prompt=prompt)

        # Models respond slightly differently
        if isinstance(response, dict):
            return response.get("response", "")

        if hasattr(response, "response"):
            return response.response

        if hasattr(response, "text"):
            return cast(Any, response).text

        return str(response)