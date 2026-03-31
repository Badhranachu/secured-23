import requests
from django.conf import settings

from .base import BaseAIProvider


class OllamaProvider(BaseAIProvider):
    provider_name = "ollama"

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout = 180

    def is_available(self) -> bool:
        return bool(self.base_url and self.model)

    def generate_chat_completion(self, messages, temperature=0.2, max_tokens=700):
        response = requests.post(
            f"{self.base_url}/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "").strip()
