import requests
from django.conf import settings

from .base import BaseAIProvider


class OpenRouterProvider(BaseAIProvider):
    provider_name = "openrouter"

    def __init__(self):
        self.base_url = settings.OPENROUTER_BASE_URL.rstrip("/")
        self.api_key = settings.OPENROUTER_API_KEY
        self.model = settings.OPENROUTER_MODEL
        self.timeout = 45

    def is_available(self) -> bool:
        return bool(self.api_key and self.model)

    def generate_chat_completion(self, messages, temperature=0.2, max_tokens=700):
        if not self.is_available():
            raise RuntimeError("OpenRouter is not configured.")

        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": settings.OPENROUTER_SITE_URL,
                "X-OpenRouter-Title": settings.OPENROUTER_APP_NAME,
            },
            json={
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()
