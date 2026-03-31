import re

from apps.ai_core.providers.ollama import OllamaProvider
from apps.ai_core.providers.openrouter import OpenRouterProvider


class AIService:
    def __init__(self):
        self.primary = OpenRouterProvider()
        self.fallback = OllamaProvider()

    def _providers(self, provider_name=None):
        providers = [self.primary, self.fallback]
        if provider_name == "ollama":
            providers = [self.fallback]
        elif provider_name == "openrouter":
            providers = [self.primary]
        return providers

    def _run_messages(self, messages, provider_name=None, temperature=0.2, max_tokens=700):
        errors = []
        for provider in self._providers(provider_name=provider_name):
            if not provider.is_available():
                continue
            try:
                return {
                    "provider": provider.provider_name,
                    "content": provider.generate_chat_completion(
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    ),
                }
            except Exception as exc:
                errors.append(f"{provider.provider_name}: {exc}")

        if errors:
            raise RuntimeError("; ".join(errors))
        raise RuntimeError("No AI provider is configured.")

    def generate_security_summary(self, project_name, findings_text, provider_name=None):
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior application-security analyst. "
                    "Write a concise security brief with exactly these plain-text headings: "
                    "Narrative Summary, Threat Story, Immediate Actions. "
                    "Keep the whole response under 180 words. "
                    "Deduplicate repeated findings that share the same root cause. "
                    "Mention GitHub code issues, API exposure, and internet-facing risk when present. "
                    "Use short sentences and practical language."
                ),
            },
            {
                "role": "user",
                "content": f"Project: {project_name}\n\nFindings:\n{findings_text}",
            },
        ]
        preferred_provider = provider_name or "openrouter"
        try:
            return self._run_messages(messages, provider_name=preferred_provider)
        except Exception:
            if preferred_provider == "openrouter":
                return self._run_messages(messages)
            raise

    def rewrite_code_for_security(self, project_name, file_path, original_content, findings, provider_name=None):
        findings_text = "\n".join(
            f"- {item.get('title')}: {item.get('description')} Recommendation: {item.get('recommendation')}"
            for item in findings
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior software engineer fixing security findings in an existing file. "
                    "Return only the full updated file content with the security fixes applied. "
                    "Do not include markdown fences, explanations, or extra commentary. "
                    "Keep unrelated code unchanged."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Project: {project_name}\n"
                    f"File: {file_path}\n\n"
                    f"Findings to fix:\n{findings_text}\n\n"
                    f"Current file content:\n{original_content}"
                ),
            },
        ]
        payload = self._run_messages(messages, provider_name=provider_name, temperature=0.1, max_tokens=4000)
        content = payload.get("content", "").strip()
        content = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        return {
            "provider": payload.get("provider", ""),
            "content": content,
        }
