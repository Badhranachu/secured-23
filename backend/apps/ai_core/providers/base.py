from abc import ABC, abstractmethod


class BaseAIProvider(ABC):
    provider_name = "base"

    @abstractmethod
    def is_available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def generate_chat_completion(self, messages, temperature=0.2, max_tokens=700):
        raise NotImplementedError
