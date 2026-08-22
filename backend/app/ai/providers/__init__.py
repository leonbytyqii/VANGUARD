"""
Provider-agnostic AI layer (docs/ARCHITECTURE.md §5). `get_provider()` is
the one place `AI_PROVIDER` is read to decide which `LLMProvider`
implementation the orchestrator talks to — application code should never
import `MockProvider`/`OpenAICompatibleProvider` directly except in tests
that are deliberately exercising one provider's behavior.
"""
from __future__ import annotations

from app.ai.providers.base import LLMProvider, ProviderError, ProviderResponse, ProviderToolCall
from app.ai.providers.mock import MockProvider
from app.core.config import settings

__all__ = ["LLMProvider", "ProviderError", "ProviderResponse", "ProviderToolCall", "MockProvider", "get_provider"]


def get_provider() -> LLMProvider:
    if settings.AI_PROVIDER == "mock":
        return MockProvider()
    if settings.AI_PROVIDER == "openai_compatible":
        from app.ai.providers.openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider()
    raise ProviderError(f"Unknown AI_PROVIDER '{settings.AI_PROVIDER}'")
