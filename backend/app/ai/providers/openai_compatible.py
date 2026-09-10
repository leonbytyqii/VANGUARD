"""
Real LLM provider using the OpenAI chat-completions function-calling
shape — works against OpenAI, Azure OpenAI, or any self-hosted
OpenAI-compatible endpoint (vLLM, LM Studio, ...) via `AI_BASE_URL`.
Deliberately implemented with a bare `httpx` POST rather than an SDK, so
switching endpoints is only ever an `.env` change (`AI_BASE_URL`,
`AI_MODEL`, `AI_API_KEY`) — never a code change or a new dependency.

Every intermediate tool call *and* the final structured report are
modeled as function calls: alongside the agent's real allowlisted tools,
one synthetic function — `submit_investigation_result`, whose JSON-schema
`parameters` is exactly `response_schema` — is always offered. When the
model calls that one, its arguments are treated as `final_output`;
any other function call is a `tool_call` the orchestrator dispatches
through the real tool-permission gateway. This is a standard ReAct-with-
tools pattern, not a VANGUARD-specific one, and it's why `MockProvider`
returns the exact same `ProviderResponse` union — both providers speak
the same "one tool call or one final answer" protocol.

Never called in the test suite (see app/ai/providers/mock.py's docstring)
— there is no live network access assumed here, and `AI_PROVIDER`
defaults to `mock` specifically so the platform never *requires* this
path to be exercised to be demonstrable.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from app.ai.providers.base import ProviderError, ProviderResponse, ProviderToolCall
from app.core.config import settings

_SUBMIT_FUNCTION_NAME = "submit_investigation_result"


def _to_openai_tools(tools: list[dict[str, Any]], response_schema: dict[str, Any]) -> list[dict[str, Any]]:
    function_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t.get("parameters", {"type": "object", "additionalProperties": True}),
            },
        }
        for t in tools
    ]
    function_tools.append(
        {
            "type": "function",
            "function": {
                "name": _SUBMIT_FUNCTION_NAME,
                "description": "Submit the final, evidence-grounded investigation result. Call this only once you have gathered enough evidence to conclude.",
                "parameters": response_schema,
            },
        }
    )
    return function_tools


def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # This platform's internal transcript already uses OpenAI's own
    # role vocabulary (system/user/assistant/tool) — the only translation
    # needed is dropping the internal-only "name" field on non-tool
    # messages, which the Chat Completions API doesn't accept there.
    out = []
    for m in messages:
        entry = {"role": m["role"], "content": m["content"]}
        if m["role"] == "tool":
            entry["tool_call_id"] = m.get("tool_call_id", m.get("name", "tool"))
            entry["name"] = m.get("name", "tool")
        out.append(entry)
    return out


class OpenAICompatibleProvider:
    def __init__(self) -> None:
        if not settings.AI_API_KEY:
            raise ProviderError(
                "AI_PROVIDER=openai_compatible requires AI_API_KEY to be set. "
                "Use AI_PROVIDER=mock (the default) to run without a key."
            )
        self._base_url = (settings.AI_BASE_URL or "https://api.openai.com/v1").rstrip("/")
        self._model = settings.AI_MODEL
        self._api_key = settings.AI_API_KEY
        self._timeout = settings.AI_REQUEST_TIMEOUT_SECONDS

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any],
    ) -> ProviderResponse:
        body = {
            "model": self._model,
            "messages": _to_openai_messages(messages),
            "tools": _to_openai_tools(tools, response_schema),
            "tool_choice": "auto",
        }
        try:
            resp = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json=body,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"AI provider request failed: {exc}") from exc

        try:
            choice = payload["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"Unexpected AI provider response shape: {payload!r}") from exc

        tool_calls = choice.get("tool_calls") or []
        if not tool_calls:
            raise ProviderError(
                "AI provider returned no tool call — every step must either call a tool or "
                f"submit_investigation_result. Raw content: {choice.get('content')!r}"
            )

        call = tool_calls[0]
        function = call["function"]
        try:
            arguments = json.loads(function["arguments"]) if function.get("arguments") else {}
        except json.JSONDecodeError as exc:
            raise ProviderError(f"AI provider returned non-JSON tool arguments: {function.get('arguments')!r}") from exc

        if function["name"] == _SUBMIT_FUNCTION_NAME:
            return ProviderResponse(final_output=arguments, reasoning_note=choice.get("content") or "")

        return ProviderResponse(
            tool_call=ProviderToolCall(name=function["name"], arguments=arguments),
            reasoning_note=choice.get("content") or "",
        )
