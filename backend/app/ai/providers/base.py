"""
Provider-agnostic LLM interface (docs/ARCHITECTURE.md §5).

Every provider — real or mock — implements exactly one method:
`complete(messages, tools, response_schema) -> ProviderResponse`. This is
deliberately the *only* seam between the orchestrator
(app/ai/orchestrator.py) and "however this particular investigation step
gets its next decision made" — swapping `AI_PROVIDER` in config never
touches orchestration logic, evidence validation, or the tool-permission
gateway (app/ai/agents/permissions.py::invoke_agent_tool).

`messages` is a real, ordinary chat-style transcript
(`[{"role": "system"|"user"|"assistant"|"tool", "content": str, "name":
str | None}]`) — every tool result the agent has seen so far is *in*
this list, wrapped in a clearly delimited block by
app/ai/orchestrator.py::render_tool_result (see that function's
docstring for the prompt-injection posture this exists to enforce). A
provider's response is one of two shapes:

- `tool_call` — the agent wants to call another tool before deciding
  anything. The orchestrator dispatches it through
  `invoke_agent_tool` (never directly), appends the result as a new
  `tool` message, and calls `complete()` again.
- `final_output` — the agent is done and this is its attempt at a
  `response_schema`-shaped structured result (validated by the
  orchestrator before being trusted — see
  app/ai/orchestrator.py::_validate_investigation_result).

Exactly one of the two is ever set.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ProviderResponse:
    tool_call: ProviderToolCall | None = None
    final_output: dict[str, Any] | None = None
    # Human-readable note on why this step was taken — persisted verbatim
    # as AgentStep.reasoning_note, purely for the replayable audit trace;
    # never itself trusted as evidence.
    reasoning_note: str = ""

    def __post_init__(self) -> None:
        if (self.tool_call is None) == (self.final_output is None):
            raise ValueError("ProviderResponse must set exactly one of tool_call or final_output")


class ProviderError(Exception):
    """Raised for a provider-level failure (bad response shape, network error, timeout, ...)."""


class LLMProvider(Protocol):
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any],
    ) -> ProviderResponse: ...
