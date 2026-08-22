"""
Deterministic, rule-based stand-in for a real LLM — `AI_PROVIDER=mock`
(the default, see .env.example), used whenever no API key is configured
so the platform is fully demonstrable offline, and exclusively in the
test suite so `pytest` never depends on network access or a paid API key.

MockProvider implements the exact same `LLMProvider.complete()` interface
a real provider does — it is handed the same `messages` transcript,
`tools` list, and `response_schema`, and returns the same
`ProviderResponse` union — it just makes its decisions with plain Python
control flow (a fixed tool-call sequence, then a template-filled final
report) instead of an API call. This is deliberate: it proves the
orchestrator, the tool-permission gateway, and the evidence validator all
work against the real interface, not a special-cased shortcut.

Because it's deterministic, it reconstructs its final report by reading
back the actual JSON tool results already present in `messages` (role
"tool") — it never invents a fact that wasn't actually returned by a real
tool call this investigation session, which is what lets
`tests/test_ai_investigation.py` assert on exact evidence contents.
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.providers.base import ProviderResponse, ProviderToolCall

# Fixed investigation script: call these tools, in this order, skipping
# any not in the agent's own allowlist (the orchestrator only ever offers
# `tools` the current agent may call, so an unavailable one is just
# absent from `tools` and skipped below).
_INVESTIGATION_TOOL_SEQUENCE = [
    "get_alert",
    "search_events",
    "get_host_info",
    "get_process_tree",
    "get_network_connections",
    "map_mitre_technique",
    "enrich_ioc",
]


def _tool_names_called(messages: list[dict[str, Any]]) -> list[str]:
    return [m["name"] for m in messages if m.get("role") == "tool" and m.get("name")]


def _tool_result(messages: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for m in reversed(messages):
        if m.get("role") == "tool" and m.get("name") == name:
            return json.loads(m["content"])
    return None


def _alert_context(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """
    The initial user message embeds the alert's own fields as a JSON block
    *after* a human-readable prefix (see orchestrator.py::_build_initial_messages),
    so the message content as a whole is not valid JSON on its own — only
    the substring starting at the first '{' is. A real model reads the
    surrounding sentence as context; this deterministic stand-in only
    needs the structured part, so it locates and parses just that slice.
    """
    for m in messages:
        if m.get("role") == "user" and m.get("name") == "alert_context":
            content = m["content"]
            brace_index = content.find("{")
            if brace_index == -1:
                return {}
            return json.loads(content[brace_index:])
    return {}


class MockProvider:
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any],
    ) -> ProviderResponse:
        available = {t["name"] for t in tools}
        already_called = set(_tool_names_called(messages))

        # Triage's response_schema is much smaller than the full
        # investigation result — detected by its distinguishing "proceed"
        # property, so this one complete() implementation serves both
        # roles the same way a real model would (same interface, same
        # transcript shape, different response_schema/tools per call).
        if "proceed" in response_schema.get("properties", {}):
            return self._triage_decision(messages)

        for tool_name in _INVESTIGATION_TOOL_SEQUENCE:
            if tool_name in available and tool_name not in already_called:
                return self._next_tool_call(tool_name, messages)

        return self._final_report(messages)

    def _next_tool_call(self, tool_name: str, messages: list[dict[str, Any]]) -> ProviderResponse:
        alert = _alert_context(messages)
        args: dict[str, Any] = {}
        if tool_name == "get_alert":
            args = {"alert_id": alert.get("id")}
        elif tool_name == "search_events":
            args = {"host_name": alert.get("host_name"), "user": alert.get("user"), "limit": 25}
        elif tool_name == "get_host_info":
            if not alert.get("host_name"):
                return self._final_report(messages, skip_tool=tool_name)
            args = {"hostname": alert.get("host_name")}
        elif tool_name == "get_process_tree":
            if not alert.get("host_name"):
                return self._final_report(messages, skip_tool=tool_name)
            args = {"hostname": alert.get("host_name")}
        elif tool_name == "get_network_connections":
            if not alert.get("host_name"):
                return self._final_report(messages, skip_tool=tool_name)
            args = {"hostname": alert.get("host_name")}
        elif tool_name == "map_mitre_technique":
            technique_ids = alert.get("mitre_technique_ids") or []
            if not technique_ids:
                return self._final_report(messages, skip_tool=tool_name)
            args = {"technique_id": technique_ids[0]}
        elif tool_name == "enrich_ioc":
            events = _tool_result(messages, "search_events") or {}
            candidate_ip = next(
                (e.get("src_ip") for e in events.get("events", []) if e.get("src_ip") and e["src_ip"] != alert.get("src_ip")),
                None,
            )
            if not candidate_ip:
                return self._final_report(messages, skip_tool=tool_name)
            args = {"ioc_type": "ip", "value": candidate_ip}

        return ProviderResponse(
            tool_call=ProviderToolCall(name=tool_name, arguments=args),
            reasoning_note=f"Gathering evidence via {tool_name} before concluding.",
        )

    def _triage_decision(self, messages: list[dict[str, Any]]) -> ProviderResponse:
        alert = _alert_context(messages)
        risk_score = alert.get("risk_score", 0)
        # Mirrors Phase 5's own INFO threshold (docs/RISK_SCORING.md) —
        # an alert scoring below what the platform's own formula treats
        # as more-than-informational isn't worth a full investigation.
        proceed = risk_score >= 20
        return ProviderResponse(
            final_output={
                "proceed": proceed,
                "initial_severity": alert.get("severity", "LOW"),
                "confidence": 0.75,
                "reasoning": (
                    f"Alert risk_score={risk_score} "
                    + ("meets" if proceed else "is below")
                    + " the investigation threshold (20)."
                ),
            },
            reasoning_note="Triage decision based on the alert's own risk score.",
        )

    def _final_report(self, messages: list[dict[str, Any]], *, skip_tool: str | None = None) -> ProviderResponse:
        alert = _alert_context(messages)
        alert_result = _tool_result(messages, "get_alert") or {}
        events_result = _tool_result(messages, "search_events") or {"events": []}
        host_result = _tool_result(messages, "get_host_info")
        technique_result = _tool_result(messages, "map_mitre_technique")
        ioc_result = _tool_result(messages, "enrich_ioc")

        observed_evidence = []
        if alert_result.get("found"):
            observed_evidence.append(
                {
                    "claim": f"Alert '{alert_result.get('title')}' fired with severity {alert_result.get('severity')}.",
                    "source_tool": "get_alert",
                    "source_event_id": None,
                    "source_table": "alerts",
                    "confidence": 1.0,
                }
            )
        for event in events_result.get("events", [])[:3]:
            observed_evidence.append(
                {
                    "claim": f"Event on {event.get('host')}: process={event.get('process')}, user={event.get('user')}.",
                    "source_tool": "search_events",
                    "source_event_id": event.get("event_id"),
                    "source_table": "events",
                    "confidence": 0.9,
                }
            )
        if host_result and host_result.get("found"):
            observed_evidence.append(
                {
                    "claim": f"Host {host_result.get('hostname')} has criticality '{host_result.get('criticality')}'.",
                    "source_tool": "get_host_info",
                    "source_event_id": None,
                    "source_table": "hosts",
                    "confidence": 1.0,
                }
            )
        if ioc_result:
            observed_evidence.append(
                {
                    "claim": f"IOC {ioc_result.get('value')} reputation: {ioc_result.get('reputation')}.",
                    "source_tool": "enrich_ioc",
                    "source_event_id": None,
                    "source_table": "iocs",
                    "confidence": 0.6,
                }
            )

        mitre_attack = []
        if technique_result and technique_result.get("found"):
            mitre_attack.append({"technique_id": technique_result["technique_id"], "tactic": technique_result.get("tactic_name", "")})

        severity = alert.get("severity", "LOW")
        risk_score = alert.get("risk_score", 0)
        confidence = min(0.5 + 0.08 * len(observed_evidence), 0.95)

        recommended_containment = []
        if severity in ("HIGH", "CRITICAL") and alert.get("host_name"):
            recommended_containment.append(
                {
                    "action": "isolate_host",
                    "target": alert["host_name"],
                    "reasoning": f"Severity {severity} on a live host warrants containment pending human review.",
                    "requires_approval": True,
                }
            )

        affected_assets = []
        if alert.get("host_name"):
            affected_assets.append({"type": "host", "id": alert["host_name"]})
        if alert.get("user"):
            affected_assets.append({"type": "user", "id": alert["user"]})

        return ProviderResponse(
            final_output={
                "severity": severity,
                "risk_score": risk_score,
                "confidence": round(confidence, 2),
                "summary": (
                    f"{alert.get('title', 'Alert')} on {alert.get('host_name', 'an unknown host')}: "
                    f"{len(observed_evidence)} pieces of evidence gathered across "
                    f"{len(_tool_names_called(messages))} tool calls."
                ),
                "observed_evidence": observed_evidence,
                "hypotheses": [
                    {
                        "statement": f"The activity behind '{alert.get('title', 'this alert')}' is consistent with the detection rule that fired.",
                        "likelihood": "medium",
                        "based_on": [str(i) for i in range(len(observed_evidence))],
                    }
                ],
                "mitre_attack": mitre_attack,
                "affected_assets": affected_assets,
                "recommended_investigation": [
                    "Review the full process tree for the affected host.",
                    "Confirm whether the user account's recent activity is expected.",
                ],
                "recommended_containment": recommended_containment,
                "false_positive_indicators": [] if len(observed_evidence) >= 2 else ["Limited corroborating evidence was found."],
            },
            reasoning_note="Synthesized final report from all evidence gathered this session.",
        )
