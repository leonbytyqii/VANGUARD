"""
The default incident-response checklist seeded onto every new incident.

Structure follows the incident-handling phases of **NIST SP 800-61r2**
(Detection & Analysis → Containment → Eradication → Recovery →
Post-Incident Activity). "Preparation", the framework's first phase, is
deliberately not represented: it is org-level work done *before* any
incident exists, so it has no place on a specific case's checklist.

Two deliberate design choices worth naming:

1. **These are prompts, not automation.** Every task is a thing a human
   does and then ticks. Nothing here triggers a tool call, and in
   particular nothing here executes a containment action — "Isolate the
   affected host" is a checklist line whose actual execution still has
   to go through the `pending → approved → executed` state machine in
   `app.services.response_actions`. The checklist can remind an analyst
   to contain a host; it can never contain one.

2. **The template is fixed, not severity-branched.** An earlier cut of
   this varied the checklist by incident severity, which sounds smarter
   and is worse: it means a case downgraded from HIGH to MEDIUM silently
   loses checklist items an analyst may already have been working, and
   it makes "did we follow the process?" unanswerable without knowing
   what the severity was at creation time. One checklist, always the
   same, is auditable. Analysts add case-specific tasks on top of it.

`sort_order` is spaced by 10 so a task added between two template items
does not require renumbering the rest.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import IncidentTaskCategory


@dataclass(frozen=True)
class IncidentTaskTemplate:
    title: str
    description: str
    category: IncidentTaskCategory


DEFAULT_IR_CHECKLIST: tuple[IncidentTaskTemplate, ...] = (
    IncidentTaskTemplate(
        title="Validate the alert and confirm it is not a false positive",
        description=(
            "Review the triggering detection's evidence and the raw events behind it. "
            "If this turns out to be a false positive, close the incident with "
            "classification 'false_positive' so the detection's precision stays measurable."
        ),
        category=IncidentTaskCategory.DETECTION_ANALYSIS,
    ),
    IncidentTaskTemplate(
        title="Determine scope: which hosts, accounts, and cloud identities are affected",
        description=(
            "Pivot on the indicators from the linked alerts to establish blast radius. "
            "Use the threat-hunting API to check whether the same behaviour appears "
            "elsewhere in the estate before assuming the scope is one host."
        ),
        category=IncidentTaskCategory.DETECTION_ANALYSIS,
    ),
    IncidentTaskTemplate(
        title="Establish an initial timeline of attacker activity",
        description=(
            "Order the known events by their own event_timestamp (not ingest time) "
            "and record the earliest confirmed malicious activity — that timestamp is "
            "what dwell time is measured from."
        ),
        category=IncidentTaskCategory.DETECTION_ANALYSIS,
    ),
    IncidentTaskTemplate(
        title="Decide and record a containment strategy",
        description=(
            "Weigh evidence preservation against ongoing damage before acting. "
            "Record the decision as an incident note so the reasoning survives the shift handover."
        ),
        category=IncidentTaskCategory.CONTAINMENT,
    ),
    IncidentTaskTemplate(
        title="Request approval for any required containment actions",
        description=(
            "Isolating a host, disabling an account, blocking an IP or revoking cloud "
            "credentials are all privileged actions: they must be filed through the "
            "response-action approval workflow and approved by a human holding "
            "'response.approve'. Ticking this task does not perform any of them."
        ),
        category=IncidentTaskCategory.CONTAINMENT,
    ),
    IncidentTaskTemplate(
        title="Preserve evidence before remediation destroys it",
        description=(
            "Capture volatile state (process list, network connections, memory where "
            "warranted) and confirm the relevant raw events are retained, before "
            "reimaging or credential rotation removes the ability to answer questions later."
        ),
        category=IncidentTaskCategory.CONTAINMENT,
    ),
    IncidentTaskTemplate(
        title="Identify and remove the root cause",
        description=(
            "Remove persistence mechanisms, malicious binaries, and attacker-created "
            "accounts. Removing the payload without removing the initial access vector "
            "is a re-infection, not an eradication."
        ),
        category=IncidentTaskCategory.ERADICATION,
    ),
    IncidentTaskTemplate(
        title="Rotate credentials and secrets exposed during the incident",
        description=(
            "Cover every credential the attacker could plausibly have accessed, not "
            "only those with confirmed use — absence of evidence of use is not evidence "
            "of absence given typical log retention."
        ),
        category=IncidentTaskCategory.ERADICATION,
    ),
    IncidentTaskTemplate(
        title="Restore affected systems to normal operation",
        description=(
            "Return isolated hosts and disabled accounts to service, and confirm the "
            "restored systems are running the patched/hardened configuration rather "
            "than the one that was compromised."
        ),
        category=IncidentTaskCategory.RECOVERY,
    ),
    IncidentTaskTemplate(
        title="Monitor for attacker return before declaring recovery complete",
        description=(
            "Watch the affected assets and indicators for a defined period after "
            "restoration. Re-entry through a missed persistence mechanism is the most "
            "common way an 'eradicated' incident reopens."
        ),
        category=IncidentTaskCategory.RECOVERY,
    ),
    IncidentTaskTemplate(
        title="Write the post-incident review and record lessons learned",
        description=(
            "What happened, what was missed, and what would have caught it sooner. "
            "This is the input to the next detection-engineering cycle."
        ),
        category=IncidentTaskCategory.POST_INCIDENT,
    ),
    IncidentTaskTemplate(
        title="Propose detection or hunt coverage for the gap this incident exposed",
        description=(
            "If existing detections did not catch this, or caught it too late, turn "
            "that into a new detection rule or a saved hunt query. An incident that "
            "produces no coverage change has not been fully closed out."
        ),
        category=IncidentTaskCategory.POST_INCIDENT,
    ),
)


def default_checklist() -> tuple[IncidentTaskTemplate, ...]:
    return DEFAULT_IR_CHECKLIST
