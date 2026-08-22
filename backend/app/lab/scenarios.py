"""
The attack-simulation scenario library (Phase 14).

Each scenario is an ordered list of event payloads with **relative**
offsets in minutes. Running one submits those payloads through the real
`POST /api/v1/events` ingestion path — the same adapters, the same
normalization, the same synchronous detection sweep, the same risk
scoring, the same alert dedup. Nothing here fabricates a detection or
writes an alert directly.

That is the whole point. A demo that inserts pre-baked alerts proves
nothing about the detection engine; a demo that replays realistic
telemetry and lets the engine find it is an end-to-end test of the
platform that a person can watch happen. It also means a scenario that
*stops* firing is a real regression signal, which is why
`tests/test_lab.py` asserts each scenario still produces the detections it
claims.

## Safety constraints on scenario data

Every scenario is synthetic and self-contained:

- IPv4 addresses come only from the RFC 5737 documentation ranges, and
  domains only from RFC 2606 reserved TLDs — the same rule
  `app/threat_intel/sample_feed.py` follows, for the same reason: a
  committed file must never name real infrastructure as malicious.
- Hostnames are obviously fictional (`SIM-*`).
- Nothing in here executes anything on the host running it. A "simulation"
  in this platform means *synthetic telemetry describing an attack*, not
  an attack. There is deliberately no scenario that shells out, drops a
  file, or touches the network, and adding one would turn a SOC training
  tool into malware.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScenarioStep:
    #: Minutes after the scenario's start time.
    offset_minutes: float
    payload: dict[str, Any]


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    description: str
    #: What a well-functioning detection stack should surface. Asserted by
    #: the test suite, and shown in the UI so a run's outcome can be
    #: checked against its own stated expectation rather than eyeballed.
    expected_detections: list[str]
    mitre_technique_ids: list[str]
    steps: list[ScenarioStep] = field(default_factory=list)


def _sysmon(host: str, process: str, *, parent: str | None = None, cmdline: str = "", user: str = "sim-user", file_hash: str | None = None) -> dict[str, Any]:
    return {
        "source": "windows_sysmon",
        "host": host,
        "user": user,
        "event_type": "process_creation",
        "process": process,
        "parent_process": parent,
        "command_line": cmdline,
        "file_hash": file_hash,
    }


def _firewall(host: str, dst_ip: str, dst_port: int, *, src_ip: str = "10.20.0.15", action: str = "allow") -> dict[str, Any]:
    return {
        "source": "firewall",
        "host": host,
        "event_type": "connection",
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "tcp",
    }


def _dns(host: str, domain: str, *, user: str = "sim-user") -> dict[str, Any]:
    return {"source": "dns", "host": host, "user": user, "event_type": "query", "domain": domain}


def _linux_auth(host: str, user: str, action: str, src_ip: str) -> dict[str, Any]:
    return {"source": "linux_auth", "host": host, "user": user, "event_type": action, "action": action, "src_ip": src_ip}


def _cloudtrail(event_name: str, user: str, *, account: str = "999988887777", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "source": "cloudtrail",
        "event_type": event_name,
        "user": user,
        "cloud_account": account,
        "cloud_region": "eu-west-1",
        "src_ip": "203.0.113.7",
        "extra": extra or {},
    }


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        scenario_id="encoded_powershell_c2",
        name="Encoded PowerShell dropper with C2 beacon",
        description=(
            "A user opens a malicious document; Word spawns an encoded PowerShell command that resolves a "
            "delivery domain and beacons out to a C2 host on a non-standard port. Exercises the Sigma engine, "
            "the DNS path, and outbound-connection correlation together."
        ),
        expected_detections=[
            "sigma_suspicious_powershell_encoded",
            "sigma_powershell_spawned_by_office",
            "custom_suspicious_outbound_port",
        ],
        mitre_technique_ids=["T1059.001", "T1027", "T1071", "T1204.002"],
        steps=[
            ScenarioStep(0, _sysmon("SIM-WKS-01", "winword.exe", parent="explorer.exe", cmdline="winword.exe /n invoice.docm")),
            ScenarioStep(
                1,
                _sysmon(
                    "SIM-WKS-01",
                    "powershell.exe",
                    parent="winword.exe",
                    cmdline="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                ),
            ),
            ScenarioStep(2, _dns("SIM-WKS-01", "malware-delivery.invalid")),
            ScenarioStep(3, _firewall("SIM-WKS-01", "203.0.113.7", 4444)),
            ScenarioStep(9, _firewall("SIM-WKS-01", "203.0.113.7", 4444)),
            ScenarioStep(18, _firewall("SIM-WKS-01", "203.0.113.7", 4444)),
        ],
    ),
    Scenario(
        scenario_id="credential_access_lsass",
        name="Credential access against LSASS",
        description=(
            "A tool is executed that reads LSASS memory to harvest credentials — the classic post-exploitation "
            "step between initial access and lateral movement."
        ),
        expected_detections=["sigma_credential_access_lsass"],
        mitre_technique_ids=["T1003.001"],
        steps=[
            ScenarioStep(
                0,
                _sysmon(
                    "SIM-WKS-01",
                    "rundll32.exe",
                    parent="cmd.exe",
                    cmdline="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full",
                ),
            ),
        ],
    ),
    Scenario(
        scenario_id="ssh_brute_force",
        name="SSH brute force followed by a successful login",
        description=(
            "A burst of failed SSH authentications from one source, followed by a success — the shape that "
            "makes a brute force worth waking someone for rather than just noise."
        ),
        expected_detections=["custom_brute_force_login"],
        mitre_technique_ids=["T1110"],
        steps=[
            *[
                ScenarioStep(i * 0.4, _linux_auth("SIM-SRV-02", "root", "failed_password", "192.0.2.44"))
                for i in range(12)
            ],
            ScenarioStep(5.5, _linux_auth("SIM-SRV-02", "root", "accepted_password", "192.0.2.44")),
        ],
    ),
    Scenario(
        scenario_id="dga_beaconing",
        name="DGA-style domain resolution",
        description=(
            "A host resolves a run of high-entropy, algorithmically-generated domains — the signature of malware "
            "cycling through a domain-generation algorithm looking for a live controller."
        ),
        expected_detections=["custom_dns_anomaly_dga"],
        mitre_technique_ids=["T1568.002"],
        steps=[
            ScenarioStep(0.0, _dns("SIM-WKS-03", "x7k2p9qw3zr8vn4t.invalid")),
            ScenarioStep(0.5, _dns("SIM-WKS-03", "b3nf8yq2wk7zx1mv.invalid")),
            ScenarioStep(1.0, _dns("SIM-WKS-03", "q9wz4xk8p2nv6rt3.invalid")),
            ScenarioStep(1.5, _dns("SIM-WKS-03", "m4kx8zq1wp7nv2yr.invalid")),
            ScenarioStep(2.0, _dns("SIM-WKS-03", "kj3h4kj2h34kjh.test")),
        ],
    ),
    Scenario(
        scenario_id="lateral_movement",
        name="Lateral movement fan-out",
        description=(
            "One compromised workstation opens SMB/RDP sessions to an unusual number of internal hosts in a "
            "short window — the fan-out pattern that distinguishes lateral movement from normal use."
        ),
        expected_detections=["custom_lateral_movement_fanout"],
        mitre_technique_ids=["T1021.002"],
        steps=[
            ScenarioStep(i * 0.6, _firewall("SIM-WKS-01", f"10.20.0.{40 + i}", 445, src_ip="10.20.0.15"))
            for i in range(10)
        ],
    ),
    Scenario(
        scenario_id="cloud_privilege_escalation",
        name="Cloud identity privilege escalation and log tampering",
        description=(
            "A developer identity assumes a deployment role, attaches an administrative policy to it, and then "
            "stops CloudTrail logging. Drives both the privilege-escalation detection and the Phase 11 IAM "
            "attack-path graph."
        ),
        expected_detections=["custom_cloud_privilege_escalation_chain"],
        mitre_technique_ids=["T1078.004", "T1548", "T1550.001"],
        steps=[
            ScenarioStep(
                0,
                _cloudtrail(
                    "AssumeRole",
                    "sim-dev-alice",
                    extra={"request_parameters": {"roleArn": "arn:aws:iam::999988887777:role/SimDeployRole"}},
                ),
            ),
            ScenarioStep(
                3,
                _cloudtrail(
                    "AttachRolePolicy",
                    "sim-dev-alice",
                    extra={
                        "request_parameters": {
                            "roleName": "SimDeployRole",
                            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        }
                    },
                ),
            ),
            ScenarioStep(
                6,
                _cloudtrail(
                    "CreateAccessKey",
                    "SimDeployRole",
                    extra={"request_parameters": {"userName": "sim-backdoor-user"}},
                ),
            ),
            ScenarioStep(
                9,
                _cloudtrail("StopLogging", "SimDeployRole", extra={"request_parameters": {"trailName": "sim-org-trail"}}),
            ),
        ],
    ),
    Scenario(
        scenario_id="impossible_travel",
        name="Impossible travel authentication",
        description=(
            "The same account authenticates from two geographically incompatible source addresses within "
            "minutes — a credential-sharing or session-theft signal."
        ),
        expected_detections=["custom_impossible_travel_proxy"],
        mitre_technique_ids=["T1078"],
        steps=[
            ScenarioStep(0, _linux_auth("SIM-SRV-02", "sim-bob", "accepted_password", "198.51.100.10")),
            ScenarioStep(4, _linux_auth("SIM-SRV-02", "sim-bob", "accepted_password", "203.0.113.200")),
        ],
    ),
    Scenario(
        scenario_id="persistence_scheduled_task",
        name="Scheduled-task persistence",
        description="A scheduled task is registered to re-launch a payload at logon — a durable foothold.",
        expected_detections=["sigma_persistence_scheduled_task"],
        mitre_technique_ids=["T1053.005"],
        steps=[
            ScenarioStep(
                0,
                _sysmon(
                    "SIM-WKS-01",
                    "schtasks.exe",
                    parent="powershell.exe",
                    cmdline="schtasks.exe /create /sc onlogon /tn UpdaterSvc /tr C:\\Temp\\payload.exe /rl highest",
                ),
            ),
        ],
    ),
)

SCENARIOS_BY_ID: dict[str, Scenario] = {s.scenario_id: s for s in SCENARIOS}
