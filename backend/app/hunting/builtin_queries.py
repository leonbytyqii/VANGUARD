"""
Curated built-in hunt query library, seeded by app/hunting/seed.py into
`HuntQuery` rows with `organization_id IS NULL, is_builtin=True` —
visible to and runnable by every organization (same "shared reference
data" posture as `DetectionRule` and the MITRE catalog).

Each `query_definition` is Sigma-shaped (named selections + a `condition`
string, see app/detections/sigma_engine/matcher.py) and deliberately casts
a **wider** net than the corresponding auto-firing Sigma/custom detection
in app/detections/ where one exists — a detection rule has to be precise
enough to alert unattended; a hunt query is a hypothesis a human reviews,
so higher recall / lower precision is the right tradeoff. Several of
these intentionally overlap in *topic* with an existing detection
(encoded PowerShell, IAM sensitive actions) while covering a broader
pattern than that detection's exact trigger — showing the "hunt now,
promote to detection later once proven precise" workflow this platform
is built to support (see app/models/hunting.py's module docstring).

MITRE tagging discipline: every `mitre_technique_ids` entry below is
verified by `tests/test_hunting.py` to exist in the curated ATT&CK
catalog (app/mitre/data.py::TECHNIQUES) — the same invariant Phase 6
enforces for detection rules. `hunt_lolbin_proxy_execution` is
deliberately left **untagged**: the real ATT&CK technique for this
pattern (T1218, Signed Binary Proxy Execution) isn't in the curated
subset, and forcing it onto a loosely-related cataloged ID (e.g. T1027)
would be a fabricated mapping — the same "never assert what isn't
actually true" discipline that governs AI-generated evidence applies
here to the platform's own metadata. Growing the MITRE catalog to add
T1218 properly is a one-line addition to `app/mitre/data.py`, not a
reason to mistag this hunt in the meantime.
"""

BUILTIN_HUNT_QUERIES: list[dict] = [
    {
        "name": "Broad PowerShell Obfuscation/Bypass Indicators",
        "description": (
            "Wider net than the auto-firing sigma_suspicious_powershell_encoded "
            "detection (which only looks for -EncodedCommand variants): also "
            "catches -NoProfile/-WindowStyle Hidden/-ExecutionPolicy Bypass "
            "flags and common download-cradle/deobfuscation cmdlets "
            "(Invoke-Expression, DownloadString, FromBase64String) anywhere on "
            "the command line. Higher recall, lower precision — intended for "
            "analyst review, not unattended alerting."
        ),
        "query_definition": {
            "selection_process": {"Image|endswith": "\\powershell.exe"},
            "selection_indicators": {
                "CommandLine|contains": [
                    "-enc ", "-EncodedCommand", "-e ", " -en ",
                    "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
                    "-ep bypass", "-executionpolicy bypass",
                    "invoke-expression", "downloadstring", "frombase64string",
                ]
            },
            "condition": "selection_process and selection_indicators",
        },
        "default_lookback_hours": 24 * 7,
        "mitre_technique_ids": ["T1059.001", "T1027"],
    },
    {
        "name": "Living-off-the-Land Binary (LOLBin) Proxy Execution",
        "description": (
            "Execution of native Windows utilities frequently abused to proxy-"
            "execute or download payloads while evading application-allowlisting "
            "and simple binary-signature defenses: certutil, regsvr32, rundll32, "
            "mshta, bitsadmin, wmic. Each has legitimate administrative uses — "
            "this is a hunting hypothesis for a human to triage, not a "
            "precise-enough-to-auto-alert detection."
        ),
        "query_definition": {
            "selection": {
                "Image|endswith": [
                    "\\certutil.exe", "\\regsvr32.exe", "\\rundll32.exe",
                    "\\mshta.exe", "\\bitsadmin.exe", "\\wmic.exe",
                ]
            },
            "condition": "selection",
        },
        "default_lookback_hours": 24 * 7,
        "mitre_technique_ids": [],  # see module docstring — no T1218 in the curated catalog
    },
    {
        "name": "Remote Administration Protocol Connections",
        "description": (
            "Every allowed (non-denied) connection on RDP (3389), SSH (22), "
            "WinRM (5985/5986), or SMB (445) within the window — a superset of "
            "the fan-out threshold custom_lateral_movement_fanout detection "
            "requires (3+ distinct destination hosts). Useful for eyeballing "
            "all remote-access activity on an asset before deciding whether "
            "fan-out crossed that threshold, or for hunting single suspicious "
            "connections that wouldn't reach it."
        ),
        "query_definition": {
            "selection_category": {"category": ["network", "firewall"]},
            "selection_port": {"DestinationPort": [3389, 22, 5985, 5986, 445]},
            "selection_denied": {"action": ["deny", "drop", "reset"]},
            "condition": "selection_category and selection_port and not selection_denied",
        },
        "default_lookback_hours": 24,
        "mitre_technique_ids": ["T1021", "T1021.001", "T1021.002", "T1021.006"],
    },
    {
        "name": "Broad IAM Sensitive / Reconnaissance Actions",
        "description": (
            "Wider net than custom_unusual_iam_activity (which only flags "
            "outright policy/permission modification calls): also includes "
            "AssumeRole, GetSessionToken, and CreateAccessKey — activity "
            "consistent with privilege-escalation reconnaissance or staging "
            "even when no policy is actually modified."
        ),
        "query_definition": {
            "selection_category": {"category": "iam"},
            "selection_action": {
                "action|contains": [
                    "putuserpolicy", "putrolepolicy", "attachuserpolicy", "attachrolepolicy",
                    "detachrolepolicy", "detachuserpolicy", "createpolicyversion",
                    "deleteuserpolicy", "deleterolepolicy", "createuser", "deleteuser",
                    "creategroup", "addusertogroup", "updateassumerolepolicy",
                    "assumerole", "getsessiontoken", "createaccesskey",
                ]
            },
            "condition": "selection_category and selection_action",
        },
        "default_lookback_hours": 24 * 7,
        "mitre_technique_ids": ["T1098.001", "T1550.001", "T1078.004"],
    },
    {
        "name": "DNS Queries to Suspicious TLDs",
        "description": (
            "DNS queries whose domain ends in a TLD disproportionately "
            "associated with disposable/low-cost domain registration used for "
            "malicious infrastructure. A coarser, non-statistical complement to "
            "the entropy-based custom_dns_anomaly_dga detection — catches "
            "low-entropy but still suspicious domains that DGA scoring misses, "
            "at the cost of flagging legitimate-but-rare use of these TLDs."
        ),
        "query_definition": {
            "selection_category": {"category": "dns"},
            "selection_tld": {
                "QueryName|endswith": [".xyz", ".top", ".tk", ".club", ".info", ".gq", ".biz"]
            },
            "condition": "selection_category and selection_tld",
        },
        "default_lookback_hours": 24 * 7,
        "mitre_technique_ids": ["T1568.002", "T1071.004"],
    },
    {
        "name": "Process Execution from User-Writable Temp Paths",
        "description": (
            "Command lines referencing an executable path under AppData\\Local\\"
            "Temp, Windows\\Temp, or Users\\Public — directories a normal user "
            "can write to, and a common landing zone for a dropped or "
            "downloaded payload before execution."
        ),
        "query_definition": {
            "selection_category": {"category": "process"},
            "selection_path": {
                "CommandLine|contains": ["\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Users\\Public\\"]
            },
            "condition": "selection_category and selection_path",
        },
        "default_lookback_hours": 24 * 7,
        "mitre_technique_ids": ["T1204.002", "T1105"],
    },
]
