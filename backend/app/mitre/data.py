"""
Curated MITRE ATT&CK (Enterprise) reference data.

**Scope, and why this is curated rather than the full STIX bundle:**
the real `enterprise-attack.json` published by MITRE is >10MB and
~800 techniques/sub-techniques. Importing it wholesale would make this
file unreviewable and mostly irrelevant to a project this size — the
same "self-written, scoped-down, and say so" choice this codebase already
made for the Sigma engine (app/detections/sigma_engine/loader.py) instead
of pulling in pySigma's full backend-conversion machinery.

Instead: all 14 Enterprise ATT&CK tactics (real tactic IDs, real
ordering), plus every technique/sub-technique referenced by this
platform's own detection rules (app/detections/registry.py) so detection
coverage is always fully resolvable, plus a broader curated set (49
techniques total) spanning every tactic so the matrix view isn't
suspiciously empty outside the handful the detections use. Swapping this
for the full MITRE STIX bundle later is a one-file change (replace
TACTICS/TECHNIQUES here, or add a loader that ingests the STIX JSON into
this same shape) — not an architecture change; app/mitre/seed.py's sync
logic and every consumer (detection-rule linking, the coverage API)
already work off `technique_id` strings and don't care where the rows
came from.

**Single-tactic-per-technique simplification:** real ATT&CK techniques
often map to multiple tactics (e.g. T1078 Valid Accounts spans Initial
Access, Persistence, Privilege Escalation, *and* Defense Evasion —
MITRE's own matrix shows it under all four). `MitreTechnique.tactic_id`
is a single FK (see that model's docstring), so each technique below is
assigned the one tactic most commonly used to introduce it in blue-team
material. This is a stated simplification, not an error — modeling the
full many-to-many would need its own join table for marginal benefit at
this project's scale, and nothing downstream (detection-rule linking,
alert tagging) depends on a technique's "primary" tactic being
exhaustive.

Every `technique_id` referenced by app/detections/registry.py's
DETECTION_REGISTRY appears below — `test_mitre.py` asserts this
invariant so a new detection referencing an unseeded technique ID fails
loudly in CI rather than silently producing an alert with a dangling
MITRE tag.
"""

# (tactic_id, name, matrix_order, description)
TACTICS: list[dict] = [
    {"tactic_id": "TA0043", "name": "Reconnaissance", "matrix_order": 1,
     "description": "The adversary is trying to gather information they can use to plan future operations."},
    {"tactic_id": "TA0042", "name": "Resource Development", "matrix_order": 2,
     "description": "The adversary is trying to establish resources they can use to support operations."},
    {"tactic_id": "TA0001", "name": "Initial Access", "matrix_order": 3,
     "description": "The adversary is trying to get into your network."},
    {"tactic_id": "TA0002", "name": "Execution", "matrix_order": 4,
     "description": "The adversary is trying to run malicious code."},
    {"tactic_id": "TA0003", "name": "Persistence", "matrix_order": 5,
     "description": "The adversary is trying to maintain their foothold."},
    {"tactic_id": "TA0004", "name": "Privilege Escalation", "matrix_order": 6,
     "description": "The adversary is trying to gain higher-level permissions."},
    {"tactic_id": "TA0005", "name": "Defense Evasion", "matrix_order": 7,
     "description": "The adversary is trying to avoid being detected."},
    {"tactic_id": "TA0006", "name": "Credential Access", "matrix_order": 8,
     "description": "The adversary is trying to steal account names and passwords."},
    {"tactic_id": "TA0007", "name": "Discovery", "matrix_order": 9,
     "description": "The adversary is trying to figure out your environment."},
    {"tactic_id": "TA0008", "name": "Lateral Movement", "matrix_order": 10,
     "description": "The adversary is trying to move through your environment."},
    {"tactic_id": "TA0009", "name": "Collection", "matrix_order": 11,
     "description": "The adversary is trying to gather data of interest to their goal."},
    {"tactic_id": "TA0011", "name": "Command and Control", "matrix_order": 12,
     "description": "The adversary is trying to communicate with compromised systems to control them."},
    {"tactic_id": "TA0010", "name": "Exfiltration", "matrix_order": 13,
     "description": "The adversary is trying to steal data."},
    {"tactic_id": "TA0040", "name": "Impact", "matrix_order": 14,
     "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."},
]

# (technique_id, name, tactic_id, parent_technique_id or None, description)
TECHNIQUES: list[dict] = [
    # Reconnaissance
    {"technique_id": "T1595", "name": "Active Scanning", "tactic_id": "TA0043", "parent_technique_id": None,
     "description": "Adversaries scan victim infrastructure to gather information for targeting."},
    {"technique_id": "T1589", "name": "Gather Victim Identity Information", "tactic_id": "TA0043", "parent_technique_id": None,
     "description": "Adversaries gather information about victim identities (names, emails, credentials)."},

    # Resource Development
    {"technique_id": "T1583", "name": "Acquire Infrastructure", "tactic_id": "TA0042", "parent_technique_id": None,
     "description": "Adversaries buy, lease, or rent infrastructure for use in targeting."},
    {"technique_id": "T1588", "name": "Obtain Capabilities", "tactic_id": "TA0042", "parent_technique_id": None,
     "description": "Adversaries buy/steal/download tools and exploits for use during operations."},

    # Initial Access
    {"technique_id": "T1566", "name": "Phishing", "tactic_id": "TA0001", "parent_technique_id": None,
     "description": "Adversaries send phishing messages to gain access to victim systems."},
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "parent_technique_id": None,
     "description": "Adversaries exploit a weakness in an Internet-facing system to gain initial access."},

    # Execution
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic_id": "TA0002", "parent_technique_id": None,
     "description": "Adversaries abuse command and script interpreters to execute commands or scripts."},
    {"technique_id": "T1059.001", "name": "PowerShell", "tactic_id": "TA0002", "parent_technique_id": "T1059",
     "description": "Adversaries abuse PowerShell commands and scripts for execution."},
    {"technique_id": "T1059.003", "name": "Windows Command Shell", "tactic_id": "TA0002", "parent_technique_id": "T1059",
     "description": "Adversaries abuse the Windows command shell (cmd.exe) for execution."},
    {"technique_id": "T1204", "name": "User Execution", "tactic_id": "TA0002", "parent_technique_id": None,
     "description": "An adversary relies on a user taking an action, such as opening a file, to gain execution."},
    {"technique_id": "T1204.002", "name": "Malicious File", "tactic_id": "TA0002", "parent_technique_id": "T1204",
     "description": "An adversary relies on a user opening a malicious file to gain execution."},
    {"technique_id": "T1047", "name": "Windows Management Instrumentation", "tactic_id": "TA0002", "parent_technique_id": None,
     "description": "Adversaries abuse WMI to execute malicious commands and payloads."},

    # Persistence
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic_id": "TA0003", "parent_technique_id": None,
     "description": "Adversaries abuse task scheduling functionality to facilitate initial or recurring execution."},
    {"technique_id": "T1053.005", "name": "Scheduled Task", "tactic_id": "TA0003", "parent_technique_id": "T1053",
     "description": "Adversaries abuse the Windows Task Scheduler to perform task scheduling for recurring execution."},
    {"technique_id": "T1098", "name": "Account Manipulation", "tactic_id": "TA0003", "parent_technique_id": None,
     "description": "Adversaries manipulate accounts to maintain access to victim systems."},
    {"technique_id": "T1098.001", "name": "Additional Cloud Credentials", "tactic_id": "TA0003", "parent_technique_id": "T1098",
     "description": "Adversaries add adversary-controlled credentials (e.g. access keys) to a cloud account."},
    {"technique_id": "T1136", "name": "Create Account", "tactic_id": "TA0003", "parent_technique_id": None,
     "description": "Adversaries create an account to maintain access to victim systems."},

    # Privilege Escalation
    {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic_id": "TA0004", "parent_technique_id": None,
     "description": "Adversaries circumvent mechanisms designed to control elevated privileges."},
    {"technique_id": "T1055", "name": "Process Injection", "tactic_id": "TA0004", "parent_technique_id": None,
     "description": "Adversaries inject code into processes to evade defenses and/or elevate privileges."},

    # Defense Evasion
    {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic_id": "TA0005", "parent_technique_id": None,
     "description": "Adversaries encode/encrypt/obfuscate content to make it harder to discover or analyze."},
    {"technique_id": "T1070", "name": "Indicator Removal", "tactic_id": "TA0005", "parent_technique_id": None,
     "description": "Adversaries delete or modify artifacts to remove evidence of their presence."},
    # Simplification, documented in this module's docstring: T1078 and
    # T1550 both span multiple real ATT&CK tactics; assigned to Defense
    # Evasion here as their single primary tactic.
    {"technique_id": "T1078", "name": "Valid Accounts", "tactic_id": "TA0005", "parent_technique_id": None,
     "description": "Adversaries obtain and abuse credentials of existing accounts as a means of gaining access."},
    {"technique_id": "T1078.004", "name": "Cloud Accounts", "tactic_id": "TA0005", "parent_technique_id": "T1078",
     "description": "Adversaries obtain and abuse credentials of existing cloud accounts."},
    {"technique_id": "T1550", "name": "Use Alternate Authentication Material", "tactic_id": "TA0005", "parent_technique_id": None,
     "description": "Adversaries use alternate authentication material to move laterally and access resources."},
    {"technique_id": "T1550.001", "name": "Application Access Token", "tactic_id": "TA0005", "parent_technique_id": "T1550",
     "description": "Adversaries use stolen application access tokens to bypass normal authentication."},

    # Credential Access
    {"technique_id": "T1110", "name": "Brute Force", "tactic_id": "TA0006", "parent_technique_id": None,
     "description": "Adversaries use brute force techniques to gain access to accounts."},
    {"technique_id": "T1110.001", "name": "Password Guessing", "tactic_id": "TA0006", "parent_technique_id": "T1110",
     "description": "Adversaries use a repetitive/iterative mechanism to guess account passwords."},
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic_id": "TA0006", "parent_technique_id": None,
     "description": "Adversaries dump credentials from the OS to obtain account login information."},
    {"technique_id": "T1003.001", "name": "LSASS Memory", "tactic_id": "TA0006", "parent_technique_id": "T1003",
     "description": "Adversaries dump the LSASS process memory to obtain credential material."},
    {"technique_id": "T1552", "name": "Unsecured Credentials", "tactic_id": "TA0006", "parent_technique_id": None,
     "description": "Adversaries search compromised systems for insecurely stored credentials."},

    # Discovery
    {"technique_id": "T1082", "name": "System Information Discovery", "tactic_id": "TA0007", "parent_technique_id": None,
     "description": "Adversaries attempt to get detailed information about the operating system and hardware."},
    {"technique_id": "T1057", "name": "Process Discovery", "tactic_id": "TA0007", "parent_technique_id": None,
     "description": "Adversaries get information about running processes on a system."},
    {"technique_id": "T1018", "name": "Remote System Discovery", "tactic_id": "TA0007", "parent_technique_id": None,
     "description": "Adversaries try to get a listing of other systems by IP address, hostname, or other identifier."},

    # Lateral Movement
    {"technique_id": "T1021", "name": "Remote Services", "tactic_id": "TA0008", "parent_technique_id": None,
     "description": "Adversaries use valid accounts to log into a service accessible remotely."},
    {"technique_id": "T1021.001", "name": "Remote Desktop Protocol", "tactic_id": "TA0008", "parent_technique_id": "T1021",
     "description": "Adversaries use RDP to log into an accessible remote system."},
    {"technique_id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic_id": "TA0008", "parent_technique_id": "T1021",
     "description": "Adversaries use SMB to interact with file shares, allowing lateral movement."},
    {"technique_id": "T1021.006", "name": "Windows Remote Management", "tactic_id": "TA0008", "parent_technique_id": "T1021",
     "description": "Adversaries use WinRM to execute commands and move laterally."},

    # Collection
    {"technique_id": "T1005", "name": "Data from Local System", "tactic_id": "TA0009", "parent_technique_id": None,
     "description": "Adversaries search local system sources to find files of interest."},
    {"technique_id": "T1114", "name": "Email Collection", "tactic_id": "TA0009", "parent_technique_id": None,
     "description": "Adversaries target user email to collect sensitive information."},

    # Command and Control
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic_id": "TA0011", "parent_technique_id": None,
     "description": "Adversaries communicate using application-layer protocols to blend in with normal traffic."},
    {"technique_id": "T1071.004", "name": "DNS", "tactic_id": "TA0011", "parent_technique_id": "T1071",
     "description": "Adversaries communicate using the DNS protocol to blend in with existing traffic."},
    {"technique_id": "T1571", "name": "Non-Standard Port", "tactic_id": "TA0011", "parent_technique_id": None,
     "description": "Adversaries communicate over a non-standard port to bypass filtering or inspection."},
    {"technique_id": "T1568", "name": "Dynamic Resolution", "tactic_id": "TA0011", "parent_technique_id": None,
     "description": "Adversaries dynamically establish C2 infrastructure to evade detection and takedown."},
    {"technique_id": "T1568.002", "name": "Domain Generation Algorithms", "tactic_id": "TA0011", "parent_technique_id": "T1568",
     "description": "Adversaries use DGAs to dynamically identify C2 infrastructure, evading static IOC lists."},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic_id": "TA0011", "parent_technique_id": None,
     "description": "Adversaries transfer tools or files from an external system into a compromised environment."},

    # Exfiltration
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic_id": "TA0010", "parent_technique_id": None,
     "description": "Adversaries steal data by exfiltrating it over an existing C2 channel."},
    {"technique_id": "T1567", "name": "Exfiltration Over Web Service", "tactic_id": "TA0010", "parent_technique_id": None,
     "description": "Adversaries use an existing, legitimate external web service to exfiltrate data."},

    # Impact
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic_id": "TA0040", "parent_technique_id": None,
     "description": "Adversaries encrypt data on target systems to interrupt availability (ransomware)."},
    {"technique_id": "T1531", "name": "Account Access Removal", "tactic_id": "TA0040", "parent_technique_id": None,
     "description": "Adversaries interrupt availability by deleting, locking, or changing credentials to accounts."},
]
