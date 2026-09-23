"""
CyberShield GPT - Detection Engine
Simulates a hospital SOC event pipeline: attack chain, access logs,
a small knowledge base, and an incident report generator.
"""

import time
import random
import datetime

INCIDENT = {
    "account": "SHIVA_ADMIN",
    "source_ip": "91.108.44.201",
    "outbound_ip": "185.221.14.92",
    "hospital": "Polu General Hospital",
}

PIPELINE_STAGES = [
    {
        "id": "normal_activity", "num": 1, "elapsed": "00:00",
        "title": "Normal hospital activity",
        "detail": "Baseline EHR and admin traffic — routine clinical logins, no anomalies.",
        "score": 0, "level": "normal", "badge": None, "stats": {},
    },
    {
        "id": "failed_logins", "num": 2, "elapsed": "00:04",
        "title": "Repeated failed login attempts",
        "detail": "38 failed logins against the admin service account in under 3 minutes, from 91.108.44.201.",
        "score": 15, "level": "warning", "badge": None, "stats": {},
    },
    {
        "id": "unusual_login", "num": 3, "elapsed": "00:07",
        "title": "Successful admin login from unusual external IP",
        "detail": "Authentication succeeded on attempt 39, from an IP never previously associated with this account.",
        "score": 25, "level": "warning", "badge": "first compromise",
        "stats": {"account": INCIDENT["account"], "source_ip": INCIDENT["source_ip"]},
    },
    {
        "id": "patient_access", "num": 4, "elapsed": "00:15",
        "title": "Access to all patient records",
        "detail": "Authenticated session queried the full patient records database — a mass access pattern.",
        "score": 20, "level": "high", "badge": None, "stats": {"records_accessed": 14820},
    },
    {
        "id": "ehr_export", "num": 5, "elapsed": "00:19",
        "title": "Large EHR exports",
        "detail": "A single export job pulled 6.4 GB of Electronic Health Records.",
        "score": 20, "level": "high", "badge": None, "stats": {"data_exported_gb": 6.4},
    },
    {
        "id": "config_access", "num": 6, "elapsed": "00:25",
        "title": "Sensitive configuration-file access",
        "detail": "Access detected on server/network configuration files outside normal admin workflow.",
        "score": 15, "level": "high", "badge": None, "stats": {},
    },
    {
        "id": "archive_created", "num": 7, "elapsed": "00:29",
        "title": "Data archive created",
        "detail": "A compressed archive bundling the exported data was created on the export host.",
        "score": 10, "level": "critical", "badge": None, "stats": {},
    },
    {
        "id": "outbound_transfer", "num": 8, "elapsed": "00:36",
        "title": "Large outbound network transfer",
        "detail": f"Archive transferred to {INCIDENT['outbound_ip']}, an unrecognized non-hospital destination.",
        "score": 15, "level": "critical", "badge": None,
        "stats": {"outbound_ip": INCIDENT["outbound_ip"]},
    },
]

RECOMMENDATIONS = [
    f"Disable {INCIDENT['account']} and revoke all active sessions",
    "Block source/destination IPs at the firewall",
    "Isolate the EHR export host pending forensic image",
    "Engage the privacy officer — this is a reportable PHI incident",
    "Preserve logs and the exported archive for investigation",
    "Begin the HIPAA breach-notification assessment clock",
    "Audit all recent configuration-file changes for tampering",
    "Enforce MFA on all admin and clinical accounts going forward",
]

SCENARIOS = {
    "data_exfiltration": {
        "label": "EHR data exfiltration",
        "description": "Brute-forced administrator account followed by bulk patient-data theft.",
        "incident": INCIDENT,
        "stages": PIPELINE_STAGES,
        "recommendations": RECOMMENDATIONS,
    },
    "ransomware": {
        "label": "Ransomware outbreak",
        "description": "A compromised workstation spreads encryption activity across hospital systems.",
        "incident": {"account": "CLINICAL_WS_17", "source_ip": "10.20.8.17", "outbound_ip": "198.51.100.24", "hospital": INCIDENT["hospital"]},
        "stages": [
            {"id": "ransom_login", "num": 1, "elapsed": "00:00", "title": "Suspicious remote login", "detail": "A clinical workstation accepts a remote session outside its normal maintenance window.", "score": 15, "level": "warning", "badge": "unusual access", "stats": {}},
            {"id": "ransom_discovery", "num": 2, "elapsed": "00:06", "title": "Network share discovery", "detail": "The workstation enumerates shared folders and backup locations across the hospital network.", "score": 20, "level": "high", "badge": None, "stats": {"systems_affected": 12}},
            {"id": "ransom_disable_backup", "num": 3, "elapsed": "00:14", "title": "Backup service tampering", "detail": "Attempts are detected to stop backup services and delete recovery snapshots.", "score": 25, "level": "high", "badge": None, "stats": {}},
            {"id": "ransom_encryption", "num": 4, "elapsed": "00:22", "title": "Mass file encryption", "detail": "Rapid file-renaming and encryption behavior appears on shared clinical folders.", "score": 30, "level": "critical", "badge": "active impact", "stats": {"systems_affected": 34, "encrypted_files_gb": 18.2}},
            {"id": "ransom_note", "num": 5, "elapsed": "00:28", "title": "Ransom note detected", "detail": "A ransom note is written to affected shares while access to clinical files is disrupted.", "score": 15, "level": "critical", "badge": None, "stats": {}},
        ],
        "recommendations": [
            "Isolate affected workstations and disable their network access",
            "Protect backup systems and preserve recovery snapshots",
            "Block the suspicious remote-access path at the firewall",
            "Preserve memory, disk images, and endpoint telemetry for forensics",
            "Activate downtime procedures for affected clinical services",
            "Notify incident leadership and the privacy officer",
        ],
    },
    "insider_misuse": {
        "label": "Insider misuse",
        "description": "A valid employee account accesses patient records outside its normal role and schedule.",
        "incident": {"account": "NURSE_A_PATEL", "source_ip": "10.14.3.44", "outbound_ip": "203.0.113.77", "hospital": INCIDENT["hospital"]},
        "stages": [
            {"id": "insider_login", "num": 1, "elapsed": "00:00", "title": "After-hours account use", "detail": "A clinical account signs in outside its normal shift and from an unusual workstation.", "score": 15, "level": "warning", "badge": "anomaly", "stats": {}},
            {"id": "insider_records", "num": 2, "elapsed": "00:08", "title": "Unusual patient-record browsing", "detail": "The account opens records for patients with no treatment relationship.", "score": 25, "level": "high", "badge": None, "stats": {"records_accessed": 86}},
            {"id": "insider_search", "num": 3, "elapsed": "00:16", "title": "Sensitive-field search", "detail": "Repeated searches target demographic and insurance fields rather than clinical information.", "score": 20, "level": "high", "badge": None, "stats": {}},
            {"id": "insider_export", "num": 4, "elapsed": "00:24", "title": "Unauthorized report export", "detail": "A report containing patient identifiers is exported from the application.", "score": 30, "level": "critical", "badge": "policy violation", "stats": {"data_exported_gb": 0.8}},
            {"id": "insider_transfer", "num": 5, "elapsed": "00:31", "title": "External upload attempt", "detail": "The DLP monitor blocks an upload to an unapproved external destination.", "score": 20, "level": "critical", "badge": None, "stats": {"outbound_ip": "203.0.113.77"}},
        ],
        "recommendations": [
            "Suspend the account pending manager and privacy review",
            "Revoke active sessions and preserve access history",
            "Determine which patients and fields were viewed or exported",
            "Review DLP controls and block the destination if required",
            "Interview the account owner through the approved HR process",
            "Document the event for privacy and compliance assessment",
        ],
    },
    "phishing_compromise": {
        "label": "Phishing-led account compromise",
        "description": "A deceptive message leads to credential use from an unfamiliar device.",
        "incident": {"account": "PHARMACY_ADMIN", "source_ip": "192.0.2.45", "outbound_ip": "198.51.100.61", "hospital": INCIDENT["hospital"]},
        "stages": [
            {"id": "phish_delivery", "num": 1, "elapsed": "00:00", "title": "Suspicious message reported", "detail": "A staff member reports a message imitating an internal password-reset notification.", "score": 10, "level": "warning", "badge": "user reported", "stats": {}},
            {"id": "phish_login", "num": 2, "elapsed": "00:09", "title": "Credential use from new device", "detail": "The account signs in from a device and location not previously associated with the user.", "score": 25, "level": "high", "badge": "first compromise", "stats": {}},
            {"id": "phish_mailbox", "num": 3, "elapsed": "00:17", "title": "Mailbox rule created", "detail": "A forwarding rule is created to hide future security notifications from the user.", "score": 25, "level": "high", "badge": None, "stats": {}},
            {"id": "phish_privilege", "num": 4, "elapsed": "00:25", "title": "Privileged application access", "detail": "The compromised account attempts to access pharmacy administration functions.", "score": 25, "level": "critical", "badge": "privilege risk", "stats": {}},
            {"id": "phish_blocked", "num": 5, "elapsed": "00:33", "title": "Suspicious session blocked", "detail": "Conditional-access policy blocks the session and raises an analyst alert.", "score": 15, "level": "critical", "badge": "contained", "stats": {}},
        ],
        "recommendations": [
            "Reset the account password and revoke all active sessions",
            "Remove unauthorized mailbox rules and inspect recent messages",
            "Check MFA registration and enforce phishing-resistant MFA",
            "Review privileged actions performed by the account",
            "Search for similar messages across the organization",
            "Preserve the reported message and authentication evidence",
        ],
    },
}


def get_scenarios():
    return [{"id": key, "label": value["label"], "description": value["description"]}
            for key, value in SCENARIOS.items()]

# ---------- Access logs (correlated across systems) ----------
def get_access_log():
    return [
        {"time": "08:55:25", "source": "EHR Platform", "event": "Login success",
         "detail": f"Routine login — {INCIDENT['account']} — internal network"},
        {"time": "08:55:27", "source": "Firewall", "event": "Failed login ×38",
         "detail": f"38 failed auth attempts against {INCIDENT['account']} from {INCIDENT['source_ip']}"},
        {"time": "08:55:30", "source": "Firewall", "event": "Login success (external)",
         "detail": f"Auth succeeded on attempt 39 from {INCIDENT['source_ip']} — never seen on this account"},
        {"time": "08:55:38", "source": "EHR Platform", "event": "Bulk record access",
         "detail": "14,820 patient records queried in a single session — baseline is ~40/day"},
        {"time": "08:55:42", "source": "EHR Platform", "event": "Export job started",
         "detail": "6.4 GB EHR export job initiated by admin session"},
        {"time": "08:55:48", "source": "Config/Identity", "event": "Config file access",
         "detail": "Access to network/server configuration files outside normal admin workflow"},
        {"time": "08:55:52", "source": "DLP", "event": "Archive created",
         "detail": "Compressed archive bundling exported data created on export host"},
        {"time": "08:56:01", "source": "DLP", "event": "Outbound transfer flagged",
         "detail": f"Large transfer to {INCIDENT['outbound_ip']} — non-hospital ASN, flagged by DLP"},
    ]


# ---------- Knowledge base ----------
KNOWLEDGE_BASE = [
    {"tag": "HIPAA", "title": "HIPAA Breach Notification Rule",
     "snippet": "Covered entities must notify affected individuals within 60 days of discovering a "
                "breach of unsecured PHI affecting 500+ people; HHS and media notification may also apply."},
    {"tag": "Exfiltration", "title": "EHR Data Exfiltration Pattern",
     "snippet": "A spike in patient-record queries followed by a large export and an outbound transfer "
                "to an unrecognized IP is a classic exfiltration signature, distinct from clinical access."},
    {"tag": "Brute force", "title": "Credential Brute-Force Detection",
     "snippet": "A burst of failed logins immediately followed by success from a new IP/geolocation "
                "indicates likely credential compromise, especially on privileged accounts."},
    {"tag": "MFA", "title": "MFA as a Compensating Control",
     "snippet": "Enforcing MFA on admin and clinical accounts significantly reduces brute-force and "
                "credential-stuffing success even when a password is already compromised."},
    {"tag": "Containment", "title": "Incident Containment Checklist",
     "snippet": "Disable compromised accounts, revoke active sessions, isolate affected hosts, and "
                "block malicious IPs at the firewall as immediate containment steps."},
    {"tag": "Forensics", "title": "Evidence Preservation",
     "snippet": "Preserve logs, exported archives, and system images before remediation to support "
                "forensic investigation and any regulatory reporting."},
]


# ---------- Incident report ----------
def generate_incident_report():
    now = datetime.datetime.now()
    incident_id = f"INC-{now.year}-{now.month:02d}{now.day:02d}-{random.randint(100, 999)}"

    lines = [
        f"# Incident Report — {incident_id}",
        "",
        f"**Hospital:** {INCIDENT['hospital']}  ",
        f"**Account:** {INCIDENT['account']}  ",
        f"**Source IP:** {INCIDENT['source_ip']}  ",
        f"**Outbound IP:** {INCIDENT['outbound_ip']}  ",
        "**Severity:** CRITICAL  ",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "A brute-forced admin credential was used to log in from an external IP never seen on this "
        "account, followed by bulk access to patient records, a large EHR export, access to "
        "configuration files, and an outbound transfer of an archived file to an external host. "
        "This matches a data-exfiltration kill chain, not routine clinical activity.",
        "",
        "## Attack chain",
    ]
    for stage in PIPELINE_STAGES:
        lines.append(f"{stage['num']}. **{stage['title']}** ({stage['elapsed']}) — {stage['detail']}")

    lines.append("")
    lines.append("## Recommended response")
    for rec in RECOMMENDATIONS:
        lines.append(f"- [ ] {rec}")
    lines.append("")

    return incident_id, "\n".join(lines)


def classify_risk(total_score: int) -> str:
    if total_score >= 70:
        return "CRITICAL"
    elif total_score >= 40:
        return "HIGH"
    elif total_score >= 15:
        return "MEDIUM"
    return "LOW"


def run_simulation(scenario_id="data_exfiltration"):
    scenario = SCENARIOS.get(scenario_id, SCENARIOS["data_exfiltration"])
    incident = scenario["incident"]
    stages = scenario["stages"]
    recommendations = scenario["recommendations"]
    cumulative_score = 0

    for stage in stages:
        time.sleep(random.uniform(1.2, 2.0))
        cumulative_score += stage["score"]
        risk_level = classify_risk(cumulative_score)

        yield {
            "type": "stage",
            "stage_id": stage["id"], "num": stage["num"], "elapsed": stage["elapsed"],
            "title": stage["title"], "detail": stage["detail"], "level": stage["level"],
            "badge": stage["badge"], "stats": stage["stats"],
            "cumulative_score": cumulative_score, "risk_level": risk_level,
            "timestamp": time.strftime("%H:%M:%S"),
        }

    time.sleep(1.0)
    final_risk = classify_risk(cumulative_score)
    yield {
        "type": "alert",
        "title": f"Suspected {scenario['label'].lower()}",
        "description": scenario["description"],
        "account": incident["account"], "source_ip": incident["source_ip"],
        "chain_length": len(stages), "time_to_detection_min": 41,
        "cumulative_score": cumulative_score, "risk_level": final_risk,
        "timestamp": time.strftime("%H:%M:%S"),
    }

    time.sleep(0.8)
    yield {"type": "recommendations", "risk_level": final_risk,
           "recommendations": recommendations, "timestamp": time.strftime("%H:%M:%S")}

    yield {"type": "done"}

    # ---------- Threat Analysis (MITRE ATT&CK-style mapping) ----------
THREAT_MAP = {
    "normal_activity": {"tactic": "—", "technique_id": "—", "technique": "Baseline activity", "severity": 0},
    "failed_logins": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force", "severity": 4},
    "unusual_login": {"tactic": "Initial Access", "technique_id": "T1078", "technique": "Valid Accounts", "severity": 7},
    "patient_access": {"tactic": "Collection", "technique_id": "T1213", "technique": "Data from Information Repositories", "severity": 6},
    "ehr_export": {"tactic": "Collection", "technique_id": "T1005", "technique": "Data from Local System", "severity": 7},
    "config_access": {"tactic": "Discovery", "technique_id": "T1082", "technique": "System Information Discovery", "severity": 5},
    "archive_created": {"tactic": "Collection", "technique_id": "T1560", "technique": "Archive Collected Data", "severity": 6},
    "outbound_transfer": {"tactic": "Exfiltration", "technique_id": "T1041", "technique": "Exfiltration Over C2 Channel", "severity": 9},
}


def get_threat_analysis():
    """Map each pipeline stage to a threat tactic/technique with severity."""
    rows = []
    for stage in PIPELINE_STAGES:
        mapping = THREAT_MAP.get(stage["id"], {})
        rows.append({
            "stage_title": stage["title"],
            "elapsed": stage["elapsed"],
            "tactic": mapping.get("tactic", "—"),
            "technique_id": mapping.get("technique_id", "—"),
            "technique": mapping.get("technique", "—"),
            "severity": mapping.get("severity", 0),
        })

    severities = [r["severity"] for r in rows if r["severity"] > 0]
    overall_score = round(sum(severities) / len(severities), 1) if severities else 0

    tactic_counts = {}
    for r in rows:
        if r["tactic"] != "—":
            tactic_counts[r["tactic"]] = tactic_counts.get(r["tactic"], 0) + 1

    return {
        "rows": rows,
        "overall_score": overall_score,
        "tactic_counts": tactic_counts,
    }


# ---------- Activity log analysis helpers ----------
def get_log_source_summary():
    """Count access-log entries per source system."""
    entries = get_access_log()
    counts = {}
    for e in entries:
        counts[e["source"]] = counts.get(e["source"], 0) + 1
    return counts