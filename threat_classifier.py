"""
CyberShield GPT - Threat Classifier
Takes free-text log/event input from the user and uses the local
Ollama LLM to classify it: attack type, tactic, severity, and
recommended response — generated dynamically, not pre-scripted.
"""

import json
import re
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "gemma4:latest"  # match whatever you're using in chatbot_engine.py
MODEL_TIMEOUT_SECONDS = 8

CLASSIFIER_SYSTEM_PROMPT = """You are a cybersecurity threat classification engine embedded in a
hospital SOC dashboard. Given a raw log line, event description, or user-reported activity,
analyze it and respond with ONLY a JSON object (no other text, no markdown fences) in this exact
shape:

{
  "is_suspicious": true or false,
  "attack_type": "short name of the attack pattern, or 'None detected' if benign",
  "mitre_tactic": "closest MITRE ATT&CK tactic name, or '-' if not applicable",
  "severity": integer from 0 to 10,
  "confidence": "Low", "Medium", or "High",
  "explanation": "1-2 sentence explanation of why this is or isn't suspicious",
  "recommended_actions": ["action 1", "action 2", "action 3"]
}

Be specific and grounded in the input given. Do not invent details not implied by the input."""


def _extract_json(text):
    """Best-effort extraction of a JSON object from the model's raw text output."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _local_classification(user_input):
    text = user_input.lower()
    indicators = []

    patterns = [
        (r"failed login|brute.?force|credential stuffing|repeated login", "Credential brute force", "Credential Access", 7),
        (r"phish|suspicious email|password reset|malicious link", "Phishing", "Initial Access", 7),
        (r"ransomware|encrypted files|file encryption|ransom note", "Ransomware", "Impact", 9),
        (r"patient records|ehr|medical records|phi", "Patient-data access", "Collection", 6),
        (r"export|download|exfiltrat|outbound transfer|external upload", "Data exfiltration", "Exfiltration", 8),
        (r"unusual ip|external ip|new device|after.?hours|outside normal", "Anomalous account activity", "Initial Access", 6),
        (r"config(uration)? file|privilege escalation|admin access", "Unauthorized privileged access", "Privilege Escalation", 7),
    ]

    for pattern, attack_type, tactic, severity in patterns:
        if re.search(pattern, text):
            indicators.append((attack_type, tactic, severity))

    if not indicators:
        return None

    attack_type, tactic, severity = max(indicators, key=lambda item: item[2])
    if len(indicators) >= 2:
        severity = min(10, severity + 1)

    names = ", ".join(item[0] for item in indicators[:3])
    return {
        "is_suspicious": True,
        "attack_type": attack_type,
        "mitre_tactic": tactic,
        "severity": severity,
        "confidence": "High" if len(indicators) >= 2 else "Medium",
        "explanation": f"The event contains indicators of {names.lower()}. Multiple security-relevant behaviors were detected in the supplied text.",
        "recommended_actions": [
            "Validate the event against authentication and endpoint logs",
            "Contain the affected account or device if the activity is confirmed",
            "Preserve relevant logs and investigate the timeline",
        ],
    }


def classify_threat(user_input):
    if not user_input.strip():
        return {"error": "No input provided."}

    local_result = _local_classification(user_input)
    if local_result is not None:
        return local_result

    messages = [
        {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this event:\n\n{user_input}"},
    ]

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL_NAME,
            "messages": messages,
            "stream": False,
        }, timeout=MODEL_TIMEOUT_SECONDS)
        response.raise_for_status()
        raw_text = response.json()["message"]["content"]
    except requests.RequestException:
        return {
            "is_suspicious": False,
            "attack_type": "Unable to complete AI analysis",
            "mitre_tactic": "-",
            "severity": 0,
            "confidence": "Low",
            "explanation": "The local model did not respond within 8 seconds. Add clearer security indicators or start Ollama and try again.",
            "recommended_actions": [
                "Check that Ollama is running with the configured model",
                "Review the event manually against authentication and endpoint logs",
            ],
        }

    parsed = _extract_json(raw_text)
    if parsed is None:
        return {
            "error": "Could not parse model output as JSON.",
            "raw_output": raw_text,
        }

    return parsed