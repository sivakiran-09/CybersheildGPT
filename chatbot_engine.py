"""
CyberShield GPT - Chatbot Engine
Uses a local Ollama model (free, no API key, no internet needed).
"""

import requests
from detection_engine import INCIDENT, PIPELINE_STAGES, RECOMMENDATIONS
from knowledge_engine import search

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2"  # change if you pulled a different model

SYSTEM_PROMPT = """You are the CyberShield GPT security assistant, built into a hospital SOC
(Security Operations Center) dashboard. You help security analysts understand the current
incident, interpret the attack chain, and reason about response steps.

Ground your answers in the incident context and retrieved knowledge-base passages provided
below. If asked something outside that context, answer using general cybersecurity/HIPAA
knowledge, but be clear when you're doing so. Keep answers concise and practical."""


def build_incident_context():
    lines = [f"Current incident — account: {INCIDENT['account']}, "
             f"source IP: {INCIDENT['source_ip']}, hospital: {INCIDENT['hospital']}", ""]
    lines.append("Attack chain so far:")
    for stage in PIPELINE_STAGES:
        lines.append(f"- {stage['title']}: {stage['detail']}")
    lines.append("")
    lines.append("Recommended response actions:")
    for rec in RECOMMENDATIONS:
        lines.append(f"- {rec}")
    return "\n".join(lines)


def ask_chatbot(user_message, chat_history=None):
    chat_history = chat_history or []

    kb_results = search(user_message, top_k=3)
    kb_context = ""
    if kb_results:
        kb_context = "\n\nRelevant knowledge-base passages:\n" + "\n".join(
            f"[{r['source']}] {r['snippet']}" for r in kb_results
        )

    full_context = build_incident_context() + kb_context

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += chat_history
    messages.append({
        "role": "user",
        "content": f"Context:\n{full_context}\n\nQuestion: {user_message}"
    })

    response = requests.post(OLLAMA_URL, json={
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False
    })
    response.raise_for_status()
    return response.json()["message"]["content"]