"""
CyberShield GPT - Flask backend
Login, signup, SOC dashboard, access logs, real document-based
knowledge retrieval (TF-IDF), incident reports, AI chatbot, and
live event streaming.
"""

import json
import os
from functools import wraps
from flask import Flask, Response, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from threat_classifier import classify_threat
from detection_engine import (
    run_simulation, INCIDENT, get_access_log, generate_incident_report,
    get_threat_analysis, get_log_source_summary, get_scenarios, SCENARIOS
)
from knowledge_engine import (
    build_index, search, list_documents, has_documents, document_count, chunk_count
)
from chatbot_engine import ask_chatbot

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-secret-key"


USERS_FILE = "users.json"

# Index documents/ folder at startup so Knowledge Base is ready immediately
build_index()


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


# ---------- Auth ----------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        users = load_users()

        if not username or not password:
            error = "Username and password are required."
        elif username in users:
            error = "That username is already taken."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            users[username] = generate_password_hash(password)
            save_users(users)
            return redirect(url_for("login", signed_up="1"))

    return render_template("signup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    signed_up = request.args.get("signed_up")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()

        if username in users and check_password_hash(users[username], password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("index"))
        error = "Invalid username or password."

    return render_template("login.html", error=error, signed_up=signed_up)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Pages ----------

@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("username"),
                            active_page="dashboard", incident=INCIDENT,
                            scenarios=get_scenarios())


@app.route("/access-logs")
@login_required
def access_logs():
    entries = get_access_log()
    source_summary = get_log_source_summary()
    return render_template("access_logs.html", username=session.get("username"),
                            active_page="access_logs", entries=entries, incident=INCIDENT,
                            source_summary=source_summary)
@app.route("/threat-analysis")
@login_required
def threat_analysis():
    analysis = get_threat_analysis()
    return render_template("threat_analysis.html", username=session.get("username"),
                            active_page="threat_analysis", analysis=analysis, incident=INCIDENT)

@app.route("/knowledge-base")
@login_required
def knowledge_base():
    return render_template(
        "knowledge_base.html",
        username=session.get("username"),
        active_page="knowledge_base",
        doc_count=document_count(),
        chunk_total=chunk_count(),
        documents=list_documents(),
        has_docs=has_documents(),
    )


@app.route("/incident-report")
@login_required
def incident_report():
    incident_id, report_md = generate_incident_report()
    return render_template("incident_report.html", username=session.get("username"),
                            active_page="incident_report", incident_id=incident_id, report_md=report_md)


# ---------- APIs ----------

@app.route("/api/stream")
@login_required
def stream():
    scenario_id = request.args.get("scenario", "data_exfiltration")
    if scenario_id not in SCENARIOS:
        scenario_id = "data_exfiltration"

    def event_generator():
        for event in run_simulation(scenario_id):
            yield f"data: {json.dumps(event)}\n\n"
    return Response(event_generator(), mimetype="text/event-stream")


@app.route("/api/kb-search")
@login_required
def kb_search():
    query = request.args.get("q", "")
    results = search(query)
    return {"results": results, "has_documents": has_documents()}


@app.route("/api/kb-reindex", methods=["POST"])
@login_required
def kb_reindex():
    build_index()
    return {"status": "ok", "doc_count": document_count(), "chunk_total": chunk_count()}


@app.route("/api/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json()
    user_message = data.get("message", "")
    history = data.get("history", [])  # [{role, content}, ...]

    if not user_message.strip():
        return {"error": "Empty message"}, 400

    try:
        reply = ask_chatbot(user_message, history)
        return {"reply": reply}
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/threat-detector")
@login_required
def threat_detector():
    return render_template("threat_detector.html", username=session.get("username"),
                            active_page="threat_detector")


@app.route("/api/classify-threat", methods=["POST"])
@login_required
def api_classify_threat():
    data = request.get_json()
    user_input = data.get("input", "")
    try:
        result = classify_threat(user_input)
        return result
    except Exception as e:
        return {"error": str(e)}, 500


if __name__ == "__main__":
    app.run(debug=True, threaded=True, port=5000)