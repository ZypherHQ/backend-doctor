import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


class Database:
    def execute(self, sql, params):
        return {"sql": sql, "params": params}


db = Database()


@app.get("/users/<int:user_id>")
def show_user(user_id: int):
    include_profile = request.args.get("include_profile", "false")
    page = request.args.get("page", 1, type=int)
    result = db.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    profile = requests.get(f"https://profiles.internal/users/{user_id}", timeout=(2, 5))
    return jsonify(
        {
            "query": result,
            "include_profile": include_profile == "true",
            "page": page,
            "profile_status": profile.status_code,
        }
    )


@app.post("/users")
def create_user():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    db.execute("INSERT INTO users (name) VALUES (%s)", (name,))
    return jsonify({"name": name}), 201


@app.post("/jobs/import")
def import_job():
    config = yaml.safe_load(request.data or "{}") or {}
    username = str(config.get("username", "nobody"))
    completed = subprocess.run(["/usr/bin/id", username], check=False, capture_output=True, text=True)
    return jsonify({"username": username, "exit_code": completed.returncode})
