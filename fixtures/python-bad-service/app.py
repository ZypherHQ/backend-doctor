import subprocess
import yaml
import requests
from flask import Flask, request

app = Flask(__name__)


@app.post("/admin/users")
def create_user():
    user_id = request.args["id"]
    requests.get("https://profiles.internal/users/" + user_id)
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    yaml.load(request.data)
    subprocess.run("useradd " + request.form["name"], shell=True)
    return "ok"
