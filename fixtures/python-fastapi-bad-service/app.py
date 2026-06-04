import subprocess

import requests
import yaml
from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/users/{user_id}")
async def read_user(user_id: str, q: str, request: Request):
    body = await request.body()
    requests.get(f"https://profiles.internal/users/{user_id}")
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    yaml.load(body)
    subprocess.run("lookup " + q, shell=True)
    return {"ok": True}
