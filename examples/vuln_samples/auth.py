"""Intentionally vulnerable sample for llmscan demos. Do NOT use in production."""

import hashlib
import os
import pickle
import sqlite3
from flask import Flask, request, redirect

app = Flask(__name__)

# Hardcoded secret — secrets agent should catch this.
SECRET_KEY = "sk-live-AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "P@ssw0rd!"


@app.route("/login")
def login():
    user = request.args.get("user", "")
    pwd = request.args.get("pwd", "")
    conn = sqlite3.connect("app.db")
    # SQL injection — injection agent should catch this.
    q = "SELECT id FROM users WHERE name='%s' AND pwd='%s'" % (user, pwd)
    row = conn.execute(q).fetchone()
    # MD5 for password hashing — crypto agent should catch this.
    h = hashlib.md5(pwd.encode()).hexdigest()
    return {"ok": bool(row), "h": h}


@app.route("/run")
def run_cmd():
    name = request.args.get("name", "")
    # Command injection — injection agent.
    os.system("ping -c 1 " + name)
    return "ok"


@app.route("/load")
def load_obj():
    blob = request.files["b"].read()
    # Unsafe deserialization — deserialization agent.
    obj = pickle.loads(blob)
    return str(obj)


@app.route("/go")
def go():
    target = request.args.get("to", "/")
    # Open redirect / SSRF-ish — ssrf agent.
    return redirect(target)
