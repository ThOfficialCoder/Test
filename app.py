"""
INTENTIONALLY VULNERABLE demo app for testing security scanners (Snyk, CodeQL).
Never deploy this. Every key below is fake.
"""
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# FLAW 1: hardcoded secret (fake value)
API_KEY = "sk_test_FAKE1234567890abcdef"

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/user")
def find_user():
    name = request.args.get("name", "")
    # Fixed: use parameterized query to prevent SQL injection
    rows = get_db().execute(
        "SELECT id, name FROM users WHERE name = ?", (name,)
    ).fetchall()
    return str(rows)


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # FLAW 3: reflected cross-site scripting (unescaped user input in HTML)
    return f"<h1>Hello {name}</h1>"


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    # FLAW 4: path traversal (user controls the file path)
    with open(os.path.join("files", filename)) as f:
        return f.read()


@app.route("/safe_user")
def find_user_safe():
    name = request.args.get("name", "")
    # CLEAN TRAP: parameterized query, should NOT be flagged
    rows = get_db().execute(
        "SELECT id, name FROM users WHERE name = ?", (name,)
    ).fetchall()
    return str(rows)


if __name__ == "__main__":
    # FLAW 5: debug mode enabled
    app.run(debug=True)
