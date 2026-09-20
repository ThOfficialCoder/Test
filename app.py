"""
INTENTIONALLY VULNERABLE demo app for testing security scanners (Snyk, CodeQL).
Never deploy this. Every key below is fake.
"""
import os
import sqlite3
from flask import Flask, request, escape
from werkzeug.utils import secure_filename

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
    # Fixed: escape user input before embedding in HTML
    return f"<h1>Hello {escape(name)}</h1>"


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return "Invalid file path", 400

    base_dir = os.path.realpath("files")
    requested_path = os.path.realpath(os.path.join(base_dir, safe_filename))

    # Ensure the requested path stays within the intended base directory
    if not (requested_path == base_dir or requested_path.startswith(base_dir + os.sep)):
        return "Invalid file path", 400

    with open(requested_path) as f:
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
    # Debug disabled to avoid exposing the interactive debugger
    app.run(debug=False)
