from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import os

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Invalid input"}), 400

    username = data["username"]
    password = data["password"].encode()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password, row[0]):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"error": "Invalid input"}), 400

    pwd = data["password"].encode()
    hashed = bcrypt.hashpw(pwd, bcrypt.gensalt())

    return jsonify({"bcrypt": hashed.decode()})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
