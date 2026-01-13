from flask import Flask, request, escape, jsonify
import hashlib
import subprocess
import re
import os

app = Flask(__name__)

# faire un env
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "default_password")

# faire un hash puissant SHA-256 
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # authentification securisee
    if username == "admin" and hash_password(password) == hash_password(ADMIN_PASSWORD):
        return jsonify({"message": "Logged in"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")

    # Validation de l'innput
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        # shell false
        result = subprocess.check_output(["ping", "-c", "1", host], text=True)
        return jsonify({"result": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Ping failed", "details": str(e)}), 500

@app.route("/hello")
def hello():
    name = request.args.get("name", "user")
    # XSS
    safe_name = escape(name)
    return f"<h1>Hello {safe_name}</h1>"

if __name__ == "__main__":
    app.run(debug=False)