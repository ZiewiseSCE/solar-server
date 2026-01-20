import json
import os
import secrets
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

# ===== CORS (Cloudtype FIX) =====
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "https://pathfinder.scenergy.co.kr",
        "https://www.scenergy.co.kr",
    ]}},
    supports_credentials=False,
    allow_headers=[
        "Content-Type",
        "X-ADMIN-KEY",
        "X-CLIENT-TOKEN",
        "X-CLIENT-FP",
    ],
    methods=["GET", "POST", "OPTIONS"],
)

@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")
    if origin in [
        "https://pathfinder.scenergy.co.kr",
        "https://www.scenergy.co.kr",
    ]:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type,X-ADMIN-KEY,X-CLIENT-TOKEN,X-CLIENT-FP"
        resp.headers["Vary"] = "Origin"
    return resp

@app.route("/api/<path:anything>", methods=["OPTIONS"])
def options_anything(anything):
    return make_response("", 204)

# ===== CONFIG =====
LICENSE_DB_PATH = "./licenses_db.json"
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
_lock = threading.Lock()

def _now():
    return datetime.now(timezone.utc)

def _load():
    if not os.path.exists(LICENSE_DB_PATH):
        return {"licenses": {}}
    with open(LICENSE_DB_PATH, "r") as f:
        return json.load(f)

def _save(db):
    with open(LICENSE_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

# ===== HEALTH =====
@app.get("/api/health")
def health():
    return jsonify(ok=True)

# ===== ADMIN =====
@app.get("/api/admin/licenses")
def admin_list():
    if request.headers.get("X-ADMIN-KEY") != ADMIN_API_KEY:
        return jsonify(ok=False), 401

    with _lock:
        db = _load()
    return jsonify(ok=True, licenses=db["licenses"])

@app.post("/api/admin/licenses")
def admin_issue():
    if request.headers.get("X-ADMIN-KEY") != ADMIN_API_KEY:
        return jsonify(ok=False), 401

    body = request.get_json() or {}
    token = body.get("token") or f"SCE-{secrets.token_urlsafe(8)}"
    expires = body.get("expires_at")

    with _lock:
        db = _load()
        db["licenses"][token] = {
            "expires_at": expires,
            "revoked": False,
            "bound_fp": "",
        }
        _save(db)

    return jsonify(ok=True, token=token)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
