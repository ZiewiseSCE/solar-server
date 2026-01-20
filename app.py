import os
import uuid
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS

# -------------------------------------------------
# Flask App
# -------------------------------------------------
app = Flask(__name__)

# -------------------------------------------------
# Basic Config
# -------------------------------------------------
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")

# 세션 쿠키 설정 (프론트 분리 + Cloudtype 대응)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,     # HTTPS 필수
    SESSION_COOKIE_SAMESITE="None"  # cross-site 요청 허용
)

# -------------------------------------------------
# CORS Config
# -------------------------------------------------
cors_origins_env = os.getenv("CORS_ORIGINS", "").strip()
origins = []

if cors_origins_env:
    origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

# 안전 기본값 (개발/비상용)
if not origins:
    origins = ["https://pathfinder.scenergy.co.kr"]

CORS(
    app,
    resources={r"/api/*": {"origins": origins}},
    supports_credentials=True,
)

# -------------------------------------------------
# In-memory User Store (DEMO)
# -------------------------------------------------
USERS = {}  # {id: {id, username, password, created_at}}

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin1234")

# -------------------------------------------------
# Helper
# -------------------------------------------------
def is_admin():
    return session.get("role") == "admin"

# -------------------------------------------------
# 🔥 ROOT (Health Check 용) 🔥
# Cloudtype가 이거 못 받으면 서버를 죽임
# -------------------------------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "solar-server"}), 200

# -------------------------------------------------
# Health API (선택)
# -------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify({"ok": True}), 200

# -------------------------------------------------
# Auth
# -------------------------------------------------
@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    # Admin login
    if username == ADMIN_USER and password == ADMIN_PASS:
        session.clear()
        session["role"] = "admin"
        session["username"] = username
        session.permanent = True
        return jsonify({
            "ok": True,
            "status": "OK",
            "role": "admin"
        }), 200

    # Normal user login (optional)
    for u in USERS.values():
        if u["username"] == username and u["password"] == password:
            session.clear()
            session["role"] = "user"
            session["username"] = username
            session.permanent = True
            return jsonify({
                "ok": True,
                "status": "OK",
                "role": "user"
            }), 200

    return jsonify({"ok": False, "msg": "invalid credentials"}), 401


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True}), 200

# -------------------------------------------------
# Admin APIs
# -------------------------------------------------
@app.get("/api/admin/users")
def list_users():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    safe_users = []
    for u in USERS.values():
        safe_users.append({
            "id": u["id"],
            "username": u["username"],
            "created_at": u["created_at"]
        })

    return jsonify({
        "ok": True,
        "status": "OK",
        "users": safe_users
    }), 200


@app.post("/api/admin/users")
def create_user():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    for u in USERS.values():
        if u["username"] == username:
            return jsonify({"ok": False, "msg": "username exists"}), 409

    user_id = str(uuid.uuid4())
    USERS[user_id] = {
        "id": user_id,
        "username": username,
        "password": password,  # DEMO ONLY (운영 시 해시)
        "created_at": datetime.utcnow().isoformat()
    }

    return jsonify({"ok": True, "status": "OK"}), 201


@app.delete("/api/admin/users/<user_id>")
def delete_user(user_id):
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    if user_id not in USERS:
        return jsonify({"ok": False, "msg": "not found"}), 404

    USERS.pop(user_id, None)
    return jsonify({"ok": True, "status": "OK"}), 200

# -------------------------------------------------
# Session Lifetime
# -------------------------------------------------
app.permanent_session_lifetime = timedelta(days=7)

# -------------------------------------------------
# Local run (Cloudtype에서는 gunicorn이 실행)
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
