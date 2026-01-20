import os
import uuid
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS

app = Flask(__name__)

# ----------------------------
# Secrets / Session cookie
# ----------------------------
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # HTTPS
    SESSION_COOKIE_SAMESITE="None",  # cross-site cookies
)

# ----------------------------
# CORS (must match frontend origin exactly)
# ----------------------------
cors_origins_env = (os.getenv("CORS_ORIGINS") or "").strip()
origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
if not origins:
    # 안전 기본값 (너는 pathfinder.scenergy.co.kr 쓰고 있으니 이걸 기본으로 둠)
    origins = ["https://pathfinder.scenergy.co.kr"]

CORS(
    app,
    resources={r"/api/*": {"origins": origins}},
    supports_credentials=True,
)

# ----------------------------
# Demo user store (RAM)
# ----------------------------
USERS = {}  # {id: {id, username, password, created_at}}

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin1234")

def is_admin():
    return session.get("role") == "admin"

# ----------------------------
# Root health (Cloudtype health check)
# ----------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "solar-server"}), 200

@app.get("/api/health")
def api_health():
    return jsonify({"ok": True}), 200

# ----------------------------
# Auth (accept BOTH: id/pw and username/password)
# ----------------------------
@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}

    # ✅ 호환: 프론트가 id/pw로 보내든 username/password로 보내든 다 받음
    username = (data.get("username") or data.get("id") or "").strip()
    password = (data.get("password") or data.get("pw") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    # Admin
    if username == ADMIN_USER and password == ADMIN_PASS:
        session.clear()
        session["role"] = "admin"
        session["username"] = username
        session.permanent = True
        return jsonify({"ok": True, "status": "OK", "role": "admin"}), 200

    # Normal user (optional)
    for u in USERS.values():
        if u["username"] == username and u["password"] == password:
            session.clear()
            session["role"] = "user"
            session["username"] = username
            session.permanent = True
            return jsonify({"ok": True, "status": "OK", "role": "user", "user": username}), 200

    return jsonify({"ok": False, "msg": "invalid credentials"}), 401

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "status": "OK"}), 200

# ----------------------------
# Admin users CRUD
# ----------------------------
@app.get("/api/admin/users")
def admin_list_users():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    safe_users = [
        {"id": u["id"], "username": u["username"], "created_at": u["created_at"]}
        for u in USERS.values()
    ]
    return jsonify({"ok": True, "status": "OK", "users": safe_users}), 200

@app.post("/api/admin/users")
def admin_create_user():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or data.get("id") or "").strip()
    password = (data.get("password") or data.get("pw") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    for u in USERS.values():
        if u["username"] == username:
            return jsonify({"ok": False, "msg": "username exists"}), 409

    user_id = str(uuid.uuid4())
    USERS[user_id] = {
        "id": user_id,
        "username": username,
        "password": password,  # demo only
        "created_at": datetime.utcnow().isoformat()
    }
    return jsonify({"ok": True, "status": "OK", "id": user_id}), 201

@app.delete("/api/admin/users/<user_id>")
def admin_delete_user(user_id):
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    if user_id not in USERS:
        return jsonify({"ok": False, "msg": "not found"}), 404

    USERS.pop(user_id, None)
    return jsonify({"ok": True, "status": "OK"}), 200

# ----------------------------
# Session lifetime
# ----------------------------
app.permanent_session_lifetime = timedelta(days=7)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
