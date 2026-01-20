import os
import uuid
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS

app = Flask(__name__)

# ----------------------------
# 기본 설정
# ----------------------------
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")

# 세션(쿠키) 설정: GitHub Pages/서브도메인 등 "다른 도메인"에서 API 호출 시 쿠키가 붙도록
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,     # HTTPS 필수 (Cloudtype는 HTTPS라 OK)
    SESSION_COOKIE_SAMESITE="None", # 핵심: cross-site fetch에서 쿠키 허용
)

# ----------------------------
# CORS 설정 (credentials 포함)
# ----------------------------
cors_origins_env = os.getenv("CORS_ORIGINS", "").strip()
origins = []

if cors_origins_env:
    origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

# 개발/테스트 편의(원하면 제거 가능)
# origins가 비어있으면 모든 origin 허용하면 위험할 수 있어서,
# 최소한 localhost만 허용하도록 기본값 지정
if not origins:
    origins = ["http://localhost:5500", "http://127.0.0.1:5500"]

CORS(
    app,
    resources={r"/api/*": {"origins": origins}},
    supports_credentials=True,
)

# ----------------------------
# In-memory user store (예시)
# 실제 운영은 DB 권장
# ----------------------------
USERS = {}  # {user_id: {"id":..., "username":..., "password":..., "created_at":...}}

# admin 계정(예시): 환경변수로 관리 권장
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin1234")


def is_admin():
    return session.get("role") == "admin"


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()}), 200


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    # admin 로그인
    if username == ADMIN_USER and password == ADMIN_PASS:
        session.clear()
        session["role"] = "admin"
        session["username"] = username
        session.permanent = True

        # 프론트 호환성: ok + status 둘다 제공
        return jsonify({"ok": True, "status": "OK", "role": "admin"}), 200

    # 일반 유저 로그인(선택)
    # 운영에서 필요 없으면 막아도 됨
    for _, u in USERS.items():
        if u["username"] == username and u["password"] == password:
            session.clear()
            session["role"] = "user"
            session["username"] = username
            session.permanent = True
            return jsonify({"ok": True, "status": "OK", "role": "user"}), 200

    return jsonify({"ok": False, "msg": "invalid credentials"}), 401


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "status": "OK"}), 200


@app.get("/api/admin/users")
def admin_list_users():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    # 비밀번호는 내려주지 않는게 안전
    safe_users = []
    for u in USERS.values():
        safe_users.append(
            {
                "id": u["id"],
                "username": u["username"],
                "created_at": u["created_at"],
            }
        )

    return jsonify({"ok": True, "status": "OK", "users": safe_users}), 200


@app.post("/api/admin/users")
def admin_create_user():
    if not is_admin():
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "username/password required"}), 400

    # 중복 체크
    for u in USERS.values():
        if u["username"] == username:
            return jsonify({"ok": False, "msg": "username already exists"}), 409

    user_id = str(uuid.uuid4())
    USERS[user_id] = {
        "id": user_id,
        "username": username,
        "password": password,  # 데모용. 운영이면 해시로 저장.
        "created_at": datetime.utcnow().isoformat(),
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


# 세션 만료(원하면 조절)
app.permanent_session_lifetime = timedelta(days=7)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
