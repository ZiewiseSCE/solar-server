import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# =========================
# App / Config
# =========================
app = Flask(__name__)

# Secret keys
app.secret_key = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "scenergy-secret"

serializer = URLSafeTimedSerializer(app.secret_key)

# =========================
# CORS (🔥 중요: None 절대 금지)
# =========================
raw_origins = os.getenv("CORS_ORIGINS", "*")

if not raw_origins or raw_origins.strip() == "*":
    cors_origins = "*"
else:
    cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

CORS(
    app,
    supports_credentials=True,
    origins=cors_origins
)

# =========================
# Health check
# =========================
@app.route("/health")
def health():
    return jsonify(ok=True, status="OK")

# =========================
# Auth
# =========================
ADMIN_ID = os.getenv("ADMIN_ID", "admin")
ADMIN_PW = os.getenv("ADMIN_PW", "1234")

def make_token(payload: dict, max_age=60 * 60 * 12):
    return serializer.dumps(payload)

def read_token(token: str):
    return serializer.loads(token, max_age=60 * 60 * 12)

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    uid = data.get("id")
    pw = data.get("pw")

    if not uid or not pw:
        return jsonify(ok=False, msg="Missing credentials"), 400

    # 관리자
    if uid == ADMIN_ID and pw == ADMIN_PW:
        token = make_token({"id": uid, "role": "admin"})
        session["user"] = uid
        session["role"] = "admin"
        return jsonify(
            ok=True,
            status="OK",
            role="admin",
            user=uid,
            token=token
        )

    # 일반 유저 (예시: DB 연동 전 임시 허용)
    token = make_token({"id": uid, "role": "user"})
    session["user"] = uid
    session["role"] = "user"
    return jsonify(
        ok=True,
        status="OK",
        role="user",
        user=uid,
        token=token
    )

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(ok=True, status="OK")

# =========================
# Admin APIs (임시 메모리)
# =========================
_USERS = [{"id": ADMIN_ID}]

def require_admin():
    role = session.get("role")
    if role != "admin":
        return False
    return True

@app.route("/api/admin/users", methods=["GET"])
def list_users():
    if not require_admin():
        return jsonify(ok=False, msg="Forbidden"), 403
    return jsonify(ok=True, status="OK", users=_USERS)

@app.route("/api/admin/users", methods=["POST"])
def add_user():
    if not require_admin():
        return jsonify(ok=False, msg="Forbidden"), 403
    data = request.get_json(force=True) or {}
    uid = data.get("id")
    if not uid:
        return jsonify(ok=False, msg="ID required"), 400
    _USERS.append({"id": uid})
    return jsonify(ok=True, status="OK")

@app.route("/api/admin/users/<uid>", methods=["DELETE"])
def remove_user(uid):
    if not require_admin():
        return jsonify(ok=False, msg="Forbidden"), 403
    global _USERS
    _USERS = [u for u in _USERS if u["id"] != uid]
    return jsonify(ok=True, status="OK")

# =========================
# Analyze Stub (프론트 대응)
# =========================
@app.route("/api/analyze/comprehensive", methods=["POST"])
def analyze():
    data = request.get_json(force=True) or {}
    return jsonify(
        status="OK",
        zoning="준공업지역",
        jimok="대",
        eco_grade="3등급",
        kepco_capacity="여유 있음",
        sun_hours=3.8,
        ai_score={"score": 62, "confidence": 78},
        price_estimate="약 3.2억",
        links={
            "eum": "https://www.eum.go.kr",
            "kepco": "https://online.kepco.co.kr",
            "heritage": "https://www.nie-ecobank.kr"
        },
        ai_comment="법적 리스크는 낮으나 수익성은 보수적 접근 필요"
    )

# =========================
# Run
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
