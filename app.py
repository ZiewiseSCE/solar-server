import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)

def _cors_origins():
    v = (os.getenv("CORS_ORIGINS") or "").strip()
    if not v:
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

# ---------------- ENV ----------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

# --------- Preflight: force 200 for /api/* ----------
@app.before_request
def _handle_preflight():
    if request.method == "OPTIONS" and request.path.startswith("/api/"):
        # 반드시 2xx로 끝내야 브라우저가 통과시킴
        return make_response("", 200)

# ---------------- helpers ----------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def sign_admin_session() -> str:
    if not ADMIN_API_KEY:
        raise RuntimeError("ADMIN_API_KEY not set")
    ts = int(now_utc().timestamp())
    nonce = secrets.token_hex(16)
    payload = f"{ts}.{nonce}".encode("utf-8")
    sig = hmac.new(ADMIN_API_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(sig)}"

def verify_admin_session(token: str) -> bool:
    if not ADMIN_API_KEY:
        return False
    try:
        p_b64, s_b64 = token.split(".", 1)
        payload = _b64urldecode(p_b64)
        sig = _b64urldecode(s_b64)
        expected = hmac.new(ADMIN_API_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
        ts_s, _nonce = payload.decode("utf-8").split(".", 1)
        ts = int(ts_s)
        return (now_utc().timestamp() - ts) <= (7 * 24 * 3600)
    except Exception:
        return False

def require_admin():
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return verify_admin_session(token)
    return False

def json_ok(**kwargs):
    d = {"ok": True}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg, code=400, **kwargs):
    d = {"ok": False, "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

# ---------------- DB ----------------
def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    token TEXT PRIMARY KEY,
                    note TEXT,
                    created_at TIMESTAMPTZ,
                    expires_at TIMESTAMPTZ,
                    bound_at TIMESTAMPTZ,
                    bound_fp TEXT,
                    registered BOOLEAN DEFAULT FALSE
                )
            """)
            conn.commit()

def get_all_licenses():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
            return cur.fetchall()

def insert_license(token, note, created_at, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (token, note, created_at, expires_at, registered)
                VALUES (%s, %s, %s, %s, FALSE)
            """, (token, note, created_at, expires_at))
            conn.commit()

# ---------------- Routes ----------------
@app.route("/api/auth/whoami", methods=["GET"])
def whoami():
    # admin.html이 이걸로 상태 체크하니까 200으로 응답해주는 게 핵심
    # Authorization 있으면 admin 여부를 같이 알려줌
    is_admin = require_admin()
    return json_ok(
        admin_enabled=bool(ADMIN_API_KEY),
        is_admin=is_admin,
        ts=now_utc().isoformat(),
    )

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_API_KEY:
        return json_bad("admin disabled (ADMIN_API_KEY not set)", 503)

    data = request.get_json(silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if not k or k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)

    return json_ok(session_token=sign_admin_session())

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    try:
        return json_ok(items=get_all_licenses())
    except Exception as e:
        # Cloudtype 로그에서 원인 보이게
        print("[ERROR] /api/admin/licenses:", repr(e))
        return json_bad("internal error (check server log)", 500)

@app.route("/api/admin/license/create", methods=["POST"])
def admin_license_create():
    if not require_admin():
        return json_bad("unauthorized", 401)

    try:
        data = request.get_json(silent=True) or {}
        days = int(data.get("days") or 30)
        note = (data.get("note") or "").strip()

        token = "LIC-" + secrets.token_urlsafe(18)
        created = now_utc()
        expires = created + timedelta(days=days)

        insert_license(token, note, created, expires)
        return json_ok(token=token, expires_at=expires.isoformat())

    except Exception as e:
        print("[ERROR] /api/admin/license/create:", repr(e))
        return json_bad("internal error (check server log)", 500)

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(
        ts=now_utc().isoformat(),
        admin_enabled=bool(ADMIN_API_KEY),
    )

# gunicorn에서도 실행되게
init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
