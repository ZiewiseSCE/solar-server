import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

from flask import Flask, request, jsonify
from flask_cors import CORS


# ------------------------------------------------------------
# App setup
# ------------------------------------------------------------
app = Flask(__name__)

def _cors_origins():
    v = (os.getenv("CORS_ORIGINS") or "").strip()
    if not v:
        # 운영에서는 CORS_ORIGINS를 꼭 지정 권장
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

# ------------------------------------------------------------
# ENV Keys
# ------------------------------------------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()

# ------------------------------------------------------------
# Database
# ------------------------------------------------------------
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

# ------------------------------------------------------------
# Base64url helpers
# ------------------------------------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

# ------------------------------------------------------------
# Admin session token (HMAC)
# ------------------------------------------------------------
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

        expected = hmac.new(
            ADMIN_API_KEY.encode("utf-8"),
            payload,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(sig, expected):
            return False

        ts_s, _nonce = payload.decode("utf-8").split(".", 1)
        ts = int(ts_s)

        # 7 days validity
        return (now_utc().timestamp() - ts) <= (7 * 24 * 3600)
    except Exception:
        return False

def require_admin() -> bool:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return verify_admin_session(token)
    return False

# ------------------------------------------------------------
# JSON helpers
# ------------------------------------------------------------
def json_ok(**kwargs):
    d = {"ok": True}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg, code=400, **kwargs):
    d = {"ok": False, "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

# ------------------------------------------------------------
# DB init & queries
# ------------------------------------------------------------
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

def find_license(token: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM licenses WHERE token=%s", (token,))
            return cur.fetchone()

def insert_license(token: str, note: str, created_at, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (token, note, created_at, expires_at, registered)
                VALUES (%s, %s, %s, %s, FALSE)
            """, (token, note, created_at, expires_at))
            conn.commit()

def delete_license(token: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM licenses WHERE token=%s", (token,))
            conn.commit()

def reset_license(token: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp=NULL, bound_at=NULL, registered=FALSE
                WHERE token=%s
            """, (token,))
            conn.commit()

def extend_license(token: str, new_expiry):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET expires_at=%s WHERE token=%s", (new_expiry, token))
            conn.commit()

def bind_license(token: str, fingerprint: str, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp=%s, bound_at=%s, expires_at=%s, registered=TRUE
                WHERE token=%s
            """, (fingerprint, now_utc(), expires_at, token))
            conn.commit()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
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
    return json_ok(items=get_all_licenses())

@app.route("/api/admin/license/create", methods=["POST"])
def admin_license_create():
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(silent=True) or {}
    days = int(data.get("days") or 30)
    note = (data.get("note") or "").strip()

    token = "LIC-" + secrets.token_urlsafe(18)
    created = now_utc()
    expires = created + timedelta(days=days)

    insert_license(token, note, created, expires)
    return json_ok(token=token, expires_at=expires.isoformat())

@app.route("/api/admin/license/delete", methods=["POST"])
def admin_license_delete():
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("token required", 400)

    delete_license(token)
    return json_ok(deleted=True)

@app.route("/api/admin/license/reset", methods=["POST"])
def admin_license_reset():
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("token required", 400)

    reset_license(token)
    return json_ok(reset=True)

@app.route("/api/admin/license/extend", methods=["POST"])
def admin_license_extend():
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    days = int(data.get("days") or 30)
    if not token:
        return json_bad("token required", 400)

    new_expiry = now_utc() + timedelta(days=days)
    extend_license(token, new_expiry)
    return json_ok(expires_at=new_expiry.isoformat())

@app.route("/api/license/activate", methods=["POST"])
def license_activate():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    fp = (data.get("fingerprint") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    row = find_license(token)
    if not row:
        return json_bad("invalid token", 404)

    # 이미 바인딩된 토큰인데 다른 fingerprint이면 차단
    if row.get("registered") and (row.get("bound_fp") or "") != fp:
        return json_bad("token already bound to another device", 409)

    expires_at = row.get("expires_at") or (now_utc() + timedelta(days=30))
    bind_license(token, fp, expires_at)

    return json_ok(token=token, expires_at=expires_at.isoformat())

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(
        ts=now_utc().isoformat(),
        admin_enabled=bool(ADMIN_API_KEY),
        vworld_key=bool(PUBLIC_VWORLD_KEY),
        kepco_key=bool(PUBLIC_KEPCO_KEY),
        gemini_key=bool(GEMINI_API_KEY),
        law_api_id=bool(LAW_API_ID),
    )

# ------------------------------------------------------------
# Ensure table exists even under gunicorn
# ------------------------------------------------------------
init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
