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


# ------------------------------------------------------------
# App setup
# ------------------------------------------------------------
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

# Preflight: /api/* OPTIONS는 무조건 200
@app.before_request
def _preflight_ok():
    if request.method == "OPTIONS" and request.path.startswith("/api/"):
        return make_response("", 200)

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

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
# base64url + HMAC admin session
# ------------------------------------------------------------
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

def require_admin() -> bool:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return verify_admin_session(auth.split(" ", 1)[1].strip())
    return False

# ------------------------------------------------------------
# DB init + queries
# ------------------------------------------------------------
def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    token TEXT PRIMARY KEY,
                    note TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    bound_at TIMESTAMPTZ,
                    bound_fp TEXT,
                    registered BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            conn.commit()

def db_diag():
    # “DB는 붙어야 한다” 요구를 확인할 수 있게 실제 접속 DB를 보여줌
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            dbname = cur.fetchone()[0]
            cur.execute("SELECT inet_server_addr()::text, inet_server_port()")
            host, port = cur.fetchone()
            cur.execute("SELECT to_regclass('public.licenses') IS NOT NULL")
            table_exists = bool(cur.fetchone()[0])
            count = None
            if table_exists:
                cur.execute("SELECT COUNT(*) FROM licenses")
                count = int(cur.fetchone()[0])
            return {
                "db_ok": True,
                "current_database": dbname,
                "server_addr": host,
                "server_port": port,
                "licenses_table_exists": table_exists,
                "licenses_count": count,
            }

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

def delete_license(token):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM licenses WHERE token=%s", (token,))
            conn.commit()
            return cur.rowcount

def reset_license(token):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp=NULL, bound_at=NULL, registered=FALSE
                WHERE token=%s
            """, (token,))
            conn.commit()
            return cur.rowcount

def extend_license(token, new_expiry):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET expires_at=%s
                WHERE token=%s
            """, (new_expiry, token))
            conn.commit()
            return cur.rowcount

# ------------------------------------------------------------
# Routes required by admin.html
# ------------------------------------------------------------
@app.route("/api/auth/whoami", methods=["GET"])
def whoami():
    # admin.html 상태 체크용: 항상 200
    return json_ok(
        ts=now_utc().isoformat(),
        admin_enabled=bool(ADMIN_API_KEY),
        is_admin=require_admin()
    )

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_API_KEY:
        return json_bad("admin disabled (ADMIN_API_KEY not set)", 503)
    data = request.get_json(silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)
    return json_ok(session_token=sign_admin_session())

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    try:
        diag = db_diag()
        if not diag["licenses_table_exists"]:
            return json_bad("licenses table missing", 500, diag=diag)
        return json_ok(items=get_all_licenses(), diag=diag)
    except Exception as e:
        err = repr(e)
        print("[ERROR] /api/admin/licenses:", err)
        return json_bad("internal error", 500, error=err)

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
        err = repr(e)
        print("[ERROR] /api/admin/license/create:", err)
        return json_bad("internal error", 500, error=err)

@app.route("/api/admin/license/delete", methods=["POST"])
def admin_license_delete():
    if not require_admin():
        return json_bad("unauthorized", 401)
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        if not token:
            return json_bad("token required", 400)
        n = delete_license(token)
        return json_ok(deleted=(n > 0))
    except Exception as e:
        err = repr(e)
        print("[ERROR] /api/admin/license/delete:", err)
        return json_bad("internal error", 500, error=err)

@app.route("/api/admin/license/reset", methods=["POST"])
def admin_license_reset():
    if not require_admin():
        return json_bad("unauthorized", 401)
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        if not token:
            return json_bad("token required", 400)
        n = reset_license(token)
        return json_ok(reset=(n > 0))
    except Exception as e:
        err = repr(e)
        print("[ERROR] /api/admin/license/reset:", err)
        return json_bad("internal error", 500, error=err)

@app.route("/api/admin/license/extend", methods=["POST"])
def admin_license_extend():
    if not require_admin():
        return json_bad("unauthorized", 401)
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        days = int(data.get("days") or 30)
        if not token:
            return json_bad("token required", 400)
        new_expiry = now_utc() + timedelta(days=days)
        n = extend_license(token, new_expiry)
        return json_ok(expires_at=new_expiry.isoformat(), extended=(n > 0))
    except Exception as e:
        err = repr(e)
        print("[ERROR] /api/admin/license/extend:", err)
        return json_bad("internal error", 500, error=err)

# 진단용 (운영 중에도 문제 확인 쉬움)
@app.route("/api/diag", methods=["GET"])
def diag():
    try:
        return json_ok(diag=db_diag(), ts=now_utc().isoformat())
    except Exception as e:
        err = repr(e)
        print("[ERROR] /api/diag:", err)
        return json_bad("db diag failed", 500, error=err)

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(ts=now_utc().isoformat())

# ------------------------------------------------------------
# Ensure DB table exists under gunicorn too
# ------------------------------------------------------------
init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
