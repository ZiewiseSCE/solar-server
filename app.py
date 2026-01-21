import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

def _cors_origins():
    v = os.getenv("CORS_ORIGINS", "").strip()
    if not v:
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    allow_headers=["Content-Type", "Authorization", "X-CLIENT-TOKEN", "X-CLIENT-FP"],
    methods=["GET", "POST", "OPTIONS"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
if not ADMIN_API_KEY:
    raise RuntimeError("ADMIN_API_KEY not set")

SECRET_KEY = (os.getenv("SECRET_KEY") or "").encode("utf-8")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set")

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def ensure_schema():
    ddl = """
    CREATE TABLE IF NOT EXISTS licenses (
        token TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        note TEXT
    );

    CREATE TABLE IF NOT EXISTS bindings (
        id BIGSERIAL PRIMARY KEY,
        token TEXT NOT NULL REFERENCES licenses(token) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bindings_fp ON bindings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_bindings_token ON bindings(token);
    """
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(ddl)
    finally:
        conn.close()

ensure_schema()

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_admin_session(ttl_hours: int = 8) -> str:
    exp = int((now_utc() + timedelta(hours=ttl_hours)).timestamp())
    nonce = secrets.token_urlsafe(12)
    payload = f"exp={exp}&nonce={nonce}".encode("utf-8")
    sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    return _b64url(payload) + "." + _b64url(sig)

def verify_admin_session(token: str) -> bool:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_dec(payload_b64)
        sig = _b64url_dec(sig_b64)
        expect = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return False
        parts = dict(x.split("=", 1) for x in payload.decode("utf-8").split("&"))
        exp = int(parts.get("exp", "0"))
        return int(now_utc().timestamp()) < exp
    except Exception:
        return False

def require_admin():
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        return False
    tok = auth.split(" ", 1)[1].strip()
    return verify_admin_session(tok)

def gen_license_token(prefix="SCE", nbytes=8) -> str:
    return f"{prefix}-" + secrets.token_hex(nbytes).upper()

def json_ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return jsonify(d)

def json_bad(msg, status=400, **kw):
    d = {"ok": False, "msg": msg}
    d.update(kw)
    return jsonify(d), status

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok()

@app.route("/api/config/public", methods=["GET"])
def public_config():
    return jsonify({
        "ok": True,
        "vworld_key": PUBLIC_VWORLD_KEY,
        "kepco_key": PUBLIC_KEPCO_KEY,
    })

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if not k or k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)
    return json_ok(session_token=sign_admin_session())

@app.route("/api/auth/whoami", methods=["GET", "OPTIONS"])
def whoami():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)
    return json_ok(role="admin")

@app.route("/api/admin/license/create", methods=["POST", "OPTIONS"])
def admin_license_create():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    days = int(data.get("days") or 30)
    if days not in (30, 60, 90, 180, 365) and not (1 <= days <= 3650):
        return json_bad("invalid days", 400)

    note = (data.get("note") or "").strip()[:500]
    token = gen_license_token()
    expires = now_utc() + timedelta(days=days)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO licenses(token, expires_at, note) VALUES(%s,%s,%s)",
                (token, expires, note),
            )
    finally:
        conn.close()

    return json_ok(token=token, expires_at=expires.isoformat(), days=days)

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, expires_at, created_at, note FROM licenses ORDER BY created_at DESC LIMIT 200"
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "items": [
            {
                "token": r[0],
                "expires_at": r[1].isoformat(),
                "created_at": r[2].isoformat(),
                "note": r[3] or "",
            } for r in rows
        ],
    })

@app.route("/api/license/activate", methods=["POST", "OPTIONS"])
def activate_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT expires_at FROM licenses WHERE token=%s", (token,))
            row = cur.fetchone()
            if not row:
                return json_bad("invalid token", 404)
            expires_at = row[0]
            if expires_at <= now_utc():
                return json_bad("expired token", 403, expires_at=expires_at.isoformat())

            cur.execute(
                "INSERT INTO bindings(token, fingerprint, expires_at) VALUES(%s,%s,%s)",
                (token, fp, expires_at),
            )
    finally:
        conn.close()

    return json_ok(expires_at=expires_at.isoformat())

@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT expires_at FROM bindings WHERE token=%s AND fingerprint=%s ORDER BY bound_at DESC LIMIT 1",
                (token, fp),
            )
            row = cur.fetchone()
            if not row:
                return json_bad("not bound", 403)
            expires_at = row[0]
            if expires_at <= now_utc():
                return json_bad("expired", 403, expires_at=expires_at.isoformat())
    finally:
        conn.close()

    return json_ok(expires_at=expires_at.isoformat())

@app.route("/api/auth/auto", methods=["POST", "OPTIONS"])
def auto_auth():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()
    if not fp:
        return json_bad("fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, expires_at FROM bindings WHERE fingerprint=%s ORDER BY bound_at DESC LIMIT 1",
                (fp,),
            )
            row = cur.fetchone()
            if not row:
                return json_bad("no binding", 403)
            token, expires_at = row
            if expires_at <= now_utc():
                return json_bad("expired", 403, expires_at=expires_at.isoformat())
    finally:
        conn.close()

    return json_ok(token=token, expires_at=expires_at.isoformat())
