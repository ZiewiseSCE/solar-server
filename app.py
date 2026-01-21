import os
import secrets
from datetime import datetime, timezone, timedelta

import psycopg2
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# =================================================
# App
# =================================================
app = Flask(__name__)

# MUST set in Cloudtype env for production
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")

# Cross-site cookie for admin.html -> backend (different domain)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1").strip() != "0"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
)

def _cors_origins():
    v = os.getenv("CORS_ORIGINS", "").strip()
    if not v:
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    supports_credentials=True,
    allow_headers=["Content-Type", "X-CLIENT-TOKEN", "X-CLIENT-FP", "X-ADMIN-KEY"],
    methods=["GET", "POST", "OPTIONS"],
)

# =================================================
# DB
# =================================================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    if not dt:
        return None
    try:
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(dt)

def ensure_schema():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        token TEXT PRIMARY KEY,
                        expires_at TIMESTAMPTZ NOT NULL,
                        revoked BOOLEAN NOT NULL DEFAULT FALSE,
                        note TEXT NOT NULL DEFAULT '',
                        bound_fp TEXT NOT NULL DEFAULT '',
                        bound_at TIMESTAMPTZ NULL
                    );
                ''')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        pw_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                ''')
    finally:
        conn.close()

ensure_schema()

# =================================================
# Admin auth
# =================================================
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or os.getenv("ADMIN_KEY") or "").strip()

def is_admin_session():
    return session.get("role") == "admin"

def require_admin():
    # Allow either:
    # 1) admin session cookie (login) OR
    # 2) X-ADMIN-KEY header (curl / terminal)
    if request.method == "OPTIONS":
        return None
    if is_admin_session():
        return None
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "msg": "ADMIN_API_KEY not set"}), 500
    k = (request.headers.get("X-ADMIN-KEY") or "").strip()
    if not k or k != ADMIN_API_KEY:
        return jsonify({"ok": False, "msg": "admin auth required"}), 401
    return None

def gen_token(prefix="SCE-"):
    return prefix + secrets.token_hex(5).upper()

def end_of_day_utc_from_now(days: int) -> datetime:
    # Expire at 23:59:59 KST on target day, stored in UTC
    kst = timezone(timedelta(hours=9))
    now_kst = datetime.now(kst)
    target_date = now_kst.date() + timedelta(days=int(days))
    exp_kst = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59, tzinfo=kst)
    return exp_kst.astimezone(timezone.utc)

# =================================================
# Health
# =================================================
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

# =================================================
# Auth (admin users)
# =================================================
@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    if not uid or not pw:
        return jsonify({"ok": False, "msg": "id/pw required"}), 400

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pw_hash, role FROM users WHERE id=%s", (uid,))
            row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "msg": "invalid credentials"}), 401
        pw_hash, role = row
        if not check_password_hash(pw_hash, pw):
            return jsonify({"ok": False, "msg": "invalid credentials"}), 401

        session["uid"] = uid
        session["role"] = role
        return jsonify({"ok": True, "status": "OK", "user": uid, "role": role})
    finally:
        conn.close()

@app.route("/api/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return ("", 204)
    session.clear()
    return jsonify({"ok": True, "status": "OK"})

@app.route("/api/auth/whoami", methods=["GET"])
def whoami():
    return jsonify({
        "ok": True,
        "user": session.get("uid"),
        "role": session.get("role"),
        "logged_in": bool(session.get("uid")),
    })

@app.route("/api/admin/users", methods=["GET", "POST", "OPTIONS"])
def admin_users():
    if request.method == "OPTIONS":
        return ("", 204)
    guard = require_admin()
    if guard is not None:
        return guard

    if request.method == "GET":
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC LIMIT 500")
                rows = cur.fetchall() or []
            users = [{"id": r[0], "role": r[1], "created_at": iso(r[2])} for r in rows]
            return jsonify({"ok": True, "status": "OK", "users": users})
        finally:
            conn.close()

    data = request.get_json(force=True, silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    role = (data.get("role") or "user").strip()

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "id/pw required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"ok": False, "msg": "invalid role"}), 400

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    '''
                    INSERT INTO users(id, pw_hash, role)
                    VALUES (%s,%s,%s)
                    ON CONFLICT (id) DO UPDATE SET
                      pw_hash=EXCLUDED.pw_hash,
                      role=EXCLUDED.role
                    ''',
                    (uid, generate_password_hash(pw), role),
                )
        return jsonify({"ok": True, "status": "OK"})
    finally:
        conn.close()

# =================================================
# License verify / activate / auto
# =================================================
@app.route("/api/license/activate", methods=["POST", "OPTIONS"])
def activate_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()
    if not token or not fp:
        return jsonify({"ok": False, "msg": "token or fingerprint missing"}), 400

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT expires_at, revoked, bound_fp FROM licenses WHERE token=%s", (token,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"ok": False, "msg": "invalid license"}), 403

                expires_at, revoked, bound_fp = row
                if revoked:
                    return jsonify({"ok": False, "msg": "license revoked"}), 403
                if expires_at < now_utc():
                    return jsonify({"ok": False, "msg": "license expired"}), 403

                if not bound_fp:
                    cur.execute(
                        "UPDATE licenses SET bound_fp=%s, bound_at=%s WHERE token=%s",
                        (fp, now_utc(), token),
                    )
                else:
                    if bound_fp != fp:
                        return jsonify({"ok": False, "msg": "license bound to another device"}), 403

        return jsonify({"ok": True, "expires_at": iso(expires_at)})
    finally:
        conn.close()

@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return jsonify({"ok": False, "msg": "token or fingerprint missing"}), 400

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT expires_at, revoked, bound_fp FROM licenses WHERE token=%s", (token,))
            row = cur.fetchone()

        if not row:
            return jsonify({"ok": False, "msg": "invalid license"}), 403

        expires_at, revoked, bound_fp = row
        if revoked:
            return jsonify({"ok": False, "msg": "license revoked"}), 403
        if expires_at < now_utc():
            return jsonify({"ok": False, "msg": "license expired"}), 403

        if not bound_fp:
            return jsonify({"ok": False, "code": "NOT_ACTIVATED", "msg": "not activated"}), 200

        if bound_fp != fp:
            return jsonify({"ok": False, "msg": "license bound to another device"}), 403

        return jsonify({"ok": True, "expires_at": iso(expires_at)})
    finally:
        conn.close()

@app.route("/api/auth/auto", methods=["POST", "OPTIONS"])
def auto_verify():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()
    if not fp:
        return jsonify({"ok": False, "msg": "fingerprint missing"}), 400

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                '''
                SELECT token, expires_at, revoked
                FROM licenses
                WHERE bound_fp=%s
                ORDER BY expires_at DESC
                LIMIT 1
                ''',
                (fp,),
            )
            row = cur.fetchone()

        if not row:
            return jsonify({"ok": False, "code": "NO_BINDING", "msg": "no license bound"}), 200

        token, expires_at, revoked = row
        if revoked:
            return jsonify({"ok": False, "msg": "license revoked"}), 403
        if expires_at < now_utc():
            return jsonify({"ok": False, "msg": "license expired"}), 403

        masked = (token[:4] + "..." + token[-4:]) if token else ""
        return jsonify({"ok": True, "expires_at": iso(expires_at), "token_masked": masked})
    finally:
        conn.close()

# =================================================
# Admin: issue/list/revoke/reset
# =================================================
@app.route("/api/admin/licenses/issue", methods=["POST", "OPTIONS"])
def admin_issue_license():
    if request.method == "OPTIONS":
        return ("", 204)
    guard = require_admin()
    if guard is not None:
        return guard

    data = request.get_json(force=True, silent=True) or {}
    days = int(data.get("days") or 0)
    note = (data.get("note") or "").strip()

    allowed = {30, 60, 90, 180, 365}
    if days not in allowed:
        return jsonify({"ok": False, "msg": f"days must be one of {sorted(list(allowed))}"}), 400

    token = gen_token()
    exp = end_of_day_utc_from_now(days)

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    '''
                    INSERT INTO licenses(token, expires_at, revoked, note, bound_fp, bound_at)
                    VALUES (%s,%s,FALSE,%s,'',NULL)
                    ''',
                    (token, exp, note),
                )
        return jsonify({"ok": True, "token": token, "expires_at": iso(exp)})
    finally:
        conn.close()

@app.route("/api/admin/licenses", methods=["GET", "OPTIONS"])
def admin_list_licenses():
    if request.method == "OPTIONS":
        return ("", 204)
    guard = require_admin()
    if guard is not None:
        return guard

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                '''
                SELECT token, expires_at, revoked, note, bound_fp, bound_at
                FROM licenses
                ORDER BY expires_at DESC
                LIMIT 500
                '''
            )
            rows = cur.fetchall() or []
        items = []
        for token, expires_at, revoked, note, bound_fp, bound_at in rows:
            items.append({
                "token": token,
                "expires_at": iso(expires_at),
                "revoked": bool(revoked),
                "note": note or "",
                "bound": bool(bound_fp),
                "bound_at": iso(bound_at),
            })
        return jsonify({"ok": True, "count": len(items), "licenses": items})
    finally:
        conn.close()

@app.route("/api/admin/licenses/<token>/revoke", methods=["POST", "OPTIONS"])
def admin_revoke(token):
    if request.method == "OPTIONS":
        return ("", 204)
    guard = require_admin()
    if guard is not None:
        return guard

    token = (token or "").strip()
    if not token:
        return jsonify({"ok": False, "msg": "token missing"}), 400

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE licenses SET revoked=TRUE WHERE token=%s", (token,))
                if cur.rowcount == 0:
                    return jsonify({"ok": False, "msg": "not found"}), 404
        return jsonify({"ok": True})
    finally:
        conn.close()

@app.route("/api/admin/licenses/<token>/reset", methods=["POST", "OPTIONS"])
def admin_reset(token):
    if request.method == "OPTIONS":
        return ("", 204)
    guard = require_admin()
    if guard is not None:
        return guard

    token = (token or "").strip()
    if not token:
        return jsonify({"ok": False, "msg": "token missing"}), 400

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE licenses SET bound_fp='', bound_at=NULL WHERE token=%s", (token,))
                if cur.rowcount == 0:
                    return jsonify({"ok": False, "msg": "not found"}), 404
        return jsonify({"ok": True})
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
