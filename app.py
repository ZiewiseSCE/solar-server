import os
import psycopg2
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

# -------------------------------------------------
# App & CORS
# -------------------------------------------------
app = Flask(__name__)

def _cors_origins():
    v = os.getenv("CORS_ORIGINS", "").strip()
    if not v:
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    allow_headers=[
        "Content-Type",
        "X-CLIENT-TOKEN",
        "X-CLIENT-FP",
        "X-ADMIN-KEY",
    ],
    methods=["GET", "POST", "OPTIONS"],
)

# -------------------------------------------------
# DB
# -------------------------------------------------
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
    # psycopg2 returns aware datetime for timestamptz
    try:
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(dt)

# -------------------------------------------------
# Health
# -------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

# -------------------------------------------------
# License Activate
# -------------------------------------------------
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
    cur = conn.cursor()

    cur.execute(
        "SELECT expires_at, revoked, bound_fp FROM licenses WHERE token=%s",
        (token,),
    )
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "msg": "invalid license"}), 403

    expires_at, revoked, bound_fp = row

    if revoked:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "msg": "license revoked"}), 403

    if expires_at < now_utc():
        cur.close()
        conn.close()
        return jsonify({"ok": False, "msg": "license expired"}), 403

    # first bind
    if not bound_fp:
        cur.execute(
            "UPDATE licenses SET bound_fp=%s, bound_at=%s WHERE token=%s",
            (fp, now_utc(), token),
        )
        conn.commit()
    else:
        if bound_fp != fp:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "msg": "license bound to another device"}), 403

    cur.close()
    conn.close()
    return jsonify({"ok": True, "expires_at": iso(expires_at)})

# -------------------------------------------------
# Verify (GET+POST 지원)
#  - GET: 헤더 X-CLIENT-TOKEN / X-CLIENT-FP
#  - POST: JSON body {token,fingerprint} (또는 헤더)
# -------------------------------------------------
@app.route("/api/auth/verify", methods=["GET", "POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ("", 204)

    if request.method == "GET":
        token = (request.headers.get("X-CLIENT-TOKEN") or "").strip()
        fp = (request.headers.get("X-CLIENT-FP") or "").strip()
    else:
        data = request.get_json(force=True, silent=True) or {}
        token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
        fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return jsonify({"ok": False, "msg": "token or fingerprint missing"}), 400

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT expires_at, revoked, bound_fp FROM licenses WHERE token=%s",
        (token,),
    )
    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return jsonify({"ok": False, "msg": "invalid license"}), 403

    expires_at, revoked, bound_fp = row

    if revoked:
        return jsonify({"ok": False, "msg": "license revoked"}), 403

    if expires_at < now_utc():
        return jsonify({"ok": False, "msg": "license expired"}), 403

    # not activated yet (exists but not bound)
    if not bound_fp:
        return jsonify({"ok": False, "code": "NOT_ACTIVATED", "msg": "not activated"}), 200

    # bound mismatch
    if bound_fp != fp:
        return jsonify({"ok": False, "msg": "license bound to another device"}), 403

    return jsonify({"ok": True, "expires_at": iso(expires_at)})
