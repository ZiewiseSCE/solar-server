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
    token = data.get("token") or request.headers.get("X-CLIENT-TOKEN")
    fp = data.get("fingerprint") or request.headers.get("X-CLIENT-FP")

    if not token or not fp:
        return jsonify({"ok": False, "error": "token or fingerprint missing"}), 400

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
        return jsonify({"ok": False, "error": "invalid license"}), 403

    expires_at, revoked, bound_fp = row

    if revoked:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "license revoked"}), 403

    if expires_at < now_utc():
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "license expired"}), 403

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
            return jsonify({"ok": False, "error": "license bound to another device"}), 403

    cur.close()
    conn.close()
    return jsonify({"ok": True})

# -------------------------------------------------
# Verify
# -------------------------------------------------
@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token") or request.headers.get("X-CLIENT-TOKEN")
    fp = data.get("fingerprint") or request.headers.get("X-CLIENT-FP")

    if not token or not fp:
        return jsonify({"ok": False}), 400

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
        return jsonify({"ok": False}), 403

    expires_at, revoked, bound_fp = row

    if revoked or expires_at < now_utc():
        return jsonify({"ok": False}), 403

    if bound_fp != fp:
        return jsonify({"ok": False}), 403

    return jsonify({"ok": True})
