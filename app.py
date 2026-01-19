import os
import datetime
import json
import psycopg2
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates")
CORS(app, supports_credentials=True)

# ===== env =====
# NOTE: use SECRET_KEY if set, otherwise fall back to FLASK_SECRET_KEY (some deployments use this name)
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "dev-secret"

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required (Postgres)")

# ===== DB =====
def get_conn():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    # 관리자 자동 생성/동기화 (ADMIN_PW가 있을 때만)
    if ADMIN_PW:
        cur.execute("SELECT pw_hash FROM users WHERE id=%s", (ADMIN_ID,))
        row = cur.fetchone()
        pw_hash = generate_password_hash(ADMIN_PW)

        if row is None:
            cur.execute(
                "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s,%s,%s,%s)",
                (ADMIN_ID, pw_hash, "admin", datetime.datetime.utcnow().isoformat())
            )
        else:
            # 비밀번호 변경 시 자동 갱신
            cur.execute(
                "UPDATE users SET pw_hash=%s WHERE id=%s",
                (pw_hash, ADMIN_ID)
            )

        conn.commit()

    cur.close()
    conn.close()

init_db()

# ===== pages =====
@app.get("/")
def home():
    return render_template("index.html")

@app.post("/report")
def report():
    """
    Front sends a hidden form with:
      form_address, form_capacity, form_kepco, form_date, form_finance, form_ai
    report.html expects Jinja data.finance, data.ai_analysis etc.
    """
    address = request.form.get("address") or request.form.get("form_address") or ""
    capacity = request.form.get("capacity") or request.form.get("form_capacity") or ""
    kepco = request.form.get("kepco") or request.form.get("form_kepco") or ""
    date = request.form.get("date") or request.form.get("form_date") or datetime.datetime.utcnow().strftime("%Y-%m-%d")

    finance_raw = request.form.get("finance") or request.form.get("form_finance") or "{}"
    ai_raw = request.form.get("ai_analysis") or request.form.get("form_ai") or "{}"

    try:
        finance = json.loads(finance_raw) if finance_raw else {}
    except Exception:
        finance = {}
    try:
        ai_analysis = json.loads(ai_raw) if ai_raw else {}
    except Exception:
        ai_analysis = {}

    data = {
        "address": address,
        "capacity": capacity,
        "kepco": kepco,
        "date": date,
        "finance": finance or {},
        "ai_analysis": ai_analysis or {}
    }
    return render_template("report.html", data=data)

# ===== health =====
@app.get("/health")
def health():
    return "ok", 200

# ===== auth =====
@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "missing id/pw"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, pw_hash, role FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or not check_password_hash(row[1], pw):
        return jsonify({"ok": False, "msg": "invalid credentials"}), 401

    session["uid"] = row[0]
    session["role"] = row[2]
    return jsonify({"ok": True, "role": row[2], "user": row[0]})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

# ===== admin: create user =====
@app.post("/api/admin/users")
def create_user():
    if session.get("role") != "admin":
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    data = request.get_json(force=True, silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    role = (data.get("role") or "user").strip()

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "missing id/pw"}), 400

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE id=%s", (uid,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"ok": False, "msg": "exists"}), 400

    cur.execute(
        "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s,%s,%s,%s)",
        (uid, generate_password_hash(pw), role, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()

    cur.close()
    conn.close()
    return jsonify({"ok": True})
