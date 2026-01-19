import os
import datetime
import psycopg2
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===== env =====
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required (Postgres)")

# (권장) HTTPS에서 세션 쿠키 안정성
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

# ===== pages =====
@app.get("/")
def home():
    return render_template("index.html")

@app.get("/report.html")
def report_page():
    return render_template("report.html")

@app.get("/report")
def report_page2():
    return render_template("report.html")

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

    # 관리자 자동 생성/동기화
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

# ===== health =====
@app.get("/health")
def health():
    return "ok", 200

# ===== auth =====
@app.post("/api/auth/login")
def login():
    data = request.json or {}
    uid = data.get("id")
    pw = data.get("pw")

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
    return jsonify({"ok": True, "role": row[2]})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

# ===== admin: list users (FIX) =====
@app.get("/api/admin/users")
def list_users():
    if session.get("role") != "admin":
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    users = [{"id": r[0], "role": r[1], "created_at": r[2]} for r in rows]
    return jsonify({"ok": True, "users": users})

# ===== admin: create user =====
@app.post("/api/admin/users")
def create_user():
    if session.get("role") != "admin":
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    data = request.json or {}
    uid = data["id"]
    pw = data["pw"]
    role = data.get("role", "user")

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
