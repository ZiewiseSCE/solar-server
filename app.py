import os
import datetime
import psycopg2
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates")
CORS(app, supports_credentials=True)

# ===== env =====
# Cloudtype에서 SECRET_KEY 또는 FLASK_SECRET_KEY 둘 중 하나로 설정한 경우를 모두 지원
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "dev-secret"

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required (Postgres)")

# HTTPS 환경(Cloudtype)에서 세션 쿠키 안정성
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE","true").lower() == "true"),
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


@app.post("/report")
def report_submit():
    """index.html에서 hidden form으로 전달된 데이터를 받아 report.html을 렌더링합니다."""
    form = request.form or {}
    # finance / ai_analysis 는 JSON 문자열로 들어옴
    def _loads(v):
        try:
            import json as _json
            return _json.loads(v) if v else {}
        except Exception:
            return {}
    data = {
        "address": form.get("address", ""),
        "capacity": form.get("capacity", ""),
        "kepco_capacity": form.get("kepco_capacity", ""),
        "date": form.get("date", ""),
        "finance": _loads(form.get("finance")),
        "ai_analysis": _loads(form.get("ai_analysis")),
    }
    # report.html 템플릿이 기대하는 키를 최대한 맞춰줌
    return render_template("report.html", data=data)

# ===== DB =====
def get_conn():
    # DATABASE_URL에 특수문자 포함 시 URL 인코딩이 필요합니다.
    # (예: ! -> %21, @ -> %40, # -> %23)
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

    # 관리자 자동 생성/동기화 (ADMIN_PW가 설정된 경우에만)
    if ADMIN_PW:
        cur.execute("SELECT id FROM users WHERE id=%s", (ADMIN_ID,))
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
                "UPDATE users SET pw_hash=%s, role='admin' WHERE id=%s",
                (pw_hash, ADMIN_ID)
            )

        conn.commit()

    cur.close()
    conn.close()

# gunicorn 워커 시작 시점에 1회 초기화
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

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "id/pw required"}), 400

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
    return jsonify({"ok": True, "status": "OK", "role": row[2], "user": row[0]})
@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

# ===== admin: list users =====
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
    uid = data.get("id")
    pw = data.get("pw")
    role = data.get("role", "user")

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "id/pw required"}), 400

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

# ===== admin: delete user =====
@app.delete("/api/admin/users/<uid>")
def delete_user(uid):
    if session.get("role") != "admin":
        return jsonify({"ok": False, "msg": "forbidden"}), 403

    # 자기 자신(관리자) 삭제 방지
    if uid == ADMIN_ID:
        return jsonify({"ok": False, "msg": "cannot delete admin"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({"ok": False, "msg": "not found"}), 404
    return jsonify({"ok": True})
