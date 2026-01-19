import os
import datetime
import psycopg2
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__, template_folder="templates")

# ===== CORS =====
# Cloudtype(backend) + GitHub Pages(front) 조합을 위해 credentials 허용
cors_origins = os.environ.get("CORS_ORIGINS", "*")
CORS(app, supports_credentials=True, origins=cors_origins if cors_origins != "*" else None)

# ===== env =====
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "dev-secret"

# 세션 쿠키 설정 (크로스사이트 환경 대응)
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "None")
app.config["SESSION_COOKIE_SECURE"] = (os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true")

# Token serializer (Bearer fallback)
serializer = URLSafeTimedSerializer(app.secret_key, salt="scenergy-auth")

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW")  # required for bootstrap

# ===== db helpers =====
def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """
    )
    conn.commit()

    # bootstrap admin
    if ADMIN_PW:
        cur.execute("SELECT id FROM users WHERE id=%s", (ADMIN_ID,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users(id, pw_hash, role) VALUES (%s, %s, 'admin')",
                (ADMIN_ID, generate_password_hash(ADMIN_PW)),
            )
            conn.commit()
    cur.close()
    conn.close()

init_db()

# ===== auth helpers =====
def issue_token(uid: str, role: str) -> str:
    return serializer.dumps({"uid": uid, "role": role})

def read_token(token: str, max_age_seconds: int = 60 * 60 * 24 * 7):
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        if isinstance(data, dict) and "uid" in data and "role" in data:
            return data
    except (BadSignature, SignatureExpired):
        return None
    except Exception:
        return None
    return None

def get_auth_context():
    # 1) session
    uid = session.get("uid")
    role = session.get("role")
    if uid and role:
        return {"uid": uid, "role": role, "via": "session"}

    # 2) bearer token
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        data = read_token(token)
        if data:
            return {"uid": data["uid"], "role": data["role"], "via": "token"}
    return None

def require_admin():
    ctx = get_auth_context()
    if not ctx or ctx.get("role") != "admin":
        return None
    return ctx

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
        return jsonify({"ok": False, "status": "ERR", "msg": "id/pw required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, pw_hash, role FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or not check_password_hash(row[1], pw):
        return jsonify({"ok": False, "status": "ERR", "msg": "invalid credentials"}), 401

    session["uid"] = row[0]
    session["role"] = row[2]

    token = issue_token(row[0], row[2])

    return jsonify({
        "ok": True,
        "status": "OK",
        "role": row[2],
        "user": row[0],
        "token": token
    })

@app.get("/api/auth/me")
def me():
    ctx = get_auth_context()
    if not ctx:
        return jsonify({"ok": False, "status": "ERR", "msg": "not logged in"}), 401
    return jsonify({"ok": True, "status": "OK", "user": ctx["uid"], "role": ctx["role"], "via": ctx["via"]})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "status": "OK"})

# ===== admin: list users =====
@app.get("/api/admin/users")
def list_users():
    if not require_admin():
        return jsonify({"ok": False, "status": "ERR", "msg": "forbidden"}), 403

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    users = [{"id": r[0], "role": r[1], "created_at": r[2].isoformat() if hasattr(r[2], "isoformat") else str(r[2])} for r in rows]
    return jsonify({"ok": True, "status": "OK", "users": users})

# ===== admin: create user =====
@app.post("/api/admin/users")
def create_user():
    if not require_admin():
        return jsonify({"ok": False, "status": "ERR", "msg": "forbidden"}), 403

    data = request.json or {}
    uid = data.get("id")
    pw = data.get("pw")
    role = data.get("role", "user")

    if not uid or not pw:
        return jsonify({"ok": False, "status": "ERR", "msg": "id/pw required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users(id, pw_hash, role) VALUES (%s, %s, %s)",
                    (uid, generate_password_hash(pw), role))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"ok": False, "status": "ERR", "msg": "already exists"}), 409
    finally:
        cur.close()
        conn.close()

    return jsonify({"ok": True, "status": "OK"})

# ===== admin: delete user =====
@app.delete("/api/admin/users/<uid>")
def delete_user(uid):
    if not require_admin():
        return jsonify({"ok": False, "status": "ERR", "msg": "forbidden"}), 403

    if uid == ADMIN_ID:
        return jsonify({"ok": False, "status": "ERR", "msg": "cannot delete admin"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({"ok": False, "status": "ERR", "msg": "not found"}), 404
    return jsonify({"ok": True, "status": "OK"})

# ===== report endpoints (keep compatibility) =====
@app.post("/report")
def report_post():
    # index.html form submit
    return render_template("report.html",
        address=request.form.get("address",""),
        capacity=request.form.get("capacity",""),
        kepco_capacity=request.form.get("kepco_capacity",""),
        date=request.form.get("date",""),
        finance=request.form.get("finance","{}"),
        ai_analysis=request.form.get("ai_analysis","{}"),
        ai_score=request.form.get("ai_score",""),
        land_price=request.form.get("land_price","")
    )
