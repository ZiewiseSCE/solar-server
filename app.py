import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone
from io import BytesIO

from flask import Flask, request, jsonify, render_template_string, make_response, redirect
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

# ------------------------------------------------------------
# App setup
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Admin key: set ADMIN_API_KEY env var in production
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY")

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()

# PostgreSQL config
DB_CONFIG = {
    "dbname": "postgres",
    "user": "root",
    "password": "Ziewise123!@#",
    "host": "svc.sel3.cloudtype.app",
    "port": 30685,
}

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def _b64url(b):
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def sign_admin_session():
    ts = int(now_utc().timestamp())
    nonce = secrets.token_hex(16)
    payload = f"{ts}.{nonce}".encode("utf-8")
    sig = hmac.new(ADMIN_API_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(sig)}"

def verify_admin_session(token):
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

def require_admin():
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return verify_admin_session(token)
    return False

def json_ok(**kwargs):
    d = {"ok": True}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg, code=400, **kwargs):
    d = {"ok": False, "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

# DB interactions
def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    token TEXT PRIMARY KEY,
                    note TEXT,
                    created_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    bound_at TIMESTAMP,
                    bound_fp TEXT,
                    registered BOOLEAN
                )
            """)
            conn.commit()

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
            cur.execute("DELETE FROM licenses WHERE token = %s", (token,))
            conn.commit()

def reset_license(token):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses SET bound_fp = NULL, bound_at = NULL, registered = FALSE
                WHERE token = %s
            """, (token,))
            conn.commit()

def extend_license(token, new_expiry):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET expires_at = %s WHERE token = %s", (new_expiry, token))
            conn.commit()

def bind_license(token, fingerprint, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp = %s, bound_at = %s, registered = TRUE
                WHERE token = %s
            """, (fingerprint, now_utc(), token))
            conn.commit()

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(force=True, silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if not k or k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)
    return json_ok(session_token=sign_admin_session())

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    items = get_all_licenses()
    return json_ok(items=items)

@app.route("/api/admin/license/create", methods=["POST"])
def admin_license_create():
    if not require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
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
    token = (request.json.get("token") or "").strip()
    delete_license(token)
    return json_ok(deleted=True)

@app.route("/api/admin/license/reset", methods=["POST"])
def admin_license_reset():
    if not require_admin():
        return json_bad("unauthorized", 401)
    token = (request.json.get("token") or "").strip()
    reset_license(token)
    return json_ok(reset=True)

@app.route("/api/admin/license/extend", methods=["POST"])
def admin_license_extend():
    if not require_admin():
        return json_bad("unauthorized", 401)
    token = (request.json.get("token") or "").strip()
    days = int(request.json.get("days") or 30)
    new_expiry = now_utc() + timedelta(days=days)
    extend_license(token, new_expiry)
    return json_ok(expires_at=new_expiry.isoformat())

@app.route("/api/license/activate", methods=["POST"])
def license_activate():
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    fp = (data.get("fingerprint") or "").strip()
    if not token or not fp:
        return json_bad("token and fingerprint required", 400)
    expires_at = now_utc() + timedelta(days=30)
    bind_license(token, fp, expires_at)
    return json_ok(token=token, expires_at=expires_at.isoformat())

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(ts=now_utc().isoformat())

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT") or 5000), debug=True)
ChatGPT said:

Thought for 9s
Cloudtype 로그에 나온 부팅 실패 원인(100% 확실) 은 이 한 줄입니다:

ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY")
괄호가 안 닫혀서 SyntaxError → gunicorn worker가 바로 죽고 서버가 안 켜집니다.

그리고 지금 코드에는 Cloudtype/운영에서 꼭 고쳐야 할 것도 같이 있어요:

init_db()가 if __name__ == "__main__": 안에만 있어서 gunicorn으로 실행되면 테이블 생성이 절대 안 됨

DB 접속 정보를 코드에 하드코딩(비번 포함) → 운영에서 위험 + Cloudtype DB 변경 시 바로 깨짐
→ DATABASE_URL 환경변수로 통일하는 게 정석

아래는 위 문제들(부팅, init_db, DB_URL, CORS/Authorization 헤더)을 전부 반영한 수정된 app.py “전체본” 입니다. 그대로 교체해서 배포하면 됩니다.

import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify
from flask_cors import CORS

import psycopg2
from psycopg2.extras import RealDictCursor


# ------------------------------------------------------------
# App setup
# ------------------------------------------------------------
app = Flask(__name__)

def _cors_origins():
    v = (os.getenv("CORS_ORIGINS") or "").strip()
    if not v:
        # 운영에서는 가급적 CORS_ORIGINS를 지정하세요.
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
# Keys (env)
# ------------------------------------------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()

# ------------------------------------------------------------
# DB (use DATABASE_URL in production)
# ------------------------------------------------------------
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()

# (선택) DATABASE_URL이 없다면 기존 DB_CONFIG 방식도 지원
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),  # 운영에서는 env로 주입
    "host": os.getenv("DB_HOST", ""),
    "port": int(os.getenv("DB_PORT", "5432")),
}

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    # fallback
    if not DB_CONFIG["host"] or not DB_CONFIG["password"]:
        raise RuntimeError("DATABASE_URL not set and DB_HOST/DB_PASSWORD not set")
    return psycopg2.connect(**DB_CONFIG)

# ------------------------------------------------------------
# Utils: base64url + HMAC session token
# ------------------------------------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def sign_admin_session() -> str:
    if not ADMIN_API_KEY:
        # 운영에서 ADMIN_API_KEY가 없으면 관리자 기능을 쓰면 안 됨
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
        token = auth.split(" ", 1)[1].strip()
        return verify_admin_session(token)
    return False

def json_ok(**kwargs):
    d = {"ok": True}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg, code=400, **kwargs):
    d = {"ok": False, "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

# ------------------------------------------------------------
# DB interactions
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
            cur.execute("DELETE FROM licenses WHERE token = %s", (token,))
            conn.commit()

def reset_license(token):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp = NULL,
                    bound_at = NULL,
                    registered = FALSE
                WHERE token = %s
            """, (token,))
            conn.commit()

def extend_license(token, new_expiry):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET expires_at = %s WHERE token = %s", (new_expiry, token))
            conn.commit()

def bind_license(token, fingerprint, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET bound_fp = %s,
                    bound_at = %s,
                    expires_at = %s,
                    registered = TRUE
                WHERE token = %s
            """, (fingerprint, now_utc(), expires_at, token))
            conn.commit()

# ------------------------------------------------------------
# API
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
    items = get_all_licenses()
    return json_ok(items=items)

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

    # 이미 등록되어 있고 fingerprint가 다르면 차단(원하면 정책 바꿔줄게)
    if row.get("registered") and (row.get("bound_fp") or "") != fp:
        return json_bad("token already bound to another device", 409)

    # expires_at이 없으면 기본 30일 부여
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
    )

# ------------------------------------------------------------
# IMPORTANT: gunicorn에서도 테이블 생성되게 "import 시점"에 실행
# ------------------------------------------------------------
init_db()

if __name__ == "__main__":
    # 로컬 실행용
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
Cloudtype에 꼭 이렇게 환경변수 넣어줘 (운영 필수)
DATABASE_URL (Cloudtype Postgres에서 제공하는 그 값 그대로)
예: postgresql://user:pass@host:5432/dbname

ADMIN_API_KEY
예: Ziewise123!@# (원하는 값으로)

(선택) CORS_ORIGINS
예:
https://pathfinder.scenergy.co.kr,https://www.scenergy.co.kr

이 버전으로 해결되는 것
✅ SyntaxError로 부팅 실패 → 해결

✅ gunicorn 실행에서도 init_db() 실행 → 테이블 생성 누락 해결

✅ DB 하드코딩 제거 → Cloudtype 운영 방식에 맞춤

✅ Authorization 헤더 허용(CORS) → 관리자 API 호출 시 preflight 문제 감소

원하면, 지금 Cloudtype에 설정된 DATABASE_URL 형식(마스킹해서) / CORS_ORIGINS 값만 알려주면, 프론트(index/admin)의 BACKEND_URL / CORS까지 한 번에 딱 맞게 정리해줄게._

You said:
Uploaded image
그리고 admin.html에서 인증키 생성하면 에러가 나는데...그 원인도 확인해줄래? 
ChatGPT said:

Analyzing CORS and 500 errors
Answer now
Okay, there’s a CORS issue blocking access and causing 500




No file chosenNo file chosen
ChatGPT can make mistakes. Check important info. See Cookie Preferences.
ChatGPT is still generating a response...
