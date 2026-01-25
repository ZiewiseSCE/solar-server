import os
import hmac
import hashlib
import base64
import secrets
import math
from datetime import datetime, timedelta, timezone
from io import BytesIO
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import time
import json
import re

import psycopg2
from psycopg2.extras import RealDictCursor

from flask import Flask, request, jsonify, make_response, render_template_string, render_template, send_file
from flask_cors import CORS

# PDF (F-22)
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


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

# Flask / session signing secret (required for admin session)
SECRET_KEY = (os.getenv("SECRET_KEY") or "").strip()

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()

# Optional land price heuristic (F-28) - won per pyeong (평 단가)
LAND_UNIT_PRICE_WON_PER_PYEONG = float(os.getenv("LAND_UNIT_PRICE_WON_PER_PYEONG") or 0)
DATA_GO_KR_SERVICE_KEY = (os.getenv("DATA_GO_KR_SERVICE_KEY") or "").strip()  # data.go.kr serviceKey


# Cookie policy (F-24)
COOKIE_SECURE = (os.getenv("COOKIE_SECURE") or "auto").strip().lower()  # auto|true|false
COOKIE_SAMESITE = (os.getenv("COOKIE_SAMESITE") or "Lax").strip()       # Lax|Strict|None

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")


# ------------------------------------------------------------
# Time / DB
# ------------------------------------------------------------
def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)


# ------------------------------------------------------------
# DB init / diagnostics / license key storage
# ------------------------------------------------------------

def init_db():
    """Create required tables if missing (and apply lightweight migrations)."""
    conn = get_conn()
    try:
        # admin_state (for legacy code compatibility; not used for auth now)
        _ensure_admin_state(conn)

        cur = conn.cursor()
        # Base table (initial columns)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                token        TEXT PRIMARY KEY,
                note         TEXT NULL,
                created_at   TIMESTAMPTZ NOT NULL,
                expires_at   TIMESTAMPTZ NOT NULL
            );
        """)
        conn.commit()

        # Lightweight migrations for existing installations
        # (CREATE TABLE IF NOT EXISTS does NOT add new columns)
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS registered   BOOLEAN NOT NULL DEFAULT FALSE;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_fp     TEXT NULL;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_at     TIMESTAMPTZ NULL;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NULL;")
        conn.commit()
    finally:
        conn.close()

def init_db_with_retry(max_wait_sec: int = 30, sleep_sec: float = 2.0) -> bool:
    """
    Cloudtype/컨테이너 환경에서 DB가 늦게 뜨는 경우가 있어 재시도.
    실패해도 프로세스는 계속 살아있게 해 부팅 실패를 방지한다.
    """
    start = time.time()
    last_err = None
    while time.time() - start < max_wait_sec:
        try:
            init_db()
            print("[BOOT] init_db OK")
            return True
        except Exception as e:
            last_err = e
            print("[BOOT] init_db retry...", repr(e))
            time.sleep(sleep_sec)
    print("[BOOT] init_db FAILED but continue:", repr(last_err))
    return False

def ensure_license_schema():
    """
    기존 운영 DB에서 licenses 테이블이 이미 존재하는 경우,
    CREATE TABLE IF NOT EXISTS로는 컬럼이 추가되지 않으므로 컬럼/제약을 보강한다.
    - 운영 중 이미 만들어진 스키마가 NOT NULL 제약을 갖고 있을 수 있어 reset 시 NULL 저장이 실패할 수 있음.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        # columns (idempotent)
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS registered   BOOLEAN NOT NULL DEFAULT FALSE;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_fp     TEXT NULL;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_at     TIMESTAMPTZ NULL;")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NULL;")

        # constraints: drop NOT NULL if legacy schema had it (idempotent-ish via try/except)
        for col in ("bound_fp", "bound_at", "last_seen_at"):
            try:
                cur.execute(f"ALTER TABLE licenses ALTER COLUMN {col} DROP NOT NULL;")
            except Exception:
                conn.rollback()
                # ignore if column missing or already nullable or permissions issues
                conn.autocommit = True
                conn.autocommit = False

        conn.commit()
    finally:
        conn.close()


def db_diag():
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            return {"ok": True}
        finally:
            conn.close()
    except Exception as e:
        return {"ok": False, "error": repr(e)}

def insert_license(token: str, note: str, created_at: datetime, expires_at: datetime):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO licenses (token, note, created_at, expires_at) VALUES (%s,%s,%s,%s)",
            (token, note or None, created_at, expires_at),
        )
        conn.commit()
    finally:
        conn.close()

def delete_license(token: str) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM licenses WHERE token=%s", (token,))
        n = cur.rowcount
        conn.commit()
        return n
    finally:
        conn.close()

def reset_license(token: str) -> int:
    ensure_license_schema()
    conn = get_conn()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                UPDATE licenses
                   SET registered=FALSE,
                       bound_fp=NULL,
                       bound_at=NULL,
                       last_seen_at=NULL
                 WHERE token=%s
                """,
                (token,),
            )
            n = cur.rowcount
            conn.commit()
            return n
        except psycopg2.errors.NotNullViolation:
            # legacy schema: bound_fp may be NOT NULL. fallback to empty string.
            conn.rollback()
            cur.execute(
                """
                UPDATE licenses
                   SET registered=FALSE,
                       bound_fp='',
                       bound_at=NULL,
                       last_seen_at=NULL
                 WHERE token=%s
                """,
                (token,),
            )
            n = cur.rowcount
            conn.commit()
            return n
    finally:
        conn.close()



def extend_license(token: str, new_expires_at: datetime) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE licenses SET expires_at=%s WHERE token=%s",
            (new_expires_at, token),
        )
        n = cur.rowcount
        conn.commit()
        return n
    finally:
        conn.close()

def find_license(token: str):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM licenses WHERE token=%s", (token,))
        return cur.fetchone()
    finally:
        conn.close()

def bind_license(token: str, fingerprint: str) -> int:
    ensure_license_schema()
    """
    - 미등록이면 등록(바인딩)
    - 이미 등록 + 같은 fingerprint면 last_seen 갱신만
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE licenses
               SET registered=TRUE,
                   bound_fp=COALESCE(bound_fp, %s),
                   bound_at=COALESCE(bound_at, NOW()),
                   last_seen_at=NOW()
             WHERE token=%s
            """,
            (fingerprint, token),
        )
        n = cur.rowcount
        conn.commit()
        return n
    finally:
        conn.close()

def touch_license(token: str) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE licenses SET last_seen_at=NOW() WHERE token=%s", (token,))
        n = cur.rowcount
        conn.commit()
        return n
    finally:
        conn.close()

def get_all_licenses():
    ensure_license_schema()
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT token, note, created_at, expires_at,
                   registered, bound_fp, bound_at, last_seen_at
              FROM licenses
             ORDER BY created_at DESC
        """)
        rows = cur.fetchall() or []
        # datetime -> iso string for JSON friendliness
        for r in rows:
            for k in ["created_at", "expires_at", "bound_at", "last_seen_at"]:
                if r.get(k) is not None:
                    r[k] = r[k].isoformat()
        return rows
    finally:
        conn.close()

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

# base64url + HMAC admin session (DB-backed, cookie-friendly)
# ------------------------------------------------------------
# 목표:
# - ADMIN_API_KEY(ENV)에 의존하지 않고 DB(PostgreSQL)에 등록된 관리자 키로 인증
# - 한 번 로그인하면 HttpOnly 쿠키로 세션 유지(브라우저 스토리지 차단 이슈 대응)
# - 최초 1회만 "관리자 키 등록(바인딩)" 후, 이후에는 같은 키로만 로그인 가능(재등록/변경 방지)

_ADMIN_COOKIE_NAME = "sp_admin"
_ADMIN_CACHE = {"loaded_at": 0.0, "secret": None, "key_hash": None}

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _ensure_admin_state(conn):
    """Create admin_state row if missing and cache it."""
    conn.cursor().execute("""
        CREATE TABLE IF NOT EXISTS admin_state (
            id              INTEGER PRIMARY KEY,
            secret          TEXT NOT NULL,
            admin_key_hash  TEXT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)
    conn.commit()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, secret, admin_key_hash FROM admin_state WHERE id=1")
    row = cur.fetchone()
    if not row:
        secret = secrets.token_hex(32)
        cur2 = conn.cursor()
        cur2.execute(
            "INSERT INTO admin_state (id, secret, admin_key_hash) VALUES (1, %s, NULL)",
            (secret,),
        )
        conn.commit()
        row = {"id": 1, "secret": secret, "admin_key_hash": None}
    return row

def _load_admin_cache(force: bool = False):
    import time
    now = time.time()
    if (not force) and _ADMIN_CACHE["secret"] and (now - _ADMIN_CACHE["loaded_at"] < 10):
        return
    conn = get_conn()
    try:
        row = _ensure_admin_state(conn)
        _ADMIN_CACHE["secret"] = row["secret"]
        _ADMIN_CACHE["key_hash"] = row.get("admin_key_hash")
        _ADMIN_CACHE["loaded_at"] = now
    finally:
        conn.close()

def _get_admin_secret() -> str:
    _load_admin_cache()
    return _ADMIN_CACHE["secret"]

def _get_admin_key_hash():
    _load_admin_cache()
    return _ADMIN_CACHE["key_hash"]

def _set_admin_key_if_empty(raw_key: str) -> bool:
    """If DB has no admin_key_hash, set it. Returns True if set, False otherwise."""
    _load_admin_cache()
    if _ADMIN_CACHE["key_hash"]:
        return False
    conn = get_conn()
    try:
        row = _ensure_admin_state(conn)
        if row.get("admin_key_hash"):
            return False
        secret = row["secret"]
        key_hash = _sha256_hex(secret + raw_key.strip())
        cur = conn.cursor()
        cur.execute(
            "UPDATE admin_state SET admin_key_hash=%s, updated_at=NOW() WHERE id=1 AND admin_key_hash IS NULL",
            (key_hash,),
        )
        conn.commit()
        _load_admin_cache(force=True)
        return cur.rowcount == 1
    finally:
        conn.close()

def _check_admin_key(raw_key: str) -> bool:
    raw_key = (raw_key or "").strip()
    if not raw_key:
        return False
    # 최초 1회 등록 허용
    if _get_admin_key_hash() is None:
        _set_admin_key_if_empty(raw_key)
    key_hash = _get_admin_key_hash()
    if not key_hash:
        return False
    return _sha256_hex(_get_admin_secret() + raw_key) == key_hash

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s: str) -> bytes:
    s = (s or "").strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_admin_session() -> str:
    """Returns a signed token string (HMAC with SECRET_KEY)."""
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY not set")
    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + 7 * 24 * 3600  # 7 days
    payload = {"iat": now, "exp": exp}
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64url(hmac.new(SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
    return f"{body}.{sig}"

def verify_admin_session(token: str) -> bool:
    try:
        if not SECRET_KEY:
            return False
        if not token or "." not in token:
            return False
        body, sig = token.split(".", 1)
        expected = _b64url(hmac.new(SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return False
        payload = json.loads(_b64urldecode(body).decode("utf-8"))
        now = int(datetime.now(timezone.utc).timestamp())
        return now <= int(payload.get("exp", 0))
    except Exception:
        return False


def _admin_auth_debug():
    auth = request.headers.get("Authorization", "") or ""
    ck = request.cookies.get(_ADMIN_COOKIE_NAME)
    return {
        "has_authorization": bool(auth),
        "auth_prefix": auth.split(" ", 1)[0] if auth else "",
        "auth_len": len(auth),
        "has_cookie": bool(ck),
        "cookie_len": len(ck) if ck else 0,
    }

def _get_admin_token_from_request():
    # 1) Bearer
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    # 2) Cookie (preferred)
    ck = request.cookies.get(_ADMIN_COOKIE_NAME)
    if ck:
        return ck
    return None

def require_admin():
    token = _get_admin_token_from_request()
    if not token or not verify_admin_session(token):
        return False
    return True

def set_admin_cookie(resp, token: str):
    # cross-site 사용을 고려: SameSite=None + Secure 권장(Cloudtype는 https)
    secure = True if COOKIE_SECURE in ("auto", "true", True) else False
    same_site = COOKIE_SAMESITE  # "Lax" / "Strict" / "None"
    # SameSite=None 이면 Secure 필수 (브라우저 정책)
    if str(same_site).lower() == "none":
        secure = True
    resp.set_cookie(
        _ADMIN_COOKIE_NAME,
        token,
        httponly=True,
        secure=secure,
        samesite=same_site,
        max_age=7 * 24 * 3600,
        path="/",
    )
    return resp

def clear_admin_cookie(resp):
    resp.set_cookie(_ADMIN_COOKIE_NAME, "", expires=0, path="/")
    return resp


@app.route("/api/auth/whoami", methods=["GET"])
@app.route("/api/admin/status", methods=["GET"])  # admin.html 호환
def whoami():
    # 상태 체크용 (admin 인증은 ENV 기반). DB 상태는 diag로만 확인.
    return json_ok(
        ts=now_utc().isoformat(),
        admin_enabled=True,
        is_admin=require_admin(),
        diag=db_diag(),
    )

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    """
    Admin login (ENV only):
    - 입력한 admin_key == ADMIN_API_KEY 이면 로그인 성공
    - DB 바인딩/등록 없이, 어떤 PC/브라우저에서도 동일 키로 로그인 가능
    """
    try:
        data = request.get_json(silent=True) or {}
        k = (data.get("admin_key") or "").strip()

        env_key = (os.getenv("ADMIN_API_KEY") or "").strip()
        if not env_key:
            return json_bad("ADMIN_API_KEY not set", 500)

        if k != env_key:
            return json_bad("invalid credential", 401)

        token = sign_admin_session()
        resp = make_response(jsonify({"ok": True, "session_token": token}))
        return set_admin_cookie(resp, token)

    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        print("[ADMIN_LOGIN_ERROR]", err)
        return json_bad("internal error", 500, error=err, diag=db_diag())


    env_key = (os.getenv("ADMIN_API_KEY") or "").strip()
    if not env_key:
        return json_bad("ADMIN_API_KEY not set", 500)

    if k != env_key:
        return json_bad("invalid credential", 401)

    token = sign_admin_session()
    resp = make_response(jsonify({"ok": True, "session_token": token}))
    return set_admin_cookie(resp, token)


@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401, auth=_admin_auth_debug(), diag=db_diag())
    return json_ok(items=get_all_licenses(), diag=db_diag())

@app.route("/api/admin/license/create", methods=["POST"])
def admin_license_create():
    if not require_admin():
        return json_bad("unauthorized", 401, auth=_admin_auth_debug(), diag=db_diag())

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
        return json_bad("unauthorized", 401, auth=_admin_auth_debug(), diag=db_diag())

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("token required", 400)

    n = delete_license(token)
    return json_ok(deleted=(n > 0))

@app.route("/api/admin/license/reset", methods=["POST"])
def admin_license_reset():
    if not require_admin():
        return json_bad("unauthorized", 401, auth=_admin_auth_debug(), diag=db_diag())

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("token required", 400)

    n = reset_license(token)
    return json_ok(reset=(n > 0))

@app.route("/api/admin/license/extend", methods=["POST"])
def admin_license_extend():
    if not require_admin():
        return json_bad("unauthorized", 401, auth=_admin_auth_debug(), diag=db_diag())

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    days = int(data.get("days") or 30)
    if not token:
        return json_bad("token required", 400)

    new_expiry = now_utc() + timedelta(days=days)
    n = extend_license(token, new_expiry)
    return json_ok(extended=(n > 0), expires_at=new_expiry.isoformat())

@app.route("/api/license/check", methods=["POST"])
def license_check():
    """
    바인딩(등록) 없이 상태만 확인.
    - token 유효 여부 / 만료 여부
    - registered 여부
    - fingerprint가 제공되면 bound_fp와 일치하는지(bound_to_me)만 판단
    """
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    fp = (data.get("fingerprint") or "").strip()

    if not token:
        return json_bad("token required", 400)

    row = find_license(token)
    if not row:
        return json_bad("invalid token", 404)

    # 만료 체크
    expires_at = row.get("expires_at")
    try:
        # row from psycopg2 RealDictCursor returns datetime
        is_expired = bool(expires_at and expires_at < now_utc())
        expires_iso = expires_at.isoformat() if expires_at else None
    except Exception:
        is_expired = False
        expires_iso = str(expires_at)

    registered = bool(row.get("registered"))
    bound_fp = (row.get("bound_fp") or "")
    bound_to_me = bool(fp and registered and bound_fp == fp)

    # 조회만이지만 운영 편의상 last_seen 갱신(원치 않으면 제거 가능)
    try:
        touch_license(token)
    except Exception:
        pass

    return json_ok(
        token=token,
        expires_at=expires_iso,
        expired=is_expired,
        registered=registered,
        bound_to_me=bound_to_me,
    )


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

    # 이미 바인딩된 토큰인데 다른 fingerprint이면 차단
    if row.get("registered") and (row.get("bound_fp") or "") != fp:
        return json_bad("token already bound to another device", 409)

    bind_license(token, fp)
    return json_ok(token=token, expires_at=row["expires_at"].isoformat())

@app.route("/api/diag", methods=["GET"])
def diag():
    return json_ok(diag=db_diag(), ts=now_utc().isoformat())

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(ts=now_utc().isoformat())

# F-24: 환경에 따라 secure cookie로 세션 유지 (선택)
@app.route("/api/session/ping", methods=["GET"])
def session_ping():
    resp = make_response(json_ok(ts=now_utc().isoformat(), https=_is_https_request()))
    # 단순 세션 쿠키: 추후 확장 가능
    set_cookie(resp, "sp_session", secrets.token_urlsafe(16), max_age_days=7)
    return resp


# ------------------------------------------------------------
# F-15/16: AI 분석 API
# ------------------------------------------------------------


# ------------------------------------------------------------
# F-30: 8대 중대 체크사항 (Backend 판정 로직 + 점수 산출)
#  - 기존 Flask app.py에 추가하여 "서버 부팅 유지" (FastAPI 별도 배포 불필요)
#  - Endpoint: POST /api/checks/analyze
# ------------------------------------------------------------

# VWorld 규제 레이어 코드는 프로젝트/계정에 따라 달라 ENV로 받습니다.
# 예) VWORLD_LAYER_ZONING="국토교통부_토지이용계획"
VWORLD_API_KEY = (os.getenv("VWORLD_API_KEY") or os.getenv("VWORLD_KEY") or "").strip()
VWORLD_LAYER_ZONING = (os.getenv("VWORLD_LAYER_ZONING") or "").strip()
VWORLD_LAYER_ECO = (os.getenv("VWORLD_LAYER_ECO") or "").strip()
VWORLD_LAYER_HERITAGE = (os.getenv("VWORLD_LAYER_HERITAGE") or "").strip()

# data.go.kr 키 이름 호환 (둘 중 하나만 있어도 동작)
if not DATA_GO_KR_SERVICE_KEY:
    DATA_GO_KR_SERVICE_KEY = (os.getenv("DATA_GO_KR_KEY") or "").strip()

def _status_to_score_delta(status: str) -> int:
    if status == "FAIL":
        return -30
    if status == "WARNING":
        return -10
    return 0

def _calc_total_score(check_list: dict) -> tuple[int, float]:
    score = 100
    fail = 0
    warn = 0
    for v in (check_list or {}).values():
        st = (v or {}).get("status", "WARNING")
        score += _status_to_score_delta(st)
        if st == "FAIL": fail += 1
        elif st == "WARNING": warn += 1
    score = max(0, min(100, score))
    # 신뢰도(휴리스틱): FAIL/WARN 많을수록 감소
    conf = 0.985 - min(0.35, warn * 0.03 + fail * 0.08)
    conf = max(0.25, min(0.99, conf))
    return score, conf

def _normalize_text(x: str) -> str:
    return re.sub(r"\s+", " ", (x or "").strip())

def _vworld_getfeature(layer: str, lat: float, lng: float):
    if not (VWORLD_API_KEY and layer):
        return None
    url = "https://api.vworld.kr/req/data"
    d = 0.0006
    bbox = f"{lng-d},{lat-d},{lng+d},{lat+d}"
    params = {
        "key": VWORLD_API_KEY,
        "service": "data",
        "request": "GetFeature",
        "data": layer,
        "geomFilter": f"BOX({bbox})",
        "size": 5,
        "page": 1,
        "format": "json",
        "geometry": "false",
        "attribute": "true",
        "crs": "EPSG:4326",
    }
    try:
        q = url + "?" + urllib.parse.urlencode(params)
        r = urllib.request.urlopen(q, timeout=8)
        j = json.loads(r.read().decode("utf-8"))
        feats = (((j.get("response") or {}).get("result") or {}).get("featureCollection") or {}).get("features") or []
        return feats[0] if feats else None
    except Exception:
        return None

def _zoning_check(lat: float, lng: float) -> dict:
    pass_kw = ["계획관리지역", "생산관리지역", "자연녹지지역"]
    fail_kw = ["농림지역", "보전녹지지역", "개발제한구역"]
    feat = _vworld_getfeature(VWORLD_LAYER_ZONING, lat, lng)
    if not feat:
        return {"status":"WARNING","value":"확인 필요","msg":"V-World 용도지역 레이어 미설정/연동 실패(VWORLD_LAYER_ZONING 확인)."}
    props = feat.get("properties") or {}
    plans = _normalize_text(str(props.get("plans") or props.get("PLAN") or props.get("plan") or ""))
    val = plans or _normalize_text(str(props))[:120]
    if any(k in plans for k in fail_kw):
        return {"status":"FAIL","value":val,"msg":"부적합 용도지역이 포함됩니다."}
    if any(k in plans for k in pass_kw):
        return {"status":"PASS","value":val,"msg":"사업 가능 지역(우선 검토)입니다."}
    return {"status":"WARNING","value":val or "기타","msg":"해당 용도지역은 추가 검토가 필요합니다."}

def _ecology_check(lat: float, lng: float) -> dict:
    feat = _vworld_getfeature(VWORLD_LAYER_ECO, lat, lng)
    if not feat:
        return {"status":"PASS","value":"등급 없음/확인 필요","msg":"생태자연도 데이터 확인이 필요합니다(없으면 대체로 적합)."}
    props = feat.get("properties") or {}
    grade = _normalize_text(str(props.get("grade") or props.get("GRD") or props.get("등급") or ""))
    if "1" in grade:
        return {"status":"FAIL","value":f"생태 {grade}","msg":"1등급 권역은 개발이 제한됩니다."}
    if "2" in grade:
        return {"status":"WARNING","value":f"생태 {grade}","msg":"2등급 권역은 조건부 가능(협의 필요)입니다."}
    return {"status":"PASS","value":f"생태 {grade or '3등급/없음'}","msg":"생태 규제 리스크가 낮습니다."}

def _heritage_check(lat: float, lng: float) -> dict:
    feat = _vworld_getfeature(VWORLD_LAYER_HERITAGE, lat, lng)
    if not feat:
        return {"status":"PASS","value":"해당 없음/확인 필요","msg":"문화재 데이터 확인이 필요합니다(없으면 적합)."}
    props = feat.get("properties") or {}
    blob = _normalize_text(" ".join([str(v) for v in props.values()])[:300])
    name = _normalize_text(str(props.get("name") or props.get("nm") or props.get("명칭") or "문화재 구역"))
    if ("현상변경허용구역" in blob) or ("보호구역" in blob):
        return {"status":"FAIL","value":name,"msg":"문화재 보호/현상변경 구역으로 규제 가능성이 높습니다."}
    return {"status":"PASS","value":name or "문화재 영향 낮음","msg":"문화재 규제 영향이 낮습니다."}

def _setback_check(address: str, dist_road_m, dist_res_m) -> dict:
    # 현재 repo에는 '거리 측정' 구현이 확정적이지 않아,
    # - 조례 기준 자동추출 실패/거리값 미제공 시 WARNING으로 안전 처리
    # - 추후 Gemini 연동 및 거리 측정값(dist_road_m/dist_residential_m) 연결 시 PASS/FAIL로 승격
    return {"status":"WARNING","value":"조례 기준 확인 필요","msg":"법제처/AI 및 거리측정 연동이 필요합니다."}

_kepco_cache = {}  # key -> (ts, rows)
def _kepco_fetch(metroCd: str, cityCd: str):
    if not PUBLIC_KEPCO_KEY:
        return []
    url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
    params = {"metroCd": metroCd, "cityCd": cityCd, "apiKey": PUBLIC_KEPCO_KEY, "returnType": "json"}
    for i in range(3):
        try:
            q = url + "?" + urllib.parse.urlencode(params)
            r = urllib.request.urlopen(q, timeout=8)
            j = json.loads(r.read().decode("utf-8"))
            return j.get("data", []) or []
        except Exception:
            time.sleep(0.4*(i+1))
    return []

def _grid_check(pnu: str, capacity_kw):
    if not pnu or len(pnu) < 5:
        return {"status":"WARNING","value":"PNU 필요","msg":"한전 여유용량 조회를 위해 PNU(19자리)가 필요합니다."}
    metroCd, cityCd = pnu[:2], pnu[2:5]
    key = f"{metroCd}-{cityCd}"
    now = time.time()
    if key in _kepco_cache and (now - _kepco_cache[key][0]) < 300:
        rows = _kepco_cache[key][1]
    else:
        rows = _kepco_fetch(metroCd, cityCd)
        _kepco_cache[key] = (now, rows)

    if not rows:
        return {"status":"WARNING","value":"확인 필요","msg":"한전 API 응답이 없거나 일시적으로 실패했습니다. 재시도 필요."}

    def to_float(x):
        try: return float(str(x).strip())
        except: return 0.0
    max_vol3 = max((to_float(r.get("vol3")) for r in rows), default=0.0)
    mw = max_vol3 / 1000.0
    req_mw = (float(capacity_kw) if capacity_kw else 1000.0) / 1000.0

    if max_vol3 == 0:
        return {"status":"FAIL","value":"여유 0MW","msg":"여유용량 0: 접속 불가 가능성이 큽니다."}
    if mw >= max(1.0, req_mw):
        return {"status":"PASS","value":f"여유 {mw:.2f}MW","msg":"여유용량이 충분합니다."}
    return {"status":"WARNING","value":f"여유 {mw:.2f}MW","msg":"여유용량이 부족할 수 있습니다(협의 필요)."}

def _slope_check(slope_deg):
    if slope_deg is None:
        return {"status":"WARNING","value":"확인 필요","msg":"경사도 데이터가 없습니다(DEM 연동 또는 프론트 계산값 전달 필요)."}
    try:
        s = float(slope_deg)
    except Exception:
        return {"status":"WARNING","value":"확인 필요","msg":"경사도 값 파싱 실패"}
    if s < 15:
        return {"status":"PASS","value":f"{s:.1f}°","msg":"경사도 기준 적합(15° 미만)입니다."}
    if s < 20:
        return {"status":"WARNING","value":f"{s:.1f}°","msg":"경사도 주의 구간(15~20°). 조례/허가 요건 확인 필요."}
    return {"status":"FAIL","value":f"{s:.1f}°","msg":"경사도 과다(20° 이상): 개발행위허가 불가 가능."}

def _insolation_check(sun_hours):
    if sun_hours is None:
        return {"status":"WARNING","value":"확인 필요","msg":"일사량 데이터가 없습니다(기상청 연동 또는 위도 기반 추정 필요)."}
    try:
        h = float(sun_hours)
    except Exception:
        return {"status":"WARNING","value":"확인 필요","msg":"일사량 값 파싱 실패"}
    if h >= 3.6:
        return {"status":"PASS","value":f"{h:.2f}h","msg":"일사량 기준 적합(≥3.6h)입니다."}
    if h < 3.2:
        return {"status":"WARNING","value":f"{h:.2f}h","msg":"일사량이 낮습니다(3.2h 미만). 수익성 저하 가능."}
    return {"status":"WARNING","value":f"{h:.2f}h","msg":"일사량 추가 검토가 필요합니다."}

def _land_price_check(pnu: str, area_m2):
    # 정보 제공용. 가능한 한 값을 채우고, 불확실하면 '(추가 확인 필요)'
    try:
        area_pyeong = (float(area_m2)/3.305785) if (area_m2 is not None and float(area_m2)>0) else None
    except Exception:
        area_pyeong = None

    unit = None
    total = None
    estimated = False

    if LAND_UNIT_PRICE_WON_PER_PYEONG and LAND_UNIT_PRICE_WON_PER_PYEONG > 0:
        unit = float(LAND_UNIT_PRICE_WON_PER_PYEONG)
        estimated = True

    if unit and area_pyeong:
        total = unit * area_pyeong

    if unit is None:
        return {"status":"WARNING","value":"추정 불가","msg":"실거래/공시지가 데이터가 부족합니다(추가 확인 필요)."}
    if total is not None:
        return {"status":"PASS","value":f"{int(unit):,}원/평 · {int(total):,}원" + (" (추가 확인 필요)" if estimated else ""), "msg":"토지가격은 참고용입니다."}
    return {"status":"PASS","value":f"{int(unit):,}원/평" + (" (추가 확인 필요)" if estimated else ""), "msg":"토지가격은 참고용입니다."}

@app.route("/api/checks/analyze", methods=["POST"])
def checks_analyze():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    lat = data.get("lat")
    lng = data.get("lng")
    pnu = (data.get("pnu") or "").strip()
    capacity_kw = data.get("capacity_kw") or None
    slope_deg = data.get("slope_deg")
    sun_hours = data.get("sun_hours")
    dist_road_m = data.get("dist_road_m")
    dist_res_m = data.get("dist_residential_m")
    area_m2 = data.get("area_m2")

    try:
        lat_f = float(lat)
        lng_f = float(lng)
    except Exception:
        return json_bad("lat/lng required", 400)

    check_list = {
        "zoning": _zoning_check(lat_f, lng_f),
        "ecology": _ecology_check(lat_f, lng_f),
        "heritage": _heritage_check(lat_f, lng_f),
        "setback": _setback_check(address, dist_road_m, dist_res_m),
        "grid": _grid_check(pnu, capacity_kw),
        "slope": _slope_check(slope_deg),
        "insolation": _insolation_check(sun_hours),
        "land_price": _land_price_check(pnu, area_m2),
    }

    total, conf = _calc_total_score(check_list)
    return json_ok(
        total_score=total,
        confidence=f"{conf*100:.1f}%",
        check_list=check_list
    )


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    mode = (data.get("mode") or "roof").strip().lower()
    lat = data.get("lat")
    lng = data.get("lng")
    panel_count = int(data.get("panel_count") or 0)
    setback_m = float(data.get("setback_m") or 0)

    checks = build_ai_checks(address, mode)
    score, confidence = conservative_score(panel_count, checks)

    # 확장 필드(미확정 데이터는 "확인 필요")
    payload = {
        "address": address or "확인 필요",
        "mode": mode,
        "lat": lat,
        "lng": lng,
        "panel_count": panel_count,
        "setback_m": setback_m,
        "checks": checks,
        "attractiveness_score": score,
        "confidence": confidence,
        # future-ready
        "kepco_capacity": None,
        "sun_hours": None,
    }
    return json_ok(**payload)


# ------------------------------------------------------------
# F-17: PF 대출 계산 API
# ------------------------------------------------------------
@app.route("/api/finance/pf", methods=["POST"])
def finance_pf():
    data = request.get_json(silent=True) or {}
    principal = float(data.get("principal") or 0)
    annual_rate_pct = float(data.get("annual_rate_pct") or 0)
    years = int(data.get("years") or 0)
    method = (data.get("method") or "equal_payment").strip()

    if method != "equal_payment":
        # 현재는 원리금균등만 지원
        method = "equal_payment"

    r = pf_equal_payment(principal, annual_rate_pct, years)
    return json_ok(
        method=method,
        principal=principal,
        annual_rate_pct=annual_rate_pct,
        years=years,
        monthly_payment=r["monthly_payment"],
        total_interest=r["total_interest"],
        total_payment=r["total_payment"],
    )


# ------------------------------------------------------------
# F-20/21/22: Report (HTML + PDF)
# ------------------------------------------------------------




def _format_won(v: int) -> str:
    try:
        return f"{int(v):,} 원"
    except Exception:
        return "0 원"

app.jinja_env.filters["format_won"] = _format_won

@app.route("/report", methods=["POST"])
def report():
    # index.html에서 hidden form POST
    form = request.form or {}
    address = (form.get("address") or "").strip() or "확인 필요"
    capacity = (form.get("capacity") or "").strip() or "-"
    kepco_capacity = (form.get("kepco_capacity") or "").strip() or "확인 필요"
    date = (form.get("date") or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _json_load(s):
        try:
            import json
            return json.loads(s) if s else {}
        except Exception:
            return {}

    finance = _json_load(form.get("finance"))
    ai_analysis = _json_load(form.get("ai_analysis"))
    solar_opt = _json_load(form.get("solar_opt"))
    land_estimate = _json_load(form.get("land_estimate"))
    ai_score_raw = _json_load(form.get("ai_score"))

    # ai_score could be number or object
    ai_score = 0
    if isinstance(ai_score_raw, (int, float)):
        ai_score = int(ai_score_raw)
    elif isinstance(ai_score_raw, dict):
        ai_score = int(ai_score_raw.get("score") or ai_score_raw.get("attractiveness_score") or 0)

    payload = {
        "address": address,
        "capacity": capacity,
        "kepco_capacity": kepco_capacity,
        "date": date,
        "finance": finance,
        "ai_analysis": ai_analysis,
        "solar_opt": solar_opt,
        "land_estimate": land_estimate,
        "ai_score": ai_score,
    }

    import json
    payload_json = json.dumps(payload, ensure_ascii=False)

        # Derived display fields (data-source-free estimates included)
    assumptions = (finance or {}).get("assumptions") or {}
    solar = {
        "sun_hours": (solar_opt or {}).get("sun_hours") if isinstance(solar_opt, dict) and (solar_opt or {}).get("sun_hours") is not None else assumptions.get("sunHours"),
        "azimuth_deg": (solar_opt or {}).get("azimuth_deg") if isinstance(solar_opt, dict) and (solar_opt or {}).get("azimuth_deg") is not None else assumptions.get("azimuthDeg"),
        "tilt_deg": (solar_opt or {}).get("tilt_deg") if isinstance(solar_opt, dict) and (solar_opt or {}).get("tilt_deg") is not None else assumptions.get("tiltDeg"),
        "ori_factor": assumptions.get("oriFactor"),
    }
    land_price_won = None
    try:
        if isinstance(land_estimate, dict) and land_estimate.get("land_price_won") is not None:
            land_price_won = land_estimate.get("land_price_won")
        else:
            land_price_won = ((finance or {}).get("roi25y") or {}).get("land_price_won")
    except Exception:
        land_price_won = ((finance or {}).get("roi25y") or {}).get("land_price_won")
    land_price = _format_won(land_price_won) if land_price_won is not None else "확인 필요"

    return render_template(
        "report.html",
        address=address,
        capacity=capacity,
        kepco_capacity=kepco_capacity,
        date=date,
        finance=finance or {},
        ai_analysis=ai_analysis or {},
        solar_opt=solar_opt or {},
        land_estimate=land_estimate or {},
        ai_score=ai_score,
        payload_json=payload_json,
        solar=solar,
        land_price=land_price,
    )


def build_pdf_bytes(payload: dict) -> bytes:
    """
    Styled PDF (report-like) using reportlab + embedded charts.
    Note: This is still a PDF (not HTML render). We mimic the dark theme + KPI cards.
    """
    from io import BytesIO
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.utils import ImageReader

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4

    def rect(x, y, w, h, fill, stroke=colors.Color(1,1,1,0.08), r=8):
        c.setStrokeColor(stroke)
        c.setFillColor(fill)
        c.roundRect(x, y, w, h, r, stroke=1, fill=1)

    # Background (dark gradient-ish)
    c.setFillColorRGB(0.03, 0.05, 0.10)
    c.rect(0, 0, W, H, stroke=0, fill=1)

    margin = 14 * mm
    x0 = margin
    y0 = H - margin

    def text(x, y, s, size=11, color=colors.whitesmoke, bold=False):
        c.setFillColor(color)
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x, y, s)

    # Data
    address = payload.get("address") or "확인 필요"
    date = payload.get("date") or ""
    finance = payload.get("finance") or {}
    ai_score = payload.get("ai_score") or (payload.get("ai_analysis") or {}).get("attractiveness_score") or 0

    roi = (finance.get("roi25y") or {}) if isinstance(finance, dict) else {}
    cf_no = roi.get("cashflows_no_land") or []
    cf_with = roi.get("cashflows_with_land") or cf_no
    dscr_min = roi.get("dscr_min")
    dscr_avg = roi.get("dscr_avg")
    loan120 = roi.get("max_loan_by_dscr_120")
    loan130 = roi.get("max_loan_by_dscr_130")

    # Header card
    card_y = y0 - 38*mm
    rect(x0, card_y, W-2*margin, 38*mm, fill=colors.Color(1,1,1,0.06))
    text(x0+12, y0-14, "Solar Pathfinder — 상세 리포트", size=16, bold=True)
    text(x0+12, y0-22, f"{date}", size=9, color=colors.Color(0.75,0.8,0.9,0.9))
    text(x0+12, y0-32, f"주소: {address}", size=10, color=colors.Color(0.85,0.9,1,0.9))

    # Score badge
    badge_w = 58*mm
    badge_h = 12*mm
    bx = W - margin - badge_w
    by = y0 - 26*mm
    rect(bx, by, badge_w, badge_h, fill=colors.Color(0.08,0.5,0.3,0.25), stroke=colors.Color(0.2,0.9,0.6,0.35), r=10)
    text(bx+10, by+4, f"구매매력도  {ai_score}", size=12, bold=True, color=colors.Color(0.85,1,0.9,1))

    # KPI cards (4)
    kpi_top = card_y - 10*mm
    kpi_h = 18*mm
    kpi_gap = 4*mm
    kpi_w = (W-2*margin - 3*kpi_gap)/4

    def won(v):
        return _format_won(v) if v is not None else "확인 필요"

    kpis = [
        ("총 사업비", won(finance.get("totalCostWon")), colors.Color(0.2,0.95,0.55,0.12)),
        ("연 총수익", won(finance.get("annualRevenueWon")), colors.Color(0.35,0.55,1.0,0.12)),
        ("월 상환액", won(finance.get("monthlyDebtWon")), colors.Color(0.5,0.35,1.0,0.12)),
        ("자본회수기간", f"{finance.get('paybackYears') or '>'} 25 년" if finance.get("paybackYears") else "> 25 년", colors.Color(1.0,0.7,0.2,0.12)),
    ]

    for i,(k,v,fc) in enumerate(kpis):
        x = x0 + i*(kpi_w + kpi_gap)
        y = kpi_top - kpi_h
        rect(x, y, kpi_w, kpi_h, fill=fc)
        text(x+8, y+kpi_h-7, k, size=9, color=colors.Color(0.75,0.82,0.92,0.9), bold=True)
        text(x+8, y+6, str(v), size=11, bold=True)

    # Charts: cashflows (no-land and with-land) + DSCR
    chart_y = y - 10*mm
    chart_h = 58*mm
    chart_w = (W-2*margin - 6*mm)/2

    def chart_image(data, title, kind="bar"):
        fig = plt.figure(figsize=(6,2.3), dpi=150)
        ax = fig.add_subplot(111)
        xs = list(range(1, len(data)+1))
        if kind == "bar":
            ax.bar(xs, data)
        else:
            ax.plot(xs, data, linewidth=2)
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("Year", fontsize=8)
        ax.tick_params(axis='both', labelsize=7)
        ax.grid(True, alpha=0.25)
        buf2 = BytesIO()
        fig.tight_layout()
        fig.savefig(buf2, format="png", transparent=True)
        plt.close(fig)
        buf2.seek(0)
        return buf2

    # Cashflow charts
    try:
        img1 = ImageReader(chart_image(cf_no[:25], "Cashflow (No Land)", "bar"))
        img2 = ImageReader(chart_image(cf_with[:25], "Cashflow (With Land)", "bar"))
        rect(x0, chart_y-chart_h, chart_w, chart_h, fill=colors.Color(1,1,1,0.05))
        rect(x0+chart_w+6*mm, chart_y-chart_h, chart_w, chart_h, fill=colors.Color(1,1,1,0.05))
        c.drawImage(img1, x0+6, chart_y-chart_h+6, width=chart_w-12, height=chart_h-12, mask='auto')
        c.drawImage(img2, x0+chart_w+6*mm+6, chart_y-chart_h+6, width=chart_w-12, height=chart_h-12, mask='auto')
    except Exception:
        pass

    # DSCR + loan sizing section
    info_y = chart_y - chart_h - 10*mm
    rect(x0, info_y-32*mm, W-2*margin, 32*mm, fill=colors.Color(1,1,1,0.05))
    text(x0+10, info_y-10, "PF 요약 (DSCR / 대출한도)", size=12, bold=True)
    text(x0+10, info_y-20, f"DSCR Min: {dscr_min if dscr_min is not None else '확인 필요'}   |   DSCR Avg: {dscr_avg if dscr_avg is not None else '확인 필요'}", size=10)
    text(x0+10, info_y-30, f"대출한도(DSCR≥1.20): {won(loan120)}   /   (DSCR≥1.30): {won(loan130)}", size=10, color=colors.Color(0.85,0.9,1,0.95))

    c.showPage()
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf
@app.route("/api/report/pdf", methods=["POST"])
def report_pdf():
    # Accept form-encoded "payload" or JSON body
    payload = None
    if request.form and request.form.get("payload"):
        import json
        try:
            payload = json.loads(request.form.get("payload"))
        except Exception:
            payload = None
    if payload is None:
        payload = request.get_json(silent=True) or {}

    pdf_bytes = build_pdf_bytes(payload)
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="solar_pathfinder_report.pdf"
    )


# ------------------------------------------------------------
# F-25/26: Infra layer APIs (연동 준비 상태)
#  - 실제 한전/기설치 데이터 소스 확정 시 이 엔드포인트 내부만 교체하면 프론트가 그대로 동작
# ------------------------------------------------------------
@app.route("/api/infra/kepco", methods=["GET"])
def infra_kepco():
    """
    Query params:
      bbox = "minLng,minLat,maxLng,maxLat"
      z    = zoom level
    Returns:
      items: substations [{id,name,lat,lng,remaining_mw,available_year,status}]
      lines: lines       [{id,coords:[[lat,lng],[lat,lng],...],remaining_mw,available_year,status}]
    """
    bbox = (request.args.get("bbox") or "").strip()
    z = int(request.args.get("z") or 0)
    # 데이터 소스 미확정: 구조만 제공
    return json_ok(
        bbox=bbox,
        z=z,
        items=[],
        lines=[],
        note="KEPCO 데이터 소스/키/스키마 미확정: 현재는 구조만 제공(확인 필요)"
    )

@app.route("/api/infra/existing", methods=["GET"])
def infra_existing():
    """
    Query params:
      bbox = "minLng,minLat,maxLng,maxLat"
      z    = zoom level
    Returns:
      items: existing plants [{id,lat,lng,capacity_kw,status}]
    """
    bbox = (request.args.get("bbox") or "").strip()
    z = int(request.args.get("z") or 0)
    # 데이터 소스 미확정: 구조만 제공
    return json_ok(
        bbox=bbox,
        z=z,
        items=[],
        note="기 설치 태양광 위치 데이터(GeoJSON/DB) 미확정: 현재는 구조만 제공(확인 필요)"
    )

# ------------------------------------------------------------
# F-27: 지역별 일사량/날씨 기반 최적 방위각/경사각 (연동 준비 상태)
#  - 데이터 소스 확정 전까지는 "확인 필요" + 구조만 제공
# ------------------------------------------------------------
@app.route("/api/solar/optimize", methods=["POST"])
def solar_optimize():
    data = request.get_json(silent=True) or {}
    lat = data.get("lat")
    lng = data.get("lng")
    address = (data.get("address") or "").strip()
    mode = (data.get("mode") or "roof").strip().lower()

    # 데이터 소스 확정 전 "무데이터(heuristic)" fallback 제공:
    # - 정남향(180°), 경사: (위도-10)°, 10~35° clamp
    # - 일사량(시간/일): 한국 위도대(33~38.5) 기준 보수적 선형 근사
    sun_hours = None
    az = 180
    tilt = 20
    try:
        if lat is not None:
            lat_f = float(lat)
            tilt = max(10, min(35, int(round(lat_f - 10))))
            # lat 33 -> 3.9, 38.5 -> 3.4
            t = max(0.0, min(1.0, (lat_f - 33.0) / (38.5 - 33.0)))
            sun_hours = 3.9 - 0.5 * t
    except Exception:
        sun_hours = None
        tilt = 20

    payload = {
        "lat": lat,
        "lng": lng,
        "address": address or "확인 필요",
        "mode": mode,
        "sun_hours": sun_hours,          # heuristic(확인 필요)
        "azimuth_deg": az,               # 정남향
        "tilt_deg": tilt,                # 위도 기반 보수적
        "source": "heuristic",
        "needs_confirm": True,
        "note": "공신력 있는 일사량/날씨 데이터 소스 확정 전: 위도 기반 보수적 heuristic 제공(확인 필요)"
    }
    return json_ok(**payload)

# ------------------------------------------------------------
# F-28: 토지 시세 AI/데이터 기반 자동 산출 (연동 준비 상태)
#  - 데이터 소스 확정 전까지는 값 자동 채움 미구현(표기 구조만)
# ------------------------------------------------------------
@app.route("/api/land/estimate", methods=["POST"])
def land_estimate():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    pnu = (data.get("pnu") or "").strip() or None
    area_m2 = data.get("area_m2")
    area_pyeong = data.get("area_pyeong")

    # 데이터 소스 확정 전 "옵션 heuristic":
    # - ENV LAND_UNIT_PRICE_WON_PER_PYEONG(평 단가) 가 설정되어 있으면 면적 기반으로 산출
    land_price = None
    unit_price = None
    try:
        if LAND_UNIT_PRICE_WON_PER_PYEONG and float(LAND_UNIT_PRICE_WON_PER_PYEONG) > 0:
            unit_price = float(LAND_UNIT_PRICE_WON_PER_PYEONG)
            ap = None
            if area_pyeong is not None:
                ap = float(area_pyeong)
            elif area_m2 is not None:
                ap = float(area_m2) / 3.3058
            if ap and ap > 0:
                land_price = ap * unit_price
    except Exception:
        land_price = None
        unit_price = None

    payload = {
        "address": address or "확인 필요",
        "pnu": pnu,
        "area_m2": area_m2,
        "area_pyeong": area_pyeong,
        "land_price_won": land_price,  # heuristic(옵션) or None
        "unit_price_won_per_pyeong": unit_price,
        "source": "heuristic" if land_price is not None else "placeholder",
        "needs_confirm": True,
        "note": "토지 시세 데이터 소스 확정 전: ENV 평단가가 있으면 면적 기반 heuristic 산출(확인 필요)"
    }
    return json_ok(**payload)

# ------------------------------------------------------------
# Global exception handler (500에서도 원인 JSON으로 반환)
# ------------------------------------------------------------
@app.errorhandler(Exception)
def handle_any_exception(e):
    err = repr(e)
    print("[FATAL]", err)
    return jsonify({"ok": False, "msg": "internal error", "error": err}), 500


# ------------------------------------------------------------
# Ensure DB table exists under gunicorn too
# ------------------------------------------------------------
init_db_with_retry()


# ------------------------------------------------------------
# data.go.kr RTMS LandTrade (토지 실거래가) -> 평단가 보수 추정
#  - Requires DATA_GO_KR_SERVICE_KEY in ENV (Cloudtype)
#  - Uses LAWD_CD(시군구 5) + DEAL_YMD(YYYYMM), tries recent months if needed
#  - Conservative: use 30th percentile of price/평
# ------------------------------------------------------------
_LAND_PRICE_CACHE = {}  # key -> (ts, payload)
_LAND_PRICE_CACHE_TTL_SEC = 3600

def _cache_get(key: str):
    v = _LAND_PRICE_CACHE.get(key)
    if not v:
        return None
    ts, payload = v
    if time.time() - ts > _LAND_PRICE_CACHE_TTL_SEC:
        _LAND_PRICE_CACHE.pop(key, None)
        return None
    return payload

def _cache_set(key: str, payload):
    _LAND_PRICE_CACHE[key] = (time.time(), payload)

def _try_float(v, default=None):
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default

def _parse_amount_to_won(s):
    """RTMS 거래금액은 통상 '만원' 단위 문자열(예: '12,345') 형태가 많음 -> 원 환산"""
    if s is None:
        return None
    s = str(s).replace(",", "").strip()
    if not s:
        return None
    try:
        v = float(s)
    except Exception:
        return None
    # heuristic: treat as 만원
    return v * 10000.0

def _parse_area_m2(s):
    if s is None:
        return None
    s = str(s).replace(",", "").strip()
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None

def _ym_list_recent(n_months=3):
    now = datetime.now()
    y, m = now.year, now.month
    out = []
    for i in range(n_months):
        mm = m - i
        yy = y
        while mm <= 0:
            mm += 12
            yy -= 1
        out.append(f"{yy}{mm:02d}")
    return out

def _fetch_rtms_land_trade(lawd_cd: str, deal_ymd: str) -> dict:
    """Fetch RTMS land trade items (XML) for a given lawd_cd(5) and deal_ymd(YYYYMM)."""
    if not DATA_GO_KR_SERVICE_KEY:
        return {}
    lawd_cd = (lawd_cd or "").strip()
    deal_ymd = (deal_ymd or "").strip()
    if not (lawd_cd.isdigit() and len(lawd_cd) == 5 and deal_ymd.isdigit() and len(deal_ymd) == 6):
        return {}

    base_url = "https://apis.data.go.kr/1613000/RTMSDataSvcLandTrade/getRTMSDataSvcLandTrade"
    params = {
        "serviceKey": DATA_GO_KR_SERVICE_KEY,
        "LAWD_CD": lawd_cd,
        "DEAL_YMD": deal_ymd,
        "numOfRows": "2000",
        "pageNo": "1",
    }
    url = base_url + "?" + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=12) as resp:
        raw = resp.read()

    try:
        root = ET.fromstring(raw)
    except Exception:
        return {}

    items = []
    for item in root.findall(".//item"):
        d = {}
        for ch in list(item):
            if ch.tag and ch.text is not None:
                d[ch.tag] = ch.text.strip()
        if d:
            items.append(d)

    result_code = (root.findtext(".//resultCode") or "").strip()
    result_msg = (root.findtext(".//resultMsg") or "").strip()
    total_count = (root.findtext(".//totalCount") or "").strip()

    return {
        "items": items,
        "meta": {
            "resultCode": result_code,
            "resultMsg": result_msg,
            "totalCount": total_count,
            "lawd_cd": lawd_cd,
            "deal_ymd": deal_ymd,
        },
    }

def _rtms_estimate_unit_price_per_pyeong(items: list) -> dict:
    """Compute conservative price per pyeong from RTMS items."""
    if not items:
        return {}
    # Typical field names for this service often include '거래금액' and '대지면적'
    amt_keys = ["거래금액", "dealAmount", "dealamount"]
    area_keys = ["대지면적", "전용면적", "면적", "area", "plottage", "landArea"]

    ratios = []
    for it in items:
        amt = None
        for k in amt_keys:
            if it.get(k):
                amt = _parse_amount_to_won(it.get(k))
                break
        if not amt:
            continue

        area = None
        for k in area_keys:
            if it.get(k):
                area = _parse_area_m2(it.get(k))
                break
        if not area or area <= 0:
            continue

        pyeong = area / 3.305785
        if pyeong <= 0:
            continue
        ratios.append(amt / pyeong)

    if not ratios:
        return {}

    ratios.sort()
    # conservative: 30th percentile
    idx = max(0, int(len(ratios) * 0.30) - 1)
    unit = ratios[idx]
    return {
        "unit_price_won_per_pyeong": round(unit),
        "sample_count": len(ratios),
        "note": "국토부 RTMS 토지 실거래가 기반 보수적 추정치(시군구/월 단위)",
    }

@app.get("/api/land/price")
def api_land_price():
    """Land price estimate (원/평, 원). Query: pnu|lawd_cd, deal_ymd(optional), area_pyeong(optional)"""
    pnu = (request.args.get("pnu") or "").strip()
    lawd_cd = (request.args.get("lawd_cd") or "").strip()
    deal_ymd = (request.args.get("deal_ymd") or "").strip()  # YYYYMM
    address = (request.args.get("address") or "").strip()
    area_pyeong = _try_float(request.args.get("area_pyeong"), None)

    # derive lawd_cd from PNU if possible
    if (not lawd_cd) and pnu and pnu.isdigit() and len(pnu) >= 5:
        lawd_cd = pnu[:5]

    # cache key
    cache_key = f"{lawd_cd}:{deal_ymd or 'AUTO'}:{area_pyeong or ''}"
    cached = _cache_get(cache_key)
    if cached:
        return json_ok(**cached)

    # 0) data.go.kr official RTMS when service key available and lawd_cd exists
    if DATA_GO_KR_SERVICE_KEY and lawd_cd and lawd_cd.isdigit() and len(lawd_cd) == 5:
        ym_list = [deal_ymd] if (deal_ymd and deal_ymd.isdigit() and len(deal_ymd) == 6) else _ym_list_recent(3)
        combined_ratios = []
        total_samples = 0
        used_months = []
        try:
            for ym in ym_list:
                rt = _fetch_rtms_land_trade(lawd_cd, ym)
                est = _rtms_estimate_unit_price_per_pyeong(rt.get("items") or [])
                unit = _try_float(est.get("unit_price_won_per_pyeong"), None)
                if unit and unit > 0:
                    # We cannot merge ratios without storing them; but we can accept first month with data
                    total = round(unit * area_pyeong) if area_pyeong else None
                    payload = dict(
                        unit_price_won_per_pyeong=unit,
                        total_price_won=total,
                        source="data.go.kr-rtms-landtrade",
                        confidence=0.70,
                        note=f"{est.get('note','실거래가 기반')} (표본 {est.get('sample_count',0)}건, {ym})",
                        lawd_cd=lawd_cd,
                        deal_ymd=ym,
                    )
                    _cache_set(cache_key, payload)
                    return json_ok(**payload)
                used_months.append(ym)
            # no data in recent months
        except Exception as e:
            pass

    # 1) fallback ENV default
    if LAND_UNIT_PRICE_WON_PER_PYEONG and LAND_UNIT_PRICE_WON_PER_PYEONG > 0:
        unit = float(LAND_UNIT_PRICE_WON_PER_PYEONG)
        total = round(unit * area_pyeong) if area_pyeong else None
        payload = dict(
            unit_price_won_per_pyeong=unit,
            total_price_won=total,
            source="env-default",
            confidence=0.35,
            note="ENV 기본 평단가 기반 추정치(확인 필요)",
            lawd_cd=lawd_cd or None,
            deal_ymd=deal_ymd or None,
        )
        _cache_set(cache_key, payload)
        return json_ok(**payload)

    # 2) fallback Gemini (best-effort) if exists in this app build
    if address and GEMINI_API_KEY:
        try:
            j = _gemini_land_price_estimate(address)
            unit = _try_float(j.get("unit_price_won_per_pyeong"), None)
            conf = _try_float(j.get("confidence_0_1"), 0.15)
            note = (j.get("note") or "AI 추정치(확인 필요)").strip()
            if unit and unit > 0:
                total = round(unit * area_pyeong) if area_pyeong else None
                payload = dict(
                    unit_price_won_per_pyeong=unit,
                    total_price_won=total,
                    source="gemini-estimate",
                    confidence=max(0.05, min(conf, 0.45)),
                    note=note,
                    lawd_cd=lawd_cd or None,
                    deal_ymd=deal_ymd or None,
                )
                _cache_set(cache_key, payload)
                return json_ok(**payload)
        except Exception:
            pass

    payload = dict(
        unit_price_won_per_pyeong=None,
        total_price_won=None,
        source="unknown",
        confidence=0.0,
        note="토지 시세 데이터 소스 미확정 또는 조회 실패(확인 필요)",
        lawd_cd=lawd_cd or None,
        deal_ymd=deal_ymd or None,
    )
    _cache_set(cache_key, payload)
    return json_ok(**payload)


if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
