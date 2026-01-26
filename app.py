import os
import threading
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

# ------------------------------------------------------------
# Daily external API usage counters (resets automatically per day)
# ------------------------------------------------------------
_API_USAGE_LOCK = threading.Lock()
API_USAGE = {
    "date": datetime.now().date().isoformat(),
    "vworld": 0,
    "kepco": 0,
    "law": 0,
}

def _reset_usage_if_needed():
    today = datetime.now().date().isoformat()
    if API_USAGE.get("date") != today:
        API_USAGE.update({"date": today, "vworld": 0, "kepco": 0, "law": 0})

def _inc_usage(name: str, n: int = 1):
    try:
        with _API_USAGE_LOCK:
            _reset_usage_if_needed()
            API_USAGE[name] = int(API_USAGE.get(name, 0)) + int(n)
    except Exception:
        pass

@app.route("/api/usage", methods=["GET"])
def api_usage():
    with _API_USAGE_LOCK:
        _reset_usage_if_needed()
        data = dict(API_USAGE)
    return json_ok(**data)


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

# ------------------------------------------------------------
# Gemini(또는 휴리스틱) 기반 토지가/면적 추정 (Fallback 강화)
#  - GEMINI_API_KEY가 없거나 호출 실패해도 None을 만들지 않고
#    주소 기반 결정론적(동일주소 동일값) 추정치를 반환
# ------------------------------------------------------------
GEMINI_MODEL = (os.getenv("GEMINI_MODEL") or "gemini-1.5-flash").strip()

def _stable_hash_int(s: str) -> int:
    s = (s or "").strip()
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return int(h[:12], 16)

def _heuristic_area_m2_from_address(address: str) -> float:
    # 최후 fallback: 250~2500㎡ 범위 결정론적
    seed = _stable_hash_int(address or "unknown")
    return float(250 + (seed % 2251))

def _heuristic_unit_price_from_address(address: str) -> float:
    # 최후 fallback: 주소 키워드 기반 매우 거친 평단가(원/평)
    addr = (address or "")
    if any(k in addr for k in ["서울", "강남", "서초", "송파"]):
        base = 35000000
    elif any(k in addr for k in ["경기", "성남", "하남", "과천"]):
        base = 20000000
    elif any(k in addr for k in ["인천", "부산", "대구", "광주", "대전", "울산"]):
        base = 12000000
    else:
        base = 7000000
    seed = _stable_hash_int(addr)
    jitter = (seed % 31 - 15) / 100.0  # -0.15 ~ +0.15
    return float(max(1000000, base * (1.0 + jitter)))

def _gemini_land_price_estimate(address: str):
    """주소 기반으로 (평단가, 면적) 보수 추정.
    반환: dict(unit_price_won_per_pyeong, area_m2, confidence_0_1, note)
    - GEMINI_API_KEY 없거나 실패 시 휴리스틱으로 채움(None 방지)
    """
    address = (address or "").strip()

    # 0) 주소 없으면 즉시 휴리스틱
    if not address:
        return {
            "unit_price_won_per_pyeong": _heuristic_unit_price_from_address("unknown"),
            "area_m2": _heuristic_area_m2_from_address("unknown"),
            "confidence_0_1": 0.12,
            "note": "주소 없음 → 휴리스틱 추정(확인 필요)"
        }

    # 1) Gemini 키 없으면 휴리스틱
    if not GEMINI_API_KEY:
        return {
            "unit_price_won_per_pyeong": _heuristic_unit_price_from_address(address),
            "area_m2": _heuristic_area_m2_from_address(address),
            "confidence_0_1": 0.18,
            "note": "AI키 없음 → 주소 기반 휴리스틱 추정(확인 필요)"
        }

    prompt = f"""너는 한국 부동산 토지 시세를 매우 보수적으로 추정하는 도우미다.
아래 주소의 토지에 대해:
1) 보수적 평단가(원/평)
2) 추정 면적(㎡) (주소에 필지 단서가 없으면 일반적인 단독주택 필지/소규모 토지 기준으로 보수 추정)
3) 신뢰도(0~1)
4) 한 줄 근거(note)

반드시 JSON만 출력해라.
키는 정확히 unit_price_won_per_pyeong, area_m2, confidence_0_1, note 를 사용해라.

주소: {address}
"""

    try:
        # REST 호출 (urllib) - 외부 라이브러리 의존 없음
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 300},
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read()
        j = json.loads(raw.decode("utf-8", errors="ignore") or "{}")

        text = ""
        try:
            text = j["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            text = ""

        # JSON만 추출
        m = re.search(r"\{.*\}", text, re.S)
        jj = json.loads(m.group(0)) if m else {}

        unit = _try_float(jj.get("unit_price_won_per_pyeong"), None)
        area_m2 = _try_float(jj.get("area_m2"), None)
        conf = _try_float(jj.get("confidence_0_1"), 0.12) or 0.12
        note = str(jj.get("note") or "AI 보수 추정(확인 필요)").strip()

        if not unit or unit <= 0:
            unit = _heuristic_unit_price_from_address(address)
            conf = min(conf, 0.25)
            note = note + " / unit fallback"
        if not area_m2 or area_m2 <= 0:
            area_m2 = _heuristic_area_m2_from_address(address)
            conf = min(conf, 0.25)
            note = note + " / area fallback"

        return {
            "unit_price_won_per_pyeong": float(unit),
            "area_m2": float(area_m2),
            "confidence_0_1": max(0.05, min(float(conf), 0.55)),
            "note": note
        }

    except Exception as e:
        return {
            "unit_price_won_per_pyeong": _heuristic_unit_price_from_address(address),
            "area_m2": _heuristic_area_m2_from_address(address),
            "confidence_0_1": 0.15,
            "note": f"AI 호출 실패 → 휴리스틱 추정(확인 필요): {repr(e)}"
        }
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

# ------------------------------------------------------------
# Hardware master tables (Modules/Inverters) - Step1
# ------------------------------------------------------------
def _ensure_hardware_tables(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pv_modules (
          id bigserial primary key,
          no int unique,
          brand text not null,
          model text not null,
          power_w int,
          module_type text,
          efficiency_pct numeric,
          price_won_per_w int,
          is_bifacial boolean default false,
          features text,
          created_at timestamptz default now()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inverters (
          id bigserial primary key,
          no int unique,
          brand text not null,
          model text not null,
          capacity_kw int,
          topology text,
          price_million_won numeric,
          price_won bigint,
          features text,
          is_integrated_connection_box boolean default false,
          created_at timestamptz default now()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS master_versions (
          id bigserial primary key,
          name text unique not null,
          imported_at timestamptz default now()
        );
    """)
    conn.commit()


def init_db():
    """Create required tables if missing (and apply lightweight migrations)."""
    conn = get_conn()
    try:
        # admin_state (for legacy code compatibility; not used for auth now)
        _ensure_admin_state(conn)

        _ensure_hardware_tables(conn)

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

# -----------------------------
# AI checks (8대 체크) + conservative scoring
# -----------------------------
def _clamp(x, lo, hi):
    try:
        x = float(x)
    except Exception:
        return lo
    return max(lo, min(hi, x))

def _as_bool(v):
    return True if v is True else False

def _check_item(title, result, passed=None, needs_confirm=False, weight=1.0, link=None, meta=None):
    return {
        "title": title,
        "result": result,
        "passed": passed,  # True/False/None
        "needs_confirm": bool(needs_confirm),
        "weight": float(weight),
        "link": link,
        "meta": meta or {},
    }

def _vworld_get_zoning(address: str):
    """
    V-World 용도지역 조회 (best-effort).
    - 주소→좌표→용도지역 레이어 조회
    - 스펙/레이어가 프로젝트마다 다를 수 있어 실패 시 needs_confirm=True로 반환
    """
    if not PUBLIC_VWORLD_KEY or not address:
        return {"ok": False, "needs_confirm": True, "zone": None, "raw": None}

    try:
        # 1) Geocode (주소->좌표)
        geocode_url = "https://api.vworld.kr/req/address"
        q = {
            "service": "address",
            "request": "getCoord",
            "version": "2.0",
            "crs": "EPSG:4326",
            "address": address,
            "format": "json",
            "type": "road",  # road/parcel (필요 시 변경)
            "key": PUBLIC_VWORLD_KEY,
        }
        u = geocode_url + "?" + urllib.parse.urlencode(q, doseq=True)
        _inc_usage('vworld')
        with urllib.request.urlopen(urllib.request.Request(u, method="GET"), timeout=8) as resp:
            raw = resp.read()
        j = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
        point = (((j.get("response") or {}).get("result") or {}).get("point") or {})
        x = point.get("x")
        y = point.get("y")
        if not x or not y:
            return {"ok": False, "needs_confirm": True, "zone": None, "raw": j}

        # 2) Zoning/landuse (레이어 ID는 운영에 맞게 교체 가능)
        land_url = "https://api.vworld.kr/req/data"
        q2 = {
            "service": "data",
            "request": "GetFeature",
            "version": "2.0",
            "format": "json",
            "crs": "EPSG:4326",
            "geomFilter": f"POINT({x} {y})",
            "data": "LT_C_UQ111",  # (예시) 용도지역/지구 레이어. 실제 레이어 ID로 교체 가능.
            "key": PUBLIC_VWORLD_KEY,
            "size": "10",
            "page": "1",
        }
        u2 = land_url + "?" + urllib.parse.urlencode(q2, doseq=True)
        _inc_usage('vworld')
        with urllib.request.urlopen(urllib.request.Request(u2, method="GET"), timeout=8) as resp2:
            raw2 = resp2.read()
        j2 = json.loads(raw2.decode("utf-8", errors="ignore") or "{}")

        features = (((j2.get("response") or {}).get("result") or {}).get("featureCollection") or {}).get("features") or []
        zone = None
        if features:
            props = (features[0].get("properties") or {})
            for k in ("zone", "uname", "dname", "lt_cate", "prposAreaDstrcNm", "prpos"):
                if props.get(k):
                    zone = props.get(k)
                    break

        return {"ok": True, "needs_confirm": (zone is None), "zone": zone, "raw": {"x": x, "y": y}}
    except Exception as e:
        return {"ok": False, "needs_confirm": True, "zone": None, "raw": {"error": repr(e)}}



def _vworld_get_zoning_point(lat, lng):
    """V-World GetFeature by POINT(lat,lng). Best-effort; failure => needs_confirm."""
    try:
        if not PUBLIC_VWORLD_KEY or lat is None or lng is None:
            return {"ok": False, "needs_confirm": True, "zone": None, "raw": None}
        land_url = "https://api.vworld.kr/req/data"
        q = {
            "service": "data",
            "request": "GetFeature",
            "version": "2.0",
            "format": "json",
            "crs": "EPSG:4326",
            "geomFilter": f"POINT({lng} {lat})",
            "data": "LT_C_UQ111",  # 프로젝트 운영 레이어 ID에 맞게 교체 가능
            "key": PUBLIC_VWORLD_KEY,
            "size": "5",
            "page": "1",
        }
        u = land_url + "?" + urllib.parse.urlencode(q, doseq=True)
        _inc_usage("vworld")
        with urllib.request.urlopen(u, timeout=10) as resp:
            raw = resp.read()
        j = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
        zone = None
        try:
            feats = j.get("response", {}).get("result", {}).get("featureCollection", {}).get("features", [])
            if feats:
                props = feats[0].get("properties", {}) or {}
                # 여러 필드명 케이스 대응
                zone = props.get("UQ111") or props.get("FULL_NM") or props.get("NAME") or props.get("LABEL")
                if not zone:
                    # 아무 키나 하나라도 문자열이면 사용
                    for k, v in props.items():
                        if isinstance(v, str) and v.strip():
                            zone = v.strip()
                            break
        except Exception:
            zone = None
        return {"ok": bool(zone), "needs_confirm": not bool(zone), "zone": zone, "raw": j}
    except Exception as e:
        return {"ok": False, "needs_confirm": True, "zone": None, "raw": {"error": str(e)}}

def _zone_guess_from_address(address: str) -> str:
    a = (address or "")
    # 매우 거친 휴리스틱(실데이터 실패 시 최소 문구 제공)
    if any(k in a for k in ["농", "전", "답", "논"]):
        return "농지/농림지역 가능성(추정)"
    if any(k in a for k in ["산", "임", "봉", "고개"]):
        return "산지/보전관리 가능성(추정)"
    if any(k in a for k in ["시", "구", "동", "대로", "로", "길"]):
        return "도시/준도시지역 가능성(추정)"
    return "용도지역 미확정(주소 기반 추정)"

def _slope_guess_from_address(address: str) -> str:
    a = (address or "")
    if any(k in a for k in ["산", "임", "봉", "고개", "계곡", "재", "령"]):
        return "경사도 주의(산지 키워드 기반 추정)"
    return "평지 가능성(키워드 기준 추정)"

def _shade_guess_from_address(address: str, mode: str) -> str:
    a = (address or "")
    if mode == "roof":
        if any(k in a for k in ["아파트", "빌라", "오피스", "타워", "센터"]):
            return "주변 건물/층고로 그늘 영향 가능"
        return "그늘 영향 낮을 가능성(추정)"
    # land
    if any(k in a for k in ["숲", "산", "임", "계곡"]):
        return "수목/지형 그늘 영향 가능"
    return "그늘 영향은 현장 확인 필요"

def _fetch_law_ordinance_summary(address: str) -> str:
    """Best-effort: 법/조례 요약 텍스트 생성. 외부 연동 없으면 휴리스틱 요약."""
    _inc_usage("law")
    a = (address or "").strip()
    # 실제 연동(법제처/조례) 대신, 현재는 보수적 요약 텍스트를 생성한다.
    base = (
        "일반적으로 태양광 개발은 국토계획법/농지법/산지관리법/환경 관련 규정 및 "
        "지자체 이격거리·경관·보전 조례의 적용을 받을 수 있습니다."
    )
    if any(k in a for k in ["산", "임", "봉", "고개"]):
        return base + " 주소 키워드상 산지 가능성이 있어 산지전용/토목·복구비 리스크 검토가 필요합니다."
    if any(k in a for k in ["농", "전", "답", "논"]):
        return base + " 주소 키워드상 농지 가능성이 있어 농지전용 허가 및 배수·농업기반시설 영향 검토가 필요합니다."
    return base + " 용도지역/지목/인접시설물에 따라 허가 요건이 달라질 수 있어 사전 협의가 권장됩니다."

def _build_ai_summary(address: str, checks: list, law_text: str) -> str:
    """Generates concise AI-style executive summary. Uses Gemini if available, otherwise heuristic."""
    try:
        if GEMINI_API_KEY:
            # small, cheap prompt
            prompt = (
                f"주소: {address}\n\n"
                f"[법/조례 요약]\n{law_text}\n\n"
                f"[체크 결과]\n" + "\n".join([f"- {c.get('title')}: {c.get('message')}" for c in (checks or [])]) + "\n\n"
                "위 내용을 종합하여 태양광 설치 가능성에 대한 전문가 총평을 5줄 이내로 작성해줘. "
                "형식: 가능성/리스크/결론. 과장 없이 보수적으로."
            )
            # Reuse Gemini call helper
            resp = _gemini_generate_text(prompt, max_tokens=240)
            if resp:
                _inc_usage("law")  # LLM 호출도 law bucket에 포함(운영 편의)
                return resp.strip()
        # fallback heuristic
        kepco = ""
        land = ""
        for c in (checks or []):
            if c.get("title", "").startswith("계통연계"):
                kepco = c.get("message", "")
            if c.get("title", "").startswith("토지비/사업성"):
                land = c.get("message", "")
        return (
            f"가능성: 본 대상지는 기본 요건 충족 여부에 따라 사업화 검토 가치가 있습니다.\n"
            f"리스크: {law_text}\n"
            f"계통: {kepco or '확인 필요'}\n"
            f"사업성: {land or '확인 필요'}\n"
            f"결론: 현장 이격거리·인허가 사전협의 후 진행 권장."
        )
    except Exception:
        return "가능성/리스크/결론: 데이터 부족으로 확인 필요. 현장 및 인허가 사전협의 권장."


def build_ai_checks(address: str, lat=None, lng=None, mode: str = "roof"):
    """
    8대 중대 체크사항(보수적): 가능한 항목은 실데이터/추정값을 채우고,
    불확실한 항목은 needs_confirm=True로 표시한다.
    """
    mode = (mode or "roof").strip().lower()
    address = (address or "").strip()
    checks = []

    # -------------------------
    # 1) 용도지역 (V-World GetFeature 우선: 좌표 -> POINT)
    # -------------------------
    vz = {}
    if lat is not None and lng is not None:
        vz = _vworld_get_zoning_point(lat, lng)
    if not (vz.get("ok") and vz.get("zone")):
        vz = _vworld_get_zoning(address)

    if vz.get("ok") and vz.get("zone"):
        checks.append(_check_item(
            "용도지역(개발행위 가능성)",
            f"조회됨: {vz['zone']}",
            passed=None,
            needs_confirm=vz.get("needs_confirm", False),
            weight=1.3,
            link="https://www.vworld.kr/",
            meta={"zone": vz.get("zone"), "raw": vz.get("raw")}
        ))
    else:
        # fallback: address keyword heuristic
        guess = _zone_guess_from_address(address)
        checks.append(_check_item(
            "용도지역(개발행위 가능성)",
            f"확인 필요 ({guess})",
            passed=None,
            needs_confirm=True,
            weight=1.3,
            link="https://www.vworld.kr/",
            meta=vz.get("raw") or {}
        ))

    # -------------------------
    # 2) 이격거리 (현장 측정 필요)
    # -------------------------
    checks.append(_check_item(
        "이격거리(경계/도로/시설)",
        "확인 필요 (현장 경계/도로/시설물 기준 이격거리 측정 필요)",
        passed=None,
        needs_confirm=True,
        weight=1.2
    ))

    # -------------------------
    # 3) 경사도 (키워드 기반 추정 + DEM 미연동 표시)
    # -------------------------
    slope_msg = _slope_guess_from_address(address)
    checks.append(_check_item(
        "경사도(토공/구조 위험)",
        f"확인 필요 ({slope_msg} - DEM 연동 필요)",
        passed=None,
        needs_confirm=True,
        weight=1.1
    ))

    # -------------------------
    # 4) 일사/그늘 (지붕/도시 키워드 기반)
    # -------------------------
    shade_msg = _shade_guess_from_address(address, mode)
    checks.append(_check_item(
        "일사/그늘(발전량 리스크)",
        f"확인 필요 ({shade_msg} - 그늘/장애물 및 일사량 데이터 연동 필요)",
        passed=None,
        needs_confirm=True,
        weight=1.1
    ))

    # -------------------------
    # 5) 계통연계 (한전 여유용량) - 항상 고정된 모의값 제공
    # -------------------------
    seed = (address or "") or f"{lat},{lng}"
    kepco_sim = _simulate_kepco_capacity_text(seed)
    checks.append(_check_item(
        "계통연계(한전 여유용량)",
        f"모의: {kepco_sim} (주소/좌표 기반 시뮬레이션)",
        passed=None,
        needs_confirm=True,
        weight=1.4,
        link="https://www.kepco.co.kr/",
        meta={"sim": kepco_sim}
    ))

    # -------------------------
    # 6) 인허가/행위제한 (보수적 문구 + 조례/법령 요약은 리포트 총평에서 처리)
    # -------------------------
    checks.append(_check_item(
        "인허가/행위제한(농지·산지·보전·도시계획)",
        "확인 필요 (농지전용/산지전용/보전관리지역/환경 규제 및 지자체 조례 검토 필요)",
        passed=None,
        needs_confirm=True,
        weight=1.2
    ))

    # -------------------------
    # 7) 접근성/공사성
    # -------------------------
    checks.append(_check_item(
        "접근성/공사성(진입로·장비 반입)",
        "확인 필요 (진입로 폭/경사/교량하중 현장 확인 필요)",
        passed=None,
        needs_confirm=True,
        weight=1.0
    ))

    # -------------------------
    # 8) 토지비/사업성 (AI 추정 평당가)
    # -------------------------
    unit_won = None
    try:
        unit_won = _gemini_land_price_estimate(address) if address else None
    except Exception:
        unit_won = None
    if isinstance(unit_won, (int, float)) and unit_won > 0:
        man = round(float(unit_won) / 10000.0, 1)
        msg = f"추정: 평당 약 {man}만원 (공시지가/주변시세 기반 추정)"
    else:
        msg = "확인 필요 (공시지가·실거래가 기반 추정 필요)"
    checks.append(_check_item(
        "토지비/사업성(토지 단가)",
        msg,
        passed=None,
        needs_confirm=True,
        weight=1.2,
        meta={"unit_won_per_pyeong": unit_won}
    ))

    # mode별 보정
    if mode == "roof":
        for c in checks:
            if c["title"].startswith("경사도"):
                c["weight"] *= 0.6
            if c["title"].startswith("토지비/사업성"):
                c["weight"] *= 0.3

    return checks

def conservative_score(panel_count: int, checks: list):
    """
    보수적 점수(0~100) + 신뢰도(confidence 5~85).
    - needs_confirm가 많을수록 감점
    """
    try:
        pc = int(panel_count or 0)
    except Exception:
        pc = 0

    items = checks if isinstance(checks, list) else []
    if not items:
        return 35, 10

    total_w = 0.0
    score_w = 0.0
    confirm_w = 0.0

    for c in items:
        w = float((c or {}).get("weight") or 1.0)
        total_w += w

        passed = (c or {}).get("passed", None)
        needs = _as_bool((c or {}).get("needs_confirm"))

        if passed is True:
            s = 1.0
        elif passed is False:
            s = 0.0
        else:
            s = 0.55

        if needs:
            s *= 0.75
            confirm_w += w

        score_w += (s * w)

    base = (score_w / max(0.001, total_w)) * 100.0

    if pc > 0 and pc < 30:
        base -= 8
    elif pc >= 30 and pc < 80:
        base -= 3

    base = _clamp(base, 0, 100)

    confirm_ratio = confirm_w / max(0.001, total_w)
    conf = (1.0 - confirm_ratio) * 70 + 10
    conf = int(round(_clamp(conf, 5, 85)))

    return int(round(base)), conf



@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    mode = (data.get("mode") or "roof").strip().lower()
    lat = data.get("lat")
    lng = data.get("lng")
    panel_count = int(data.get("panel_count") or 0)
    setback_m = float(data.get("setback_m") or 0)

    checks = build_ai_checks(address, lat=lat, lng=lng, mode=mode)
    score, confidence = conservative_score(panel_count, checks)
    law_text = _fetch_law_ordinance_summary(address)
    ai_summary = _build_ai_summary(address or '확인 필요', checks, law_text)

    # 확장 필드(미확정 데이터는 "확인 필요")
    payload = {
        "address": address or "확인 필요",
        "mode": mode,
        "lat": lat,
        "lng": lng,
        "panel_count": panel_count,
        "setback_m": setback_m,
        "checks": checks,
        "law_text": law_text,
        "ai_summary": ai_summary,
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

mode = (form.get("mode") or "").strip() or "roof"
lat = form.get("lat")
lng = form.get("lng")
pnu = (form.get("pnu") or "").strip()
try:
    lat = float(lat) if lat not in (None, "", "null") else None
except Exception:
    lat = None
try:
    lng = float(lng) if lng not in (None, "", "null") else None
except Exception:
    lng = None

    def _json_load(s):
        try:
            import json
            return json.loads(s) if s else {}
        except Exception:
            return {}

    finance = _json_load(form.get("finance"))
    ai_analysis = _json_load(form.get("ai_analysis"))
    # 법/조례 요약 + AI 총평 (리포트 핵심)
    law_text = (ai_analysis.get('law_text') or '').strip() if isinstance(ai_analysis, dict) else ''
    if not law_text:
        law_text = _fetch_law_ordinance_summary(address)
    ai_summary = (ai_analysis.get('ai_summary') or '').strip() if isinstance(ai_analysis, dict) else ''
    if not ai_summary:
        # build_ai_checks not available here, so use ai_analysis.checks if present
        checks = []
        try:
            checks = ai_analysis.get('checks') or []
        except Exception:
            checks = []
        ai_summary = _build_ai_summary(address, checks, law_text)
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
        "mode": mode,
        "lat": lat,
        "lng": lng,
        "pnu": pnu,
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


    # -----------------------------
    # Page 2: AI 총평 / 법·조례 요약 / 8대 체크사항
    # -----------------------------
    c.showPage()
    c.setFillColorRGB(0.03, 0.05, 0.10)
    c.rect(0, 0, W, H, stroke=0, fill=1)

    law_text = payload.get("law_text") or (payload.get("ai_analysis") or {}).get("law_text") or ""
    ai_summary = payload.get("ai_summary") or (payload.get("ai_analysis") or {}).get("ai_summary") or ""
    checks = (payload.get("ai_analysis") or {}).get("checks") or []

    y = H - margin
    rect(x0, y-34*mm, W-2*margin, 34*mm, fill=colors.Color(1,1,1,0.06))
    text(x0+12, y-18, "AI 종합 총평 (법·조례 해석 기반)", size=14, bold=True)
    # wrap summary
    def wrap_lines(s, max_chars=52):
        s = (s or "").strip()
        if not s:
            return ["(총평 데이터 없음)"]
        out = []
        for para in s.split("\n"):
            para = para.strip()
            if not para:
                continue
            while len(para) > max_chars:
                out.append(para[:max_chars])
                para = para[max_chars:]
            out.append(para)
        return out[:14]

    sy = y-32
    for line in wrap_lines(ai_summary, 60):
        text(x0+14, sy, line, size=10, color=colors.Color(0.9,0.95,1,0.95))
        sy -= 12

    # Law/ordinance summary box
    ly = sy - 10
    rect(x0, ly-44*mm, W-2*margin, 44*mm, fill=colors.Color(1,1,1,0.05))
    text(x0+12, ly-14, "법·조례 요약", size=12, bold=True)
    ty = ly-28
    for line in wrap_lines(law_text, 72):
        text(x0+14, ty, line, size=9, color=colors.Color(0.82,0.88,0.98,0.92))
        ty -= 11

    # Checks
    cy = ty - 12
    rect(x0, cy-110*mm, W-2*margin, 110*mm, fill=colors.Color(1,1,1,0.04))
    text(x0+12, cy-14, "8대 중대 체크사항", size=12, bold=True)
    yy = cy-30
    for citem in (checks or [])[:8]:
        title = str(citem.get("title") or "")
        msg = str(citem.get("message") or "")
        text(x0+14, yy, f"• {title}", size=10, bold=True, color=colors.Color(0.88,0.95,1,0.95))
        yy -= 12
        for line in wrap_lines(msg, 80)[:2]:
            text(x0+22, yy, line, size=9, color=colors.Color(0.8,0.86,0.98,0.9))
            yy -= 11
        yy -= 6
        if yy < margin + 30:
            break

    c.save()
    pdf = buf.getvalue()

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

def _kepco_best_effort_parse(raw_bytes: bytes):
    """KEPCO 응답(JSON/XML/text) best-effort 파싱 -> (capacity_text, meta_dict)"""
    txt = (raw_bytes or b"").decode("utf-8", errors="ignore").strip()
    if not txt:
        return None, {"raw": ""}

    # JSON
    try:
        j = json.loads(txt)
        for k in ("kepco_capacity", "availableCapacity", "spareCapacity", "remainCapacity", "remain_mw", "remaining_mw"):
            if k in j and j.get(k) is not None:
                return str(j.get(k)), {"parsed_as": "json", "hit": k}
        return None, {"parsed_as": "json", "note": "no known capacity field", "keys": list(j)[:25]}
    except Exception:
        pass

    # XML
    try:
        root = ET.fromstring(raw_bytes)
        for tag in ("kepco_capacity", "availableCapacity", "spareCapacity", "remainCapacity", "remainingMw", "remaining_mw"):
            v = root.findtext(f".//{tag}")
            if v:
                return v.strip(), {"parsed_as": "xml", "hit": tag}
        return None, {"parsed_as": "xml", "note": "no known tag"}
    except Exception:
        pass

    return None, {"parsed_as": "text", "raw_preview": txt[:2000]}



def _simulate_kepco_capacity_text(seed_str: str) -> str:
    """Deterministic simulated KEPCO capacity text (for demo/fallback).
    Always returns a non-empty Korean string like '4MW 이상'.
    """
    s = (seed_str or "unknown").strip()
    seed = _stable_hash_int(s)
    r = seed % 1000
    if r < 220:
        return "4MW 이상"
    if r < 520:
        return "2~4MW"
    if r < 820:
        return "1~2MW"
    return "1MW 미만"

@app.route("/api/infra/kepco", methods=["GET"])
def infra_kepco():
    """
    Query:
      - pnu=... (카드 표시용)
      - bbox=minLng,minLat,maxLng,maxLat&z=... (레이어용)
    Env:
      - KEPCO_KEY (PUBLIC_KEPCO_KEY)
      - KEPCO_API_URL (실제 한전 OpenAPI 엔드포인트)
    """
    _inc_usage('kepco')
    pnu = (request.args.get("pnu") or "").strip()
    bbox = (request.args.get("bbox") or "").strip()
    z = int(request.args.get("z") or 0)

    api_key = (PUBLIC_KEPCO_KEY or "").strip()
    api_url = (os.getenv("KEPCO_API_URL") or "").strip()

    if not api_url or not api_key:
        # Fallback: deterministic simulated capacity so UI does not stay empty
        seed = pnu or (request.args.get("address") or "").strip() or bbox or "unknown"
        sim = _simulate_kepco_capacity_text(seed)
        return json_ok(
            pnu=pnu or None,
            bbox=bbox or None,
            z=z,
            items=[],
            lines=[],
            kepco_capacity=sim,
            source="simulated",
            note="KEPCO_API_URL/KEPCO_KEY 미설정 → 모의 용량 표시(확인 필요)",
            needs_confirm=True,
        )
    try:
        params = {"serviceKey": api_key}
        if pnu:
            params["pnu"] = pnu
        if bbox:
            params["bbox"] = bbox
            params["z"] = str(z)

        url = api_url + ("?" if "?" not in api_url else "&") + urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read()

        cap, meta = _kepco_best_effort_parse(raw)

        return json_ok(
            pnu=pnu or None,
            bbox=bbox or None,
            z=z,
            kepco_capacity=cap,
            items=[],
            lines=[],
            source="kepco-openapi",
            needs_confirm=(cap is None),
            meta=meta,
        )
    except Exception as e:
        return json_ok(
            pnu=pnu or None,
            bbox=bbox or None,
            z=z,
            items=[],
            lines=[],
            kepco_capacity=None,
            source="kepco-openapi",
            needs_confirm=True,
            note="KEPCO 호출 실패(엔드포인트/파라미터/응답 스키마 확인 필요)",
            error=repr(e),
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
    lat = data.get("lat")
    lng = data.get("lng")

    # 1) 면적 보정 (프론트가 못 주는 경우가 있어 fallback 강화)
    try:
        if area_m2 is not None:
            area_m2 = float(area_m2)
    except Exception:
        area_m2 = None

    try:
        if area_pyeong is not None:
            area_pyeong = float(area_pyeong)
    except Exception:
        area_pyeong = None

    # 2) 면적이 비었거나 0이면: AI/휴리스틱으로 면적까지 추정
    ai_note = None
    ai_conf = 0.0
    if (area_m2 is None or area_m2 <= 0) or (area_pyeong is None or area_pyeong <= 0):
        try:
            j = _gemini_land_price_estimate(address or (f"PNU:{pnu}" if pnu else ""))
            area_m2 = float(j.get("area_m2") or 0) or None
            if area_m2 and area_m2 > 0:
                area_pyeong = float(area_m2) / 3.3058
            ai_note = j.get("note")
            ai_conf = float(j.get("confidence_0_1") or 0) or 0.0
        except Exception:
            pass

    # 3) 평단가 우선순위: RTMS(가능하면) > ENV > AI(또는 휴리스틱)
    unit = None
    total = None
    source = "unknown"
    confidence = 0.0
    note = "확인 필요"

    try:
        lawd_cd = (pnu[:5] if (pnu and pnu.isdigit() and len(pnu) >= 5) else None)

        # (A) data.go.kr RTMS 실거래가 기반
        if DATA_GO_KR_SERVICE_KEY and lawd_cd and lawd_cd.isdigit() and len(lawd_cd) == 5:
            ym_list = _ym_list_recent(3)
            for ym in ym_list:
                rt = _fetch_rtms_land_trade(lawd_cd, ym)
                est = _rtms_estimate_unit_price_per_pyeong(rt.get("items") or [])
                unit0 = _try_float(est.get("unit_price_won_per_pyeong"), None)
                if unit0 and unit0 > 0:
                    unit = unit0
                    source = "data.go.kr-rtms-landtrade"
                    confidence = 0.70
                    note = f"{est.get('note','실거래가 기반')} (표본 {est.get('sample_count',0)}건, {ym})"
                    break

        # (B) ENV 기본 평단가
        if unit is None and LAND_UNIT_PRICE_WON_PER_PYEONG and float(LAND_UNIT_PRICE_WON_PER_PYEONG) > 0:
            unit = float(LAND_UNIT_PRICE_WON_PER_PYEONG)
            source = "env-default"
            confidence = 0.35
            note = "ENV 기본 평단가 기반 추정치(확인 필요)"

        # (C) AI/휴리스틱 평단가
        if unit is None:
            j = _gemini_land_price_estimate(address or (f"PNU:{pnu}" if pnu else ""))
            unit = _try_float(j.get("unit_price_won_per_pyeong"), None)
            source = "gemini-or-heuristic"
            confidence = max(confidence, min(0.45, _try_float(j.get("confidence_0_1"), 0.2)))
            note = j.get("note") or "AI/휴리스틱 추정(확인 필요)"

    except Exception as e:
        unit = unit if unit else None
        source = source if source != "unknown" else "unknown"
        confidence = confidence if confidence else 0.0
        note = f"조회 실패(확인 필요): {repr(e)}"

    # 4) 총액 계산 (unit/area가 있으면 반드시 숫자 생성)
    try:
        if unit and area_pyeong and area_pyeong > 0:
            total = round(float(unit) * float(area_pyeong))
    except Exception:
        total = None

    # 5) 노트/신뢰도 보강
    if ai_note and source != "data.go.kr-rtms-landtrade":
        note = f"{note} / {ai_note}"
        confidence = max(confidence, min(0.40, ai_conf))

    payload = {
        "address": address or "확인 필요",
        "pnu": pnu,
        "lat": lat,
        "lng": lng,
        "area_m2": area_m2,
        "area_pyeong": area_pyeong,
        "land_price_won": total,                 # ✅ 프론트 호환 필드
        "unit_price_won_per_pyeong": unit,
        "source": source,
        "confidence": confidence,
        "needs_confirm": True if confidence < 0.8 else False,
        "note": note,
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

    # 2) fallback Gemini/Heuristic (always; never return null just because AI key is missing)
    seed_addr = (address or (f"PNU:{pnu}" if pnu else "") or (lawd_cd or "")).strip()
    if seed_addr:
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




# ------------------------------------------------------------
# Step2: Hardware selection + electrical spec + cost engine
# ------------------------------------------------------------

def _db_fetchone(sql, params=()):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchone()
    finally:
        conn.close()

def _db_fetchall(sql, params=()):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()

def _pick_dc_cable(module_power_w, module_type, is_bifacial):
    module_power_w = module_power_w or 0
    module_type = (module_type or "")
    hi = (module_power_w >= 600) or ("N-Type" in module_type) or bool(is_bifacial)
    if hi:
        return {"name":"H1Z2Z2-K 6sq", "unit_cost_per_m":2000, "reason":"고출력/고전류"}
    return {"name":"H1Z2Z2-K 4sq", "unit_cost_per_m":1500, "reason":"일반"}

def _pick_ac_cable(inverter_kw):
    inverter_kw = inverter_kw or 0
    if inverter_kw < 50:
        return {"name":"F-CV 25sq", "unit_cost_per_m":10000}
    if 50 <= inverter_kw <= 80:
        return {"name":"F-CV 35sq", "unit_cost_per_m":15000}
    if 81 <= inverter_kw <= 120:
        return {"name":"F-CV 70sq", "unit_cost_per_m":25000}
    return {"name":"F-CV 95sq 이상", "unit_cost_per_m":35000}

def _connection_box_cost(is_integrated):
    if is_integrated:
        return {"required": False, "extra_cost_won": 0, "msg":"접속반 일체형 → 0원"}
    return {"required": True, "extra_cost_won": 2_000_000, "msg":"접속반 분리형 → +200만원"}

def _ai_comment(module_brand, module_type, inverter_brand, inverter_integrated):
    korean_modules = {"한화큐셀","현대에너지","HD현대","신성이엔지","에스에너지","한솔테크닉스","탑선","서전","다스코"}
    korean_inverters = {"LS산전","현대에너지","동양이엔피","효성","다쓰테크","윌링스","금비전자"}

    is_km = module_brand in korean_modules
    is_ki = inverter_brand in korean_inverters

    if is_km and is_ki:
        return "🏛️ 초기 비용은 높지만, 국산 기자재 사용으로 공공기관 입찰 시 가점 확보가 가능하며 A/S 리스크가 가장 낮습니다."
    if ("N-Type" in (module_type or "")) and (inverter_brand in {"선그로우","화웨이"}) and inverter_integrated:
        return "💰 현재 시장에서 ROI가 가장 높은 '국민 조합'입니다. N타입의 추가 발전량과 접속반 시공비 절감 효과로 원금 회수 기간을 획기적으로 단축합니다."
    if (module_brand in {"JA솔라","트리나솔라","론지솔라","징코솔라","라이센","DMEGC","Seraphim","GCL","솔라스페이스"}) and (inverter_brand in {"굿위","그로와트"}):
        return "⚡ 초기 자본 부담을 최소화한 구성입니다. 전선 규격(sq)만 권장 스펙대로 시공한다면 가장 빠르게 손익분기점에 도달할 수 있습니다."
    return "📌 선택하신 조합은 표준 설계 범위 내입니다. 현장 케이블 거리/접속 방식에 따라 CAPEX가 달라질 수 있습니다."

def _fmt_won(n):
    try:
        if n is None:
            return None
        return f"{int(round(n)):,}원"
    except Exception:
        return None

@app.get("/api/hardware/modules")
def api_hardware_modules():
    rows = _db_fetchall("SELECT no, brand, model, power_w, module_type, efficiency_pct, price_won_per_w, is_bifacial, features FROM pv_modules ORDER BY no ASC;")
    return jsonify({"ok": True, "items": rows})

@app.get("/api/hardware/inverters")
def api_hardware_inverters():
    rows = _db_fetchall("SELECT no, brand, model, capacity_kw, topology, price_million_won, price_won, is_integrated_connection_box, features FROM inverters ORDER BY no ASC;")
    return jsonify({"ok": True, "items": rows})

@app.post("/api/hardware/design")
def api_hardware_design():
    body = request.get_json(force=True, silent=True) or {}

    module_no = body.get("module_no")
    inverter_no = body.get("inverter_no")

    dc_length_m = float(body.get("dc_length_m") or 0)
    ac_length_m = float(body.get("ac_length_m") or 0)

    project_dc_kw = body.get("project_dc_kw")  # optional
    panel_count = body.get("panel_count")      # optional

    # If user didn't supply project_dc_kw, but provided panel_count, use it.
    module = _db_fetchone("SELECT * FROM pv_modules WHERE no=%s;", (module_no,))
    inv = _db_fetchone("SELECT * FROM inverters WHERE no=%s;", (inverter_no,))
    if not module or not inv:
        return jsonify({"ok": False, "msg": "선택된 기자재가 DB에 없습니다(번호 확인)."}), 400
    if module.get("price_won_per_w") is None or module.get("power_w") is None:
        return jsonify({"ok": False, "msg": "선택된 모듈의 가격/출력 정보가 미정입니다."}), 400
    if inv.get("price_won") is None:
        return jsonify({"ok": False, "msg": "선택된 인버터 가격 정보가 미정입니다."}), 400

    power_w = int(module["power_w"])
    price_w = int(module["price_won_per_w"])

    if project_dc_kw is not None:
        project_dc_kw = float(project_dc_kw)
        if project_dc_kw <= 0:
            project_dc_kw = None

    if panel_count is not None:
        try:
            panel_count = int(panel_count)
            if panel_count <= 0:
                panel_count = None
        except Exception:
            panel_count = None

    if project_dc_kw is None and panel_count is None:
        return jsonify({"ok": False, "msg": "project_dc_kw 또는 panel_count 중 1개는 필요합니다."}), 400

    if panel_count is None:
        panel_count = math.ceil((project_dc_kw * 1000.0) / power_w)

    dc_kw = (panel_count * power_w) / 1000.0

    # Cable specs
    dc = _pick_dc_cable(power_w, module.get("module_type"), module.get("is_bifacial"))
    ac = _pick_ac_cable(inv.get("capacity_kw"))

    # Costs
    module_cost = panel_count * power_w * price_w  # won
    inverter_cost = int(inv["price_won"])
    dc_cable_cost = int(round(dc_length_m * dc["unit_cost_per_m"]))
    ac_cable_cost = int(round(ac_length_m * ac["unit_cost_per_m"]))

    cb = _connection_box_cost(bool(inv.get("is_integrated_connection_box")))
    cb_cost = int(cb["extra_cost_won"])

    hardware_cost = module_cost + inverter_cost
    construction_cost = dc_cable_cost + ac_cable_cost + cb_cost

    total_capex = hardware_cost + construction_cost

    # ROI: if user supplies annual_cashflow_won, compute; else return "추가 확인 필요"
    annual_cashflow = body.get("annual_cashflow_won")
    roi_year = None
    if annual_cashflow:
        try:
            annual_cashflow = float(annual_cashflow)
            if annual_cashflow > 0:
                roi_year = round(total_capex / annual_cashflow, 2)
        except Exception:
            roi_year = None

    resp = {
      "ok": True,
      "selected_hardware": {
        "module": f'{module["brand"]} {module["model"]} ({power_w}W)',
        "inverter": f'{inv["brand"]} {inv["model"]} ({inv.get("capacity_kw")}kW)'
      },
      "electrical_spec": {
        "dc_cable": f'{dc["name"]} ({dc["reason"]})',
        "ac_cable": ac["name"],
        "connection_box_required": cb["required"]
      },
      "financial_analysis": {
        "module_count": panel_count,
        "project_dc_kw": round(dc_kw, 2),
        "hardware_cost_won": hardware_cost,
        "construction_cost_won": construction_cost,
        "total_capex_won": total_capex,
        "hardware_cost": _fmt_won(hardware_cost),
        "construction_cost": _fmt_won(construction_cost),
        "total_capex_range": f'{_fmt_won(total_capex)} (케이블/접속반 포함, 기타 EPC는 별도)',
        "expected_roi_year": (f"{roi_year}년" if roi_year is not None else "추가 확인 필요(연 순현금흐름 입력 필요)")
      },
      "ai_comment": _ai_comment(module["brand"], module.get("module_type"), inv["brand"], bool(inv.get("is_integrated_connection_box")))
    }
    return jsonify(resp)


if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
