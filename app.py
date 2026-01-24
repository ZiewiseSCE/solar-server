import os
import hmac
import hashlib
import base64
import secrets
import math
from datetime import datetime, timedelta, timezone
from io import BytesIO

import psycopg2
from psycopg2.extras import RealDictCursor

from flask import Flask, request, jsonify, make_response, render_template_string, send_file
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

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()

# Optional land price heuristic (F-28) - won per pyeong (평 단가)
LAND_UNIT_PRICE_WON_PER_PYEONG = float(os.getenv("LAND_UNIT_PRICE_WON_PER_PYEONG") or 0)

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
# base64url + HMAC admin session
# ------------------------------------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64urldecode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def sign_admin_session() -> str:
    if not ADMIN_API_KEY:
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

        expected = hmac.new(
            ADMIN_API_KEY.encode("utf-8"),
            payload,
            hashlib.sha256
        ).digest()

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


# ------------------------------------------------------------
# Cookies (F-24)
# ------------------------------------------------------------
def _is_https_request() -> bool:
    # Works behind reverse-proxy if it sets X-Forwarded-Proto
    if request.is_secure:
        return True
    xf = (request.headers.get("X-Forwarded-Proto") or "").lower()
    return xf == "https"

def set_cookie(resp, name: str, value: str, max_age_days: int = 30):
    secure = False
    if COOKIE_SECURE == "true":
        secure = True
    elif COOKIE_SECURE == "false":
        secure = False
    else:
        secure = _is_https_request()

    samesite = COOKIE_SAMESITE
    if samesite not in ("Lax", "Strict", "None"):
        samesite = "Lax"

    resp.set_cookie(
        name,
        value,
        max_age=max_age_days * 24 * 3600,
        httponly=True,
        secure=secure,
        samesite=samesite
    )


# ------------------------------------------------------------
# DB: init + CRUD (public schema forced)
# ------------------------------------------------------------
def init_db():
    # public 스키마에 고정 (schema 혼선 제거)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE SCHEMA IF NOT EXISTS public;")
            cur.execute("SET search_path TO public;")

            # 테이블 생성
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.licenses (
                    token TEXT PRIMARY KEY,
                    note TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    bound_at TIMESTAMPTZ,
                    bound_fp TEXT,
                    registered BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)

            # 혹시 예전 잘못된 스키마였던 경우를 위해 컬럼 보정(안전)
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS note TEXT")
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS bound_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS bound_fp TEXT")
            cur.execute("ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS registered BOOLEAN DEFAULT FALSE")

            # NULL 값 있으면 채우기(기존 row가 있었다면)
            cur.execute("UPDATE public.licenses SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL")
            cur.execute("UPDATE public.licenses SET expires_at = COALESCE(expires_at, NOW() + INTERVAL '30 days') WHERE expires_at IS NULL")
            cur.execute("UPDATE public.licenses SET registered = COALESCE(registered, FALSE) WHERE registered IS NULL")

            # NOT NULL 강제
            cur.execute("ALTER TABLE public.licenses ALTER COLUMN created_at SET NOT NULL")
            cur.execute("ALTER TABLE public.licenses ALTER COLUMN expires_at SET NOT NULL")

            conn.commit()

def db_diag():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("SELECT current_database()")
            dbname = cur.fetchone()[0]
            cur.execute("SELECT inet_server_addr()::text, inet_server_port()")
            host, port = cur.fetchone()

            cur.execute("SELECT to_regclass('public.licenses') IS NOT NULL")
            table_exists = bool(cur.fetchone()[0])
            cnt = None
            if table_exists:
                cur.execute("SELECT COUNT(*) FROM public.licenses")
                cnt = int(cur.fetchone()[0])

            return {
                "db_ok": True,
                "current_database": dbname,
                "server_addr": host,
                "server_port": port,
                "licenses_table_exists": table_exists,
                "licenses_count": cnt,
            }

def get_all_licenses():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("SELECT * FROM public.licenses ORDER BY created_at DESC")
            return cur.fetchall()

def insert_license(token: str, note: str, created_at, expires_at):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("""
                INSERT INTO public.licenses (token, note, created_at, expires_at, registered)
                VALUES (%s, %s, %s, %s, FALSE)
            """, (token, note, created_at, expires_at))
            conn.commit()

def delete_license(token: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("DELETE FROM public.licenses WHERE token=%s", (token,))
            conn.commit()
            return cur.rowcount

def reset_license(token: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("""
                UPDATE public.licenses
                SET bound_fp=NULL, bound_at=NULL, registered=FALSE
                WHERE token=%s
            """, (token,))
            conn.commit()
            return cur.rowcount

def extend_license(token: str, new_expiry) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("""
                UPDATE public.licenses
                SET expires_at=%s
                WHERE token=%s
            """, (new_expiry, token))
            conn.commit()
            return cur.rowcount

def find_license(token: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("SELECT * FROM public.licenses WHERE token=%s", (token,))
            return cur.fetchone()

def bind_license(token: str, fingerprint: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO public;")
            cur.execute("""
                UPDATE public.licenses
                SET bound_fp=%s, bound_at=%s, registered=TRUE
                WHERE token=%s
            """, (fingerprint, now_utc(), token))
            conn.commit()
            return cur.rowcount


# ------------------------------------------------------------
# Finance (F-17) - PF equal payment
# ------------------------------------------------------------
def pf_equal_payment(principal: float, annual_rate_pct: float, years: int):
    principal = float(principal or 0)
    years = int(years or 0)
    annual_rate_pct = float(annual_rate_pct or 0)
    if principal <= 0 or years <= 0:
        return {
            "monthly_payment": 0,
            "total_interest": 0,
            "total_payment": 0
        }

    r = (annual_rate_pct / 100.0) / 12.0
    n = years * 12
    if r <= 0:
        monthly = principal / n
        total_payment = principal
        total_interest = 0.0
    else:
        monthly = principal * r * ((1 + r) ** n) / (((1 + r) ** n) - 1)
        total_payment = monthly * n
        total_interest = max(0.0, total_payment - principal)

    return {
        "monthly_payment": float(monthly),
        "total_interest": float(total_interest),
        "total_payment": float(total_payment)
    }


# ------------------------------------------------------------
# AI analysis (F-15/16) - API-first 구조
#   * 실제 외부 데이터 연동 전: "확인 필요" + 링크 구조를 보존
# ------------------------------------------------------------
def build_ai_checks(address: str, mode: str):
    addr_q = (address or "").strip()
    mode = (mode or "roof").strip().lower()
    # 링크들은 "검색/바로가기" 용도로만 제공(실제 파라미터/키는 추후 확정)
    return [
        {
            "category": "도시/자치 조례 확인(ELIS)",
            "title": "도시/자치 조례 확인",
            "result": "확인 필요",
            "link": "https://www.elis.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "토지이음 용도지역/지구 확인",
            "title": "토지이음 용도지역/지구",
            "result": "확인 필요",
            "link": "https://www.eum.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "상위법 규제(환경/농지 등) 확인(법제처)",
            "title": "상위법 규제(환경/농지 등)",
            "result": "확인 필요",
            "link": "https://www.law.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "자연·생태 등급(환경공간정보서비스)",
            "title": "자연·생태 등급",
            "result": "확인 필요",
            "link": "https://egis.me.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "문화재/국가유산 규제(공간정보)",
            "title": "문화재/국가유산 규제",
            "result": "확인 필요",
            "link": "https://www.gis.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "국토환경성평가지도(경사도/환경)",
            "title": "국토환경성평가지도",
            "result": "정확도 확인필요",
            "link": "https://egis.me.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "소규모 환경영향평가 대상 여부",
            "title": "소규모 환경영향평가",
            "result": "면적/용도지역 기반 확인 필요",
            "link": "https://www.me.go.kr/",
            "needs_confirm": True,
        },
        {
            "category": "한전 용량 확인(한전ON)",
            "title": "한전 선로/변전소 용량",
            "result": "확인 필요",
            "link": "https://online.kepco.co.kr/",
            "needs_confirm": True,
            "extra": {"need_more_info": True}
        },
    ]


def conservative_score(panel_count: int, checks: list):
    # 0~100 보수적: 확인 필요/리스크가 많을수록 감점
    base = 80
    if panel_count <= 0:
        base -= 40

    risk = 0
    for c in checks:
        if c.get("needs_confirm"):
            risk += 5
        r = (c.get("result") or "")
        if "정확도" in r or "확인" in r:
            risk += 2
    score = max(0, min(100, base - risk))
    # confidence: 데이터가 확정된 항목이 적으면 낮게
    confirmed = sum(1 for c in checks if not c.get("needs_confirm"))
    conf = max(10, min(95, confirmed * 12))
    return score, conf


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.route("/api/auth/whoami", methods=["GET"])
def whoami():
    # admin.html 상태 체크용: 항상 200
    return json_ok(
        ts=now_utc().isoformat(),
        admin_enabled=bool(ADMIN_API_KEY),
        is_admin=require_admin()
    )

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_API_KEY:
        return json_bad("admin disabled (ADMIN_API_KEY not set)", 503)

    data = request.get_json(silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)

    return json_ok(session_token=sign_admin_session())

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    return json_ok(items=get_all_licenses(), diag=db_diag())

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

    n = delete_license(token)
    return json_ok(deleted=(n > 0))

@app.route("/api/admin/license/reset", methods=["POST"])
def admin_license_reset():
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("token required", 400)

    n = reset_license(token)
    return json_ok(reset=(n > 0))

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
    n = extend_license(token, new_expiry)
    return json_ok(extended=(n > 0), expires_at=new_expiry.isoformat())

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
REPORT_HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Solar Pathfinder Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-slate-50 text-slate-800">
  <div class="max-w-5xl mx-auto p-6">
    <div class="bg-white rounded-xl shadow border border-slate-200 p-5">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h1 class="text-xl font-extrabold">상세 리포트</h1>
          <div class="text-xs text-slate-500 mt-1">{{ date }}</div>
          <div class="mt-3 text-sm">
            <div class="font-bold text-slate-700">주소</div>
            <div class="text-slate-600 break-words">{{ address }}</div>
          </div>
        </div>
        <div class="text-right">
          <div class="text-xs text-slate-500">용량</div>
          <div class="text-lg font-bold text-cyan-700">{{ capacity }}</div>
          <div class="text-xs text-slate-500 mt-1">한전 용량</div>
          <div class="font-mono text-sm text-amber-600">{{ kepco_capacity }}</div>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-6">
        <div class="bg-slate-900 text-white rounded-lg p-4">
          <div class="text-xs text-slate-300">총 사업비</div>
          <div class="text-lg font-bold mt-1">{{ finance.totalCostWon|default(0) | int | format_won }}</div>
          <div class="text-xs text-slate-400 mt-2">연 수익</div>
          <div class="font-bold text-amber-300">{{ finance.annualRevenueWon|default(0) | int | format_won }}</div>
        </div>
        <div class="bg-indigo-900 text-white rounded-lg p-4">
          <div class="text-xs text-indigo-200">월 상환액(PF)</div>
          <div class="text-lg font-bold mt-1">{{ finance.monthlyDebtWon|default(0) | int | format_won }}</div>
          <div class="text-xs text-indigo-200 mt-2">총 이자</div>
          <div class="font-bold">{{ finance.totalInterestWon|default(0) | int | format_won }}</div>
        </div>
        <div class="bg-emerald-800 text-white rounded-lg p-4">
          <div class="text-xs text-emerald-100">자본회수기간</div>
          <div class="text-lg font-bold mt-1">{{ finance.paybackYears if finance.paybackYears else "> 25" }} 년</div>
          <div class="text-xs text-emerald-100 mt-2">구매매력도(AI)</div>
          <div class="font-bold">{{ ai_score }} 점</div>
        </div>
      </div>

      <div class="bg-white rounded-lg border border-slate-200 p-4 mt-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="font-bold text-sm">ROI/NPV/IRR (25년)</div>
          <div class="flex items-center gap-2 text-xs">
            <span class="text-slate-500">할인율</span>
            <input id="discountRate" type="number" step="0.1" value="6.0" class="w-20 px-2 py-1 border border-slate-300 rounded" />
            <span class="text-slate-500">%</span>
            <button id="recalcRoi" class="px-3 py-1 rounded bg-slate-900 text-white font-bold">재계산</button>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
          <div class="bg-slate-50 rounded border border-slate-200 p-3">
            <div class="text-xs font-bold text-slate-600 mb-2">토지비 제외</div>
            <div class="text-sm">NPV: <span id="npvNo" class="font-bold"></span></div>
            <div class="text-sm">IRR: <span id="irrNo" class="font-bold"></span></div>
          </div>
          <div class="bg-slate-50 rounded border border-slate-200 p-3">
            <div class="text-xs font-bold text-slate-600 mb-2">토지비 포함</div>
            <div class="text-sm">NPV: <span id="npvWith" class="font-bold"></span></div>
            <div class="text-sm">IRR: <span id="irrWith" class="font-bold"></span></div>
          </div>
        </div>
      </div>


      <div class="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="bg-white rounded-lg border border-slate-200 p-4">
          <div class="font-bold text-sm mb-2">25년 현금흐름(토지비 제외)</div>
          <canvas id="cfChartNoLand" height="160"></canvas>
        </div>
        <div class="bg-white rounded-lg border border-slate-200 p-4">
          <div class="font-bold text-sm mb-2">25년 현금흐름(토지비 포함)</div>
          <div class="text-[10px] text-slate-500 mb-2">※ 토지가격 데이터가 없으면 제외/포함 차이가 없을 수 있습니다.</div>
          <canvas id="cfChartWithLand" height="160"></canvas>
        </div>
      </div>

      <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="bg-white rounded-lg border border-slate-200 p-4">
          <div class="font-bold text-sm mb-2">추정 가정(무데이터 보정 포함)</div>
          <div class="text-xs text-slate-600 space-y-1">
            <div><span class="font-bold">일사량:</span> {{ solar.sun_hours or "확인 필요" }} h/일</div>
            <div><span class="font-bold">방위/경사:</span> {{ solar.azimuth_deg or "확인 필요" }}° / {{ solar.tilt_deg or "확인 필요" }}°</div>
            <div><span class="font-bold">방위/경사 보정:</span> {{ solar.ori_factor or "확인 필요" }}</div>
            <div><span class="font-bold">토지가격:</span> {{ land_price }}</div>
            <div class="text-[10px] text-amber-600 font-bold">※ 데이터 소스 확정 전: 보수적 추정이며 "확인 필요"입니다.</div>
          </div>
        </div>
        <div class="bg-white rounded-lg border border-slate-200 p-4">
          <div class="font-bold text-sm mb-2">8대 중대 체크사항</div>
          <div class="space-y-2 text-xs">
            {% for c in ai_analysis.checks or [] %}
              <div class="p-2 rounded border border-slate-200 flex items-center justify-between gap-3">
                <div>
                  <div class="font-bold text-slate-700">{{ c.title or c.category }}</div>
                  <div class="text-slate-600">{{ c.result }}</div>
                </div>
                {% if c.link %}
                  <a class="text-blue-600 font-bold" href="{{ c.link }}" target="_blank">링크</a>
                {% endif %}
              </div>
            {% endfor %}
            {% if (ai_analysis.checks or [])|length == 0 %}
              <div class="text-slate-400">AI 분석 데이터가 없습니다.</div>
            {% endif %}
          </div>
        </div>
      </div>

      <div class="flex flex-wrap gap-2 mt-6">
        <form method="POST" action="/api/report/pdf">
          <input type="hidden" name="payload" value="{{ payload_json|e }}">
          <button class="px-4 py-2 rounded bg-slate-900 text-white font-bold hover:bg-slate-800" type="submit">PDF 즉시 출력</button>
        </form>
        <a class="px-4 py-2 rounded bg-white border border-slate-300 font-bold hover:bg-slate-50" href="javascript:window.print()">브라우저 인쇄</a>
      </div>
    </div>
  </div>

<script>
  const payload = {{ payload_json|safe }};
  const roi = (payload.finance && payload.finance.roi25y) ? payload.finance.roi25y : {};
  const cfNo = Array.isArray(roi.cashflows_no_land) ? roi.cashflows_no_land : [];
  const cfWith = Array.isArray(roi.cashflows_with_land) ? roi.cashflows_with_land : cfNo;
  const labels = (cfNo.length ? cfNo : cfWith).map((_, i) => `Y${i+1}`);

  function makeBar(id, data){
    const el = document.getElementById(id);
    if(!el) return;
    const ctx = el.getContext('2d');
    new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ label: '현금흐름(원)', data }] },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { maxRotation: 0, autoSkip: true } } }
      }
    });
  }

  

  function fmtWon(n){
    try{ return Math.round(n).toLocaleString() + " 원"; }catch(e){ return "확인 필요"; }
  }

  function npv(ratePct, cashflows){
    const r = (ratePct/100);
    let v = 0;
    for(let i=0;i<cashflows.length;i++){
      const t = i+1;
      v += cashflows[i] / Math.pow(1+r, t);
    }
    return v;
  }

  // Simple IRR (Newton + fallback bisection)
  function irr(cashflows){
    // cashflows are yearly, already include equity at t0? Our series starts Y1.
    // We approximate with t0=0 investment included in first year if present.
    // Use heuristic: if all flows positive -> no IRR.
    let hasNeg = false, hasPos = false;
    for(const c of cashflows){ if(c<0) hasNeg=true; if(c>0) hasPos=true; }
    if(!(hasNeg && hasPos)) return null;

    // Newton
    let x = 0.08; // 8%
    for(let it=0; it<40; it++){
      let f=0, df=0;
      for(let i=0;i<cashflows.length;i++){
        const t=i+1;
        const denom = Math.pow(1+x, t);
        f += cashflows[i]/denom;
        df += -t * cashflows[i] / (denom*(1+x));
      }
      if(Math.abs(df) < 1e-9) break;
      const nx = x - f/df;
      if(!isFinite(nx)) break;
      if(Math.abs(nx-x) < 1e-6) { x=nx; return x*100; }
      x = nx;
      if(x < -0.9) x = -0.9;
      if(x > 2.0) x = 2.0;
    }

    // Bisection in [-0.5, 1.5]
    let lo=-0.5, hi=1.5;
    function f(rate){
      let s=0;
      for(let i=0;i<cashflows.length;i++){
        const t=i+1;
        s += cashflows[i]/Math.pow(1+rate, t);
      }
      return s;
    }
    let flo=f(lo), fhi=f(hi);
    if(!isFinite(flo) || !isFinite(fhi) || flo*fhi>0) return null;

    for(let it=0; it<80; it++){
      const mid = (lo+hi)/2;
      const fm = f(mid);
      if(Math.abs(fm) < 1e-6) return mid*100;
      if(flo*fm <= 0){ hi=mid; fhi=fm; }
      else { lo=mid; flo=fm; }
    }
    return ((lo+hi)/2)*100;
  }

  function recomputeRoiMetrics(){
    const rate = parseFloat(document.getElementById("discountRate")?.value || "6") || 6;
    const nNo = npv(rate, cfNo);
    const nWith = npv(rate, cfWith);
    const iNo = irr(cfNo);
    const iWith = irr(cfWith);

    const npvNoEl = document.getElementById("npvNo");
    const npvWithEl = document.getElementById("npvWith");
    const irrNoEl = document.getElementById("irrNo");
    const irrWithEl = document.getElementById("irrWith");

    if(npvNoEl) npvNoEl.innerText = fmtWon(nNo);
    if(npvWithEl) npvWithEl.innerText = fmtWon(nWith);
    if(irrNoEl) irrNoEl.innerText = (iNo===null ? "확인 필요" : (iNo.toFixed(2) + " %"));
    if(irrWithEl) irrWithEl.innerText = (iWith===null ? "확인 필요" : (iWith.toFixed(2) + " %"));
  }

  document.getElementById("recalcRoi")?.addEventListener("click", (e)=>{ e.preventDefault(); recomputeRoiMetrics(); });
  recomputeRoiMetrics();

  makeBar('cfChartNoLand', cfNo);
  makeBar('cfChartWithLand', cfWith);
</script>
</body>
</html>
"""

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

    return render_template_string(
        REPORT_HTML,
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
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4

    x0 = 18 * mm
    y = H - 18 * mm

    def line(txt, dy=6*mm, size=11, bold=False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x0, y, txt)
        y -= dy

    address = payload.get("address") or "확인 필요"
    date = payload.get("date") or ""
    capacity = payload.get("capacity") or "-"
    kepco = payload.get("kepco_capacity") or "확인 필요"
    finance = payload.get("finance") or {}
    ai_score = payload.get("ai_score") or 0
    ai = payload.get("ai_analysis") or {}

    line("Solar Pathfinder Report", size=16, bold=True, dy=10*mm)
    line(f"Date: {date}", size=10, dy=7*mm)
    line(f"Address: {address}", size=10, dy=7*mm)
    line(f"Capacity: {capacity}", size=10, dy=7*mm)
    line(f"KEPCO: {kepco}", size=10, dy=10*mm)
    # solar assumptions (may be heuristic)
    assumptions = (finance.get("assumptions") or {}) if isinstance(finance, dict) else {}
    sunh = assumptions.get("sunHours")
    az = assumptions.get("azimuthDeg")
    tilt = assumptions.get("tiltDeg")
    ori = assumptions.get("oriFactor")
    land_price_won = ((finance.get("roi25y") or {}).get("land_price_won")) if isinstance(finance, dict) else None

    line(f"Solar: sun_hours={sunh if sunh is not None else '확인 필요'} h/day", size=10, dy=7*mm)
    line(f"Angles: azimuth={az if az is not None else '확인 필요'} deg, tilt={tilt if tilt is not None else '확인 필요'} deg", size=10, dy=7*mm)
    line(f"Orientation factor: {ori if ori is not None else '확인 필요'}", size=10, dy=7*mm)
    line(f"Land price: {_format_won(land_price_won) if land_price_won is not None else '확인 필요'}", size=10, dy=10*mm)

    line("Finance Summary", bold=True, dy=8*mm)
    line(f"Total Cost: {_format_won(finance.get('totalCostWon',0))}", size=10)
    line(f"Annual Revenue: {_format_won(finance.get('annualRevenueWon',0))}", size=10)
    line(f"Monthly Debt(PF): {_format_won(finance.get('monthlyDebtWon',0))}", size=10)
    line(f"Total Interest: {_format_won(finance.get('totalInterestWon',0))}", size=10)
    pb = finance.get("paybackYears")
    line(f"Payback: {pb if pb else '> 25'} years", size=10, dy=10*mm)

    line(f"AI Attractiveness Score: {ai_score}", bold=True, dy=8*mm)
    # NPV (discount 6%) for both cases (simple)
    def _npv(rate, cashflows):
        try:
            r = rate
            v = 0.0
            for i, cf in enumerate(cashflows, start=1):
                v += float(cf) / ((1+r) ** i)
            return v
        except Exception:
            return None

    roi = finance.get("roi25y") if isinstance(finance, dict) else {}
    cf_no = (roi.get("cashflows_no_land") or []) if isinstance(roi, dict) else []
    cf_with = (roi.get("cashflows_with_land") or []) if isinstance(roi, dict) else []
    disc = 0.06
    npv_no = _npv(disc, cf_no) if cf_no else None
    npv_with = _npv(disc, cf_with) if cf_with else None

    line("NPV (discount 6%)", bold=True, dy=8*mm)
    line(f"No-land: {_format_won(npv_no) if npv_no is not None else '확인 필요'}", size=10)
    line(f"With-land: {_format_won(npv_with) if npv_with is not None else '확인 필요'}", size=10, dy=10*mm)

    checks = (ai.get("checks") or [])
    if checks:
        line("8 Critical Checks:", bold=True, dy=8*mm)
        c.setFont("Helvetica", 9)
        for idx, item in enumerate(checks[:8], start=1):
            if y < 20*mm:
                c.showPage()
                y = H - 18*mm
                c.setFont("Helvetica", 9)
            title = item.get("title") or item.get("category") or f"Item {idx}"
            result = item.get("result") or "확인 필요"
            c.drawString(x0, y, f"{idx}. {title}: {result}")
            y -= 5*mm
    else:
        line("No AI checks available.", size=10)

    c.showPage()
    c.save()
    return buf.getvalue()


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
init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT") or 5000)
    app.run(host="0.0.0.0", port=port, debug=True)
