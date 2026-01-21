import os
import hmac
import hashlib
import base64
import secrets
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import BytesIO

from flask import Flask, request, jsonify, render_template_string, make_response, redirect
from flask_cors import CORS

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm


# ------------------------------------------------------------
# App setup
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)

APP_DIR = Path(__file__).resolve().parent

# Admin key: set ADMIN_API_KEY env var in production
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "admin1234").strip()

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()

LICENSE_DB_FILE = (os.getenv("LICENSE_DB_FILE") or "licenses_db.json").strip()
LICENSE_DB_PATH = (APP_DIR / LICENSE_DB_FILE).resolve()

_db_lock = threading.Lock()


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64urldecode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def sign_admin_session() -> str:
    """
    Small stateless token for admin session.
    NOTE: not a full auth system; matches existing admin.html behavior.
    """
    ts = int(now_utc().timestamp())
    nonce = secrets.token_hex(16)
    payload = f"{ts}.{nonce}".encode("utf-8")
    sig = hmac.new(ADMIN_API_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(sig)}"


def verify_admin_session(token: str) -> bool:
    try:
        p_b64, s_b64 = token.split(".", 1)
        payload = _b64urldecode(p_b64)
        sig = _b64urldecode(s_b64)
        expected = hmac.new(ADMIN_API_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
        ts_s, _nonce = payload.decode("utf-8").split(".", 1)
        ts = int(ts_s)
        # 7 days validity
        return (now_utc().timestamp() - ts) <= (7 * 24 * 3600)
    except Exception:
        return False


def require_admin() -> bool:
    # admin.html sends "Authorization: Bearer <session>"
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return verify_admin_session(token)
    return False


def json_ok(**kwargs):
    d = {"ok": True}
    d.update(kwargs)
    return jsonify(d)


def json_bad(msg: str, code: int = 400, **kwargs):
    d = {"ok": False, "msg": msg}
    d.update(kwargs)
    return jsonify(d), code


# ------------------------------------------------------------
# JSON DB (licenses_db.json)
# ------------------------------------------------------------
def _ensure_db_file():
    if LICENSE_DB_PATH.exists():
        return
    LICENSE_DB_PATH.write_text(json.dumps({"licenses": {}, "bindings": {}}, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_db() -> dict:
    _ensure_db_file()
    try:
        return json.loads(LICENSE_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        # if corrupted, keep a safe empty db
        return {"licenses": {}, "bindings": {}}


def _save_db(db: dict) -> None:
    tmp = LICENSE_DB_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(LICENSE_DB_PATH)


def gen_license_token() -> str:
    # readable-ish token
    return "LIC-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:24]


def _license_status(expires_at_iso: str) -> str:
    try:
        exp = datetime.fromisoformat(expires_at_iso.replace("Z", "+00:00"))
        return "expired" if exp <= now_utc() else "active"
    except Exception:
        return "unknown"


def _get_binding(db: dict, fp: str):
    b = (db.get("bindings") or {}).get(fp)
    return b if isinstance(b, dict) else None


# ------------------------------------------------------------
# Basic endpoints
# ------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(ts=now_utc().isoformat())


@app.route("/api/config/public", methods=["GET"])
def config_public():
    return json_ok(
        vworld_key=PUBLIC_VWORLD_KEY,
        kepco_key=PUBLIC_KEPCO_KEY,
    )


# ------------------------------------------------------------
# Admin endpoints (for admin.html)
# ------------------------------------------------------------
@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    k = (data.get("admin_key") or "").strip()
    if not k or k != ADMIN_API_KEY:
        return json_bad("invalid credential", 401)
    return json_ok(session_token=sign_admin_session())


@app.route("/api/auth/whoami", methods=["GET", "OPTIONS"])
def whoami():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)
    return json_ok(role="admin")


@app.route("/api/admin/license/create", methods=["POST", "OPTIONS"])
def admin_license_create():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    days = int(data.get("days") or 30)
    if days <= 0 or days > 3650:
        return json_bad("invalid days", 400)

    note = (data.get("note") or "").strip()[:500]
    token = gen_license_token()
    created = now_utc()
    expires = created + timedelta(days=days)

    with _db_lock:
        db = _load_db()
        db.setdefault("licenses", {})
        db["licenses"][token] = {
            "token": token,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "note": note,
        }
        _save_db(db)

    return json_ok(token=token, expires_at=expires.isoformat(), days=days)



@app.route("/api/admin/license/reset", methods=["POST", "OPTIONS"])
def admin_license_reset():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("missing token", 400)
    with _db_lock:
        db = _load_db()
        if token not in (db.get("licenses") or {}):
            return json_bad("token not found", 404)
        bindings = db.get("bindings") or {}
        removed = 0
        for fp in list(bindings.keys()):
            b = bindings.get(fp) or {}
            if isinstance(b, dict) and b.get("token") == token:
                bindings.pop(fp, None)
                removed += 1
        db["bindings"] = bindings
        _save_db(db)
    return json_ok(removed=removed)


@app.route("/api/admin/license/delete", methods=["POST", "OPTIONS"])
def admin_license_delete():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return json_bad("missing token", 400)
    with _db_lock:
        db = _load_db()
        licenses = db.get("licenses") or {}
        if token not in licenses:
            return json_bad("token not found", 404)
        licenses.pop(token, None)
        bindings = db.get("bindings") or {}
        removed_bindings = 0
        for fp in list(bindings.keys()):
            b = bindings.get(fp) or {}
            if isinstance(b, dict) and b.get("token") == token:
                bindings.pop(fp, None)
                removed_bindings += 1
        db["licenses"] = licenses
        db["bindings"] = bindings
        _save_db(db)
    return json_ok(deleted=True, removed_bindings=removed_bindings)


@app.route("/api/admin/license/extend", methods=["POST", "OPTIONS"])
def admin_license_extend():
    if request.method == "OPTIONS":
        return ("", 204)
    if not require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    days = int(data.get("days") or 30)
    if not token:
        return json_bad("missing token", 400)
    if days <= 0 or days > 3650:
        return json_bad("invalid days", 400)
    with _db_lock:
        db = _load_db()
        licenses = db.get("licenses") or {}
        rec = licenses.get(token)
        if not isinstance(rec, dict):
            return json_bad("token not found", 404)
        # extend from current expiry if in future, else from now
        try:
            exp = datetime.fromisoformat((rec.get("expires_at") or "").replace("Z", "+00:00"))
        except Exception:
            exp = now_utc()
        base_dt = exp if exp > now_utc() else now_utc()
        new_exp = base_dt + timedelta(days=days)
        rec["expires_at"] = new_exp.isoformat().replace("+00:00", "Z")
        licenses[token] = rec
        db["licenses"] = licenses
        _save_db(db)
    return json_ok(token=token, expires_at=rec["expires_at"])


@app.route("/api/admin/licenses", methods=["GET", "OPTIONS"])
def admin_list_licenses():
    if request.method == "OPTIONS":
        return json_ok()
    if not require_admin():
        return json_bad("unauthorized", 401)

    with _db_lock:
        db = _load_db()
        lic = db.get("licenses") or {}
        bindings = db.get("bindings") or {}

    # map token -> bound_count and latest fingerprint
    bound_map = {}
    for fp, b in bindings.items():
        if not isinstance(b, dict):
            continue
        t = b.get("token")
        if not t:
            continue
        bound_map.setdefault(t, {"count": 0, "fps": []})
        bound_map[t]["count"] += 1
        bound_map[t]["fps"].append(fp)

    items = []
    for token, row in lic.items():
        if not isinstance(row, dict):
            continue
        expires_at = row.get("expires_at") or ""
        status = _license_status(expires_at)
        info = bound_map.get(token) or {"count": 0, "fps": []}
        items.append(
            {
                "token": token,
                "created_at": row.get("created_at"),
                "expires_at": expires_at,
                "note": row.get("note") or "",
                "status": status,
                "bound_count": info["count"],
                "fingerprints": info["fps"][:5],
            }
        )

    # newest first
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return json_ok(items=items)


# ------------------------------------------------------------
# Client licensing endpoints
# ------------------------------------------------------------
@app.route("/api/license/activate", methods=["POST", "OPTIONS"])
def activate_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    with _db_lock:
        db = _load_db()
        lic = (db.get("licenses") or {}).get(token)
        if not lic:
            return json_bad("invalid token", 403)

        expires_at = lic.get("expires_at")
        if _license_status(expires_at) != "active":
            return json_bad("expired", 403, expires_at=expires_at)

        # bind fp to token
        db.setdefault("bindings", {})
        db["bindings"][fp] = {
            "fingerprint": fp,
            "token": token,
            "bound_at": now_utc().isoformat(),
            "expires_at": expires_at,
        }
        _save_db(db)

    return json_ok(token=token, expires_at=expires_at)


@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    with _db_lock:
        db = _load_db()
        b = _get_binding(db, fp)
        if not b or b.get("token") != token:
            return json_bad("not bound", 403)
        expires_at = b.get("expires_at")
        if _license_status(expires_at) != "active":
            return json_bad("expired", 403, expires_at=expires_at)

    return json_ok(expires_at=expires_at)


@app.route("/api/auth/auto", methods=["POST", "OPTIONS"])
def auto_auth():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()
    if not fp:
        return json_bad("fingerprint required", 400)

    with _db_lock:
        db = _load_db()
        b = _get_binding(db, fp)
        if not b:
            return json_bad("not bound", 403)
        expires_at = b.get("expires_at")
        if _license_status(expires_at) != "active":
            return json_bad("expired", 403, expires_at=expires_at)
        token = b.get("token")

    return json_ok(token=token, expires_at=expires_at)


# -----------------------------
# AI-lite comprehensive analysis (server-side stub)
# -----------------------------
def _mock_sun_hours(lat: float) -> float:
    # rough annual average PSH in Korea-like latitudes: 3.3~4.4
    base = 4.0
    # very rough adjustment by latitude
    if lat and lat > 37.5:
        base -= 0.15
    if lat and lat < 35.5:
        base += 0.1
    return max(3.0, min(4.6, base))


def _score_conservative(payload: dict) -> dict:
    # Conservative scoring: start at 70 and subtract risks.
    score = 70
    reasons = []
    # slope / eco / heritage unknown => subtract
    unknown_penalty = 10
    for k in ("land_use", "eco_grade", "heritage", "env_map", "local_ordinance", "kepco_capacity"):
        v = (payload.get(k) or "").strip()
        if not v or "확인필요" in v or "정보 없음" in v:
            score -= unknown_penalty
            reasons.append(f"{k}: 확인필요(-{unknown_penalty})")

    # oversize / capacity etc
    cap = payload.get("kepco_over") is True
    if cap:
        score -= 15
        reasons.append("한전 용량 초과 가능(-15)")

    # clamp
    score = max(0, min(100, score))
    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "D"
    return {"score": score, "grade": grade, "reasons": reasons}


@app.route("/api/analyze/comprehensive", methods=["POST", "OPTIONS"])
def analyze_comprehensive():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    lat = float(data.get("lat") or 0) if str(data.get("lat") or "").strip() else 0.0
    lon = float(data.get("lon") or 0) if str(data.get("lon") or "").strip() else 0.0

    # Stub info + references for the 8 key checks
    checks = [
        {"title": "도시별 조례정보 확인", "link": "https://www.elis.go.kr/", "result": "확인필요"},
        {"title": "토지이음(국토계획/용도지역) 확인", "link": "https://www.eum.go.kr/web/am/amMain.jsp", "result": "확인필요"},
        {"title": "법제처(상위법: 환경법/농지법 등) 규제 확인", "link": "https://www.law.go.kr/", "result": "확인필요"},
        {"title": "자연/생태 등급 확인(환경부 지침)", "link": "https://aid.mcee.go.kr/", "result": "확인필요"},
        {"title": "문화재(국가유산) 공간정보/보존관리지도 확인", "link": "https://www.nie-ecobank.kr/cmmn/Index.do", "result": "확인필요"},
        {"title": "국토환경성평가지도(경사도/지적/환경)", "link": "https://webgis.neins.go.kr/map.do", "result": "평균 경사도만 제시(확인필요)"},
        {"title": "소규모 환경영향평가 대상 여부", "link": "https://www.law.go.kr/", "result": "확인필요(용도/면적 기준)"},
        {"title": "한전온(허용용량/가능시점)", "link": "https://online.kepco.co.kr/", "result": "확인필요"},
    ]

    # compute conservative score inputs
    score_payload = {
        "land_use": "확인필요",
        "eco_grade": "확인필요",
        "heritage": "확인필요",
        "env_map": "확인필요",
        "local_ordinance": "확인필요",
        "kepco_capacity": "정보 없음",
        "kepco_over": False,
    }
    ai_score = _score_conservative(score_payload)

    return json_ok(
        checks=checks,
        sun_hours=_mock_sun_hours(lat),
        ai_score=ai_score,
        ai_comment="외부 규제/환경/용량 정보는 반드시 공식 시스템에서 재확인이 필요합니다.",
        kepco_capacity="정보 없음(확인필요)",
    )

@app.route("/api/ai/analyze", methods=["POST", "OPTIONS"])
def ai_analyze():
    """Alias endpoint for AI compliance checklist + conservative attractiveness score."""
    if request.method == "OPTIONS":
        return ("", 204)
    # Reuse comprehensive analyzer to keep behavior consistent
    # Accept both {lat,lon} and {lat,lng} keys
    data = request.get_json(force=True, silent=True) or {}
    if "lon" not in data and "lng" in data:
        data["lon"] = data.get("lng")
    # Call existing logic by invoking function directly
    resp = analyze_comprehensive()
    # analyze_comprehensive returns a Flask response via json_ok(...)
    # Convert to dict for remapping keys
    try:
        payload = resp.get_json() if hasattr(resp, "get_json") else None
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return resp
    # Map fields to the new spec contract
    checks = payload.get("checks") or []
    checklist = []
    for c in checks:
        checklist.append({
            "category": c.get("title") or c.get("name") or "",
            "link": c.get("link") or "",
            "status": c.get("result") or c.get("check") or "확인필요",
            "needs_confirmation": "확인필요" in str(c.get("result") or c.get("check") or "")
        })
    ai_score = payload.get("ai_score") or {}
    score_val = ai_score.get("score") if isinstance(ai_score, dict) else None
    return json_ok(
        checklist=checklist,
        attractiveness_score=score_val if score_val is not None else 0,
        reasons=(ai_score.get("reasons") if isinstance(ai_score, dict) else []),
        ai_comment=payload.get("ai_comment") or "",
        kepco_capacity=payload.get("kepco_capacity") or ""
    )



# ------------------------------------------------------------
# Report rendering (HTML + PDF)
# ------------------------------------------------------------
FALLBACK_REPORT_TEMPLATE = r"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Solar Pathfinder Report</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;color:#111}
    .wrap{max-width:980px;margin:0 auto}
    h1{margin:0 0 8px;font-size:28px}
    .sub{color:#555;margin:0 0 18px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .card{border:1px solid #e6e6e6;border-radius:10px;padding:14px}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;font-size:13px}
    .bar{height:12px;background:#eee;border-radius:999px;overflow:hidden}
    .bar>div{height:12px;background:#111}
    .btn{display:inline-block;padding:10px 14px;border:1px solid #111;border-radius:10px;text-decoration:none;color:#111}
    .muted{color:#666;font-size:13px}
  </style>
</head>
<body>
<div class="wrap">
  <h1>태양광 정밀 리포트</h1>
  <p class="sub">주소: <b>{{ data.address or "확인 필요" }}</b> · 날짜: {{ data.date or "-" }}</p>

  <p><a class="btn" href="#" onclick="document.getElementById('pdfForm').submit();return false;">PDF 다운로드</a></p>

  <form id="pdfForm" method="POST" action="/report/pdf" style="display:none">
    <input name="address" value="{{ data.address or '' }}">
    <input name="capacity" value="{{ data.capacity or '' }}">
    <input name="date" value="{{ data.date or '' }}">
    <input name="kepco" value="{{ data.kepco or '' }}">
    <input name="land_price" value="{{ data.land_price or '' }}">
    <input name="finance" value='{{ (data.finance or {})|tojson }}'>
    <input name="ai_analysis" value='{{ (data.ai_analysis or [])|tojson }}'>
    <input name="ai_score" value='{{ (data.ai_score or {})|tojson }}'>
  </form>

  <div class="grid">
    <div class="card">
      <h3 style="margin:0 0 10px">구매매력도</h3>
      {% set s = (data.ai_score.score if data.ai_score and data.ai_score.score is not none else 0) %}
      <div class="bar" title="{{ s }}/100"><div style="width: {{ s }}%"></div></div>
      <p class="muted" style="margin:10px 0 0">{{ data.ai_score.ai_comment if data.ai_score else "" }}</p>
      {% if data.ai_score and data.ai_score.reasons %}
        <ul class="muted">
          {% for r in data.ai_score.reasons %}
            <li>{{ r }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">재무 요약</h3>
      {% if data.finance %}
        <table>
          <tr><th>항목</th><th>값</th></tr>
          <tr><td>연간 발전량</td><td>{{ data.finance.annualKwh or "-" }}</td></tr>
          <tr><td>연간 매출</td><td>{{ data.finance.annualRev or "-" }}</td></tr>
          <tr><td>총 비용</td><td>{{ data.finance.totalCost or "-" }}</td></tr>
          <tr><td>25년 총매출</td><td>{{ data.finance.totalRev25 or "-" }}</td></tr>
          <tr><td>연간 대출상환</td><td>{{ data.finance.annualDebt or "-" }}</td></tr>
          <tr><td>회수기간</td><td>{{ data.finance.payback or "-" }}</td></tr>
        </table>
      {% else %}
        <p class="muted">재무 데이터가 없습니다.</p>
      {% endif %}
    </div>

    <div class="card" style="grid-column:1 / -1">
      <h3 style="margin:0 0 10px">AI 중대 체크사항(8대 항목)</h3>
      {% if data.ai_analysis %}
        <table>
          <tr><th>항목</th><th>상태</th><th>링크</th></tr>
          {% for c in data.ai_analysis %}
            <tr>
              <td>{{ c.title or c.name or "-" }}</td>
              <td>{{ c.result or c.check or "확인필요" }}</td>
              <td>{% if c.link %}<a href="{{ c.link }}" target="_blank">열기</a>{% else %}-{% endif %}</td>
            </tr>
          {% endfor %}
        </table>
      {% else %}
        <p class="muted">AI 분석 결과가 없습니다.</p>
      {% endif %}
      <p class="muted" style="margin-top:10px">※ 국토환경성평가지도/생태등급 등 일부 데이터는 정확도 이슈가 있을 수 있으니 반드시 공식 시스템에서 재확인하세요.</p>
    </div>
  </div>
</div>
</body>
</html>
"""


@app.route("/api/finance/pf", methods=["POST", "OPTIONS"])
def finance_pf():
    """PF loan calculator (amortized / 원리금균등)."""
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    try:
        principal = float(data.get("principal") or 0)
        annual_rate = float(data.get("rate") or 0) / 100.0
        years = int(float(data.get("years") or 0))
        if principal <= 0 or years <= 0:
            return json_err("principal/years must be positive")
        n = years * 12
        r = annual_rate / 12.0
        if r == 0:
            monthly = principal / n
        else:
            monthly = principal * (r * (1 + r) ** n) / ((1 + r) ** n - 1)
        total_payment = monthly * n
        total_interest = total_payment - principal
        return json_ok(
            monthly=round(monthly),
            total_interest=round(total_interest),
            total_payment=round(total_payment),
            months=n,
            principal=principal,
            rate=annual_rate,
            years=years,
            method="원리금균등"
        )
    except Exception as e:
        return json_err(f"invalid input: {e}")

def _load_report_template() -> str:
    p = APP_DIR / "report.html"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    return FALLBACK_REPORT_TEMPLATE


def _parse_report_form(form) -> dict:
    def _json_field(name: str):
        try:
            return json.loads(form.get(name) or "{}")
        except Exception:
            return {}

    return {
        "address": form.get("address") or "",
        "capacity": form.get("capacity") or "",
        "kepco": form.get("kepco") or "",
        "date": form.get("date") or "",
        "finance": _json_field("finance"),
        "ai_analysis": _json_field("ai_analysis"),
        "ai_score": _json_field("ai_score"),
        "land_price": form.get("land_price") or "",
    }


@app.route("/report", methods=["GET", "POST"])
def report_html():
    # GET: allow user to open link without POST (shows empty template)
    if request.method == "GET":
        tpl = _load_report_template()
        html = render_template_string(tpl, data=_parse_report_form({}))
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    data = _parse_report_form(request.form)
    tpl = _load_report_template()
    html = render_template_string(tpl, data=data)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/report.html", methods=["GET"])
def report_html_alias():
    return redirect("/report", code=302)


@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = _parse_report_form(request.form)

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    x0 = 18 * mm
    y = h - 18 * mm
    lh = 6.5 * mm

    def draw_line(txt, size=11, bold=False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x0, y, txt)
        y -= lh

    draw_line("Solar Pathfinder Report", 16, True)
    draw_line(f"Date: {data.get('date') or '-'}", 11, False)
    draw_line(f"Address: {data.get('address') or '-'}", 11, False)
    draw_line(f"Capacity: {data.get('capacity') or '-'}", 11, False)
    draw_line(f"KEPCO: {data.get('kepco') or '-'}", 11, False)
    y -= lh

    fin = data.get("finance") or {}
    ai_score = data.get("ai_score") or {}
    draw_line("Financial Summary", 13, True)
    for k in ["annualKwh", "annualRev", "totalCost", "totalRev25", "annualDebt", "payback"]:
        v = fin.get(k)
        if v is None:
            continue
        draw_line(f"- {k}: {v}", 10, False)

    y -= lh
    draw_line("AI Score", 13, True)
    draw_line(f"Score: {ai_score.get('score', '-')}/100  Grade: {ai_score.get('grade','-')}", 11, True)
    reasons = ai_score.get("reasons") or []
    if reasons:
        draw_line("Reasons:", 11, False)
        for r in reasons[:12]:
            draw_line(f"  • {r}", 9, False)

    c.showPage()
    c.save()

    pdf = buf.getvalue()
    resp = make_response(pdf)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="solar_report.pdf"'
    return resp


@app.route("/api/report/pdf", methods=["POST", "OPTIONS"])
def api_report_pdf():
    """JSON-based PDF generation endpoint (alias)."""
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    # Convert to a fake form dict compatible with existing PDF generator expectations
    # We call report_pdf() by temporarily populating request.form is not trivial; instead,
    # we generate here by reusing the same internal logic as /report/pdf.
    # Minimal PDF content mirrors report_pdf.
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    def _t(s): 
        return str(s) if s is not None else ""

    y = h - 60
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "태양광 발전사업 리포트")
    y -= 26
    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"주소: {_t(data.get('address','확인 필요'))}")
    y -= 16
    c.drawString(40, y, f"용량: {_t(data.get('capacity','-'))}")
    y -= 16
    c.drawString(40, y, f"날짜: {_t(data.get('date','-'))}")
    y -= 22

    # AI score
    score = data.get("attractiveness_score")
    if score is None and isinstance(data.get("ai_score"), dict):
        score = data["ai_score"].get("score")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, f"구매매력도: {_t(score)}/100")
    y -= 18

    checklist = data.get("checklist") or data.get("checks") or []
    if checklist:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "8대 체크 항목")
        y -= 14
        c.setFont("Helvetica", 10)
        for item in checklist[:12]:
            title = item.get("category") or item.get("title") or item.get("name") or ""
            status = item.get("status") or item.get("result") or item.get("check") or ""
            c.drawString(46, y, f"• {title}: {status}")
            y -= 12
            if y < 60:
                c.showPage()
                y = h - 60
                c.setFont("Helvetica", 10)

    c.showPage()
    c.save()

    pdf = buf.getvalue()
    resp = make_response(pdf)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="solar_report.pdf"'
    return resp

if __name__ == "__main__":
    # default: http://127.0.0.1:5000
    app.run(host="0.0.0.0", port=int(os.getenv("PORT") or 5000), debug=True)
