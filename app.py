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


@app.route("/api/admin/licenses", methods=["GET"])
def admin_list_licenses():
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


# ------------------------------------------------------------
# Report rendering (HTML + PDF)
# ------------------------------------------------------------
def _load_report_template() -> str:
    p = APP_DIR / "report.html"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    return "<html><body><h1>report.html not found</h1></body></html>"


def _parse_report_form(form) -> dict:
    def _json_field(*names: str):
        # accept multiple possible field names (backward/forward compatibility)
        for name in names:
            if not name:
                continue
            raw = form.get(name)
            if raw is None:
                continue
            raw = raw.strip() if isinstance(raw, str) else raw
            if raw in ("", None):
                continue
            try:
                return json.loads(raw)
            except Exception:
                # if it's already a dict-like or invalid json, ignore
                pass
        return {}

    return {
        "address": form.get("address") or "",
        "capacity": form.get("capacity") or "",
        # old/new field names support
        "kepco": (form.get("kepco") or form.get("kepco_capacity") or ""),
        "date": form.get("date") or "",
        "finance": _json_field("finance"),
        # support solar_pathfinder.html hidden fields: ai / ai_analysis
        "ai_analysis": _json_field("ai_analysis", "ai"),
        "ai_score": _json_field("ai_score", "score"),
        "land_price": (form.get("land_price") or form.get("price") or ""),
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


if __name__ == "__main__":
    # default: http://127.0.0.1:5000
    app.run(host="0.0.0.0", port=int(os.getenv("PORT") or 5000), debug=True)
