import os
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, request, jsonify, render_template_string, make_response
import json
from pathlib import Path
from io import BytesIO
from flask_cors import CORS

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle


app = Flask(__name__)

def _cors_origins():
    v = os.getenv("CORS_ORIGINS", "").strip()
    if not v:
        return ["*"]
    return [x.strip() for x in v.split(",") if x.strip()]

CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins()}},
    allow_headers=["Content-Type", "Authorization", "X-CLIENT-TOKEN", "X-CLIENT-FP"],
    methods=["GET", "POST", "OPTIONS"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
if not ADMIN_API_KEY:
    raise RuntimeError("ADMIN_API_KEY not set")

SECRET_KEY = (os.getenv("SECRET_KEY") or "").encode("utf-8")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set")

PUBLIC_VWORLD_KEY = (os.getenv("VWORLD_KEY") or "").strip()
PUBLIC_KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()

def now_utc():
    return datetime.now(timezone.utc)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def ensure_schema():
    ddl = """
    CREATE TABLE IF NOT EXISTS licenses (
        token TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        note TEXT
    );

    CREATE TABLE IF NOT EXISTS bindings (
        id BIGSERIAL PRIMARY KEY,
        token TEXT NOT NULL REFERENCES licenses(token) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bindings_fp ON bindings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_bindings_token ON bindings(token);
    """
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(ddl)
    finally:
        conn.close()

ensure_schema()

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_admin_session(ttl_hours: int = 8) -> str:
    exp = int((now_utc() + timedelta(hours=ttl_hours)).timestamp())
    nonce = secrets.token_urlsafe(12)
    payload = f"exp={exp}&nonce={nonce}".encode("utf-8")
    sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    return _b64url(payload) + "." + _b64url(sig)

def verify_admin_session(token: str) -> bool:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_dec(payload_b64)
        sig = _b64url_dec(sig_b64)
        expect = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return False
        parts = dict(x.split("=", 1) for x in payload.decode("utf-8").split("&"))
        exp = int(parts.get("exp", "0"))
        return int(now_utc().timestamp()) < exp
    except Exception:
        return False

def require_admin():
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        return False
    tok = auth.split(" ", 1)[1].strip()
    return verify_admin_session(tok)

def gen_license_token(prefix="SCE", nbytes=8) -> str:
    return f"{prefix}-" + secrets.token_hex(nbytes).upper()

def json_ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return jsonify(d)

def json_bad(msg, status=400, **kw):
    d = {"ok": False, "msg": msg}
    d.update(kw)
    return jsonify(d), status

@app.route("/api/health", methods=["GET"])
def health():
    return json_ok()

@app.route("/api/config/public", methods=["GET"])
def public_config():
    return jsonify({
        "ok": True,
        "vworld_key": PUBLIC_VWORLD_KEY,
        "kepco_key": PUBLIC_KEPCO_KEY,
    })

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
    if days not in (30, 60, 90, 180, 365) and not (1 <= days <= 3650):
        return json_bad("invalid days", 400)

    note = (data.get("note") or "").strip()[:500]
    token = gen_license_token()
    expires = now_utc() + timedelta(days=days)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO licenses(token, expires_at, note) VALUES(%s,%s,%s)",
                (token, expires, note),
            )
    finally:
        conn.close()

    return json_ok(token=token, expires_at=expires.isoformat(), days=days)

@app.route("/api/admin/licenses", methods=["GET"])
def admin_licenses():
    if not require_admin():
        return json_bad("unauthorized", 401)
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, expires_at, created_at, note FROM licenses ORDER BY created_at DESC LIMIT 200"
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "items": [
            {
                "token": r[0],
                "expires_at": r[1].isoformat(),
                "created_at": r[2].isoformat(),
                "note": r[3] or "",
            } for r in rows
        ],
    })

@app.route("/api/license/activate", methods=["POST", "OPTIONS"])
def activate_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT expires_at FROM licenses WHERE token=%s", (token,))
            row = cur.fetchone()
            if not row:
                return json_bad("invalid token", 404)
            expires_at = row[0]
            if expires_at <= now_utc():
                return json_bad("expired token", 403, expires_at=expires_at.isoformat())

            cur.execute(
                "INSERT INTO bindings(token, fingerprint, expires_at) VALUES(%s,%s,%s)",
                (token, fp, expires_at),
            )
    finally:
        conn.close()

    return json_ok(expires_at=expires_at.isoformat())

@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify_license():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or request.headers.get("X-CLIENT-TOKEN") or "").strip()
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()

    if not token or not fp:
        return json_bad("token and fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT expires_at FROM bindings WHERE token=%s AND fingerprint=%s ORDER BY bound_at DESC LIMIT 1",
                (token, fp),
            )
            row = cur.fetchone()
            if not row:
                return json_bad("not bound", 403)
            expires_at = row[0]
            if expires_at <= now_utc():
                return json_bad("expired", 403, expires_at=expires_at.isoformat())
    finally:
        conn.close()

    return json_ok(expires_at=expires_at.isoformat())

@app.route("/api/auth/auto", methods=["POST", "OPTIONS"])
def auto_auth():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    fp = (data.get("fingerprint") or request.headers.get("X-CLIENT-FP") or "").strip()
    if not fp:
        return json_bad("fingerprint required", 400)

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, expires_at FROM bindings WHERE fingerprint=%s ORDER BY bound_at DESC LIMIT 1",
                (fp,),
            )
            row = cur.fetchone()
            if not row:
                return json_bad("no binding", 403)
            token, expires_at = row
            if expires_at <= now_utc():
                return json_bad("expired", 403, expires_at=expires_at.isoformat())
    finally:
        conn.close()

    return json_ok(token=token, expires_at=expires_at.isoformat())


# -----------------------------
# AI-lite comprehensive analysis (server-side stub)
# -----------------------------
def _mock_sun_hours(lat: float) -> float:
    # rough annual average PSH in Korea-like latitudes: 3.3~4.4
    base = 4.2 - abs(lat - 36.5) * 0.05
    return float(max(3.2, min(4.5, base)))

def _conservative_score(payload: dict) -> dict:
    # conservative scoring: start from 60 then subtract risks
    score = 60
    reasons = []
    addr = (payload.get("address") or "").lower()

    # risk heuristics
    if "pnu" in addr or "토지" in addr:
        score -= 3
        reasons.append("토지는 인허가/환경 리스크가 상대적으로 큼")
    if any(k in addr for k in ["농", "임야", "보전", "문화재"]):
        score -= 10
        reasons.append("규제 가능성이 있는 키워드(농/임야/보전/문화재) 포함")

    # kepco capacity missing -> penalize
    kepco = payload.get("kepco_capacity") or ""
    if not kepco or "정보" in kepco or "확인" in kepco or "DB" in kepco:
        score -= 12
        reasons.append("한전 연계 가능용량 확인 필요")

    # keep within 0~100
    score = int(max(0, min(100, score)))
    if score >= 75:
        grade = "매력도 상"
    elif score >= 55:
        grade = "매력도 중"
    elif score >= 35:
        grade = "매력도 하"
    else:
        grade = "투자 비추천"

    if not reasons:
        reasons = ["주요 리스크 항목 추가 확인 필요"]
    return {"score": score, "grade": grade, "reasons": reasons}

@app.route("/api/analyze/comprehensive", methods=["POST", "OPTIONS"])
def analyze_comprehensive():
    if request.method == "OPTIONS":
        return ("", 204)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        lat = float(payload.get("lat") or 0)
        lng = float(payload.get("lng") or 0)
    except Exception:
        lat, lng = 0.0, 0.0

    address = (payload.get("address") or "").strip()

    sun = _mock_sun_hours(lat) if lat else 4.0

    # KEPCO: real integration not included in this template; return placeholder
    kepco_cap = "확인필요 (한전온/내부DB 연동 필요)"

    data = {
        "status": "OK",
        "address": address,
        "lat": lat,
        "lng": lng,
        "zoning": "확인필요 (토지이음/지자체 조례)",
        "env_assessment": "확인필요 (소규모 환경영향평가 대상 여부)",
        "eco_grade": "확인필요 (자연/생태 등급)",
        "heritage": "확인필요 (문화재/국가유산 규제)",
        "slope_note": "경사도/생태등급은 오차 가능 → 평균 경사도만 참고 후 '확인필요'",
        "kepco_capacity": kepco_cap,
        "sun_hours": round(sun, 2),
        "links": {
            "elis": "https://www.elis.go.kr/",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "law": "https://www.law.go.kr/",
            "aid": "https://aid.mcee.go.kr/",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?",
            "neins": "https://webgis.neins.go.kr/map.do",
            "kepco": "https://online.kepco.co.kr/",
        },
    }

    data["ai_score"] = _conservative_score({**payload, "kepco_capacity": data["kepco_capacity"]})
    data["ai_comment"] = (
        f"일사량(추정): {data['sun_hours']}h/day. "
        f"규제/인허가(조례·상위법·환경·문화재) 및 한전 연계용량은 링크에서 반드시 재확인하세요."
    )
    return jsonify(data)

# -----------------------------
# Report rendering (HTML) + PDF download
# -----------------------------
_REPORT_HTML = Path(__file__).with_name("report.html")

def _load_report_template() -> str:
    try:
        return _REPORT_HTML.read_text(encoding="utf-8")
    except Exception:
        # fallback: minimal template
        return "<html><body><pre>{{ data|tojson }}</pre></body></html>"

def _parse_report_form(form) -> dict:
    address = (form.get("address") or "").strip()
    date = (form.get("date") or "").strip() or datetime.now().strftime("%Y-%m-%d")
    kepco = (form.get("kepco") or "").strip()

    finance_raw = form.get("finance") or "{}"
    ai_raw = form.get("ai") or "{}"

    try:
        finance = json.loads(finance_raw)
    except Exception:
        finance = {}
    try:
        ai = json.loads(ai_raw)
    except Exception:
        ai = {}

    # keep compatibility fields
    data = {
        "address": address,
        "date": date,
        "kepco_capacity": kepco or ai.get("kepco_capacity") or "",
        "finance": finance,
        "ai_analysis": ai,
    }
    return data

@app.route("/report", methods=["POST"])
def report_html():
    data = _parse_report_form(request.form)
    tpl = _load_report_template()
    html = render_template_string(tpl, data=data)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = _parse_report_form(request.form)
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    def t(x, y, s, size=11, bold=False):
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x, y, s)

    y = h - 20*mm
    t(20*mm, y, "SCEnergy 태양광 분석 리포트", 16, True); y -= 10*mm
    t(20*mm, y, f"주소: {data.get('address','-')}", 11); y -= 6*mm
    t(20*mm, y, f"작성일: {data.get('date','-')}", 11); y -= 10*mm

    fin = data.get("finance") or {}
    ai = data.get("ai_analysis") or {}
    score = (ai.get("ai_score") or {}).get("score")
    grade = (ai.get("ai_score") or {}).get("grade")

    rows = [
        ["항목", "값"],
        ["AC 용량", fin.get("acCapacity") or fin.get("capacity") or "-"],
        ["연 발전량", fin.get("annualKwh") or "-"],
        ["연 매출", fin.get("annualRev") or "-"],
        ["총 사업비", fin.get("totalCost") or "-"],
        ["25년 총매출", fin.get("totalRev25") or "-"],
        ["PF 상환(연)", fin.get("annualDebt") or "-"],
        ["회수기간", fin.get("payback") or "-"],
        ["한전 연계용량", ai.get("kepco_capacity") or data.get("kepco_capacity") or "-"],
        ["일사량(추정)", f"{ai.get('sun_hours','-')} h/day"],
        ["구매매력도", f"{score}점 ({grade})" if score is not None else "-"],
    ]
    table = Table(rows, colWidths=[35*mm, 140*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("BACKGROUND", (0,1), (-1,-1), colors.whitesmoke),
    ]))
    table.wrapOn(c, w, h)
    table.drawOn(c, 20*mm, y-85*mm)
    y -= 95*mm

    # reasons
    reasons = (ai.get("ai_score") or {}).get("reasons") or []
    t(20*mm, y, "주요 확인/리스크", 12, True); y -= 6*mm
    c.setFont("Helvetica", 9)
    for r in reasons[:8]:
        c.drawString(23*mm, y, f"• {str(r)[:120]}")
        y -= 5*mm

    c.showPage()
    c.save()
    buf.seek(0)
    pdf = buf.getvalue()
    resp = make_response(pdf)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = "attachment; filename=solar_report.pdf"
    return resp
