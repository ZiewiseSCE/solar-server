import os
import secrets
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import BytesIO

from flask import Flask, request, jsonify, make_response, render_template_string, redirect, send_file
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer

# Optional ReportLab (PDF)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
except Exception:
    A4 = None

# -----------------------------
# App init
# -----------------------------
app = Flask(__name__)

# -----------------------------
# Config (env)
# -----------------------------
APP_DIR = Path(__file__).resolve().parent

# [보안] ADMIN 키 설정
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
if not ADMIN_API_KEY:
    generated_key = secrets.token_urlsafe(32)
    print(f"\n[WARNING] ADMIN_API_KEY is not set! Using random key: {generated_key}\n")
    ADMIN_API_KEY = generated_key

SECRET_KEY = (os.getenv("SECRET_KEY") or "dev-secret").strip()
app.secret_key = SECRET_KEY

# [DB] PostgreSQL 연결 정보
DATABASE_URL = os.getenv("DATABASE_URL")

# CORS (중복 제거 및 통합)
_raw_origins = (os.getenv("CORS_ORIGINS") or "https://pathfinder.scenergy.co.kr").strip()
CORS_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# 모든 경로에 대해 CORS 허용 (Credentials 포함)
CORS(
    app,
    resources={r"/*": {"origins": CORS_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key"]
)

# -----------------------------
# Database Helpers (PostgreSQL)
# -----------------------------
def get_db_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set.")
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    if not DATABASE_URL:
        print("[DB] DATABASE_URL not set. Running in stateless mode.")
        return
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                token TEXT PRIMARY KEY,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                note TEXT NOT NULL DEFAULT '',
                bound_fp TEXT NOT NULL DEFAULT '',
                bound_at TIMESTAMPTZ NULL
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[DB] Initialized.")
    except Exception as e:
        print(f"[DB] Initialization failed: {e}")

with app.app_context():
    init_db()

# -----------------------------
# Auth & Helpers
# -----------------------------
def _serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="admin-session")

def _issue_admin_token():
    return _serializer().dumps({"role": "admin"})

def _verify_admin_token(token, max_age=60*60*24*7):
    return _serializer().loads(token, max_age=max_age)

def json_ok(**kwargs):
    d = {"ok": True, "status": "OK"}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg: str, code: int = 400, **kwargs):
    d = {"ok": False, "status": "ERROR", "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

def _require_admin():
    # 1. Check Bearer Token
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = _verify_admin_token(token)
            if payload.get("role") == "admin":
                return True
        except Exception as e:
            print(f"[Auth] Token verify failed: {e}")
            pass

    # 2. Check Admin Key (Direct)
    key = (request.headers.get("X-Admin-Key") or request.args.get("admin_key") or "").strip()
    return key == ADMIN_API_KEY

def _now_utc():
    return datetime.now(timezone.utc)

def _iso(dt: datetime):
    return dt.astimezone(timezone.utc).isoformat()

# -----------------------------
# Admin Page Route
# -----------------------------
@app.route("/admin", methods=["GET"])
def admin_page():
    p = APP_DIR / "admin.html"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    return "<h1>Admin file not found</h1>", 404

# -----------------------------
# Admin Auth Endpoints
# -----------------------------
@app.route("/api/auth/whoami", methods=["GET", "OPTIONS"])
def whoami():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)
    return json_ok(role="admin")

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS": return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    admin_key = (data.get("admin_key") or "").strip()

    if admin_key != ADMIN_API_KEY:
        return json_bad("unauthorized", 401)

    token = _issue_admin_token()
    return json_ok(token=token, role="admin")

# -----------------------------
# License Management (DB Connected)
# -----------------------------
@app.route("/api/admin/licenses", methods=["GET", "OPTIONS"])
def admin_list_licenses():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM licenses ORDER BY expires_at DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()

        results = []
        for row in rows:
            item = dict(row)
            if item.get('expires_at'): item['expires_at'] = _iso(item['expires_at'])
            if item.get('bound_at'): item['bound_at'] = _iso(item['bound_at'])
            item['fingerprints'] = [item['bound_fp']] if item['bound_fp'] else []
            results.append(item)

        return json_ok(items=results)
    except Exception as e:
        return json_bad("DB Error", 500, detail=str(e))

@app.route("/api/admin/license/create", methods=["POST", "OPTIONS"])
def admin_create_license():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)

    data = request.get_json(force=True, silent=True) or {}
    note = (data.get("note") or "").strip()
    days = int(data.get("days") or 365)
    
    token = "SCE-" + secrets.token_hex(5).upper()
    now = _now_utc()
    expires_at = now + timedelta(days=days)

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO licenses (token, expires_at, note, revoked, bound_fp)
            VALUES (%s, %s, %s, FALSE, '')
            RETURNING token
        """, (token, expires_at, note))
        conn.commit()
        cur.close()
        conn.close()

        item = {
            "token": token,
            "created_at": _iso(now),
            "expires_at": _iso(expires_at),
            "note": note,
            "fingerprints": []
        }
        return json_ok(item=item)
    except Exception as e:
        return json_bad("DB Insert Failed", 500, detail=str(e))

@app.route("/api/admin/license/reset", methods=["POST", "OPTIONS"])
def admin_license_reset():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)
    
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE licenses SET bound_fp = '', bound_at = NULL WHERE token = %s RETURNING token", (token,))
        updated = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        if not updated:
            return json_bad("not found", 404)
        return json_ok(removed=1)
    except Exception as e:
        return json_bad("DB Error", 500, detail=str(e))

@app.route("/api/admin/license/extend", methods=["POST", "OPTIONS"])
def admin_license_extend():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)
    
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    days = int(data.get("days") or 30)

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT expires_at FROM licenses WHERE token = %s", (token,))
        row = cur.fetchone()
        if not row:
            return json_bad("not found", 404)
        
        current_expiry = row[0]
        if current_expiry < _now_utc():
            new_expiry = _now_utc() + timedelta(days=days)
        else:
            new_expiry = current_expiry + timedelta(days=days)
            
        cur.execute("UPDATE licenses SET expires_at = %s WHERE token = %s RETURNING expires_at", (new_expiry, token))
        conn.commit()
        cur.close()
        conn.close()
        return json_ok(expires_at=_iso(new_expiry))
    except Exception as e:
        return json_bad("DB Error", 500, detail=str(e))

@app.route("/api/admin/license/delete", methods=["POST", "OPTIONS"])
def admin_license_delete():
    if request.method == "OPTIONS": return ("", 204)
    if not _require_admin(): return json_bad("unauthorized", 401)
    
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM licenses WHERE token = %s RETURNING token", (token,))
        deleted = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if not deleted:
            return json_bad("not found", 404)
        return json_ok()
    except Exception as e:
        return json_bad("DB Error", 500, detail=str(e))

# -----------------------------
# AI Analysis & Report (유지)
# -----------------------------
def _build_ai_result(lat: float, lng: float, address: str, mode: str = "", area_m2: float = 0.0):
    checks = [
        {"title":"1. 도시/자치 조례 (이격거리)", "result":"확인 필요 (지자체 조례 참조)", "link":"https://www.elis.go.kr/"},
        {"title":"2. 용도지역 (토지이음)", "result":"확인 필요", "link":"https://www.eum.go.kr/web/am/amMain.jsp"},
        {"title":"3. 상위법 규제 (환경/농지)", "result":"확인 필요", "link":"https://www.law.go.kr/"},
        {"title":"4. 자연/생태 등급", "result":"확인 필요", "link":"https://aid.mcee.go.kr/"},
        {"title":"5. 문화재/국가유산", "result":"확인 필요", "link":"https://www.nie-ecobank.kr/"},
        {"title":"6. 국토환경성평가 (경사도)", "result":"평균 경사도: 확인 필요 (정확도 확인필요)", "link":"https://webgis.neins.go.kr/map.do"},
        {"title":"7. 소규모 환경영향평가", "result":"면적/용도지역 기반 확인 필요", "link":"https://www.law.go.kr/"},
        {"title":"8. 한전 선로 용량", "result":"확인 필요 (한전ON)", "link":"https://online.kepco.co.kr/"},
    ]

    score = 70
    reasons = []
    uncertain = sum(1 for c in checks if "확인 필요" in (c.get("result") or ""))
    score -= min(35, uncertain * 4)
    if area_m2 and area_m2 < 300:
        score -= 10; reasons.append("면적이 작아 경제성이 낮을 수 있음 (-10)")
    if mode == "land":
        score -= 5; reasons.append("토지형은 인허가 변수/리스크가 커 보수적으로 감점 (-5)")
    if score < 0: score = 0

    ai_score = {
        "score": score,
        "grade": ("A" if score>=85 else "B" if score>=70 else "C" if score>=55 else "D"),
        "confidence": max(55, 90-uncertain*4),
        "reasons": reasons if reasons else ["체크리스트 확인 필요 항목이 다수 존재하여 보수적 평가"]
    }

    return {
        "checks": checks,
        "sun_hours": 3.8,
        "kepco_capacity": "확인 필요",
        "ai_score": ai_score,
        "ai_comment": "데이터 확정 전까지는 보수적 점수이며, 체크리스트 링크에서 필수 확인이 필요합니다."
    }

@app.route("/api/analyze/comprehensive", methods=["POST","OPTIONS"])
def analyze_comprehensive():
    if request.method == "OPTIONS": return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    result = _build_ai_result(
        float(data.get("lat") or 0),
        float(data.get("lng") or 0),
        (data.get("address") or "").strip(),
        (data.get("mode") or "").strip(),
        float(data.get("area_m2") or 0)
    )
    return json_ok(**result)

@app.route("/api/ai/analyze", methods=["POST","OPTIONS"])
def ai_analyze():
    if request.method == "OPTIONS": return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    result = _build_ai_result(
        float(data.get("lat") or 0),
        float(data.get("lng") or 0),
        (data.get("address") or "").strip(),
        (data.get("mode") or "").strip(),
        float(data.get("area_m2") or 0)
    )
    checklist = []
    for c in result["checks"]:
        checklist.append({
            "category": c["title"],
            "status": c["result"],
            "link": c.get("link",""),
            "needs_review": ("확인 필요" in (c.get("result") or "")) or ("확인필요" in (c.get("result") or ""))
        })

    return jsonify({
        "ok": True,
        "checklist": checklist,
        "attractiveness_score": result["ai_score"]["score"],
        "reasons": result["ai_score"].get("reasons", []),
        **result
    })

# -----------------------------
# Finance & Report
# -----------------------------
@app.route("/api/finance/pf", methods=["POST","OPTIONS"])
def finance_pf():
    if request.method == "OPTIONS": return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    try:
        principal = float(data.get("principal") or 0)
        rate = float(data.get("rate") or 0) / 100.0
        years = int(data.get("years") or 0)
        if principal <= 0 or rate < 0 or years <= 0: return json_bad("invalid inputs", 400)
        n = years * 12
        r = rate / 12.0
        monthly = principal / n if r == 0 else principal * (r * (1+r)**n) / ((1+r)**n - 1)
        total_payment = monthly * n
        total_interest = total_payment - principal
        return json_ok(
            monthly_payment=round(monthly),
            total_payment=round(total_payment),
            total_interest=round(total_interest),
            schedule="원리금균등"
        )
    except Exception as e:
        return json_bad("calc failed", 500, detail=str(e))

def _load_report_template() -> str:
    p = APP_DIR / "report.html"
    if p.exists(): return p.read_text(encoding="utf-8", errors="ignore")
    return "<h1>Report Template Missing</h1>"

def _parse_report_form(form) -> dict:
    def _json_field(*names):
        for name in names:
            v = form.get(name)
            if not v: continue
            try: return json.loads(v)
            except Exception: continue
        return {}

    return {
        "address": form.get("address") or "",
        "capacity": form.get("capacity") or "",
        "kepco_capacity": form.get("kepco_capacity") or form.get("kepco") or "",
        "date": form.get("date") or "",
        "finance": _json_field("finance"),
        "ai_analysis": _json_field("ai_analysis","ai"),
        "ai_score": _json_field("ai_score","score"),
        "land_price": form.get("land_price") or form.get("price") or "",
    }

@app.route("/report", methods=["GET","POST"])
def report_html():
    if request.method == "GET":
        tpl = _load_report_template()
        html = render_template_string(tpl, data={})
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
def report_alias():
    return redirect("/report")

def _render_pdf(data: dict) -> bytes:
    if A4 is None: return b""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    x0 = 18 * mm
    y = h - 18 * mm
    lh = 7 * mm

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x0, y, "Solar PV Analysis Report")
    y -= lh*2
    
    c.setFont("Helvetica", 10)
    c.drawString(x0, y, f"Address: {data.get('address','')}")
    y -= lh
    c.drawString(x0, y, f"Date: {data.get('date','')}")
    y -= lh*2

    fin = data.get("finance") or {}
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x0, y, "[Financial Summary]")
    y -= lh
    c.setFont("Helvetica", 10)
    for k in ["acCapacity","dcCapacity","totalCost","annualRev","annualKwh","loan","equity","payback"]:
        c.drawString(x0+10, y, f"{k}: {fin.get(k,'-')}")
        y -= lh
    y -= lh
    
    c.showPage()
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf

@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = _parse_report_form(request.form)
    pdf = _render_pdf(data)
    resp = make_response(pdf)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="solar_report.pdf"'
    return resp

@app.route("/api/report/pdf", methods=["POST","OPTIONS"])
def api_report_pdf():
    if request.method == "OPTIONS": return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    pdf = _render_pdf(data)
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name="solar_report.pdf")

@app.route("/api/health", methods=["GET"])
def health():
    db_status = "ok"
    try:
        conn = get_db_connection()
        conn.close()
    except Exception as e:
        db_status = f"error: {str(e)}"
    return json_ok(ts=_iso(_now_utc()), db=db_status)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT") or 5000))
