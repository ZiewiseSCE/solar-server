import os
import datetime
import psycopg2
import json
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

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
    SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE','None'),
    SESSION_COOKIE_SECURE=(os.environ.get('SESSION_COOKIE_SECURE','true').lower()=='true'),
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
    # Accept both form-encoded and JSON payloads
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        address = payload.get("address","")
        capacity = payload.get("capacity","")
        kepco_capacity = payload.get("kepco_capacity","")
        date = payload.get("date","")
        finance = payload.get("finance") or {}
        ai = payload.get("ai_analysis") or payload.get("ai") or {}
    else:
        address = request.form.get("address","")
        capacity = request.form.get("capacity","")
        kepco_capacity = request.form.get("kepco_capacity","")
        date = request.form.get("date","")
        finance = _safe_json(request.form.get("finance","{}"))
        ai = _safe_json(request.form.get("ai","{}"))
    return render_template("report.html",
                           address=address,
                           capacity=capacity,
                           kepco_capacity=kepco_capacity,
                           date=date,
                           finance_json=json.dumps(finance, ensure_ascii=False),
                           ai_json=json.dumps(ai, ensure_ascii=False))


def _safe_json(s):
    try:
        if not s:
            return {}
        return json.loads(s)
    except Exception:
        return {}

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

@app.post("/api/finance/pf")
def api_pf_calc():
    payload = request.get_json(silent=True) or {}
    principal = float(payload.get("principal", 0) or 0)
    annual_rate = float(payload.get("annual_rate", 0) or 0) / 100.0
    years = int(payload.get("years", 0) or 0)
    months = max(1, years*12)
    r = annual_rate/12.0
    if principal <= 0 or annual_rate <= 0 or years <= 0:
        return jsonify({"ok":True, "principal":principal, "annual_rate":annual_rate*100, "years":years,
                        "monthly_payment":0, "total_payment":principal, "total_interest":0})
    # annuity payment
    try:
        monthly = principal * (r * (1+r)**months) / (((1+r)**months) - 1)
    except ZeroDivisionError:
        monthly = principal / months
    total = monthly * months
    interest = max(0, total - principal)
    return jsonify({"ok":True,
                    "principal":principal,
                    "annual_rate":annual_rate*100,
                    "years":years,
                    "monthly_payment":round(monthly,2),
                    "total_payment":round(total,2),
                    "total_interest":round(interest,2)})

@app.get("/health")
def health():
    return "ok", 200

# ===== auth =====

@app.post("/api/ai/analyze")
def api_ai_analyze():
    # NOTE: 외부 "AI 검색"은 키/약관/크롤링 이슈가 있어 서버에서는 직접 조회하지 않고,
    # 사용자가 확인할 수 있도록 근거 링크 + 보수적 스코어링을 제공합니다.
    payload = request.get_json(silent=True) or {}
    lat = payload.get("lat")
    lng = payload.get("lng")
    address = payload.get("address","")
    pnu = payload.get("pnu") or payload.get("PNU")

    # 8대 중대 체크사항 (근거 링크 포함)
    checks = [
        {"name":"도시/자치 조례", "source":"자치법규정보시스템(ELIS)", "url":"https://www.elis.go.kr/", "result":"확인필요", "note":"해당 지자체 조례(이격/제한구역/경관지구 등) 확인"},
        {"name":"토지 용도지역/지구", "source":"토지이음", "url":"https://www.eum.go.kr/web/am/amMain.jsp", "result":"확인필요", "note":"국토계획법상 용도지역/지구/구역 확인"},
        {"name":"상위법 규제", "source":"법제처", "url":"https://www.law.go.kr/", "result":"확인필요", "note":"환경법/농지법/산지법 등 상위법상 제한 확인"},
        {"name":"자연·생태 등급", "source":"환경공간정보서비스", "url":"https://aid.mcee.go.kr/", "result":"확인필요", "note":"육상태양광 지침/생태자연도 등급 확인"},
        {"name":"문화재/국가유산 규제", "source":"국가유산/생태관광(에코뱅크)", "url":"https://www.nie-ecobank.kr/cmmn/Index.do", "result":"확인필요", "note":"국가유산 보존관리지도/규제 범위 확인"},
        {"name":"국토환경성평가지도", "source":"국토환경성평가지도", "url":"https://webgis.neins.go.kr/map.do", "result":"참고", "note":"경사도/환경성은 오차가 있어 평균값만 참고(확인필요)"},
        {"name":"소규모 환경영향평가", "source":"법제처(검색)", "url":"https://www.law.go.kr/", "result":"확인필요", "note":"용도지역/면적 기준 해당 여부 표시 필요"},
        {"name":"한전 선로/변전소 용량", "source":"한전ON", "url":"https://online.kepco.co.kr/", "result":"확인필요", "note":"허용용량/초과 시 가능 연도 확인(수기 확인/자료 연동 필요)"},
    ]

    # 보수적 스코어링: 데이터가 없을수록 낮게
    score = 35
    if address: score += 10
    if pnu: score += 5
    # 위치가 있다면 약간 가산
    if lat is not None and lng is not None: score += 5
    # 기본 상한
    score = max(0, min(100, score))

    return jsonify({
        "status":"OK",
        "address": address,
        "pnu": pnu,
        "checks": checks,
        "kepco_capacity": None,
        "score": score,
        "note":"일부 항목은 공식 사이트/서류 확인이 필요합니다."
    })


@app.post("/api/report/pdf")
def api_report_pdf():
    payload = request.get_json(silent=True) or {}
    address = payload.get("address","")
    date = payload.get("date","")
    finance = payload.get("finance") or {}
    ai = payload.get("ai_analysis") or payload.get("ai") or {}
    score = ai.get("score")

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    # Basic font (Korean rendering depends on system fonts; we fall back gracefully)
    y = h - 20*mm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20*mm, y, "태양광 발전사업 분석 리포트")
    y -= 10*mm
    c.setFont("Helvetica", 10)
    c.drawString(20*mm, y, f"주소: {address}")
    y -= 6*mm
    c.drawString(20*mm, y, f"작성일: {date}")
    y -= 10*mm

    # Summary table
    cap = finance.get("capacity") or finance.get("acCapacity") or ""
    annual = finance.get("annualProfit") or finance.get("annual_profit") or finance.get("annualRevenue") or ""
    roi25 = finance.get("roi25") or finance.get("roi_25") or ""
    rows = [
        ["항목", "값"],
        ["설비용량(kW)", str(cap)],
        ["연 추정수익(원)", str(annual)],
        ["25년 ROI(%)", str(roi25)],
        ["구매매력도(0-100)", str(score) if score is not None else "—"],
    ]
    t = Table(rows, colWidths=[45*mm, 120*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(1,0), colors.lightgrey),
        ('GRID',(0,0),(-1,-1), 0.5, colors.grey),
        ('FONT',(0,0),(-1,0), 'Helvetica-Bold'),
        ('FONT',(0,1),(-1,-1), 'Helvetica'),
        ('ALIGN',(1,1),(1,-1),'LEFT'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    tw, th = t.wrapOn(c, w-40*mm, h)
    t.drawOn(c, 20*mm, y-th)
    y -= th + 12*mm

    # 8 checks
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20*mm, y, "8대 중대 체크사항")
    y -= 6*mm
    c.setFont("Helvetica", 9)
    checks = ai.get("checks") or []
    for chk in checks[:8]:
        line = f"- {chk.get('name','')}: {chk.get('result','')} ({chk.get('source','')})"
        c.drawString(22*mm, y, line[:120])
        y -= 5*mm
        if y < 25*mm:
            c.showPage()
            y = h - 20*mm
            c.setFont("Helvetica", 9)

    c.showPage()
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return (pdf, 200, {
        "Content-Type":"application/pdf",
        "Content-Disposition":"attachment; filename=report.pdf"
    })

@app.post("/api/auth/login")
def login():
    data = request.json or {}
    uid = data.get("id")
    pw = data.get("pw")

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "id/pw required"}), 400

    # 관리자 계정은 ADMIN_PW 환경변수로 초기화됩니다. 누락되면 로그인 불가
    if uid == ADMIN_ID and not ADMIN_PW:
        return jsonify({"ok": False, "msg": "ADMIN_PW is not configured on server"}), 500

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


@app.get("/api/auth/me")
def me():
    if not session.get("uid"):
        return jsonify({"ok": False, "loggedIn": False}), 200
    return jsonify({"ok": True, "loggedIn": True, "user": session.get("uid"), "role": session.get("role")})

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
