import os
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List

import psycopg2
from psycopg2.pool import SimpleConnectionPool
from flask import Flask, request, jsonify
from flask_cors import CORS

# =================================================
# App
# =================================================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")

# =================================================
# CORS (for public web UI only)
# NOTE: Admin operations are recommended via Cloudtype Terminal (curl),
# so CORS is mostly for public endpoints.
# =================================================
cors_origins_env = (os.getenv("CORS_ORIGINS", "") or "").strip()
ORIGINS = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else []
if not ORIGINS:
    ORIGINS = ["https://pathfinder.scenergy.co.kr", "https://www.scenergy.co.kr"]

CORS(
    app,
    resources={r"/api/*": {"origins": ORIGINS}},
    supports_credentials=False,
    allow_headers=["Content-Type", "X-CLIENT-TOKEN", "X-CLIENT-FP", "X-ADMIN-KEY"],
    methods=["GET", "POST", "OPTIONS"],
)

# =================================================
# Config
# =================================================
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

# =================================================
# DB Pool
# =================================================
_pool_lock = threading.Lock()
_pool: Optional[SimpleConnectionPool] = None


def _pool_get() -> SimpleConnectionPool:
    global _pool
    if _pool is not None:
        return _pool
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")

    with _pool_lock:
        if _pool is None:
            # Cloudtype internal Postgres usually works without sslmode.
            # If you use external managed Postgres, append ?sslmode=require if needed.
            _pool = SimpleConnectionPool(minconn=1, maxconn=5, dsn=DATABASE_URL)
    return _pool


def _db_exec(sql: str, params: tuple = (), fetch: str = "none"):
    """
    fetch: "none" | "one" | "all"
    """
    pool = _pool_get()
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch == "one":
                row = cur.fetchone()
            elif fetch == "all":
                row = cur.fetchall()
            else:
                row = None
        conn.commit()
        return row
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def _init_db() -> None:
    _db_exec(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            token TEXT PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            note TEXT NOT NULL DEFAULT '',
            bound_fp TEXT NOT NULL DEFAULT '',
            bound_at TIMESTAMPTZ NULL
        );
        """,
        fetch="none",
    )


# Init DB once (Flask 3 removed before_first_request)
_db_inited = False
_db_init_lock = threading.Lock()

def _ensure_db_inited() -> None:
    global _db_inited
    if _db_inited:
        return
    with _db_init_lock:
        if _db_inited:
            return
        _init_db()
        _db_inited = True

# =================================================
# Helpers
# =================================================
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(dt_str: str) -> datetime:
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _require_admin() -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (request.headers.get("X-ADMIN-KEY") or request.headers.get("X-Admin-Key") or "").strip()
    return key == ADMIN_API_KEY


def get_client_token() -> str:
    return (request.headers.get("X-CLIENT-TOKEN") or request.headers.get("X-Client-Token") or "").strip()


def get_client_fp() -> str:
    return (request.headers.get("X-CLIENT-FP") or request.headers.get("X-Client-Fp") or "").strip()


def _row_to_license(row) -> Dict[str, Any]:
    # row: (token, expires_at, revoked, note, bound_fp, bound_at)
    token, expires_at, revoked, note, bound_fp, bound_at = row
    return {
        "token": token,
        "expires_at": expires_at.astimezone(timezone.utc).isoformat() if expires_at else None,
        "revoked": bool(revoked),
        "note": note or "",
        "bound_fp": bound_fp or "",
        "bound_at": bound_at.astimezone(timezone.utc).isoformat() if bound_at else "",
    }


def _db_get_license(token: str) -> Optional[Dict[str, Any]]:
    row = _db_exec(
        "SELECT token, expires_at, revoked, note, bound_fp, bound_at FROM licenses WHERE token=%s",
        (token,),
        fetch="one",
    )
    return _row_to_license(row) if row else None


def _db_list_licenses() -> List[Dict[str, Any]]:
    rows = _db_exec(
        "SELECT token, expires_at, revoked, note, bound_fp, bound_at FROM licenses ORDER BY expires_at ASC, token ASC",
        (),
        fetch="all",
    ) or []
    return [_row_to_license(r) for r in rows]


def _db_insert_license(token: str, expires_at: datetime, note: str) -> None:
    _db_exec(
        "INSERT INTO licenses(token, expires_at, revoked, note, bound_fp, bound_at) VALUES (%s,%s,FALSE,%s,'',NULL)",
        (token, expires_at, note),
        fetch="none",
    )


def _db_update_binding(token: str, fp: str) -> None:
    _db_exec(
        "UPDATE licenses SET bound_fp=%s, bound_at=%s WHERE token=%s",
        (fp, _now_utc(), token),
        fetch="none",
    )


def _db_revoke(token: str) -> bool:
    row = _db_exec("UPDATE licenses SET revoked=TRUE WHERE token=%s RETURNING token", (token,), fetch="one")
    return bool(row)


def _db_reset(token: str) -> bool:
    row = _db_exec(
        "UPDATE licenses SET bound_fp='', bound_at=NULL WHERE token=%s RETURNING token", (token,), fetch="one"
    )
    return bool(row)


def _license_status(lic: Optional[Dict[str, Any]], fp: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Returns (ok, code, license_dict_or_none)."""
    if not lic:
        return False, "NOT_FOUND", None

    if lic.get("revoked") is True:
        return False, "REVOKED", lic

    expires_at = lic.get("expires_at")
    if not expires_at:
        return False, "NO_EXPIRY", lic

    try:
        exp = _parse_iso(expires_at)
    except Exception:
        return False, "BAD_EXPIRY", lic

    if _now_utc() > exp:
        return False, "EXPIRED", lic

    bound_fp = (lic.get("bound_fp") or "").strip()
    if not bound_fp:
        return False, "NOT_ACTIVATED", lic

    if not fp:
        return False, "MISSING_FP", lic

    if fp != bound_fp:
        return False, "FP_MISMATCH", lic

    return True, "OK", lic


def _code_to_message(code: str) -> str:
    return {
        "NOT_FOUND": "라이선스 키를 찾을 수 없습니다.",
        "REVOKED": "라이선스가 폐기(차단)되었습니다.",
        "NO_EXPIRY": "라이선스 만료 정보가 없습니다.",
        "BAD_EXPIRY": "라이선스 만료 정보가 올바르지 않습니다.",
        "EXPIRED": "라이선스가 만료되었습니다. 새 키를 발급받아 다시 등록해 주세요.",
        "NOT_ACTIVATED": "라이선스가 아직 이 기기에 등록(활성화)되지 않았습니다.",
        "MISSING_FP": "기기 식별 정보를 확인할 수 없습니다.",
        "FP_MISMATCH": "이 라이선스는 다른 기기에 등록되어 있어 사용할 수 없습니다.",
        "OK": "정상",
    }.get(code, "인증에 실패했습니다.")


# =================================================
# Public endpoints
# =================================================
PUBLIC_API_PATHS = {"/api/health", "/api/auth/verify", "/api/license/activate"}


@app.before_request
def _require_license_for_api():
    # CORS preflight
    if request.method == "OPTIONS":
        return None

    path = request.path or ""
    # Initialize DB lazily (skip for health so it can work even if DB is down)
    if path != "/api/health":
        _ensure_db_inited()
    if not path.startswith("/api/"):
        return None

    # Admin endpoints: recommended to call via Cloudtype Terminal, protected by admin key
    if path.startswith("/api/admin/") or path == "/api/admin/licenses":
        return None

    if path in PUBLIC_API_PATHS:
        return None

    token = get_client_token()
    fp = get_client_fp()
    lic = _db_get_license(token)
    ok, code, _ = _license_status(lic, fp)
    if not ok:
        return jsonify({"ok": False, "code": code, "msg": _code_to_message(code)}), 401
    return None


@app.get("/")
def root():
    return jsonify({"ok": True, "service": "solar-server"}), 200


@app.get("/api/health")
def health():
    return jsonify({"ok": True}), 200


@app.get("/api/auth/verify")
def verify():
    token = get_client_token()
    fp = get_client_fp()

    lic = _db_get_license(token)
    ok, code, lic2 = _license_status(lic, fp)

    # If license exists but not activated yet, return 200 with ok=false so UI can guide activation.
    if not ok and code in {"NOT_ACTIVATED", "MISSING_FP"}:
        return (
            jsonify(
                {
                    "ok": False,
                    "code": code,
                    "msg": _code_to_message(code),
                    "expires_at": (lic2 or {}).get("expires_at"),
                }
            ),
            200,
        )

    if not ok:
        return jsonify({"ok": False, "code": code, "msg": _code_to_message(code)}), 401

    return jsonify({"ok": True, "expires_at": (lic2 or {}).get("expires_at")}), 200


@app.post("/api/license/activate")
def activate():
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    fp = (body.get("fingerprint") or "").strip()

    if not token:
        return jsonify({"ok": False, "code": "MISSING_TOKEN", "msg": "라이선스 키가 필요합니다."}), 400
    if not fp:
        return jsonify({"ok": False, "code": "MISSING_FP", "msg": "기기 식별 정보가 필요합니다."}), 400

    lic = _db_get_license(token)
    if not lic:
        return jsonify({"ok": False, "code": "NOT_FOUND", "msg": _code_to_message("NOT_FOUND")}), 404
    if lic.get("revoked") is True:
        return jsonify({"ok": False, "code": "REVOKED", "msg": _code_to_message("REVOKED")}), 401

    # expiry check
    try:
        exp = _parse_iso(lic.get("expires_at") or "")
    except Exception:
        return jsonify({"ok": False, "code": "BAD_EXPIRY", "msg": _code_to_message("BAD_EXPIRY")}), 400
    if _now_utc() > exp:
        return jsonify({"ok": False, "code": "EXPIRED", "msg": _code_to_message("EXPIRED")}), 401

    bound_fp = (lic.get("bound_fp") or "").strip()
    if bound_fp and bound_fp != fp:
        return (
            jsonify(
                {
                    "ok": False,
                    "code": "FP_MISMATCH",
                    "msg": _code_to_message("FP_MISMATCH"),
                    "expires_at": lic.get("expires_at"),
                }
            ),
            409,
        )

    _db_update_binding(token, fp)
    return jsonify({"ok": True, "expires_at": lic.get("expires_at")}), 200


# =================================================
# Admin endpoints (use Cloudtype Terminal/curl)
# =================================================
@app.get("/api/admin/licenses")
def admin_list_licenses():
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401

    items = []
    for lic in _db_list_licenses():
        items.append(
            {
                "token": lic["token"],
                "expires_at": lic["expires_at"],
                "revoked": bool(lic["revoked"]),
                "note": lic.get("note") or "",
                "bound": bool((lic.get("bound_fp") or "").strip()),
                "bound_at": lic.get("bound_at") or "",
            }
        )

    return jsonify({"ok": True, "count": len(items), "licenses": items}), 200


@app.post("/api/admin/licenses")
def admin_issue_license():
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401

    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip() or f"SCE-{secrets.token_urlsafe(12)}"
    expires_at_str = (body.get("expires_at") or "").strip()
    note = (body.get("note") or "").strip()

    if not expires_at_str:
        return jsonify({"ok": False, "msg": "expires_at is required (ISO8601)"}), 400

    try:
        exp = _parse_iso(expires_at_str)
    except Exception:
        return jsonify({"ok": False, "msg": "expires_at must be ISO8601 with timezone, e.g. 2026-02-29T23:59:59+09:00"}), 400

    # insert (fail if exists)
    try:
        _db_insert_license(token, exp, note)
    except psycopg2.errors.UniqueViolation:
        return jsonify({"ok": False, "msg": "token already exists"}), 409

    return jsonify({"ok": True, "token": token, "expires_at": exp.isoformat()}), 200


@app.post("/api/admin/licenses/<token>/revoke")
def admin_revoke(token: str):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401
    ok = _db_revoke(token)
    if not ok:
        return jsonify({"ok": False, "msg": "not found"}), 404
    return jsonify({"ok": True}), 200


@app.post("/api/admin/licenses/<token>/reset")
def admin_reset_binding(token: str):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401
    ok = _db_reset(token)
    if not ok:
        return jsonify({"ok": False, "msg": "not found"}), 404
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    # Cloudtype sets PORT sometimes; keep fallback
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
