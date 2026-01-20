import json, os
from datetime import datetime, timezone
import psycopg2

DATABASE_URL = os.getenv("DATABASE_URL")
JSON_PATH = os.getenv("LICENSE_DB_PATH", "./licenses_db.json")

def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def main():
    if not DATABASE_URL:
        raise SystemExit("DATABASE_URL is not set")
    if not os.path.exists(JSON_PATH):
        raise SystemExit(f"JSON not found: {JSON_PATH}")

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        db = json.load(f) or {}
    licenses = (db.get("licenses") or {})
    print("found", len(licenses), "licenses in", JSON_PATH)

    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
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

    upserts = 0
    for token, lic in licenses.items():
        expires_at = lic.get("expires_at")
        if not expires_at:
            continue
        exp = parse_iso(expires_at)
        revoked = bool(lic.get("revoked"))
        note = lic.get("note") or ""
        bound_fp = (lic.get("bound_fp") or "").strip()
        bound_at = lic.get("bound_at") or ""
        bound_at_dt = parse_iso(bound_at) if bound_at else None

        cur.execute("""
            INSERT INTO licenses(token, expires_at, revoked, note, bound_fp, bound_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (token) DO UPDATE SET
                expires_at=EXCLUDED.expires_at,
                revoked=EXCLUDED.revoked,
                note=EXCLUDED.note,
                bound_fp=EXCLUDED.bound_fp,
                bound_at=EXCLUDED.bound_at
        """, (token, exp, revoked, note, bound_fp, bound_at_dt))
        upserts += 1

    conn.commit()
    cur.close()
    conn.close()
    print("upserted", upserts, "rows")

if __name__ == "__main__":
    main()
