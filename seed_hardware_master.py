#!/usr/bin/env python3
"""
Seed Hardware Master DB (2026)
- Reads hardware_master_2026.json
- Upserts into PostgreSQL tables: pv_modules, inverters, master_versions
Env:
  DATABASE_URL (required)
Usage:
  python seed_hardware_master.py
"""
import os, json
import psycopg2
from psycopg2.extras import execute_values

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

HERE = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(HERE, "hardware_master_2026.json")

def ensure_tables(conn):
    cur = conn.cursor()
    cur.execute("""
    create table if not exists pv_modules (
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
    create table if not exists inverters (
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
    create table if not exists master_versions (
      id bigserial primary key,
      name text unique not null,
      imported_at timestamptz default now()
    );
    """)
    conn.commit()

def upsert_modules(conn, modules):
    rows = []
    for m in modules:
        rows.append((
            m.get("no"),
            m.get("brand"),
            m.get("model"),
            m.get("power_w"),
            m.get("module_type"),
            m.get("efficiency_pct"),
            m.get("price_won_per_w"),
            bool(m.get("is_bifacial")),
            m.get("features"),
        ))
    sql = """
    insert into pv_modules
      (no, brand, model, power_w, module_type, efficiency_pct, price_won_per_w, is_bifacial, features)
    values %s
    on conflict (no) do update set
      brand=excluded.brand,
      model=excluded.model,
      power_w=excluded.power_w,
      module_type=excluded.module_type,
      efficiency_pct=excluded.efficiency_pct,
      price_won_per_w=excluded.price_won_per_w,
      is_bifacial=excluded.is_bifacial,
      features=excluded.features;
    """
    execute_values(conn.cursor(), sql, rows)
    conn.commit()

def upsert_inverters(conn, inverters):
    rows = []
    for inv in inverters:
        rows.append((
            inv.get("no"),
            inv.get("brand"),
            inv.get("model"),
            inv.get("capacity_kw"),
            inv.get("topology"),
            inv.get("price_million_won"),
            inv.get("price_won"),
            inv.get("features"),
            bool(inv.get("is_integrated_connection_box")),
        ))
    sql = """
    insert into inverters
      (no, brand, model, capacity_kw, topology, price_million_won, price_won, features, is_integrated_connection_box)
    values %s
    on conflict (no) do update set
      brand=excluded.brand,
      model=excluded.model,
      capacity_kw=excluded.capacity_kw,
      topology=excluded.topology,
      price_million_won=excluded.price_million_won,
      price_won=excluded.price_won,
      features=excluded.features,
      is_integrated_connection_box=excluded.is_integrated_connection_box;
    """
    execute_values(conn.cursor(), sql, rows)
    conn.commit()

def mark_version(conn, name):
    cur = conn.cursor()
    cur.execute("insert into master_versions(name) values (%s) on conflict(name) do nothing;", (name,))
    conn.commit()

def main():
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    ver = data.get("version") or "hardware_master_2026"
    modules = data.get("modules") or []
    inverters = data.get("inverters") or []

    conn = psycopg2.connect(DATABASE_URL)
    try:
        ensure_tables(conn)
        upsert_modules(conn, modules)
        upsert_inverters(conn, inverters)
        mark_version(conn, ver)
        print(f"OK: seeded {len(modules)} modules, {len(inverters)} inverters, version={ver}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
