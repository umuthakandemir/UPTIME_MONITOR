#!/usr/bin/env python3
"""One-time migration of an old service_monitor.db into PostgreSQL.

Usage:
  python migrate_sqlite_to_postgres.py ./service_monitor.db \
    postgresql+psycopg://user:password@localhost:5432/uptime_monitor
"""
import sys
from sqlalchemy import create_engine, MetaData, select, text
from sqlalchemy.orm import Session
from backend.models import Base

TABLE_ORDER = [
    "security_config", "users", "auth_tokens", "app_settings", "smtp_settings", "integrations",
    "notification_groups", "services", "service_notification_groups", "check_results", "incidents",
    "service_screenshots", "event_logs", "audit_logs", "app_notifications", "app_notification_reads",
]

def main():
    if len(sys.argv) != 3:
        raise SystemExit("Kullanım: python migrate_sqlite_to_postgres.py ./service_monitor.db <POSTGRES_URL>")
    source_url = "sqlite:///" + sys.argv[1]
    target_url = sys.argv[2]
    src = create_engine(source_url)
    dst = create_engine(target_url, pool_pre_ping=True)
    Base.metadata.create_all(dst)
    src_meta = MetaData(); src_meta.reflect(bind=src)
    dst_meta = MetaData(); dst_meta.reflect(bind=dst)
    with src.connect() as sc, dst.begin() as dc:
        for name in TABLE_ORDER:
            if name not in src_meta.tables or name not in dst_meta.tables:
                continue
            src_table, dst_table = src_meta.tables[name], dst_meta.tables[name]
            rows = [dict(r._mapping) for r in sc.execute(select(src_table)).fetchall()]
            if not rows:
                continue
            cols = [c.name for c in dst_table.columns if c.name in rows[0]]
            dc.execute(dst_table.insert().values([{k: row.get(k) for k in cols} for row in rows]))
            if "id" in dst_table.columns:
                try:
                    dc.execute(text(f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), COALESCE((SELECT MAX(id) FROM {name}), 1), true)"))
                except Exception:
                    pass
            print(f"{name}: {len(rows)} kayıt")
    print("Migration tamamlandı.")

if __name__ == "__main__":
    main()
