import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import event

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./service_monitor.db")

engine_kwargs = {"pool_pre_ping": True, "pool_recycle": 1800}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 60}
else:
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "20")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "30")),
        "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT", "30")),
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_runtime_pragmas(dbapi_connection, connection_record):
        cur=dbapi_connection.cursor()
        try:
            cur.execute("PRAGMA busy_timeout=60000")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
        finally:
            cur.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ensure_performance_indexes():
    """Create additive indexes for existing installations as well as fresh DBs."""
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_services_name_id ON services (name, id)",
        "CREATE INDEX IF NOT EXISTS ix_services_enabled ON services (enabled)",
        "CREATE INDEX IF NOT EXISTS ix_check_results_checked_at ON check_results (checked_at)",
        "CREATE INDEX IF NOT EXISTS ix_check_results_status_time ON check_results (status, checked_at)",
        "CREATE INDEX IF NOT EXISTS ix_monitor_controls_enabled_interval ON monitor_controls (enabled, interval_seconds)",
    )
    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))
