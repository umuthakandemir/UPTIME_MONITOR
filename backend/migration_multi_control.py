"""
Additive migration for the multi-control monitoring architecture.

Safe for the existing SQLite/PostgreSQL deployment: no legacy column is removed.
The first existing Service is converted to exactly one MonitorControl and its
legacy notification settings become per-event policies.
"""
import json
from datetime import datetime
from sqlalchemy import inspect, text
from .database import engine, SessionLocal
from .models import Service, MonitorControl, ControlNotificationPolicy

EVENT_DEFAULTS = {
    "UP": ("UP | {{SERVICE_NAME}} | {{MONITOR_TYPE}}",
           "SERVICE MONITOR — UP\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nZaman: {{EVENT_TIME}}\nLatency: {{LATENCY_MS}} ms"),
    "DOWN": ("DOWN | {{SERVICE_NAME}} | {{MONITOR_TYPE}}",
             "SERVICE MONITOR — DOWN\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nOlay: {{EVENT_TYPE}}\nZaman: {{EVENT_TIME}}\nLatency: {{LATENCY_MS}} ms\nHata: {{ERROR_MESSAGE}}"),
    "RECOVERY": ("RECOVERY | {{SERVICE_NAME}} | {{MONITOR_TYPE}}",
                 "SERVICE MONITOR — RECOVERY\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nZaman: {{EVENT_TIME}}\nLatency: {{LATENCY_MS}} ms\nNeden: {{REASON}}"),
    "WARNING": ("WARNING | {{SERVICE_NAME}} | {{MONITOR_TYPE}}",
                "SERVICE MONITOR — WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nLatency: {{LATENCY_MS}} ms\nNeden: {{REASON}}"),
}

def _add_column(conn, table, column, definition):
    inspector = inspect(conn)
    cols = {x["name"] for x in inspector.get_columns(table)}
    if column not in cols:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))

def run():
    # create_all creates the new tables and is idempotent.
    from .database import Base
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        # Nullable foreign-key columns keep old rows valid.
        for table, col, definition in [
            ("check_results", "control_id", "INTEGER"),
            ("incidents", "control_id", "INTEGER"),
            ("event_logs", "control_id", "INTEGER"),
            ("audit_logs", "control_id", "INTEGER"),
            ("service_screenshots", "control_id", "INTEGER"),
            ("app_notifications", "control_id", "INTEGER"),
            ("control_notification_policies", "threshold_ms", "INTEGER DEFAULT 1000"),
        ]:
            _add_column(conn, table, col, definition)

    db = SessionLocal()
    try:
        for service in db.query(Service).all():
            controls = db.query(MonitorControl).filter_by(service_id=service.id).all()
            if controls:
                continue

            control = MonitorControl(
                service_id=service.id,
                name=service.name,
                control_type={"http":"web", "https":"web", "postgres":"postgresql", "pgsql":"postgresql"}.get((service.monitor_type or "web").lower(), (service.monitor_type or "web").lower()),
                enabled=bool(service.enabled),
                url=service.url or "",
                interval_seconds=max(5, int(service.interval_seconds or 30)),
                failure_threshold=max(1, int(service.failure_threshold or 3)),
                evaluation_window_minutes=max(1, int(service.evaluation_window_minutes or 5)),
                status_ranges=service.status_ranges or "200-299",
                ignored_http_status_codes=service.ignored_http_status_codes or "401,403",
                config_json=service.protocol_options or "{}",
                advanced_options_json=json.dumps({
                    "content_monitoring": bool(service.content_monitoring),
                    "content_mode": service.content_mode or "contains",
                    "content_keywords": json.loads(service.content_keywords or "[]"),
                    "header_monitoring": bool(service.header_monitoring),
                    "expected_headers": json.loads(service.expected_headers or "{}"),
                    "certificate_monitoring": bool(service.certificate_monitoring),
                    "certificate_alert_enabled": bool(service.certificate_alert_enabled),
                    "certificate_alert_days": int(service.certificate_alert_days or 30),
                    "certificate_notification_group_ids": list(getattr(service, "certificate_notification_group_ids", []) or []),
                    "certificate_notification_subject": getattr(service, "certificate_notification_subject", "") or "",
                    "certificate_notification_message": getattr(service, "certificate_notification_message", "") or "",
                    "sla_enabled": bool(service.sla_enabled),
                    "sla_target": float(service.sla_target or 99.9),
                    "dependency_ids": json.loads(service.dependency_ids or "[]") if getattr(service, "dependency_ids", None) else [],
                    "dependency_notifications_enabled": bool(service.dependency_notifications_enabled),
                    "ignore_cert_errors": bool(service.ignore_cert_errors),
                    "advanced_alarm": bool(service.advanced_alarm),
                    "latency_warning_ms": int(service.latency_warning_ms or 1000),
                    "latency_critical_ms": int(service.latency_critical_ms or 3000),
                    "sla_enabled": bool(service.sla_enabled),
                    "sla_target": float(service.sla_target or 99.9),
                }, ensure_ascii=False),
                last_status=service.last_status or "UNKNOWN",
                last_latency_ms=service.last_latency_ms or 0,
                last_check_at=service.last_check_at,
                consecutive_failures=service.consecutive_failures or 0,
                last_error=service.last_error or "",
                last_http_status=service.last_http_status,
                last_resolved_ip=service.last_resolved_ip or "",
                last_cert_days=service.last_cert_days,
                last_cert_subject=service.cert_subject or "",
                last_cert_issuer=service.cert_issuer or "",
                last_cert_expires_at=service.cert_expires_at,
            )
            db.add(control)
            db.flush()

            selected = []
            try:
                selected = [int(x) for x in json.loads(service.notification_group_ids_json or "[]")]
            except Exception:
                pass
            if not selected:
                selected = [g.id for g in service.notification_groups]

            for event in ("UP", "DOWN", "RECOVERY", "WARNING"):
                subject, message = EVENT_DEFAULTS[event]
                if event == "DOWN":
                    subject = service.down_notification_subject or subject
                    message = service.down_notification_message or message
                    enabled = bool(selected)
                elif event == "RECOVERY":
                    subject = service.recovery_notification_subject or subject
                    message = service.recovery_notification_message or message
                    enabled = bool(selected)
                elif event == "WARNING":
                    subject = service.warning_notification_subject or subject
                    message = service.warning_notification_message or message
                    enabled = bool(selected)
                else:
                    enabled = False
                policy = ControlNotificationPolicy(
                    control_id=control.id, event_type=event, enabled=enabled,
                    subject=subject, message=message,
                    threshold_ms=1000,
                )
                policy.groups = [g for g in service.notification_groups if g.id in selected]
                db.add(policy)

        # Legacy history belonged to the single legacy monitor; attach it to the
        # migrated control so historical reports do not disappear.
        from .models import CheckResult, Incident, EventLog, AuditLog, ServiceScreenshot, AppNotification
        for service in db.query(Service).all():
            first=db.query(MonitorControl).filter_by(service_id=service.id).order_by(MonitorControl.id.asc()).first()
            if not first: continue
            for model in (CheckResult, Incident, EventLog, AuditLog, ServiceScreenshot, AppNotification):
                if hasattr(model, "control_id"):
                    db.query(model).filter(model.service_id==service.id, model.control_id.is_(None)).update(
                        {"control_id": first.id}, synchronize_session=False
                    )
        db.commit()
    finally:
        db.close()
