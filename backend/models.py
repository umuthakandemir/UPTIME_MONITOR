from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, Text, DateTime, ForeignKey, Table, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from .database import Base

service_groups = Table(
    "service_notification_groups", Base.metadata,
    Column("service_id", ForeignKey("services.id"), primary_key=True),
    Column("group_id", ForeignKey("notification_groups.id"), primary_key=True),
)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    id = Column(Integer, primary_key=True)
    role = Column(String(60), nullable=False, index=True)
    permission = Column(String(120), nullable=False, index=True)
    enabled = Column(Boolean, default=False, nullable=False)
    __table_args__ = (UniqueConstraint("role", "permission", name="ux_role_permission"),)

class UserPermission(Base):
    __tablename__ = "user_permissions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = Column(String(120), nullable=False, index=True)
    enabled = Column(Boolean, default=False, nullable=False)
    __table_args__ = (UniqueConstraint("user_id", "permission", name="ux_user_permission"),)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(500), nullable=False)
    role = Column(String(40), default="read_only_admin", nullable=False)
    display_name = Column(String(200), default="")
    email = Column(String(320), default="")
    email_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    is_initial_admin = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = Column(DateTime)

class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(128), unique=True, nullable=False)
    kind = Column(String(40), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityConfig(Base):
    __tablename__ = "security_config"
    id = Column(Integer, primary_key=True, default=1)
    jwt_secret_sha = Column(String(128), nullable=False)
    jwt_secret_created_at = Column(DateTime, default=datetime.utcnow)

class AppSettings(Base):
    __tablename__ = "app_settings"
    id = Column(Integer, primary_key=True, default=1)
    system_email = Column(String, default="")
    monitoring_level = Column(String, default="basic")
    cert_alert_days = Column(Integer, default=30)
    daily_summary_enabled = Column(Boolean, default=False)
    daily_summary_time = Column(String, default="23:55")
    recovery_enabled = Column(Boolean, default=True)
    default_notification_group_id = Column(Integer, nullable=True)
    default_notification_subject = Column(String, default="Service Monitor - {{STATUS}} - {{SERVICE_NAME}}")
    default_notification_message = Column(Text, default="Servis: {{SERVICE_NAME}}\nDurum: {{STATUS}}\nNeden: {{REASON}}")
    down_notification_subject = Column(String, default="DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}")
    down_notification_message = Column(Text, default="Service Monitor - DOWN\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\n24 saat min/max latency: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\n24 saat olay sayısı: {{INCIDENT_COUNT_24H}}\n24 saat downtime: {{DOWNTIME_24H}} sn\nNeden: {{REASON}}")
    recovery_notification_subject = Column(String, default="RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}")
    recovery_notification_message = Column(Text, default="Service Monitor - RECOVERY\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nKontrol zamanı: {{TIME}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\nKesinti nedeni: {{REASON}}\nArdışık hata: {{FAILURE_COUNT}}")
    warning_notification_subject = Column(String, default="WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}")
    warning_notification_message = Column(Text, default="Service Monitor - WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\nNeden: {{REASON}}")
    latency_notification_subject = Column(String, default="LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms")
    latency_notification_message = Column(Text, default="Service Monitor - LATENCY WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nAnlık latency: {{LATENCY_MS}} ms\n24 saat ortalama: {{AVG_LATENCY_24H}} ms\n24 saat min/max: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nKontrol sayısı: {{CHECK_COUNT_24H}}\nUptime: %{{UPTIME_24H}}\nKontrol zamanı: {{TIME}}")
    # Veri saklama politikası — varsayılan olarak kapalıdır; Ayarlar > Veri Saklama
    # üzerinden kurum politikasına göre etkinleştirilebilir.
    retention_enabled = Column(Boolean, default=False)
    retention_checks_days = Column(Integer, default=30)
    retention_logs_days = Column(Integer, default=90)
    retention_audit_days = Column(Integer, default=365)
    retention_incidents_days = Column(Integer, default=3650)
    retention_cleanup_hour = Column(Integer, default=3)
    screenshot_on_http_failure = Column(Boolean, default=True)
    screenshot_interval_seconds = Column(Integer, default=900)
    screenshot_timeout_seconds = Column(Integer, default=30)
    screenshot_wait_seconds = Column(Integer, default=2)
    screenshot_retention_days = Column(Integer, default=30)
    screenshot_trigger_codes = Column(String, default="404,500-599")
    screenshot_capture_on_down = Column(Boolean, default=True)
    screenshot_capture_on_up = Column(Boolean, default=False)
    screenshot_routine_enabled = Column(Boolean, default=True)
    tls_scan_enabled = Column(Boolean, default=True)
    tls_scan_interval_days = Column(Integer, default=7)
    branding_logo_url = Column(String, default="/static/assets/um-logo.svg")
    mail_subject = Column(String, default="Service Monitor - {{STATUS}} - {{SERVICE_NAME}}")
    mail_template = Column(Text, default=(
        "Servis: {{SERVICE_NAME}}\nHost: {{HOST_NAME}}\nDurum: {{STATUS}}\n"
        "Zaman: {{TIME}}\nKontrol aralığı: {{INTERVAL_TIME}}\n"
        "Ardışık hata: {{FAILURE_COUNT}}\nGecikme: {{LATENCY_MS}} ms\n"
        "Neden: {{REASON}}\nSertifika bitişi: {{CERT_EXPIRY}}"
    ))

class SMTPSettings(Base):
    __tablename__ = "smtp_settings"
    id = Column(Integer, primary_key=True, default=1)
    host = Column(String, default="")
    port = Column(Integer, default=587)
    username = Column(String, default="")
    password = Column(String, default="")
    from_email = Column(String, default="")
    use_tls = Column(Boolean, default=True)
    use_ssl = Column(Boolean, default=False)
    auth_enabled = Column(Boolean, default=True)
    mode = Column(String, default="auth")  # auth | relay
    helo_name = Column(String, default="")
    test_recipient = Column(String, default="")

class Integration(Base):
    __tablename__ = "integrations"
    id = Column(Integer, primary_key=True)
    provider = Column(String, unique=True)
    enabled = Column(Boolean, default=False)
    config_json = Column(Text, default="{}")

class NotificationGroup(Base):
    __tablename__ = "notification_groups"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    enabled = Column(Boolean, default=True)
    auto_add_new_services = Column(Boolean, default=False)
    channels_json = Column(Text, default="{}")
    recipients_json = Column(Text, default="{}")

class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        Index("ix_services_name_id", "name", "id"),
        Index("ix_services_enabled", "enabled"),
    )
    id = Column(Integer, primary_key=True)
    name = Column(String)
    monitor_type = Column(String, default="http")
    url = Column(String, default="")
    interval_seconds = Column(Integer, default=30)
    status_ranges = Column(Text, default="200-299")
    ignored_http_status_codes = Column(String, default="401,403")
    failure_threshold = Column(Integer, default=3)
    evaluation_window_minutes = Column(Integer, default=5)
    enabled = Column(Boolean, default=True)
    maintenance = Column(Boolean, default=False)
    maintenance_until = Column(DateTime)
    maintenance_reason = Column(String, default="")
    description = Column(Text, default="")
    service_authorized_name = Column(String, default="")
    last_headers_json = Column(Text, default="{}")
    last_header_security_json = Column(Text, default="{}")
    last_tls_security_json = Column(Text, default="{}")
    last_tls_scan_at = Column(DateTime)
    last_screenshot_path = Column(String, default="")
    last_screenshot_at = Column(DateTime)

    ignore_cert_errors = Column(Boolean, default=False)
    certificate_monitoring = Column(Boolean, default=True)
    certificate_alert_enabled = Column(Boolean, default=False)
    certificate_alert_days = Column(Integer, default=30)
    certificate_notification_group_ids = Column(Text, default="[]")
    certificate_notification_subject = Column(String, default="Sertifika uyarısı - {{SERVICE_NAME}}")
    certificate_notification_message = Column(Text, default="{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor. Bitiş: {{CERT_EXPIRY}}")

    content_monitoring = Column(Boolean, default=False)
    content_mode = Column(String, default="contains")
    content_keywords = Column(Text, default="[]")
    header_monitoring = Column(Boolean, default=False)
    expected_headers = Column(Text, default="{}")

    advanced_alarm = Column(Boolean, default=False)
    latency_warning_ms = Column(Integer, default=1000)
    latency_critical_ms = Column(Integer, default=3000)
    sla_enabled = Column(Boolean, default=False)
    sla_target = Column(Float, default=99.9)

    protocol_options = Column(Text, default="{}")
    dependency_ids = Column(Text, default="[]")
    dependency_notifications_enabled = Column(Boolean, default=False)

    notification_group_ids_json = Column(Text, default="[]")
    custom_notification_enabled = Column(Boolean, default=False)
    custom_notification_message = Column(Text, default="")
    custom_notification_group_ids = Column(Text, default="[]")
    notification_group_configs = Column(Text, default="[]")
    notification_rules = Column(Text, default="[]")
    notification_cooldown_minutes = Column(Integer, default=0)
    down_notification_subject = Column(String, default="DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}")
    down_notification_message = Column(Text, default="Service Monitor - DOWN\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nSon kontrol: {{LAST_CHECK}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\n24 saat min/max latency: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\n24 saat olay sayısı: {{INCIDENT_COUNT_24H}}\n24 saat downtime: {{DOWNTIME_24H}} sn\nNeden: {{REASON}}")
    recovery_notification_subject = Column(String, default="RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}")
    recovery_notification_message = Column(Text, default="Service Monitor - RECOVERY\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nKontrol zamanı: {{TIME}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\nKesinti nedeni: {{REASON}}\nArdışık hata: {{FAILURE_COUNT}}")
    warning_notification_subject = Column(String, default="WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}")
    warning_notification_message = Column(Text, default="Service Monitor - WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\nNeden: {{REASON}}")
    latency_notification_subject = Column(String, default="LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms")
    latency_notification_message = Column(Text, default="Service Monitor - LATENCY WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nAnlık latency: {{LATENCY_MS}} ms\n24 saat ortalama: {{AVG_LATENCY_24H}} ms\n24 saat min/max: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nKontrol sayısı: {{CHECK_COUNT_24H}}\nUptime: %{{UPTIME_24H}}\nKontrol zamanı: {{TIME}}")

    last_status = Column(String, default="UNKNOWN")
    last_latency_ms = Column(Float, default=0)
    last_check_at = Column(DateTime)
    consecutive_failures = Column(Integer, default=0)
    last_error = Column(Text, default="")
    last_http_status = Column(Integer)
    last_resolved_ip = Column(String, default="")
    last_cert_days = Column(Integer)
    last_rule_signature = Column(String, default="")
    last_latency_alarm = Column(String, default="")
    cert_subject = Column(String, default="")
    cert_issuer = Column(String, default="")
    cert_expires_at = Column(DateTime)
    cert_alert_sent = Column(Boolean, default=False)

    notification_groups = relationship("NotificationGroup", secondary=service_groups)

class CheckResult(Base):
    __tablename__ = "check_results"
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id"))
    control_id = Column(Integer, ForeignKey("monitor_controls.id"), nullable=True, index=True)
    checked_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String)
    http_status = Column(Integer)
    latency_ms = Column(Float, default=0)
    error = Column(Text, default="")
    certificate_days = Column(Integer)
    rule_signature = Column(String, default="")
    headers_json = Column(Text, default="{}")
    header_security_json = Column(Text, default="{}")
    tls_security_json = Column(Text, default="{}")
    __table_args__ = (
        Index("ix_check_results_control_time", "control_id", "checked_at"),
        Index("ix_check_results_checked_at", "checked_at"),
        Index("ix_check_results_status_time", "status", "checked_at"),
    )

class ServiceScreenshot(Base):
    __tablename__ = "service_screenshots"
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    control_id = Column(Integer, ForeignKey("monitor_controls.id"), nullable=True, index=True)
    captured_at = Column(DateTime, default=datetime.utcnow, index=True)
    reason = Column(Text, default="")
    status = Column(String, default="DOWN")
    http_status = Column(Integer)
    path = Column(String, default="")
    url = Column(String, default="")
    __table_args__ = (Index("ix_service_screenshots_control_time", "control_id", "captured_at"),)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id"))
    control_id = Column(Integer, ForeignKey("monitor_controls.id"), nullable=True, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    status = Column(String, default="OPEN")
    failure_count = Column(Integer, default=0)
    downtime_seconds = Column(Float, default=0)
    reason = Column(Text, default="")
    __table_args__ = (Index("ix_incidents_control_started", "control_id", "started_at"),)

class EventLog(Base):
    __tablename__ = "event_logs"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    level = Column(String, default="INFO")
    category = Column(String, default="SYSTEM")
    service_id = Column(Integer)
    control_id = Column(Integer, nullable=True, index=True)
    message = Column(Text)
    __table_args__ = (Index("ix_event_logs_service_control_time", "service_id", "control_id", "created_at"),)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    actor = Column(String, default="system")
    action = Column(String)
    service_id = Column(Integer)
    control_id = Column(Integer, nullable=True, index=True)
    details = Column(Text)

class AppNotification(Base):
    __tablename__ = "app_notifications"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    category = Column(String(40), default="system", nullable=False, index=True)
    event_type = Column(String(80), default="", index=True)
    title = Column(String(300), default="", nullable=False)
    message = Column(Text, default="", nullable=False)
    link = Column(String(500), default="")
    service_id = Column(Integer, ForeignKey("services.id"), nullable=True, index=True)
    control_id = Column(Integer, nullable=True, index=True)
    target_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    metadata_json = Column(Text, default="{}")

class AppNotificationRead(Base):
    __tablename__ = "app_notification_reads"
    id = Column(Integer, primary_key=True)
    notification_id = Column(Integer, ForeignKey("app_notifications.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    read_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Multi-control monitoring model (v2)
# ---------------------------------------------------------------------------
control_notification_groups = Table(
    "control_notification_groups", Base.metadata,
    Column("policy_id", ForeignKey("control_notification_policies.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("notification_groups.id", ondelete="CASCADE"), primary_key=True),
)

class MonitorControl(Base):
    """A single independent monitoring probe owned by a Service."""
    __tablename__ = "monitor_controls"
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False, default="")
    control_type = Column(String(40), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    url = Column(String, default="")
    interval_seconds = Column(Integer, default=30, nullable=False)
    failure_threshold = Column(Integer, default=3, nullable=False)
    evaluation_window_minutes = Column(Integer, default=5, nullable=False)
    status_ranges = Column(Text, default="200-299")
    ignored_http_status_codes = Column(String, default="401,403")
    config_json = Column(Text, default="{}")
    advanced_options_json = Column(Text, default="{}")
    description = Column(Text, default="")

    last_status = Column(String(20), default="UNKNOWN", index=True)
    last_latency_ms = Column(Float, default=0)
    last_check_at = Column(DateTime, index=True)
    consecutive_failures = Column(Integer, default=0)
    last_error = Column(Text, default="")
    last_http_status = Column(Integer)
    last_resolved_ip = Column(String, default="")
    last_cert_days = Column(Integer)
    last_cert_subject = Column(String, default="")
    last_cert_issuer = Column(String, default="")
    last_cert_expires_at = Column(DateTime)
    last_result_json = Column(Text, default="{}")
    last_rule_signature = Column(String, default="")
    last_latency_alarm = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    service = relationship("Service", backref="monitor_controls")
    notification_policies = relationship(
        "ControlNotificationPolicy",
        cascade="all, delete-orphan",
        back_populates="control",
        order_by="ControlNotificationPolicy.event_type",
    )

class ControlNotificationPolicy(Base):
    """Notification policy scoped to one control and one event type."""
    __tablename__ = "control_notification_policies"
    id = Column(Integer, primary_key=True)
    control_id = Column(Integer, ForeignKey("monitor_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(30), nullable=False)  # UP | DOWN | RECOVERY | WARNING | LATENCY
    enabled = Column(Boolean, default=False, nullable=False)
    subject = Column(String(500), default="")
    message = Column(Text, default="")
    cooldown_minutes = Column(Integer, default=0, nullable=False)
    threshold_ms = Column(Integer, default=1000, nullable=False)
    last_sent_at = Column(DateTime)

    control = relationship("MonitorControl", back_populates="notification_policies")
    groups = relationship("NotificationGroup", secondary=control_notification_groups)

    __table_args__ = (
        UniqueConstraint("control_id", "event_type", name="ux_control_notification_event"),
    )
