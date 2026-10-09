import json, io, csv, threading, time, os, re, ipaddress, pathlib, shutil
import httpx
from urllib.parse import urlparse
from types import SimpleNamespace
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import text, and_, or_
from .database import Base, engine, SessionLocal, get_db, ensure_performance_indexes
from .models import *
from .checker import check, in_ranges, certificate, analyze_security_headers, tls_security_scan, http_status_is_up, _resolved_host_ip, _ping
from .notifier import render, notify, email, telegram_send, telegram_request, NOTIFICATION_FIELDS
from .auth import ROLES, WRITE_ROLES, SUPER_ROLES, current_user, ensure_admin, ensure_security, create_token, _hash_password, verify_password
from .migration_multi_control import run as migrate_multi_control
from .multi_monitor import ControlScheduler
from . import cache_hooks  # noqa: F401  (Service/Control değişimlerinde analitik önbelleği geçersiz kılar)

Base.metadata.create_all(bind=engine)
ensure_performance_indexes()
migrate_multi_control()
# Seed notification groups idempotently; no channels or recipients are configured.
try:
    with SessionLocal() as _seed_db:
        for _group_name in ("Varsayılan Bildirim Grubu", "Güvenlik Bildirim Grubu", "Sistem Bildirim Grubu"):
            if not _seed_db.query(NotificationGroup).filter(NotificationGroup.name == _group_name).first():
                _seed_db.add(NotificationGroup(name=_group_name, enabled=True, auto_add_new_services=True, channels_json="{}", recipients_json="{}"))
        _seed_db.commit()
except Exception:
    pass
os.makedirs("screenshots", exist_ok=True)
app=FastAPI(title="Uptime Monitor Service")
from .multi_api import router as multi_router
app.include_router(multi_router)
app.mount("/static", StaticFiles(directory="frontend"), name="static")
app.mount("/screenshots", StaticFiles(directory="screenshots", check_dir=False), name="screenshots")

PERMISSION_CATALOG = {
    "branding.manage": "Uygulama logosunu değiştirme",
    "dashboard.view": "Dashboard görüntüleme",
    "services.view": "Servisleri görüntüleme",
    "services.create": "Servis ekleme",
    "services.update": "Servis düzenleme",
    "services.delete": "Servis silme",
    "services.security": "Servis güvenlik/TLS analizi çalıştırma",
    "services.screenshot": "Servis ekran görüntüsü alma",
    "instant_test.execute": "Anlık test çalıştırma",
    "instant_test.audit": "Diğer kullanıcıların anlık test ayrıntılarını görüntüleme",
    "groups.view": "Bildirim gruplarını görüntüleme",
    "groups.create": "Bildirim grubu oluşturma",
    "groups.update": "Bildirim grubu düzenleme",
    "groups.delete": "Bildirim grubu silme",
    "settings.view": "Ayarları görüntüleme",
    "settings.update": "Ayarları değiştirme",
    "integrations.view": "Entegrasyonları görüntüleme",
    "integrations.update": "Entegrasyonları değiştirme",
    "notification_templates.view": "Bildirim şablonlarını görüntüleme",
    "notification_templates.update": "Bildirim şablonlarını değiştirme",
    "notifications.view": "Uygulama bildirimlerini görüntüleme",
    "notifications.manage": "Bildirimleri okundu işaretleme",
    "logs.view": "İşlem kayıtlarını görüntüleme",
    "incidents.view": "Olayları görüntüleme",
    "audit.view": "Denetim kayıtlarını görüntüleme",
    "reports.view": "Raporları görüntüleme",
    "reports.export": "Export alma",
    "retention.view": "Veri saklama ayarlarını görüntüleme",
    "retention.update": "Veri saklama/temizleme işlemleri",
    "users.view": "Kullanıcıları görüntüleme",
    "users.create": "Kullanıcı oluşturma",
    "users.update": "Kullanıcı düzenleme",
    "users.delete": "Kullanıcı silme",
}

READ_PERMISSION_FOR = {
    "services.create":"services.view", "services.update":"services.view", "services.delete":"services.view", "services.security":"services.view", "services.screenshot":"services.view",
    "groups.create":"groups.view", "groups.update":"groups.view", "groups.delete":"groups.view",
    "settings.update":"settings.view", "integrations.update":"integrations.view", "notification_templates.update":"notification_templates.view",
    "notifications.manage":"notifications.view", "reports.export":"reports.view", "retention.update":"retention.view",
    "users.create":"users.view", "users.update":"users.view", "users.delete":"users.view",
}

def role_is_read_only(role):
    return role in {"read_only_super_admin","read_only_admin","read_only_semi_admin"}

def user_permission_keys(db, user):
    if user.role == "super_admin":
        return set(PERMISSION_CATALOG)
    if user.role == "read_only_super_admin":
        return {k for k in PERMISSION_CATALOG if k.endswith(".view") or k in {"dashboard.view","instant_test.execute","notifications.manage","reports.export"}}
    role_rows=db.query(RolePermission).filter(RolePermission.role==user.role, RolePermission.enabled.is_(True)).all()
    user_rows_all=db.query(UserPermission).filter(UserPermission.user_id==user.id).all()
    user_rows=[x for x in user_rows_all if x.enabled and x.permission in PERMISSION_CATALOG]
    role_keys={x.permission for x in role_rows}; user_keys={x.permission for x in user_rows}
    # Semi Admin is always per-user. Admin uses role defaults until its permissions are explicitly configured; afterwards the user checklist is authoritative.
    if user.role in {"semi_admin","read_only_semi_admin"}:
        keys=user_keys
    elif user.role in {"admin","read_only_admin"} and any(x.permission=="__configured__" for x in user_rows_all):
        keys=user_keys
    else:
        keys=role_keys | user_keys
    if role_is_read_only(user.role):
        keys={k for k in keys if k.endswith(".view") or k in {"dashboard.view","instant_test.execute","instant_test.audit","notifications.manage","reports.export"}}
    return keys

def has_permission(db, user, permission):
    if user.role == "super_admin": return True
    keys=user_permission_keys(db,user)
    if role_is_read_only(user.role):
        if permission in {"dashboard.view","instant_test.execute","instant_test.audit"} or permission.endswith(".view"):
            return permission in keys
        if permission == "notifications.manage": return "notifications.view" in keys
        if permission == "reports.export": return "reports.view" in keys
        return False
    return permission in keys

def required_permission(path, method):
    m=method.upper()
    # Auth/session endpoints are handled separately.
    if path in {"/api/auth/change-password","/api/auth/me","/api/auth/logout"}: return None
    if path.startswith("/api/auth/"): return None
    if path.startswith("/api/dashboard") or path=="/api/dashboard": return "dashboard.view"
    if path.startswith("/api/instant-test"): return "instant_test.execute"
    if path.startswith("/api/v2/"):
        if path.startswith("/api/v2/reports/"):
            return "reports.view" if m=="GET" else "reports.export"
        if path.startswith("/api/v2/screenshots"):
            return "services.view"
        if m=="GET": return "services.view"
        if m=="POST": return "services.create"
        if m in {"PUT","PATCH"}: return "services.update"
        if m=="DELETE": return "services.delete"
    if path.startswith("/api/services"):
        if "/security/" in path: return "services.security"
        if path.endswith("/screenshot"): return "services.screenshot"
        if m=="GET": return "services.view"
        if m=="POST": return "services.create"
        if m=="PUT": return "services.update"
        if m=="DELETE": return "services.delete"
    if path.startswith("/api/groups"):
        if m=="GET": return "groups.view"
        return {"POST":"groups.create","PUT":"groups.update","DELETE":"groups.delete"}.get(m)
    if path.startswith("/api/branding"):
        return "branding.manage" if m!="GET" else "settings.view"
    if path.startswith("/api/screenshots"):
        return "settings.view"
    if path.startswith("/api/settings/retention"):
        return "retention.view" if m=="GET" else "retention.update"
    if path=="/api/settings" or path.startswith("/api/settings/"):
        return "settings.view" if m=="GET" else "settings.update"
    if path.startswith("/api/providers") or path.startswith("/api/telegram") or path.startswith("/api/smtp"):
        return "integrations.view" if m=="GET" else "integrations.update"
    if path.startswith("/api/notification-templates"):
        return "notification_templates.view" if m=="GET" else "notification_templates.update"
    if path.startswith("/api/notifications"):
        return "notifications.view" if m=="GET" else "notifications.manage"
    if path.startswith("/api/logs"): return "logs.view"
    if path.startswith("/api/incidents"): return "incidents.view"
    if path.startswith("/api/audit"): return "audit.view"
    if path.startswith("/api/export"): return "reports.export"
    if path.startswith("/api/users"):
        return {"GET":"users.view","POST":"users.create","PUT":"users.update","DELETE":"users.delete"}.get(m)
    if path.startswith("/api/roles/"):
        return "users.update" if m!="GET" else "users.view"
    return None

PUBLIC_PATHS={"/api/auth/login","/api/auth/forgot-password","/api/auth/verify-email","/api/auth/reset-password","/api/services/schema","/api/openapi-short","/api/branding","/api/health","/openapi.json","/docs","/docs/oauth2-redirect","/redoc","/swagger"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path=request.url.path
    # Screenshot files are private even though the frontend uses direct image URLs.
    if path.startswith("/screenshots/"):
        db=SessionLocal()
        try:
            user=current_user(request, db)
            if not has_permission(db, user, "services.view"):
                return JSONResponse({"detail":"Ekran görüntülerini görüntüleme yetkiniz yok."}, status_code=403, headers={"Cache-Control":"no-store"})
            request.state.user_id=user.id
            request.state.user_username=user.username
            request.state.user_role=user.role
        except HTTPException as exc:
            return JSONResponse({"detail":exc.detail}, status_code=exc.status_code, headers={"Cache-Control":"no-store"})
        finally:
            db.close()
        response=await call_next(request)
        response.headers["Cache-Control"]="private, no-store, max-age=0"
        response.headers["X-Content-Type-Options"]="nosniff"
        return response
    public_path = path in PUBLIC_PATHS and (request.method == "GET" or path not in {"/api/branding", "/api/services/schema"})
    if path.startswith("/static") or public_path or not path.startswith("/api"):
        return await call_next(request)
    # Attach authenticated user to request state; endpoint-level role checks are applied below.
    db=SessionLocal()
    try:
        user=current_user(request,db)
        request.state.user_id=user.id
        request.state.user_username=user.username
        request.state.user_role=user.role
        request.state.must_change_password=user.must_change_password
    except HTTPException as exc:
        return JSONResponse({"detail":exc.detail},status_code=exc.status_code)
    finally:
        db.close()
    # Mandatory password rotation blocks all application operations until the password is changed.
    if getattr(request.state, "must_change_password", False) and path not in {"/api/auth/me", "/api/auth/change-password", "/api/auth/logout"}:
        return JSONResponse({"detail":"İlk girişte şifrenizi değiştirmeniz gerekiyor."},status_code=428)
    permission=required_permission(path, request.method)
    if permission:
        db=SessionLocal()
        try:
            user=db.get(User, request.state.user_id)
            if not user or not has_permission(db,user,permission):
                return JSONResponse({"detail":f"Bu işlem için yetkiniz yok: {PERMISSION_CATALOG.get(permission, permission)}"},status_code=403)
        finally:
            db.close()
    return await call_next(request)



@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def migrate():
    """Portable additive migration for legacy SQLite/PostgreSQL databases."""
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    def add_columns(table, additions):
        if table not in tables:
            return
        existing = {c["name"] for c in inspect(engine).get_columns(table)}
        with engine.begin() as conn:
            for name, ddl in additions.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))

    add_columns("services", {
        "monitor_type":"VARCHAR DEFAULT 'http'", "status_ranges":"TEXT DEFAULT '200-299'", "last_http_status":"INTEGER",
        "last_resolved_ip":"VARCHAR DEFAULT ''", "description":"TEXT DEFAULT ''", "service_authorized_name":"VARCHAR DEFAULT ''",
        "last_headers_json":"TEXT DEFAULT '{}'", "last_header_security_json":"TEXT DEFAULT '{}'", "last_tls_security_json":"TEXT DEFAULT '{}'", "last_tls_scan_at":"TIMESTAMP", "ignored_http_status_codes":"VARCHAR DEFAULT '401,403'",
        "last_screenshot_path":"VARCHAR DEFAULT ''", "last_screenshot_at":"TIMESTAMP", "last_cert_days":"INTEGER",
        "last_rule_signature":"VARCHAR DEFAULT ''", "dependency_ids":"TEXT DEFAULT '[]'", "dependency_notifications_enabled":"BOOLEAN DEFAULT FALSE",
        "notification_group_ids_json":"TEXT DEFAULT '[]'", "custom_notification_enabled":"BOOLEAN DEFAULT FALSE", "custom_notification_message":"TEXT DEFAULT ''",
        "custom_notification_group_ids":"TEXT DEFAULT '[]'", "notification_group_configs":"TEXT DEFAULT '[]'", "notification_rules":"TEXT DEFAULT '[]'", "notification_cooldown_minutes":"INTEGER DEFAULT 0",
        "down_notification_subject":"VARCHAR DEFAULT 'DOWN - {{SERVICE_NAME}}'", "down_notification_message":"TEXT DEFAULT '{{SERVICE_NAME}} erişilemiyor. Neden: {{REASON}}'",
        "recovery_notification_subject":"VARCHAR DEFAULT 'RECOVERY - {{SERVICE_NAME}}'", "recovery_notification_message":"TEXT DEFAULT '{{SERVICE_NAME}} yeniden erişilebilir durumda.'",
        "warning_notification_subject":"VARCHAR DEFAULT 'WARNING - {{SERVICE_NAME}}'", "warning_notification_message":"TEXT DEFAULT '{{SERVICE_NAME}} WARNING durumunda. Neden: {{REASON}}'",
        "latency_notification_subject":"VARCHAR DEFAULT 'LATENCY - {{SERVICE_NAME}}'", "latency_notification_message":"TEXT DEFAULT '{{SERVICE_NAME}} latency alarmı: {{LATENCY_MS}} ms.'",
        "last_latency_alarm":"VARCHAR DEFAULT ''", "certificate_notification_group_ids":"TEXT DEFAULT '[]'",
        "certificate_notification_subject":"VARCHAR DEFAULT 'Sertifika uyarısı - {{SERVICE_NAME}}'",
        "certificate_notification_message":"TEXT DEFAULT '{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor. Bitiş: {{CERT_EXPIRY}}'",
    })
    add_columns("check_results", {
        "headers_json":"TEXT DEFAULT '{}'", "header_security_json":"TEXT DEFAULT '{}'", "tls_security_json":"TEXT DEFAULT '{}'"
    })
    add_columns("app_settings", {
        "default_notification_group_id":"INTEGER", "default_notification_subject":"VARCHAR DEFAULT 'Service Monitor - {{STATUS}} - {{SERVICE_NAME}}'",
        "default_notification_message":"TEXT DEFAULT 'Servis: {{SERVICE_NAME}}\\nDurum: {{STATUS}}\\nNeden: {{REASON}}'",
        "down_notification_subject":"VARCHAR DEFAULT 'DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}'", "down_notification_message":"TEXT DEFAULT 'Service Monitor - DOWN'",
        "recovery_notification_subject":"VARCHAR DEFAULT 'RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}'", "recovery_notification_message":"TEXT DEFAULT 'Service Monitor - RECOVERY'",
        "warning_notification_subject":"VARCHAR DEFAULT 'WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}'", "warning_notification_message":"TEXT DEFAULT 'Service Monitor - WARNING'",
        "latency_notification_subject":"VARCHAR DEFAULT 'LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms'", "latency_notification_message":"TEXT DEFAULT 'Service Monitor - LATENCY WARNING'",
        "screenshot_on_http_failure":"BOOLEAN DEFAULT TRUE", "screenshot_interval_seconds":"INTEGER DEFAULT 900", "screenshot_timeout_seconds":"INTEGER DEFAULT 30", "screenshot_wait_seconds":"INTEGER DEFAULT 2", "screenshot_retention_days":"INTEGER DEFAULT 30", "screenshot_trigger_codes":"VARCHAR DEFAULT '404,500-599'", "screenshot_capture_on_down":"BOOLEAN DEFAULT TRUE", "screenshot_capture_on_up":"BOOLEAN DEFAULT FALSE", "screenshot_routine_enabled":"BOOLEAN DEFAULT TRUE", "tls_scan_enabled":"BOOLEAN DEFAULT TRUE", "tls_scan_interval_days":"INTEGER DEFAULT 7", "branding_logo_url":"VARCHAR DEFAULT '/static/assets/um-logo.svg'",
        "retention_enabled":"BOOLEAN DEFAULT FALSE", "retention_checks_days":"INTEGER DEFAULT 30", "retention_logs_days":"INTEGER DEFAULT 90",
        "retention_audit_days":"INTEGER DEFAULT 365", "retention_incidents_days":"INTEGER DEFAULT 3650", "retention_cleanup_hour":"INTEGER DEFAULT 3",
    })
    add_columns("smtp_settings", {
        "auth_enabled":"BOOLEAN DEFAULT TRUE", "mode":"VARCHAR DEFAULT 'auth'", "helo_name":"VARCHAR DEFAULT ''", "test_recipient":"VARCHAR DEFAULT ''"
    })
    add_columns("app_notifications", {"target_user_id":"INTEGER"})
    if "services" in tables:
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE services SET header_monitoring=FALSE, expected_headers='{}' WHERE header_monitoring=TRUE"))
        except Exception:
            pass

migrate()

# Hot-path indexes. These are safe on both PostgreSQL and SQLite.
try:
    with engine.begin() as c:
        for ddl in [
            "CREATE INDEX IF NOT EXISTS ix_event_logs_created_at ON event_logs(created_at)",
            "CREATE INDEX IF NOT EXISTS ix_event_logs_category_level ON event_logs(category, level)",
            "CREATE INDEX IF NOT EXISTS ix_event_logs_service_created ON event_logs(service_id, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs(created_at)",
            "CREATE INDEX IF NOT EXISTS ix_check_results_service_checked ON check_results(service_id, checked_at)",
            "CREATE INDEX IF NOT EXISTS ix_check_results_status_checked ON check_results(status, checked_at)",
            "CREATE INDEX IF NOT EXISTS ix_incidents_service_started ON incidents(service_id, started_at)",
            "CREATE INDEX IF NOT EXISTS ix_incidents_status_started ON incidents(status, started_at)",
            "CREATE INDEX IF NOT EXISTS ix_service_screenshots_service_captured ON service_screenshots(service_id, captured_at)",
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_notification_reads_user_notification ON app_notification_reads(user_id, notification_id)",
            "CREATE INDEX IF NOT EXISTS ix_app_notifications_created_category ON app_notifications(created_at, category)",
            "CREATE INDEX IF NOT EXISTS ix_app_notifications_target_created ON app_notifications(target_user_id, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_role_permissions_role_enabled ON role_permissions(role, enabled)",
            "CREATE INDEX IF NOT EXISTS ix_user_permissions_user_enabled ON user_permissions(user_id, enabled)",
        ]:
            try:
                c.execute(text(ddl))
            except Exception:
                pass
except Exception:
    pass


def cleanup_retention_once():
    db=SessionLocal()
    try:
        a=db.query(AppSettings).first()
        if not a or not getattr(a,"retention_enabled",False):
            return {"ok":True,"enabled":False,"deleted":{}}
        now=datetime.utcnow(); deleted={}
        policies=[
            ("checks",CheckResult,"checked_at",max(1,int(a.retention_checks_days or 30))),
            ("logs",EventLog,"created_at",max(1,int(a.retention_logs_days or 90))),
            ("audit",AuditLog,"created_at",max(1,int(a.retention_audit_days or 365))),
        ]
        for key,model,col,days in policies:
            cutoff=now-timedelta(days=days)
            n=db.query(model).filter(col < cutoff).delete(synchronize_session=False)
            deleted[key]=int(n)
        cutoff=now-timedelta(days=max(1,int(a.retention_incidents_days or 3650)))
        n=db.query(Incident).filter(Incident.status!="OPEN",Incident.resolved_at.isnot(None),Incident.resolved_at < cutoff).delete(synchronize_session=False)
        deleted["incidents"]=int(n)
        db.commit()
        # Toplu DELETE ORM olayı üretmez; geçmiş veri değiştiği için analitik önbelleğini açıkça geçersiz kıl.
        cache_hooks.invalidate_analytics()
        return {"ok":True,"enabled":True,"deleted":deleted}
    except Exception:
        db.rollback()
        return {"ok":False,"enabled":True,"deleted":{}}
    finally:
        db.close()

def _retention_worker():
    last_run_day=None
    while True:
        try:
            db=SessionLocal(); a=db.query(AppSettings).first(); now=datetime.utcnow()
            enabled=bool(a and getattr(a,"retention_enabled",False)); hour=int(getattr(a,"retention_cleanup_hour",3) or 3) if a else 3
            db.close()
            day_key=now.strftime("%Y-%m-%d")
            if enabled and now.hour==max(0,min(23,hour)) and last_run_day!=day_key:
                cleanup_retention_once(); last_run_day=day_key
        except Exception: pass
        time.sleep(60)

threading.Thread(target=_retention_worker,daemon=True,name="retention-cleanup").start()

def _screenshot_retention_worker():
    while True:
        try:
            db=SessionLocal();a=db.query(AppSettings).first();days=max(1,int(getattr(a,"screenshot_retention_days",30) or 30)) if a else 30;cutoff=datetime.utcnow()-timedelta(days=days);old=db.query(ServiceScreenshot).filter(ServiceScreenshot.captured_at<cutoff).all()
            for sh in old:
                try:
                    rel=(sh.path or "").replace("/screenshots/","",1).lstrip("/");fp=os.path.join("screenshots",rel)
                    if os.path.isfile(fp):os.remove(fp)
                except Exception:pass
            if old:db.query(ServiceScreenshot).filter(ServiceScreenshot.id.in_([x.id for x in old])).delete(synchronize_session=False);db.commit()
            else:db.rollback()
            db.close()
        except Exception:pass
        time.sleep(3600)

def _tls_scan_service(sid):
    db=SessionLocal()
    try:
        s=db.get(Service,sid)
        if not s or not s.enabled or not bool(getattr(s,"certificate_monitoring",True)):return
        typ=(s.monitor_type or "").lower()
        if typ not in {"web","http","https","ssl"}:return
        opts=jd(s.protocol_options,"{}")
        if typ=="ssl":host=opts.get("host") or s.url;port=int(opts.get("port",443))
        else:
            u=s.url or opts.get("url","");u=u if "://" in u else "https://"+u;pu=urlparse(u);host=pu.hostname or "";port=pu.port or 443
            if pu.scheme!="https" and not opts.get("force_tls_scan"):return
        if not host:return
        result=tls_security_scan(host,port);s.last_tls_security_json=json.dumps(result or {},ensure_ascii=False,default=str);s.last_tls_scan_at=datetime.utcnow();log(db,"TLS",f"Periyodik TLS analizi tamamlandı · {host}:{port}","INFO",s.id);db.commit()
    except Exception as exc:
        try:
            s=db.get(Service,sid)
            if s:s.last_tls_security_json=json.dumps({"available":False,"error":str(exc)[:1000]},ensure_ascii=False);s.last_tls_scan_at=datetime.utcnow();log(db,"TLS",f"TLS analizi başarısız: {exc}","WARNING",sid);db.commit()
        except Exception:db.rollback()
    finally:db.close()

def _tls_worker():
    while True:
        try:
            db=SessionLocal();now=datetime.utcnow();a=db.query(AppSettings).first();enabled=bool(a and getattr(a,"tls_scan_enabled",True));default_days=max(1,int(getattr(a,"tls_scan_interval_days",7) or 7)) if a else 7;due=[]
            if enabled:
                for x in db.query(Service).filter(Service.enabled.is_(True)).all():
                    if (x.monitor_type or "").lower() not in {"web","http","https","ssl"}:continue
                    try:interval=max(1,int(jd(x.protocol_options,"{}").get("tls_scan_interval_days",default_days) or default_days))
                    except Exception:interval=default_days
                    if not x.last_tls_scan_at or (now-x.last_tls_scan_at).total_seconds()>=interval*86400:due.append(x.id)
            db.close()
            for sid in due[:3]:_tls_scan_service(sid)
        except Exception:pass
        time.sleep(60)

threading.Thread(target=_tls_worker,daemon=True,name="tls-security-scan").start()
threading.Thread(target=_screenshot_retention_worker,daemon=True,name="screenshot-retention").start()

# Upgrade untouched legacy service templates to the detailed operational format.
try:
    _tmpls={
        "down_notification_subject":"DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}",
        "down_notification_message":"Service Monitor - DOWN\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nSon kontrol: {{LAST_CHECK}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\n24 saat min/max latency: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\n24 saat olay sayısı: {{INCIDENT_COUNT_24H}}\n24 saat downtime: {{DOWNTIME_24H}} sn\nNeden: {{REASON}}",
        "recovery_notification_subject":"RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}",
        "recovery_notification_message":"Service Monitor - RECOVERY\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nKontrol zamanı: {{TIME}}\nKontrol aralığı: {{INTERVAL_TIME}}\n24 saat kontrol sayısı: {{CHECK_COUNT_24H}}\n24 saat uptime: %{{UPTIME_24H}}\nLatency: {{LATENCY_MS}} ms\nKesinti nedeni: {{REASON}}\nArdışık hata: {{FAILURE_COUNT}}",
        "warning_notification_subject":"WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}",
        "warning_notification_message":"Service Monitor - WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nHTTP: {{HTTP_STATUS}}\nKontrol zamanı: {{TIME}}\nLatency: {{LATENCY_MS}} ms\n24 saat ortalama latency: {{AVG_LATENCY_24H}} ms\nArdışık hata: {{FAILURE_COUNT}}\nNeden: {{REASON}}",
        "latency_notification_subject":"LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms",
        "latency_notification_message":"Service Monitor - LATENCY WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nDurum: {{STATUS}}\nAnlık latency: {{LATENCY_MS}} ms\n24 saat ortalama: {{AVG_LATENCY_24H}} ms\n24 saat min/max: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nKontrol sayısı: {{CHECK_COUNT_24H}}\nUptime: %{{UPTIME_24H}}\nKontrol zamanı: {{TIME}}"
    }
    _legacy={
        "down_notification_subject":"DOWN - {{SERVICE_NAME}}","down_notification_message":"{{SERVICE_NAME}} erişilemiyor. Neden: {{REASON}}",
        "recovery_notification_subject":"RECOVERY - {{SERVICE_NAME}}","recovery_notification_message":"{{SERVICE_NAME}} yeniden erişilebilir durumda.",
        "warning_notification_subject":"WARNING - {{SERVICE_NAME}}","warning_notification_message":"{{SERVICE_NAME}} WARNING durumunda. Neden: {{REASON}}",
        "latency_notification_subject":"LATENCY - {{SERVICE_NAME}}","latency_notification_message":"{{SERVICE_NAME}} latency alarmı: {{LATENCY_MS}} ms."
    }
    with engine.begin() as _c:
        for _col,_old in _legacy.items():
            _c.execute(text(f"UPDATE services SET {_col}=:new WHERE {_col}=:old"), {"new":_tmpls[_col],"old":_old})
except Exception:
    pass

# Professional default notification templates. Existing custom templates are preserved unless they match known defaults.
try:
    _professional={
      "down_notification_subject":"DOWN | {{SERVICE_NAME}} | {{HOST_NAME}}",
      "down_notification_message":"SERVICE MONITOR — DOWN\n\nServis: {{SERVICE_NAME}} (ID: {{SERVICE_ID}})\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nPort: {{PORT}}\n\nDURUM\nMevcut: {{STATUS}}\nÖnceki: {{PREVIOUS_STATUS}}\nOlay: {{EVENT_TYPE}}\nOlay zamanı: {{EVENT_TIME}}\nSon kontrol: {{LAST_CHECK}}\n\nPERFORMANS\nLatency: {{LATENCY_MS}} ms\nOrtalama: {{AVG_LATENCY_24H}} ms\nMin/Max: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nUptime (24s): %{{UPTIME_24H}}\nKontrol: {{CHECK_COUNT_24H}} | Başarılı: {{SUCCESS_COUNT_24H}} | Başarısız: {{FAILURE_COUNT_24H}}\nArdışık hata: {{FAILURE_COUNT}}\nOlay sayısı: {{INCIDENT_COUNT_24H}} | Downtime: {{DOWNTIME_24H}} sn\n\nHTTP / HATA\nHTTP: {{HTTP_STATUS}}\nHata: {{ERROR_MESSAGE}}\nNeden: {{REASON}}\n\nSSL\nDurum: {{CERT_STATUS}}\nSahip: {{CERT_SUBJECT}}\nSağlayıcı: {{CERT_ISSUER}}\nBitiş: {{CERT_EXPIRY}}\nKalan: {{CERT_DAYS}} gün",
      "recovery_notification_subject":"RECOVERY | {{SERVICE_NAME}} | {{HOST_NAME}}",
      "recovery_notification_message":"SERVICE MONITOR — RECOVERY\n\nServis: {{SERVICE_NAME}} (ID: {{SERVICE_ID}})\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nURL: {{HOST_URL}}\nIP: {{RESOLVED_IP}}\nPort: {{PORT}}\n\nDURUM\nMevcut: {{STATUS}}\nÖnceki: {{PREVIOUS_STATUS}}\nOlay: {{EVENT_TYPE}}\nOlay zamanı: {{EVENT_TIME}}\nSon kontrol: {{LAST_CHECK}}\n\nPERFORMANS\nLatency: {{LATENCY_MS}} ms\nOrtalama: {{AVG_LATENCY_24H}} ms\nUptime (24s): %{{UPTIME_24H}}\nKontrol: {{CHECK_COUNT_24H}} | Başarılı: {{SUCCESS_COUNT_24H}} | Başarısız: {{FAILURE_COUNT_24H}}\nDowntime (24s): {{DOWNTIME_24H}} sn\n\nHTTP: {{HTTP_STATUS}}\nSon hata: {{ERROR_MESSAGE}}\nKurtarma nedeni: {{REASON}}\n\nSSL\nDurum: {{CERT_STATUS}}\nBitiş: {{CERT_EXPIRY}}\nKalan: {{CERT_DAYS}} gün",
      "warning_notification_subject":"WARNING | {{SERVICE_NAME}} | {{HOST_NAME}}",
      "warning_notification_message":"SERVICE MONITOR — WARNING\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nIP: {{RESOLVED_IP}}\n\nDurum: {{STATUS}} | Önceki: {{PREVIOUS_STATUS}}\nOlay: {{EVENT_TYPE}} | Zaman: {{EVENT_TIME}}\n\nLatency: {{LATENCY_MS}} ms | Ortalama: {{AVG_LATENCY_24H}} ms\nUptime: %{{UPTIME_24H}}\nKontroller: {{CHECK_COUNT_24H}} | Başarısız: {{FAILURE_COUNT_24H}}\nArdışık hata: {{FAILURE_COUNT}}\nHTTP: {{HTTP_STATUS}}\nHata: {{ERROR_MESSAGE}}\nNeden: {{REASON}}\nSSL: {{CERT_STATUS}} | Bitiş: {{CERT_EXPIRY}} | Kalan: {{CERT_DAYS}} gün",
      "latency_notification_subject":"LATENCY | {{SERVICE_NAME}} | {{LATENCY_MS}} ms",
      "latency_notification_message":"SERVICE MONITOR — LATENCY ALARM\n\nServis: {{SERVICE_NAME}}\nTip: {{MONITOR_TYPE}}\nHost: {{HOST_NAME}}\nIP: {{RESOLVED_IP}}\n\nDurum: {{STATUS}}\nOlay: {{EVENT_TYPE}}\nZaman: {{EVENT_TIME}}\n\nAnlık latency: {{LATENCY_MS}} ms\n24s ortalama: {{AVG_LATENCY_24H}} ms\n24s min/max: {{MIN_LATENCY_24H}} / {{MAX_LATENCY_24H}} ms\nUptime: %{{UPTIME_24H}}\nKontrol sayısı: {{CHECK_COUNT_24H}}\n\nHTTP: {{HTTP_STATUS}}\nHata: {{ERROR_MESSAGE}}\nNeden: {{REASON}}\n\nSSL: {{CERT_STATUS}}\nSertifika bitiş: {{CERT_EXPIRY}}\nSertifika kalan: {{CERT_DAYS}} gün"
    }
    with engine.begin() as _c:
        _legacy_subjects={"down_notification_subject":["DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}","DOWN - {{SERVICE_NAME}}"],"recovery_notification_subject":["RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}","RECOVERY - {{SERVICE_NAME}}"],"warning_notification_subject":["WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}","WARNING - {{SERVICE_NAME}}"],"latency_notification_subject":["LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms","LATENCY - {{SERVICE_NAME}}"]}
        for col,vals in _legacy_subjects.items():
            for oldv in vals:_c.execute(text(f"UPDATE app_settings SET {col}=:new WHERE {col}=:old"),{"new":_professional[col],"old":oldv})
        # Known previous detailed defaults are upgraded; arbitrary user-customized text is left intact.
        _old_down="Service Monitor - DOWN\n\nServis: {{SERVICE_NAME}}"
        _old_rec="Service Monitor - RECOVERY\n\nServis: {{SERVICE_NAME}}"
        _old_warn="Service Monitor - WARNING\n\nServis: {{SERVICE_NAME}}"
        _old_lat="Service Monitor - LATENCY WARNING\n\nServis: {{SERVICE_NAME}}"
        for col,oldv in [("down_notification_message",_old_down),("recovery_notification_message",_old_rec),("warning_notification_message",_old_warn),("latency_notification_message",_old_lat)]:
            _c.execute(text(f"UPDATE app_settings SET {col}=:new WHERE {col}=:old"),{"new":_professional[col],"old":oldv})
        for col,newv in _professional.items():
            if col.endswith("_subject"):
                for oldv in _legacy_subjects.get(col,[]):_c.execute(text(f"UPDATE services SET {col}=:new WHERE {col}=:old"),{"new":newv,"old":oldv})
            else:
                # Previous ZIP used the same "Service Monitor - ..." detailed defaults.
                prefix={"down_notification_message":"Service Monitor - DOWN","recovery_notification_message":"Service Monitor - RECOVERY","warning_notification_message":"Service Monitor - WARNING","latency_notification_message":"Service Monitor - LATENCY WARNING"}.get(col)
                if prefix:
                    _c.execute(text(f"UPDATE app_settings SET {col}=:new WHERE {col} LIKE :old"),{"new":newv,"old":prefix+"%"})
                    _c.execute(text(f"UPDATE services SET {col}=:new WHERE {col} LIKE :old"),{"new":newv,"old":prefix+"%"})
except Exception:
    pass

pool=ThreadPoolExecutor(max_workers=20); running=set(); lock=threading.Lock(); scheduler_started=False

def seed():
    db=SessionLocal()
    # Permission defaults are stored in DB so Admin and Semi Admin can be configured without code changes.
    role_defaults = {
        "admin": {"dashboard.view","services.view","services.create","services.update","services.security","instant_test.execute","instant_test.audit","groups.view","groups.create","groups.update","settings.view","integrations.view","notification_templates.view","notifications.view","logs.view","incidents.view","audit.view","reports.view","retention.view","users.view"},
        "read_only_admin": {"dashboard.view","services.view","instant_test.execute","instant_test.audit","groups.view","settings.view","integrations.view","notification_templates.view","notifications.view","logs.view","incidents.view","audit.view","reports.view","retention.view","users.view"},
    }
    for _role, _keys in role_defaults.items():
        for _key in _keys:
            if not db.query(RolePermission).filter_by(role=_role, permission=_key).first():
                db.add(RolePermission(role=_role, permission=_key, enabled=True))
    db.commit()
    try:
        if not db.query(AppSettings).first():db.add(AppSettings())
        if not db.query(SMTPSettings).first():db.add(SMTPSettings())
        if not db.query(NotificationGroup).first():
            db.add(NotificationGroup(name="Varsayılan Bildirim Grubu",auto_add_new_services=True,channels_json='{"email":true}',recipients_json='{"email":[]}'))
        for p in ["telegram","discord","slack","webhook","cloudflare","aws","better_uptime","pingdom"]:
            if not db.query(Integration).filter_by(provider=p).first():db.add(Integration(provider=p))
        db.commit()
        # Migrate legacy Telegram credentials from notification groups into the global integration once.
        tg=db.query(Integration).filter_by(provider="telegram").first()
        if tg and not json.loads(tg.config_json or "{}").get("token"):
            for _g in db.query(NotificationGroup).all():
                _r=json.loads(_g.recipients_json or "{}")
                if _r.get("telegram_token") and _r.get("telegram_chat_id"):
                    tg.enabled=True
                    tg.config_json=json.dumps({"token":_r["telegram_token"],"chat_id":_r["telegram_chat_id"],"parse_mode":_r.get("telegram_parse_mode","HTML")},ensure_ascii=False)
                    break
        appset=db.query(AppSettings).first()
        # Ensure a fresh installation receives the professional templates too.
        for _col,_new in _professional.items():
            _cur=getattr(appset,_col,None)
            if _col.endswith("_subject") and (_cur in {None,"", "DOWN - {{SERVICE_NAME}} - {{HOST_NAME}}","RECOVERY - {{SERVICE_NAME}} - {{HOST_NAME}}","WARNING - {{SERVICE_NAME}} - {{HOST_NAME}}","LATENCY - {{SERVICE_NAME}} - {{LATENCY_MS}} ms"} or _cur.startswith("DOWN - {{SERVICE_NAME}}") or _cur.startswith("RECOVERY - {{SERVICE_NAME}}") or _cur.startswith("WARNING - {{SERVICE_NAME}}") or _cur.startswith("LATENCY - {{SERVICE_NAME}}")):
                setattr(appset,_col,_new)
            elif _col.endswith("_message") and (_cur in {None,""} or str(_cur).startswith("Service Monitor - ")):
                setattr(appset,_col,_new)
        first=db.query(NotificationGroup).order_by(NotificationGroup.id).first()
        if not appset.default_notification_group_id and first:
            appset.default_notification_group_id=first.id;db.commit()
    finally:db.close()
seed()

# İlk kurulum hesabı: admin / admin. İlk hesap için e-posta doğrulaması zorunlu değildir.
_db_init=SessionLocal()
try:
    ensure_admin(_db_init)
finally:
    _db_init.close()

def jd(v,default):
    try:return json.loads(v or default)
    except Exception:return json.loads(default)

def sd(s):
    d={c.name:getattr(s,c.name) for c in Service.__table__.columns}
    # Never lazy-load notification_groups in the hot path. The JSON field is already persisted with the service.
    d["notification_group_ids"]=jd(s.notification_group_ids_json,"[]")
    d["dependency_ids"]=jd(s.dependency_ids,"[]")
    d["custom_notification_group_ids"]=jd(s.custom_notification_group_ids,"[]")
    d["certificate_notification_group_ids"]=jd(s.certificate_notification_group_ids,"[]")
    d["notification_rules"]=jd(s.notification_rules,"[]")
    d["resolved_ip"]=s.last_resolved_ip or None
    d["ignored_http_status_codes"]=[int(x.strip()) for x in str(getattr(s,"ignored_http_status_codes","401,403") or "").split(",") if x.strip().isdigit()]
    d["last_tls_scan_at"]=s.last_tls_scan_at
    d["notification_group_configs"]=jd(getattr(s,"notification_group_configs","[]"),"[]")
    d["content_keywords"]=jd(s.content_keywords,"[]")
    d["expected_headers"]=jd(s.expected_headers,"{}")
    d["protocol_options"]=jd(s.protocol_options,"{}")
    d["headers"]=jd(s.last_headers_json,"{}")
    d["header_security"]=jd(s.last_header_security_json,"{}")
    d["tls_security"]=jd(s.last_tls_security_json,"{}")
    return d

def log(db,cat,msg,level="INFO",sid=None):
    # Do not commit from inside monitoring work. One check = one transaction.
    db.add(EventLog(category=cat,message=msg,level=level,service_id=sid))

def app_notification(db, category, event_type, title, message, link="", service_id=None, metadata=None, target_user_id=None):
    db.add(AppNotification(category=category, event_type=event_type, title=title, message=message,
                           link=link, service_id=service_id, target_user_id=target_user_id,
                           metadata_json=json.dumps(metadata or {}, ensure_ascii=False, default=str)))

def default_groups(db):
    a=db.query(AppSettings).first()
    if a and a.default_notification_group_id:
        g=db.get(NotificationGroup,a.default_notification_group_id)
        if g and g.enabled:
            return [g]
    return db.query(NotificationGroup).filter_by(auto_add_new_services=True,enabled=True).all()

def groups_for_service(db,s):
    ids=jd(s.notification_group_ids_json,"[]")
    if ids:
        groups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(ids),NotificationGroup.enabled.is_(True)).all()
        if groups:
            return groups
    return default_groups(db)

def notify_default(db,s,subject,body):
    return notify(db,s,subject,body,default_groups(db))

def _root_cause(r):
    err=str(r.get("error") or "").lower()
    if r.get("server_reachable") is False or "ping başarısız" in err or "host erişilem" in err:return "server_down"
    if r.get("code") is not None:return f"http_{r.get('code')}"
    if "port" in err and ("kapalı" in err or "closed" in err or "connect" in err):return "port_closed"
    if err:return "check_error"
    return "ok"

def _rule_matches(rule,s,r):
    code=r.get("code")
    if rule.get("range") and code is not None:
        try:
            if not in_ranges(int(code),rule.get("range","200-299")):return False
        except Exception:return False
    conditions=rule.get("conditions") or []
    if not conditions:return True
    typ=(s.monitor_type or "web").lower();status=str(getattr(s,"last_status",None) or r.get("status") or "DOWN").upper();cause=_root_cause(r);results=[]
    for cond in conditions:
        field=str(cond.get("field") or "").lower();value=str(cond.get("value") or "").strip().lower()
        if field in {"service_type","type"}:ok=typ==value or (value=="db" and typ in {"mysql","postgresql","redis"})
        elif field in {"status","service_status"}:ok=value in {"both","any",""} or status==value.upper()
        elif field in {"root_cause","cause"}:ok=value in {cause,"any","all"} or (value and value in str(r.get("error") or "").lower())
        elif field in {"http_status","code"}:
            try:ok=int(r.get("code"))==int(value)
            except Exception:ok=False
        else:ok=True
        results.append(ok)
    return all(results) if str(rule.get("logic","AND")).upper()!="OR" else any(results)

def send_rule_notification(db,s,rule,r):
    st=db.query(AppSettings).first();status_text=f"HTTP {r.get('code')}" if r.get("code") is not None else str(r.get("status") or "DOWN")
    base_subject=rule.get("subject") or render(st.default_notification_subject,s,{"STATUS":status_text})
    base_msg=render(rule.get("message") or st.default_notification_message,s,{"STATUS":status_text,"REASON":r.get("error","")})
    ids=[int(x) for x in (rule.get("group_ids") or []) if str(x).isdigit()]
    groups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(ids),NotificationGroup.enabled.is_(True)).all() if ids else default_groups(db)
    configs={int(x.get("group_id")):x for x in jd(getattr(s,"notification_group_configs","[]"),"[]") if str(x.get("group_id","")).isdigit()}
    results=[]
    for g in groups:
        cfg=configs.get(g.id,{})
        subject=(cfg.get("subject") or base_subject) if cfg.get("custom_enabled") else base_subject
        msg=render(cfg.get("message") or base_msg,s,{"STATUS":status_text,"REASON":r.get("error","")}) if cfg.get("custom_enabled") else base_msg
        results.extend(notify(db,s,subject,msg,[g]))
    return results

def _screenshot_bucket(status, reason, http_status=None):
    if status == "DOWN": return "down"
    if status == "UP": return "up"
    return "routine"

def capture_service_screenshot(db, s, url, reason, status, http_status):
    """Capture a screenshot and store it under screenshots/<service>/<bucket>."""
    if not url or (s.monitor_type or "").lower() not in {"web","http","https"}:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        log(db,"SCREENSHOT",f"Ekran görüntüsü alınamadı: Playwright kurulu değil: {exc}","WARNING",s.id)
        return None
    now=datetime.utcnow()
    service_name=re.sub(r"[^a-zA-Z0-9_-]+","_",s.name).strip("_")[:80] or f"service-{s.id}"
    bucket=_screenshot_bucket(status,reason,http_status)
    code_text=f"response-{http_status or 'none'}"
    filename=f"{service_name}-{code_text}-{now.strftime('%Y%m%d-%H%M%S')}.png"
    folder=os.path.join("screenshots",service_name,bucket)
    os.makedirs(folder,exist_ok=True)
    path=os.path.join(folder,filename)
    timeout=max(5,int(getattr(db.query(AppSettings).first(),"screenshot_timeout_seconds",30) or 30))*1000
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page(viewport={"width":1440,"height":1000},device_scale_factor=1)
            page.goto(url,wait_until="domcontentloaded",timeout=timeout)
            wait_seconds=max(0,min(300,int(getattr(db.query(AppSettings).first(),"screenshot_wait_seconds",2) or 2)))
            if wait_seconds:
                page.wait_for_timeout(wait_seconds*1000)
            page.screenshot(path=path,full_page=True)
            browser.close()
        rel=f"{service_name}/{bucket}/{filename}"
        snap=ServiceScreenshot(service_id=s.id,captured_at=now,reason=reason,status=status,http_status=http_status,path="/screenshots/"+rel,url=url)
        db.add(snap)
        s.last_screenshot_path=snap.path
        s.last_screenshot_at=now
        log(db,"SCREENSHOT",f"Ekran görüntüsü alındı: {snap.path} · HTTP {http_status} · {reason}","WARNING",s.id)
        return snap
    except Exception as exc:
        log(db,"SCREENSHOT",f"Ekran görüntüsü alınamadı: {exc}","WARNING",s.id)
        return None

def _code_in_list(code,text):
    if code is None:return False
    try:return in_ranges(int(code),str(text or ""))
    except Exception:return False

def should_auto_screenshot(http_status):
    if http_status is None:return False
    db=SessionLocal()
    try:
        a=db.query(AppSettings).first();return _code_in_list(http_status,getattr(a,"screenshot_trigger_codes","404,500-599") if a else "404,500-599")
    finally:db.close()

def process(sid):
    db=SessionLocal()
    try:
        s=db.get(Service,sid)
        if not s:return
        if not s.enabled:return
        if s.maintenance and (not s.maintenance_until or s.maintenance_until>datetime.utcnow()):
            return
        if s.maintenance and s.maintenance_until and s.maintenance_until<=datetime.utcnow():
            s.maintenance=False;s.maintenance_until=None
        old=s.last_status
        r=check(s)
        s.last_check_at=datetime.utcnow();s.last_latency_ms=r["latency"];s.last_error=r["error"];s.last_http_status=r.get("code");s.last_resolved_ip=r.get("resolved_ip") or s.last_resolved_ip or ""
        if (s.monitor_type or "").lower() in {"web","http","https"}:
            s.last_headers_json=json.dumps(r.get("headers") or {},ensure_ascii=False)
            s.last_header_security_json=json.dumps(r.get("header_security") or {},ensure_ascii=False)
        if r.get("tls_security"):
            s.last_tls_security_json=json.dumps(r.get("tls_security") or {},ensure_ascii=False,default=str)
        if r.get("cert"):
            old_expiry=s.cert_expires_at
            s.cert_subject,s.cert_issuer,s.cert_expires_at=r["cert"]
            if old_expiry and s.cert_expires_at and abs((s.cert_expires_at-old_expiry).total_seconds()) > 3600:
                s.cert_alert_sent=False
            s.last_cert_days=max(0,int((s.cert_expires_at-datetime.utcnow()).total_seconds()/86400))
        if r["status"]=="UP":s.consecutive_failures=0;new="UP"
        else:
            s.consecutive_failures+=1
            new="DOWN" if s.consecutive_failures>=max(1,s.failure_threshold) else "WARNING"
            if (s.monitor_type or "").lower() in {"web","http","https"} and r.get("server_reachable") is not None:
                if r.get("server_reachable"):
                    r["error"]=(r.get("error") or "")+" · Sunucu ayakta (ping başarılı), web uygulaması yanıtı sorunlu."
                else:
                    r["error"]=(r.get("error") or "")+" · Sunucuya ping başarısız; host erişilemiyor olabilir."
        # Optional advanced latency state. It never forces DOWN; it is an alarm layer.
        latency_alarm=None
        if s.advanced_alarm and s.last_latency_ms:
            if s.last_latency_ms>=s.latency_critical_ms:latency_alarm="CRITICAL"
            elif s.last_latency_ms>=s.latency_warning_ms:latency_alarm="WARNING"
        s.last_status=new
        app_settings=db.query(AppSettings).first()
        rules_configured=bool(jd(s.notification_rules,"[]"))
        if (s.monitor_type or "").lower() in {"web","http","https"} and bool(getattr(app_settings,"screenshot_on_http_failure",True)):
            last_shot=s.last_screenshot_at;interval=max(1,int(getattr(app_settings,"screenshot_interval_seconds",900) or 900));due=not last_shot or (datetime.utcnow()-last_shot).total_seconds()>=interval
            trigger=_code_in_list(r.get("code"),getattr(app_settings,"screenshot_trigger_codes","404,500-599"));periodic=due and bool(getattr(app_settings,"screenshot_routine_enabled",True));transition_down=due and new=="DOWN" and old!="DOWN" and bool(getattr(app_settings,"screenshot_capture_on_down",True));transition_up=due and new=="UP" and old not in {"UP",None,"UNKNOWN"} and bool(getattr(app_settings,"screenshot_capture_on_up",False))
            if due and (trigger or periodic or transition_down or transition_up):
                reason=f"HTTP {r.get('code')} tetikleyici" if trigger else ("DOWN geçişi" if transition_down else ("UP geçişi" if transition_up else "Periyodik rutin"))
                capture_service_screenshot(db,s,r.get("effective_url") or s.url,reason,new,r.get("code"))
        if r.get("cert") and s.certificate_alert_enabled and s.cert_expires_at:
            days=s.last_cert_days
            if days<=s.certificate_alert_days and not s.cert_alert_sent:
                st=db.query(AppSettings).first()
                subject=render(s.certificate_notification_subject or st.default_notification_subject,s,{"STATUS":"CERTIFICATE WARNING","CERT_DAYS":days})
                body=render(s.certificate_notification_message or st.default_notification_message,s,{"STATUS":"CERTIFICATE WARNING","CERT_DAYS":days,"REASON":f"Sertifika {days} gün içinde sona eriyor."})
                cids=jd(s.certificate_notification_group_ids,"[]")
                groups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(cids)).all() if cids else default_groups(db)
                results=notify(db,s,subject,body,groups)
                for gname,channel,ok,msg in results:
                    log(db,"NOTIFICATION",f"{channel.upper()} {'başarılı' if ok else 'BAŞARISIZ'} · {gname} · {msg}","INFO" if ok else "ERROR",s.id)
                s.cert_alert_sent=any(x[2] for x in results) if results else False
        # Multi-criteria notification rules (AND/OR), with legacy HTTP range support.
        matched=[]
        for idx,rule in enumerate(jd(s.notification_rules,"[]")):
            try:
                if rule.get("enabled",True) and _rule_matches(rule,s,r):
                    matched.append((idx,rule))
            except Exception:continue
        cause=_root_cause(r);status=str(getattr(s,"last_status",None) or new).upper();code=r.get("code")
        sig="|".join(f"rule:{idx}:{status}:{cause}:{code if code is not None else ''}" for idx,_ in matched)
        if sig and sig!=s.last_rule_signature:
            for _,rule in matched:send_rule_notification(db,s,rule,r)
        s.last_rule_signature=sig
        db.add(CheckResult(service_id=s.id,status=new,http_status=r.get("code"),latency_ms=r["latency"],error=r["error"],certificate_days=s.last_cert_days,rule_signature=sig,
                            headers_json=json.dumps(r.get("headers") or {},ensure_ascii=False),header_security_json=json.dumps(r.get("header_security") or {},ensure_ascii=False),tls_security_json=json.dumps(r.get("tls_security") or {},ensure_ascii=False)))
        if latency_alarm and latency_alarm!=s.last_latency_alarm:
            st=db.query(AppSettings).first();subject=render(st.latency_notification_subject or st.default_notification_subject,s,{"STATUS":f"LATENCY {latency_alarm}","EVENT_TYPE":"LATENCY","EVENT_TIME":datetime.utcnow(),"LATENCY_MS":s.last_latency_ms})
            body=render(st.latency_notification_message or st.default_notification_message,s,{"STATUS":f"LATENCY {latency_alarm}","EVENT_TYPE":"LATENCY","EVENT_TIME":datetime.utcnow(),"REASON":f"Gecikme {s.last_latency_ms} ms.","LATENCY_MS":s.last_latency_ms})
            for gname,channel,ok,msg in notify_default(db,s,subject,body) or []:
                log(db,"NOTIFICATION",f"{channel.upper()} {'başarılı' if ok else 'BAŞARISIZ'} · {gname} · {msg}","INFO" if ok else "ERROR",s.id)
            app_notification(db,"service","LATENCY_ALARM",f"Latency alarmı: {s.name}",f"Anlık latency {round(s.last_latency_ms)} ms ({latency_alarm}).",f"service-detail:{s.id}",s.id,{"latency_ms":s.last_latency_ms,"level":latency_alarm})
            s.last_latency_alarm=latency_alarm
        elif not latency_alarm:
            s.last_latency_alarm=""
        if old not in {"WARNING","DOWN"} and new=="WARNING":
            app_notification(db,"service","SERVICE_WARNING",f"Servis WARNING: {s.name}",r.get("error") or "Servis uyarı durumunda.",f"service-detail:{s.id}",s.id,{"status":"WARNING","http_status":r.get("code")})
            st=db.query(AppSettings).first()
            subject=render(st.warning_notification_subject or st.default_notification_subject,s,{"STATUS":"WARNING"})
            body=render(st.warning_notification_message or st.default_notification_message,s,{"STATUS":"WARNING","REASON":r["error"]})
            if not rules_configured:
                for gname,channel,ok,msg in notify(db,s,subject,body,groups_for_service(db,s)):
                    log(db,"NOTIFICATION",f"{channel.upper()} {'başarılı' if ok else 'BAŞARISIZ'} · {gname} · {msg}","INFO" if ok else "ERROR",s.id)
        if old!="DOWN" and new=="DOWN":
            db.add(Incident(service_id=s.id,reason=r["error"],failure_count=s.consecutive_failures));st=db.query(AppSettings).first()
            subject=render(st.down_notification_subject or st.default_notification_subject,s,{"STATUS":"DOWN","PREVIOUS_STATUS":old,"EVENT_TYPE":"DOWN","EVENT_TIME":datetime.utcnow()});body=render(st.down_notification_message or st.default_notification_message,s,{"STATUS":"DOWN","PREVIOUS_STATUS":old,"EVENT_TYPE":"DOWN","EVENT_TIME":datetime.utcnow(),"REASON":r["error"]})
            groups=groups_for_service(db,s)
            if not rules_configured:
                for gname,channel,ok,msg in notify(db,s,subject,body,groups):
                    log(db,"NOTIFICATION",f"{channel.upper()} {'başarılı' if ok else 'BAŞARISIZ'} · {gname} · {msg}","INFO" if ok else "ERROR",s.id)
                if s.custom_notification_enabled and s.custom_notification_message:
                    cids=jd(s.custom_notification_group_ids,"[]"); cgroups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(cids)).all() if cids else groups
                    notify(db,s,subject,render(s.custom_notification_message,s,{"STATUS":"DOWN","REASON":r["error"]}),cgroups)
            log(db,"INCIDENT","Olay açıldı: "+s.name,"ERROR",s.id)
            app_notification(db,"service","SERVICE_DOWN",f"Servis DOWN: {s.name}",r.get("error") or "Servis erişilemiyor.",f"service-detail:{s.id}",s.id,{"status":"DOWN","http_status":r.get("code"),"server_reachable":r.get("server_reachable")})
        if old=="DOWN" and new=="UP":
            inc=db.query(Incident).filter_by(service_id=s.id,status="OPEN").order_by(Incident.id.desc()).first()
            if inc:inc.status="RESOLVED";inc.resolved_at=datetime.utcnow();inc.downtime_seconds=(inc.resolved_at-inc.started_at).total_seconds()
            st=db.query(AppSettings).first()
            if st.recovery_enabled:
                subject=render(st.recovery_notification_subject or st.default_notification_subject,s,{"STATUS":"RECOVERY","PREVIOUS_STATUS":old,"EVENT_TYPE":"RECOVERY","EVENT_TIME":datetime.utcnow()});body=render(st.recovery_notification_message or st.default_notification_message,s,{"STATUS":"RECOVERY","PREVIOUS_STATUS":old,"EVENT_TYPE":"RECOVERY","EVENT_TIME":datetime.utcnow(),"REASON":"Servis yeniden erişilebilir."})
                groups=groups_for_service(db,s)
                if not rules_configured:
                    notify(db,s,subject,body,groups)
                    if s.custom_notification_enabled and s.custom_notification_message:
                        cids=jd(s.custom_notification_group_ids,"[]"); cgroups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(cids)).all() if cids else groups
                        notify(db,s,subject,render(s.custom_notification_message,s,{"STATUS":"RECOVERY","REASON":"Servis yeniden erişilebilir."}),cgroups)
            log(db,"RECOVERY","Kurtarıldı: "+s.name,sid=s.id)
            app_notification(db,"service","SERVICE_RECOVERY",f"Servis düzeldi: {s.name}","Servis yeniden erişilebilir durumda.",f"service-detail:{s.id}",s.id,{"status":"UP"})
        # Dependency notification is opt-in and disabled by default.
        deps=jd(s.dependency_ids,"[]")
        if deps:
            bad=[db.get(Service,int(x)) for x in deps];bad=[x for x in bad if x and x.last_status=="DOWN"]
            if bad and s.dependency_notifications_enabled:
                st=db.query(AppSettings).first();subject=render(st.default_notification_subject,s,{"STATUS":"DEPENDENCY DOWN"})
                body=render(st.default_notification_message,s,{"STATUS":"DEPENDENCY DOWN","REASON":"Bağımlı servis: "+", ".join(x.name for x in bad)})
                results=notify(db,s,subject,body,groups_for_service(db,s))
                for gname,channel,ok,msg in results:
                    log(db,"NOTIFICATION",f"{channel.upper()} {'başarılı' if ok else 'BAŞARISIZ'} · {gname} · {msg}","INFO" if ok else "ERROR",s.id)
        db.commit()
    except Exception as e:
        db.rollback()
        try:
            log(db,"ERROR",f"Kontrol hatası #{sid}: {e}","ERROR",sid)
            db.commit()
        except Exception:
            db.rollback()
    finally:db.close()

def build_daily_summary(db):
    since=datetime.utcnow()-timedelta(days=1)
    services=db.query(Service).all()
    lines=["Service Monitor - Son 24 Saat Özeti","",f"Oluşturulma: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",""]
    for s in services:
        controls=db.query(MonitorControl).filter_by(service_id=s.id).order_by(MonitorControl.id.asc()).all()
        lines += [f"{s.name}",f"  Servis durumu: {s.last_status}"]
        if controls:
            for c in controls:
                rows=db.query(CheckResult).filter(CheckResult.control_id==c.id,CheckResult.checked_at>=since).all()
                total=len(rows);up=sum(r.status=="UP" for r in rows);lat=[r.latency_ms for r in rows if r.latency_ms is not None]
                inc=db.query(Incident).filter(Incident.control_id==c.id,Incident.started_at>=since).count()
                upt=round(up/total*100,2) if total else 0
                lines += [f"  [{c.control_type.upper()}] {c.name}",
                          f"    Durum: {c.last_status} · Uptime: %{upt} · Kontrol: {total}",
                          f"    Ortalama gecikme: {round(sum(lat)/len(lat),2) if lat else 0} ms · Olay: {inc}",
                          f"    Son hata: {c.last_error or '-'}"]
        else:
            rows=db.query(CheckResult).filter(CheckResult.service_id==s.id,CheckResult.checked_at>=since).all()
            total=len(rows);up=sum(r.status=="UP" for r in rows);lat=[r.latency_ms for r in rows if r.latency_ms is not None]
            inc=db.query(Incident).filter(Incident.service_id==s.id,Incident.started_at>=since).count()
            upt=round(up/total*100,2) if total else 0
            lines += [f"  Uptime: %{upt}",f"  Kontrol: {total}",f"  Ortalama gecikme: {round(sum(lat)/len(lat),2) if lat else 0} ms",f"  Olay: {inc}",f"  Son hata: {s.last_error or '-'}"]
        lines.append("")
    return "\n".join(lines)

def scheduler():
    """Cadence scheduler for independent MonitorControl probes."""
    control_scheduler = ControlScheduler(pool, lock, running)
    last_summary = None
    while True:
        db = SessionLocal()
        try:
            control_scheduler.tick()
            a = db.query(AppSettings).first()
            local = datetime.now()
            key = local.strftime("%Y-%m-%d")
            if a and a.daily_summary_enabled and a.system_email and local.strftime("%H:%M") == str(a.daily_summary_time or "23:55") and last_summary != key:
                ok,msg=email(db,[a.system_email],"Service Monitor - Günlük Detaylı Özet",build_daily_summary(db))
                log(db,"DAILY_SUMMARY",msg,"INFO" if ok else "ERROR")
                db.commit()
                last_summary=key
        finally:
            db.close()
        time.sleep(2)

threading.Thread(target=scheduler,daemon=True).start()

@app.get("/",response_class=HTMLResponse)
def home():return open("frontend/index.html",encoding="utf8").read()


class LoginIn(BaseModel):
    username:str
    password:str

class UserIn(BaseModel):
    username:str
    password:str|None=None
    role:str="read_only_admin"
    display_name:str=""
    email:str=""
    is_active:bool=True
    must_change_password:bool=True

@app.get("/api/health")
def health(): return {"ok":True,"service":"Service Monitor"}

@app.post("/api/auth/login")
def login(p:LoginIn,request:Request,response:Response,db:Session=Depends(get_db)):
    u=db.query(User).filter(User.username==p.username).first()
    if not u or not u.is_active or not verify_password(p.password,u.password_hash):
        raise HTTPException(401,"Kullanıcı adı veya şifre hatalı")
    ensure_admin(db)
    login_time=datetime.utcnow()
    u.last_login_at=login_time
    ip=(request.client.host if request.client else "-")
    app_notification(db,"user","LOGIN","Yeni oturum açıldı",f"{u.username} hesabıyla {ip} IP adresinden giriş yapıldı.","settings",metadata={"username":u.username,"time":login_time.isoformat(),"ip":ip},target_user_id=u.id)
    db.commit()
    token=create_token(db,u)
    response.set_cookie("um_access_token", token, httponly=True, secure=os.getenv("COOKIE_SECURE","false").lower() in {"1","true","yes"}, samesite="strict", max_age=43200, path="/")
    return {"access_token":token,"token_type":"bearer","user":{"id":u.id,"username":u.username,"display_name":u.display_name,"role":u.role,"email":u.email,"must_change_password":u.must_change_password,"is_initial_admin":u.is_initial_admin,"permissions":sorted(user_permission_keys(db,u))}}


def _token_hash(raw:str)->str:
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()

def _smtp_ready(db):
    s=db.query(SMTPSettings).first()
    return bool(s and s.host and s.from_email)

@app.post("/api/auth/forgot-password")
def forgot_password(p:dict,db:Session=Depends(get_db)):
    u=db.query(User).filter(User.email==str(p.get("email","")).strip()).first()
    # Do not reveal whether an address exists when SMTP is unavailable or account is absent.
    if not u or not u.email or not _smtp_ready(db):
        return {"ok":True,"message":"İstek alındı. SMTP yapılandırılmışsa uygun kullanıcıya e-posta gönderilir."}
    import secrets
    raw=secrets.token_urlsafe(32)
    db.add(AuthToken(user_id=u.id,token_hash=_token_hash(raw),kind="password_reset",expires_at=datetime.utcnow()+timedelta(minutes=30)))
    db.commit()
    ok,msg=email(db,[u.email],"Service Monitor şifre yenileme",f"Şifrenizi yenilemek için bu token ile /api/auth/reset-password isteği yapabilirsiniz. Token: {raw}")
    return {"ok":ok,"message":msg}

@app.post("/api/auth/verify-email-request/{uid}")
def verify_email_request(uid:int,request:Request,db:Session=Depends(get_db)):
    if request.state.user_role!="super_admin": raise HTTPException(403,"Yalnızca Super Admin doğrulama maili gönderebilir")
    u=db.get(User,uid)
    if not u or not u.email: raise HTTPException(404,"Kullanıcı/e-posta bulunamadı")
    if not _smtp_ready(db): raise HTTPException(409,"SMTP Relay/AUTH henüz yapılandırılmamış")
    import secrets
    raw=secrets.token_urlsafe(32)
    db.add(AuthToken(user_id=u.id,token_hash=_token_hash(raw),kind="email_verify",expires_at=datetime.utcnow()+timedelta(hours=24)));db.commit()
    ok,msg=email(db,[u.email],"Service Monitor e-posta doğrulama",f"E-posta adresinizi doğrulamak için Service Monitor adresinizde /api/auth/verify-email?token={raw} bağlantısını açın.")
    return {"ok":ok,"message":msg}

@app.get("/api/auth/verify-email",response_class=HTMLResponse)
def verify_email(token:str,db:Session=Depends(get_db)):
    t=db.query(AuthToken).filter(AuthToken.token_hash==_token_hash(token),AuthToken.kind=="email_verify",AuthToken.used_at==None).first()
    if not t or t.expires_at<datetime.utcnow(): return HTMLResponse("<h2>E-posta doğrulama bağlantısı geçersiz veya süresi dolmuş.</h2>",status_code=400)
    u=db.get(User,t.user_id);u.email_verified=True;t.used_at=datetime.utcnow();db.commit()
    return HTMLResponse("<h2>E-posta adresiniz doğrulandı.</h2><p>Service Monitor'a dönebilirsiniz.</p>")

@app.post("/api/auth/reset-password")
def reset_password(p:dict,db:Session=Depends(get_db)):
    token=str(p.get("token", ""));new=str(p.get("new_password", ""))
    if len(new)<6: raise HTTPException(400,"Şifre en az 6 karakter olmalı")
    t=db.query(AuthToken).filter(AuthToken.token_hash==_token_hash(token),AuthToken.kind=="password_reset",AuthToken.used_at==None).first()
    if not t or t.expires_at<datetime.utcnow(): raise HTTPException(400,"Şifre yenileme tokenı geçersiz veya süresi dolmuş")
    u=db.get(User,t.user_id);u.password_hash=_hash_password(new);u.must_change_password=False;t.used_at=datetime.utcnow();db.commit();return {"ok":True}


@app.post("/api/auth/logout")
def logout(response:Response):
    response.delete_cookie("um_access_token", path="/", httponly=True, samesite="strict")
    return {"ok":True}

@app.get("/api/auth/me")
def me(request:Request,db:Session=Depends(get_db)):
    u=current_user(request,db)
    return {"id":u.id,"username":u.username,"display_name":u.display_name,"role":u.role,"email":u.email,"email_verified":u.email_verified,"must_change_password":u.must_change_password,"is_initial_admin":u.is_initial_admin,"permissions":sorted(user_permission_keys(db,u))}

@app.post("/api/auth/change-password")
def change_password(p:dict,request:Request,db:Session=Depends(get_db)):
    u=current_user(request,db)
    if not p.get("new_password") or len(p["new_password"])<6: raise HTTPException(400,"Şifre en az 6 karakter olmalı")
    if not u.is_initial_admin and not verify_password(p.get("current_password", ""),u.password_hash): raise HTTPException(400,"Mevcut şifre hatalı")
    changed_at=datetime.utcnow()
    u.password_hash=_hash_password(p["new_password"]);u.must_change_password=False;u.updated_at=changed_at
    ip=(request.client.host if request.client else "-")
    app_notification(db,"user","PASSWORD_CHANGED","Şifre değiştirildi",f"Hesabınızın şifresi {ip} IP adresinden başarıyla değiştirildi.","settings",metadata={"username":u.username,"time":changed_at.isoformat(),"ip":ip},target_user_id=u.id)
    db.commit()
    return {"ok":True,"message":"Şifre güncellendi"}

def _notification_scope(uid):
    """Kullanıcının görebildiği bildirimler ve okundu birleşimi."""
    visible=(AppNotification.target_user_id.is_(None) | (AppNotification.target_user_id==uid))
    read_join=and_(AppNotificationRead.notification_id==AppNotification.id,AppNotificationRead.user_id==uid)
    return visible,read_join

def _notification_text(value, fallback='-'):
    # Eski/genişletilmiş bildirimlerde yapısal başlık/mesaj olabilir; UI'da [object Object] görünmesin.
    if value is None:
        return fallback
    if isinstance(value,(dict,list,tuple)):
        return json.dumps(value,ensure_ascii=False,default=str,indent=2)
    text_value=str(value)
    return fallback if text_value=='[object Object]' else text_value

def _notification_item(n, read_at, svc_info, can_view_instant_audit):
    metadata=jd(n.metadata_json,"{}")
    if n.event_type in {"INSTANT_TEST_EXECUTED","INSTANT_TEST_EXPORTED"} and not can_view_instant_audit:
        metadata={"restricted":True,"target":metadata.get("target"),"test_type":metadata.get("test_type"),"time":metadata.get("time")}
    return {"id":n.id,"created_at":n.created_at,"read_at":read_at,"category":n.category,"event_type":n.event_type,
            "title":_notification_text(n.title,'Bildirim'),"message":_notification_text(n.message,'Bildirim ayrıntısı mevcut değil.'),
            "link":n.link,"service_id":n.service_id,"service_name":svc_info[0] if svc_info else None,
            "monitor_type":svc_info[1] if svc_info else None,"metadata":metadata,
            "template_subject":"","template_message":""}

def _notification_unread_counts(db, uid):
    """Okunmamış sayıları TEK sorguda (GROUP BY) hesaplar."""
    from sqlalchemy import func, case
    visible,read_join=_notification_scope(uid)
    has_service=case((AppNotification.service_id.isnot(None),1),else_=0)
    rows=(db.query(AppNotification.category,AppNotification.event_type,has_service.label("has_service"),func.count(AppNotification.id))
          .outerjoin(AppNotificationRead,read_join)
          .filter(AppNotificationRead.id.is_(None),visible)
          .group_by(AppNotification.category,AppNotification.event_type,has_service).all())
    counts={"service":0,"security":0,"user":0,"system":0}
    services=0; incidents=0
    for category,event_type,has_svc,n in rows:
        counts[category]=counts.get(category,0)+int(n)
        if has_svc: services+=int(n)
        if event_type in {"SERVICE_DOWN","SERVICE_WARNING","SERVICE_RECOVERY"}: incidents+=int(n)
    return {"unread":sum(counts.values()),"counts":counts,"services":services,"incidents":incidents}

@app.get("/api/notifications/summary")
def notifications_summary(request:Request, db:Session=Depends(get_db)):
    """Zil rozeti ve menü sayaçları için hafif uç nokta. Periyodik yoklama bunu kullanır; liste çekilmez."""
    return _notification_unread_counts(db,request.state.user_id)

@app.get("/api/notifications")
def notifications_api(request:Request, category:str="all", limit:int=60, include_read:bool=False, db:Session=Depends(get_db)):
    uid=request.state.user_id
    viewer=db.get(User,uid)
    can_view_instant_audit=has_permission(db, viewer, "instant_test.audit") if viewer else False
    limit=max(1,min(300,int(limit or 60)))
    visible,read_join=_notification_scope(uid)
    q=(db.query(AppNotification, AppNotificationRead.read_at.label("read_at"))
       .outerjoin(AppNotificationRead, read_join)
       .filter(visible))
    if not include_read:
        q=q.filter(AppNotificationRead.id.is_(None))
    if category and category != "all": q=q.filter(AppNotification.category==category[:40])
    rows=q.order_by(AppNotification.created_at.desc(),AppNotification.id.desc()).limit(limit).all()
    # Servis adları tek sorguda alınır (satır başına sorgu yok). Şablon render'ı burada YAPILMAZ:
    # her bildirim için 24 saatlik istatistik sorguları çalıştırmak listeyi yavaşlatıyordu.
    # Şablon ayrıntısı, bildirim açıldığında GET /api/notifications/{id} ile istenir.
    service_ids={n.service_id for n,_ in rows if n.service_id}
    svc_map={}
    if service_ids:
        svc_map={sid:(name,mtype) for sid,name,mtype in db.query(Service.id,Service.name,Service.monitor_type).filter(Service.id.in_(service_ids)).all()}
    items=[_notification_item(n,read_at,svc_map.get(n.service_id),can_view_instant_audit) for n,read_at in rows]
    summary=_notification_unread_counts(db,uid)
    return {"items":items,"unread":summary["unread"],"counts":summary["counts"],"services":summary["services"],"incidents":summary["incidents"],"include_read":include_read}

@app.get("/api/notifications/{notification_id}")
def notification_detail(notification_id:int, request:Request, db:Session=Depends(get_db)):
    """Tek bildirimin ayrıntısı; gönderilen bildirim şablonu burada, yalnızca istendiğinde render edilir."""
    uid=request.state.user_id
    visible,read_join=_notification_scope(uid)
    row=(db.query(AppNotification, AppNotificationRead.read_at.label("read_at"))
         .outerjoin(AppNotificationRead,read_join)
         .filter(AppNotification.id==notification_id,visible).first())
    if not row: raise HTTPException(404,"Bildirim bulunamadı")
    n,read_at=row
    viewer=db.get(User,uid)
    can_view_instant_audit=has_permission(db, viewer, "instant_test.audit") if viewer else False
    svc=db.get(Service,n.service_id) if n.service_id else None
    item=_notification_item(n,read_at,(svc.name,svc.monitor_type) if svc else None,can_view_instant_audit)
    metadata=item["metadata"]
    if svc and n.category=='service':
        st=db.query(AppSettings).first()
        template_map={
            'SERVICE_DOWN':('down_notification_subject','down_notification_message','DOWN'),
            'SERVICE_RECOVERY':('recovery_notification_subject','recovery_notification_message','RECOVERY'),
            'SERVICE_WARNING':('warning_notification_subject','warning_notification_message','WARNING'),
            'LATENCY_ALARM':('latency_notification_subject','latency_notification_message','LATENCY'),
            'CONTROL_DOWN':('down_notification_subject','down_notification_message','DOWN'),
            'CONTROL_RECOVERY':('recovery_notification_subject','recovery_notification_message','RECOVERY'),
            'CONTROL_WARNING':('warning_notification_subject','warning_notification_message','WARNING'),
        }
        keys=template_map.get(n.event_type)
        if keys and st:
            subject_key,message_key,status=keys
            extra=dict(metadata or {})
            extra.setdefault('STATUS',status)
            extra.setdefault('EVENT_TYPE',n.event_type)
            extra.setdefault('EVENT_TIME',n.created_at)
            if n.event_type in {'SERVICE_DOWN','CONTROL_DOWN'}:
                extra.setdefault('REASON',item["message"])
            try:
                item["template_subject"]=render(getattr(svc,subject_key,None) or getattr(st,subject_key,None) or st.default_notification_subject,svc,extra,db=db)
                item["template_message"]=render(getattr(svc,message_key,None) or getattr(st,message_key,None) or st.default_notification_message,svc,extra,db=db)
            except Exception:
                # Şablon render hatası bildirimin açılmasını engellemez.
                item["template_subject"]="";item["template_message"]=""
        if '[object Object]' in str(n.title or '') and item["template_subject"]:
            item["title"]=item["template_subject"]
        if '[object Object]' in str(n.message or '') and item["template_message"]:
            item["message"]=item["template_message"]
    return item

@app.post("/api/notifications/{notification_id}/read")
def notification_read(notification_id:int, request:Request, db:Session=Depends(get_db)):
    n=db.get(AppNotification,notification_id)
    if not n: raise HTTPException(404,"Bildirim bulunamadı")
    uid=request.state.user_id
    exists=db.query(AppNotificationRead).filter_by(notification_id=notification_id,user_id=uid).first()
    if not exists:
        db.add(AppNotificationRead(notification_id=notification_id,user_id=uid,read_at=datetime.utcnow()))
        db.commit()
    return {"ok":True}

@app.post("/api/notifications/read-all")
def notifications_read_all(request:Request, db:Session=Depends(get_db)):
    from sqlalchemy import and_
    uid=request.state.user_id
    unread=(db.query(AppNotification.id)
            .outerjoin(AppNotificationRead,and_(AppNotificationRead.notification_id==AppNotification.id,AppNotificationRead.user_id==uid))
            .filter(AppNotificationRead.id.is_(None), (AppNotification.target_user_id.is_(None) | (AppNotification.target_user_id==uid))).limit(500).all())
    now=datetime.utcnow()
    for (nid,) in unread:
        db.add(AppNotificationRead(notification_id=nid,user_id=uid,read_at=now))
    db.commit()
    return {"ok":True,"count":len(unread)}

@app.get("/api/users")
def users(request:Request,db:Session=Depends(get_db)):
    role=request.state.user_role
    if not has_permission(db, db.get(User,request.state.user_id), "users.view"): raise HTTPException(403,"Kullanıcıları görüntüleme yetkiniz yok")
    return [{"id":u.id,"username":u.username,"display_name":u.display_name,"role":u.role,"email":u.email,"email_verified":u.email_verified,"is_active":u.is_active,"is_initial_admin":u.is_initial_admin,"must_change_password":u.must_change_password,"created_at":u.created_at,"last_login_at":u.last_login_at,"permissions":sorted(user_permission_keys(db,u))} for u in db.query(User).order_by(User.id).all()]

@app.post("/api/users")
def user_add(p:UserIn,request:Request,db:Session=Depends(get_db)):
    if not has_permission(db,db.get(User,request.state.user_id),"users.create"): raise HTTPException(403,"Kullanıcı oluşturma yetkiniz yok")
    if p.role not in ROLES: raise HTTPException(400,"Geçersiz rol")
    if request.state.user_role!="super_admin" and p.role in {"super_admin","read_only_super_admin"}: raise HTTPException(403,"Bu rol yalnızca Super Admin tarafından atanabilir")
    if not p.password or len(p.password)<6: raise HTTPException(400,"Yeni kullanıcı şifresi en az 6 karakter olmalı")
    if db.query(User).filter(User.username==p.username).first(): raise HTTPException(409,"Kullanıcı adı zaten mevcut")
    u=User(username=p.username,password_hash=_hash_password(p.password),role=p.role,display_name=p.display_name,email=p.email,is_active=p.is_active,must_change_password=p.must_change_password,created_at=datetime.utcnow())
    db.add(u);db.add(AuditLog(actor=request.state.user_username,action="CREATE_USER",details=p.username));db.commit();db.refresh(u)
    return {"id":u.id,"username":u.username,"role":u.role}

@app.put("/api/users/{uid}")
def user_update(uid:int,p:UserIn,request:Request,db:Session=Depends(get_db)):
    actor=db.get(User,request.state.user_id)
    if not has_permission(db,actor,"users.update"): raise HTTPException(403,"Kullanıcı düzenleme yetkiniz yok")
    if actor.role!="super_admin" and uid==actor.id and p.role!=actor.role: raise HTTPException(403,"Kendi rolünüzü değiştiremezsiniz")
    u=db.get(User,uid)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı")
    if u.is_initial_admin and p.role!="super_admin": raise HTTPException(400,"İlk Super Admin'in rolü düşürülemez")
    if p.role not in ROLES: raise HTTPException(400,"Geçersiz rol")
    if request.state.user_role!="super_admin" and p.role in {"super_admin","read_only_super_admin"}: raise HTTPException(403,"Bu rol yalnızca Super Admin tarafından atanabilir")
    if p.username!=u.username and db.query(User).filter(User.username==p.username).first(): raise HTTPException(409,"Kullanıcı adı zaten mevcut")
    u.username=p.username;u.role=p.role;u.display_name=p.display_name;u.email=p.email;u.is_active=p.is_active;u.must_change_password=p.must_change_password;u.updated_at=datetime.utcnow()
    if p.password: u.password_hash=_hash_password(p.password)
    db.add(AuditLog(actor=request.state.user_username,action="UPDATE_USER",details=u.username));db.commit()
    return {"ok":True}

@app.delete("/api/users/{uid}")
def user_delete(uid:int,request:Request,db:Session=Depends(get_db)):
    if not has_permission(db,db.get(User,request.state.user_id),"users.delete"): raise HTTPException(403,"Kullanıcı silme yetkiniz yok")
    u=db.get(User,uid)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı")
    if u.is_initial_admin: raise HTTPException(400,"İlk Super Admin silinemez")
    db.delete(u);db.add(AuditLog(actor=request.state.user_username,action="DELETE_USER",details=str(uid)));db.commit();return {"ok":True}

@app.post("/api/users/{uid}/verify-email")
def verify_email(uid:int,request:Request,db:Session=Depends(get_db)):
    if request.state.user_role!="super_admin": raise HTTPException(403,"Yalnızca Super Admin e-posta doğrulayabilir")
    u=db.get(User,uid)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı")
    if not u.email: raise HTTPException(400,"Kullanıcının e-postası yok")
    # İlk aşamada relay kurulmadan e-posta gönderilmez; endpoint açıkça SMTP durumunu bildirir.
    smtp=db.query(SMTPSettings).first()
    if not smtp or not smtp.host or not smtp.from_email:
        raise HTTPException(409,"SMTP Relay/AUTH henüz yapılandırılmamış; doğrulama maili gönderilemez")
    ok,msg=email(db,[u.email],"Service Monitor e-posta doğrulama","Hesabınız için e-posta doğrulama isteği oluşturuldu.")
    if ok: u.email_verified=True;db.commit()
    return {"ok":ok,"message":msg}

@app.get("/api/roles")
def roles(request:Request,db:Session=Depends(get_db)):
    user=db.get(User,request.state.user_id)
    return {"roles":[{"key":k,"name":v,"read_only":role_is_read_only(k)} for k,v in ROLES.items()],"permissions":[{"key":k,"name":v} for k,v in PERMISSION_CATALOG.items()],"current_permissions":sorted(user_permission_keys(db,user))}

@app.get("/api/roles/{role}/permissions")
def role_permissions(role:str,request:Request,db:Session=Depends(get_db)):
    if role not in ROLES: raise HTTPException(404,"Rol bulunamadı")
    rows=db.query(RolePermission).filter(RolePermission.role==role,RolePermission.enabled.is_(True)).all()
    return {"role":role,"permissions":sorted(x.permission for x in rows)}

@app.put("/api/roles/{role}/permissions")
def role_permissions_update(role:str,p:dict,request:Request,db:Session=Depends(get_db)):
    actor=db.get(User,request.state.user_id)
    if actor.role!="super_admin": raise HTTPException(403,"Rol varsayılanlarını yalnızca Super Admin değiştirebilir")
    if role not in ROLES: raise HTTPException(404,"Rol bulunamadı")
    keys={str(x) for x in (p.get("permissions") or []) if str(x) in PERMISSION_CATALOG}
    db.query(RolePermission).filter(RolePermission.role==role).delete(synchronize_session=False)
    if role not in {"super_admin","read_only_super_admin"}:
        for key in keys: db.add(RolePermission(role=role,permission=key,enabled=True))
    db.commit(); return {"ok":True,"role":role,"permissions":sorted(keys)}

@app.get("/api/users/{uid}/permissions")
def user_permissions(uid:int,request:Request,db:Session=Depends(get_db)):
    actor=db.get(User,request.state.user_id); target=db.get(User,uid)
    if not target: raise HTTPException(404,"Kullanıcı bulunamadı")
    if actor.role!="super_admin" and uid!=actor.id: raise HTTPException(403,"Bu kullanıcının yetkilerini görüntüleme yetkiniz yok")
    rows=db.query(UserPermission).filter(UserPermission.user_id==uid,UserPermission.enabled.is_(True)).all()
    return {"user_id":uid,"role":target.role,"permissions":sorted(x.permission for x in rows),"effective_permissions":sorted(user_permission_keys(db,target))}

@app.put("/api/users/{uid}/permissions")
def user_permissions_update(uid:int,p:dict,request:Request,db:Session=Depends(get_db)):
    actor=db.get(User,request.state.user_id); target=db.get(User,uid)
    if actor.role!="super_admin" and not has_permission(db,actor,"users.update"): raise HTTPException(403,"Kullanıcı yetkilerini değiştirme yetkiniz yok")
    if actor.role!="super_admin" and uid==actor.id: raise HTTPException(403,"Kendi yetkilerinizi değiştiremezsiniz")
    if not target: raise HTTPException(404,"Kullanıcı bulunamadı")
    if target.role in {"super_admin","read_only_super_admin"}: return {"ok":True,"permissions":sorted(user_permission_keys(db,target)),"locked":True}
    keys={str(x) for x in (p.get("permissions") or []) if str(x) in PERMISSION_CATALOG}
    if actor.role!="super_admin": keys &= user_permission_keys(db,actor)
    db.query(UserPermission).filter(UserPermission.user_id==uid).delete(synchronize_session=False)
    db.add(UserPermission(user_id=uid,permission="__configured__",enabled=True))
    for key in keys: db.add(UserPermission(user_id=uid,permission=key,enabled=True))
    db.add(AuditLog(actor=actor.username,action="UPDATE_USER_PERMISSIONS",details=f"{target.username}: {', '.join(sorted(keys))}"))
    db.commit(); return {"ok":True,"user_id":uid,"permissions":sorted(keys)}

@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db)):
    total=db.query(Service.id).count()
    up=db.query(Service.id).filter(Service.last_status=="UP").count()
    down=db.query(Service.id).filter(Service.last_status=="DOWN").count()
    warning=db.query(Service.id).filter(Service.last_status=="WARNING").count()
    active=db.query(Incident.id).filter(Incident.status=="OPEN").count()
    # Dashboard only needs a small featured set; never hydrate the whole service table here.
    featured=(db.query(Service)
              .filter(Service.enabled.is_(True))
              .order_by(text("CASE last_status WHEN 'DOWN' THEN 0 WHEN 'WARNING' THEN 1 WHEN 'UP' THEN 2 ELSE 3 END"), Service.last_latency_ms.asc().nullslast(), Service.id.desc())
              .limit(12).all())
    return {"total":total,"up":up,"down":down,"warning":warning,"active_incidents":active,
            "services":[sd(x) for x in featured]}

@app.get("/api/services")
def services(q:str="",page:int=1,page_size:int=20,status:str="ALL",sort:str="name_az",db:Session=Depends(get_db)):
    q=(q or "").strip()[:100]
    page=max(1,int(page)); page_size=min(250,max(10,int(page_size or 20)))
    query=db.query(Service)
    if q:
        like=f"%{q}%"
        query=query.filter((Service.name.ilike(like))|(Service.url.ilike(like))|(Service.monitor_type.ilike(like)))
    status=(status or "ALL").upper()
    if status in {"UP","WARNING","DOWN","UNKNOWN"}:
        query=query.filter(Service.last_status==status)
    order_map={
        "name_az":(Service.name.asc(),Service.id.asc()),
        "name_za":(Service.name.desc(),Service.id.desc()),
        "up_down_warning":(text("CASE last_status WHEN 'UP' THEN 0 WHEN 'DOWN' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END"),Service.name.asc()),
        "down_up_warning":(text("CASE last_status WHEN 'DOWN' THEN 0 WHEN 'UP' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END"),Service.name.asc()),
        "warning_down_up":(text("CASE last_status WHEN 'WARNING' THEN 0 WHEN 'DOWN' THEN 1 WHEN 'UP' THEN 2 ELSE 3 END"),Service.name.asc()),
        "latest":(Service.last_check_at.desc().nullslast(),Service.id.desc()),
    }
    query=query.order_by(*order_map.get(sort,order_map["name_az"]))
    total=query.count()
    pages=max(1,(total+page_size-1)//page_size)
    page=min(page,pages)
    items=query.offset((page-1)*page_size).limit(page_size).all()
    return {"items":[sd(x) for x in items],"page":page,"page_size":page_size,"total":total,"pages":pages}

@app.get("/api/services/{sid}/certificate")
def service_certificate(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    typ=(s.monitor_type or "web").lower()
    if typ=="ssl":
        opts=jd(s.protocol_options,"{}"); host=opts.get("host") or s.url; port=int(opts.get("port",443))
    elif typ in {"web","http","https"}:
        raw=(s.url or "").strip()
        if "://" not in raw: raw="https://"+raw
        parsed=__import__("urllib.parse",fromlist=["urlparse"]).urlparse(raw)
        if parsed.scheme!="https":
            raise HTTPException(400,"Bu Web servisi HTTPS kullanmıyor; sertifika sorgusu için HTTPS URL gerekir.")
        host=parsed.hostname; port=parsed.port or 443
    else:
        raise HTTPException(400,f"{typ} servis tipi için genel SSL sertifika sorgusu kullanılmaz.")
    if not host: raise HTTPException(400,"Sertifika host bilgisi bulunamadı.")
    try:
        c=certificate(host,port)
    except Exception as e:
        raise HTTPException(502,f"Sertifika sorgusu başarısız: {e}")
    s.cert_subject=c["subject"];s.cert_issuer=c["issuer"];s.cert_expires_at=c["expires_at"]
    s.last_cert_days=max(0,int((c["expires_at"]-datetime.utcnow()).total_seconds()/86400))
    db.commit()
    return c

@app.post("/api/services/{sid}/security/headers")
def service_security_headers(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    if (s.monitor_type or "").lower() not in {"web","http","https"}:
        raise HTTPException(400,"Security Headers testi yalnızca Web servislerinde kullanılabilir.")
    r=check(s)
    s.last_headers_json=json.dumps(r.get("headers") or {},ensure_ascii=False)
    s.last_header_security_json=json.dumps(r.get("header_security") or {},ensure_ascii=False)
    db.add(AuditLog(action="SECURITY_HEADERS_TEST",service_id=sid,details=json.dumps(r.get("header_security") or {},ensure_ascii=False)))
    db.commit()
    return {"service_id":sid,"headers":r.get("headers",{}),"header_security":r.get("header_security",{}),"status":r.get("status"),"http_status":r.get("code")}

@app.post("/api/services/{sid}/security/tls")
def service_security_tls(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    typ=(s.monitor_type or "").lower()
    if typ=="ssl":
        o=jd(s.protocol_options,"{}");host=o.get("host") or s.url;port=int(o.get("port",443))
    elif typ in {"web","http","https"}:
        raw=s.url or ""
        if "://" not in raw:raw="https://"+raw
        u=__import__("urllib.parse",fromlist=["urlparse"]).urlparse(raw);host=u.hostname;port=u.port or 443
    else: raise HTTPException(400,"TLS testi yalnızca Web veya SSL servislerinde kullanılabilir.")
    if not host: raise HTTPException(400,"TLS host bulunamadı.")
    result=tls_security_scan(host,port)
    s.last_tls_security_json=json.dumps(result,ensure_ascii=False,default=str)
    db.add(AuditLog(action="TLS_SECURITY_TEST",service_id=sid,details=json.dumps(result,ensure_ascii=False,default=str)[:10000]))
    db.commit()
    return {"service_id":sid,"host":host,"port":port,"tls_security":result}

@app.get("/api/services/{sid}/screenshots")
def service_screenshots(sid:int,db:Session=Depends(get_db)):
    if not db.get(Service,sid): raise HTTPException(404,"Servis bulunamadı")
    rows=db.query(ServiceScreenshot).filter_by(service_id=sid).order_by(ServiceScreenshot.id.desc()).limit(500).all()
    return [{"id":x.id,"captured_at":x.captured_at,"reason":x.reason,"status":x.status,"http_status":x.http_status,"path":x.path,"url":x.url} for x in rows]

@app.post("/api/services/{sid}/screenshot")
def service_screenshot_manual(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    if (s.monitor_type or "").lower() not in {"web","http","https"}: raise HTTPException(400,"Ekran görüntüsü yalnızca Web servislerinde kullanılabilir.")
    url=s.url if "://" in (s.url or "") else "https://"+(s.url or "")
    snap=capture_service_screenshot(db,s,url,"Manuel ekran görüntüsü",s.last_status,s.last_http_status)
    db.commit()
    if not snap: raise HTTPException(503,"Ekran görüntüsü alınamadı. Playwright/Chromium kurulumunu kontrol edin.")
    return {"ok":True,"screenshot":{"id":snap.id,"captured_at":snap.captured_at,"path":snap.path,"reason":snap.reason}}

@app.get("/api/services/{sid}/detail")
def detail(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s:raise HTTPException(404)
    # Automatically populate TLS data for HTTPS-capable web services when no cached scan exists.
    if not jd(s.last_tls_security_json,"{}") and (s.monitor_type or "").lower() in {"web","http","https","ssl"}:
        try:
            if (s.monitor_type or "").lower()=="ssl":
                oo=jd(s.protocol_options,"{}"); hh=oo.get("host") or s.url; pp=int(oo.get("port",443))
            else:
                rr=(s.url or ""); rr=rr if "://" in rr else "https://"+rr; uu=__import__("urllib.parse",fromlist=["urlparse"]).urlparse(rr); hh=uu.hostname; pp=uu.port or 443
            if hh and (str(s.url or "").lower().startswith("https://") or (s.monitor_type or "").lower()=="ssl"):
                s.last_tls_security_json=json.dumps(tls_security_scan(hh,pp,deep=False),ensure_ascii=False,default=str); db.commit()
        except Exception:
            db.rollback()
    c=db.query(CheckResult).filter_by(service_id=sid).order_by(CheckResult.id.desc()).limit(1000).all();i=db.query(Incident).filter_by(service_id=sid).order_by(Incident.id.desc()).limit(100).all()
    cert_details=None
    if s.cert_expires_at:
        cert_details={
            "subject":s.cert_subject or "",
            "issuer":s.cert_issuer or "",
            "expires_at":s.cert_expires_at,
            "remaining_days":s.last_cert_days,
        }
    shots=db.query(ServiceScreenshot).filter_by(service_id=sid).order_by(ServiceScreenshot.id.desc()).limit(100).all()
    return {"service":sd(s),"certificate":cert_details,
            "headers":jd(s.last_headers_json,"{}"),"header_security":jd(s.last_header_security_json,"{}"),"tls_security":jd(s.last_tls_security_json,"{}"),
            "screenshots":[{"id":x.id,"captured_at":x.captured_at,"reason":x.reason,"status":x.status,"http_status":x.http_status,"path":x.path,"url":x.url} for x in shots],
            "checks":[{"time":x.checked_at,"status":x.status,"latency":x.latency_ms,"code":x.http_status,"error":x.error,"certificate_days":x.certificate_days,"rule_signature":x.rule_signature,"headers":jd(x.headers_json,"{}"),"header_security":jd(x.header_security_json,"{}"),"tls_security":jd(x.tls_security_json,"{}")} for x in reversed(c)],
            "incidents":[{"id":x.id,"status":x.status,"started":x.started_at,"resolved":x.resolved_at,"duration":x.downtime_seconds,"reason":x.reason} for x in i]}

@app.get("/api/services/{sid}/preview")
def preview_service(sid:int,db:Session=Depends(get_db)):
    """Run a one-off live check without creating a CheckResult or incident."""
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    r=check(s)
    return {
        "service_id":sid,
        "service":s.name,
        "monitor_type":s.monitor_type,
        "status":r.get("status","DOWN"),
        "latency_ms":r.get("latency",0),
        "http_status":r.get("code"),
        "resolved_ip":r.get("resolved_ip") or s.last_resolved_ip or "",
        "host":r.get("host"),
        "port":r.get("port"),
        "dns_addresses":r.get("dns_addresses",[]),
        "error":r.get("error","") or "",
        "certificate":r.get("cert_details"),
        "effective_url":r.get("effective_url")
    }

class ServiceIn(BaseModel):
    @field_validator("certificate_alert_days", mode="before")
    @classmethod
    def normalize_certificate_alert_days(cls, v):
        if v is None or v == "":
            return 30
        try:
            n = int(v)
            return max(0, n)
        except (TypeError, ValueError):
            return 30

    @field_validator("latency_notification_message", mode="before")
    @classmethod
    def normalize_latency_notification_message(cls, v):
        if v is None or not isinstance(v, str):
            return ""
        return v

    name:str;monitor_type:str="web";url:str="";description:str="";service_authorized_name:str="";interval_seconds:int=30;status_ranges:str="200-299";ignored_http_status_codes:str="401,403";failure_threshold:int=3;evaluation_window_minutes:int=5
    enabled:bool=True;maintenance:bool=False;maintenance_until:str|None=None;maintenance_reason:str="";ignore_cert_errors:bool=False;certificate_monitoring:bool=True;certificate_alert_enabled:bool=False;certificate_alert_days:int=30;certificate_notification_group_ids:list[int]=[];certificate_notification_subject:str="Sertifika uyarısı - {{SERVICE_NAME}}";certificate_notification_message:str="{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor. Bitiş: {{CERT_EXPIRY}}"
    content_monitoring:bool=False;content_mode:str="contains";content_keywords:list[str]=[]
    advanced_alarm:bool=False;latency_warning_ms:int=1000;latency_critical_ms:int=3000;sla_enabled:bool=False;sla_target:float=99.9;protocol_options:dict={}
    dependency_ids:list[int]=[];dependency_notifications_enabled:bool=False;notification_group_ids:list[int]=[]
    custom_notification_enabled:bool=False;custom_notification_message:str="";custom_notification_group_ids:list[int]=[];notification_group_configs:list[dict]=[];notification_rules:list[dict]=[];down_notification_subject:str="";down_notification_message:str="";recovery_notification_subject:str="";recovery_notification_message:str="";warning_notification_subject:str="";warning_notification_message:str="";latency_notification_subject:str="";latency_notification_message:str=""

def prep(x):
    x=x.model_dump();g=x.pop("notification_group_ids")
    if str(x.get("monitor_type", "")).lower() in {"web","http","https"}:
        raw=str(x.get("url") or "").strip()
        if raw:
            raw=raw if "://" in raw else "https://"+raw
            parsed=urlparse(raw)
            if parsed.scheme not in {"http","https"} or not parsed.hostname:
                raise HTTPException(422, "Web hedefi geçerli bir domain veya HTTP(S) URL olmalıdır.")
            x["url"]=raw
    allowed={"web","http","https","ping","tcp","dns","ssl","smtp","mysql","postgresql","redis"}
    typ=str(x.get("monitor_type") or "web").lower()
    if typ not in allowed:
        raise HTTPException(400,f"Desteklenmeyen servis tipi: {typ}")
    if typ in {"http","https"}: typ="web"
    x["monitor_type"]=typ
    x["ignored_http_status_codes"]=",".join(str(int(v.strip())) for v in str(x.get("ignored_http_status_codes","401,403") or "").split(",") if v.strip().isdigit()) or "401,403"
    opts=x.get("protocol_options") or {}
    required={
        "ping":["host"], "tcp":["host","port"], "dns":["host"], "ssl":["host"],
        "smtp":["host","port"], "mysql":["host","port"], "postgresql":["host","port"], "redis":["host","port"]
    }
    if typ=="web" and not str(x.get("url") or "").strip():
        raise HTTPException(400,"Web servisi için URL zorunludur")
    missing=[k for k in required.get(typ,[]) if opts.get(k) in (None,"")]
    if missing:
        raise HTTPException(400,f"{typ} servisi için eksik alanlar: {', '.join(missing)}")
    for k in ["certificate_notification_group_ids","content_keywords","protocol_options","dependency_ids","custom_notification_group_ids","notification_group_configs","notification_rules"]:x[k]=json.dumps(x[k],ensure_ascii=False)
    if x["maintenance_until"]:
        dt=datetime.fromisoformat(x["maintenance_until"]); x["maintenance_until"]=(dt.astimezone(__import__("datetime").timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt)
    else:x["maintenance_until"]=None
    return x,g

@app.post("/api/services/type/{monitor_type}")
def add_typed(monitor_type:str,d:ServiceIn,db:Session=Depends(get_db)):
    """Servis tipini URL üzerinden zorunlu kılar; Swagger/otomasyon için açık typed API."""
    allowed={"web","http","https","ping","tcp","dns","ssl","smtp","mysql","postgresql","redis"}
    monitor_type=monitor_type.lower()
    if monitor_type not in allowed:
        raise HTTPException(400,f"Desteklenmeyen servis tipi: {monitor_type}")
    d=d.model_copy(update={"monitor_type":"web" if monitor_type in {"http","https"} else monitor_type})
    x,g=prep(d);s=Service(**x)
    s.notification_group_ids_json=json.dumps(g or [x.id for x in default_groups(db)],ensure_ascii=False)
    db.add(s);db.commit();db.refresh(s);return sd(s)

@app.post("/api/services")
def add(d:ServiceIn,db:Session=Depends(get_db)):
    x,g=prep(d);s=Service(**x);s.notification_group_ids_json=json.dumps(g or [x.id for x in default_groups(db)],ensure_ascii=False);db.add(s);db.commit();return sd(s)

@app.put("/api/services/{sid}")
def update(sid:int,d:ServiceIn,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s:raise HTTPException(404)
    x,g=prep(d)
    for k,v in x.items():setattr(s,k,v)
    s.notification_group_ids_json=json.dumps(g or [x.id for x in default_groups(db)],ensure_ascii=False)
    db.add(AuditLog(action="UPDATE_SERVICE",service_id=sid,details=s.name));db.commit();return sd(s)

@app.delete("/api/services/{sid}")
def delete(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s:raise HTTPException(404)
    # Explicit cleanup keeps PostgreSQL from accumulating orphaned monitoring history.
    db.query(CheckResult).filter(CheckResult.service_id==sid).delete(synchronize_session=False)
    db.query(Incident).filter(Incident.service_id==sid).delete(synchronize_session=False)
    db.query(ServiceScreenshot).filter(ServiceScreenshot.service_id==sid).delete(synchronize_session=False)
    db.query(EventLog).filter(EventLog.service_id==sid).delete(synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.service_id==sid).delete(synchronize_session=False)
    db.query(AppNotificationRead).filter(AppNotificationRead.notification_id.in_(db.query(AppNotification.id).filter(AppNotification.service_id==sid))).delete(synchronize_session=False)
    db.query(AppNotification).filter(AppNotification.service_id==sid).delete(synchronize_session=False)
    safe_name=re.sub(r"[^a-zA-Z0-9_-]+","_",s.name).strip("_")[:80] or f"service-{sid}"
    shutil.rmtree(os.path.join("screenshots",safe_name),ignore_errors=True)
    db.delete(s);db.commit();cache_hooks.invalidate_analytics();return {"ok":True}


@app.get("/api/notification-fields")
def notification_fields():
    return {"fields":NOTIFICATION_FIELDS,"groups":{
        "service":["SERVICE_ID","SERVICE_NAME","MONITOR_TYPE","HOST_NAME","HOST_URL","RESOLVED_IP","PORT"],
        "event":["STATUS","PREVIOUS_STATUS","EVENT_TYPE","EVENT_TIME","TIME","LAST_CHECK","REASON","ERROR_MESSAGE"],
        "performance":["LATENCY_MS","AVG_LATENCY_24H","MIN_LATENCY_24H","MAX_LATENCY_24H","CHECK_COUNT_24H","SUCCESS_COUNT_24H","FAILURE_COUNT_24H","UPTIME_24H","DOWNTIME_24H","INCIDENT_COUNT_24H","FAILURE_COUNT"],
        "http":["HTTP_STATUS"],"certificate":["CERT_STATUS","CERT_SUBJECT","CERT_ISSUER","CERT_EXPIRY","CERT_DAYS","CERT_ALERT_DAYS"]}}

@app.post("/api/instant-test")
def instant_test(p:dict, request:Request, db:Session=Depends(get_db)):
    started=datetime.utcnow()
    target=str(p.get("target") or "").strip()
    requested_type=str(p.get("test_type") or "auto").lower()
    if not target: raise HTTPException(422,"URL, domain veya IP zorunludur")
    try:
        ipaddress.ip_address(target.strip("[]")); is_ip=True
    except ValueError: is_ip=False
    test_type=requested_type
    if test_type=="auto":
        test_type="ping" if is_ip else "web"
    allowed={"web","headers","ssl","ping","tcp","dns","smtp","mysql","postgresql","redis"}
    if test_type not in allowed: raise HTTPException(400,"Desteklenmeyen anlık test tipi")
    from urllib.parse import urlparse
    parsed=urlparse(target if "://" in target else ("https://"+target if test_type in {"web","headers","ssl"} else target))
    host=parsed.hostname or target.strip("[]")
    url_port=parsed.port if parsed.port else None
    try:
        if test_type in {"ping","dns"}: port=None
        elif test_type in {"ssl","tcp"}: port=int(p.get("port") or url_port or (443 if test_type=="ssl" else 80))
        elif test_type=="smtp": port=int(p.get("port") or url_port or 587)
        elif test_type=="mysql": port=int(p.get("port") or 3306)
        elif test_type=="postgresql": port=int(p.get("port") or 5432)
        elif test_type=="redis": port=int(p.get("port") or 6379)
        else: port=url_port
    except (TypeError,ValueError): raise HTTPException(400,"Port 1-65535 arasında olmalıdır")
    if port is not None and not (1<=port<=65535): raise HTTPException(400,"Port 1-65535 arasında olmalıdır")
    if test_type in {"ping","dns"} and "port" in p: port=None
    options=dict(p.get("options") or {})
    options["host"]=host
    if port is not None: options["port"]=port
    # Test-specific defaults / inputs.
    if test_type=="ping": options["timeout"]=float(p.get("timeout") or 5)
    if test_type=="tcp": options["timeout"]=float(p.get("timeout") or 8)
    if test_type=="dns": options["expected"]=str(p.get("expected") or "").strip()
    if test_type in {"smtp","mysql","postgresql","redis"}:
        options["username"]=str(options.get("username") or p.get("username") or "")
        options["database"]=str(options.get("database") or p.get("database") or "")
        options["password"]=str(options.get("password") or p.get("password") or "")
    if test_type=="smtp":
        options["tls"]=bool(p.get("tls",options.get("tls",True))); options["ssl"]=bool(p.get("ssl",options.get("ssl",False)))
    safe_options={k:v for k,v in options.items() if k not in {"password","token","secret","api_key"}}
    fake=SimpleNamespace(monitor_type=test_type,url=target,protocol_options=json.dumps(options),ignore_cert_errors=False,certificate_monitoring=True,content_monitoring=False,content_keywords="[]",content_mode="contains",header_monitoring=False,expected_headers="{}",status_ranges="200-299")
    if test_type in {"web","headers"}:
        raw=target if "://" in target else "https://"+target
        try:
            _t0=time.perf_counter()
            rr=httpx.get(raw,timeout=float(p.get("timeout") or 15),follow_redirects=True)
            hs={k:v for k,v in rr.headers.items()}
            result={"target":target,"test_type":test_type,"status":"UP" if http_status_is_up(rr.status_code,"200-399","401,403") else "DOWN","http_status":rr.status_code,"latency_ms":round((time.perf_counter()-_t0)*1000,2),"effective_url":str(rr.url),"resolved_ip":_resolved_host_ip(urlparse(str(rr.url)).hostname or host),"host":urlparse(str(rr.url)).hostname or host,"port":urlparse(str(rr.url)).port or (443 if str(rr.url).lower().startswith("https://") else 80),"headers":hs,"header_security":analyze_security_headers(rr.headers,str(rr.url).lower().startswith("https://"))}
        except Exception as exc:
            try: ping_ok=bool(_ping(host,3))
            except Exception: ping_ok=False
            result={"target":target,"test_type":test_type,"status":"DOWN","latency_ms":0,"resolved_ip":_resolved_host_ip(host),"error":str(exc),"server_reachable":ping_ok}
    elif test_type=="ssl":
        result={"target":target,"test_type":"ssl","status":"UP","port":port,"host":host}
        try:
            result["certificate"]=certificate(host,port); result["tls_security"]=tls_security_scan(host,port)
        except Exception as exc:
            result["status"]="DOWN"; result["error"]=str(exc)
    else:
        r=check(fake)
        result={"target":target,"test_type":test_type,"status":r.get("status"),"latency_ms":r.get("latency"),"http_status":r.get("code"),"resolved_ip":r.get("resolved_ip"),"host":r.get("host",host),"port":r.get("port",port),"dns_addresses":r.get("dns_addresses",[]),"error":r.get("error",""),"certificate":r.get("cert_details"),"headers":r.get("headers",{}),"header_security":r.get("header_security",{}),"tls_security":r.get("tls_security",{}),"server_reachable":r.get("server_reachable")}
    result["requested_type"]=requested_type; result["started_at"]=started; result["completed_at"]=datetime.utcnow()
    ip=(request.client.host if request.client else "-")
    actor=db.get(User,request.state.user_id)
    details={"username":actor.username if actor else request.state.user_username,"display_name":actor.display_name if actor else request.state.user_username,"target":target,"test_type":test_type,"requested_type":requested_type,"host":host,"port":port,"options":safe_options,"status":result.get("status"),"http_status":result.get("http_status"),"latency_ms":result.get("latency_ms"),"ip":ip,"time":started.isoformat(),"exported":False}
    db.add(AuditLog(actor=actor.username if actor else request.state.user_username,action="INSTANT_TEST",details=json.dumps(details,ensure_ascii=False,default=str)))
    log(db,"INSTANT_TEST",f"{details['username']} anlık {test_type} testi yaptı: {target}{(':'+str(port)) if port else ''}","INFO")
    app_notification(db,"system","INSTANT_TEST_EXECUTED","Anlık test çalıştırıldı",f"{details['display_name']} kullanıcısı {test_type} testi yaptı.","instant-test",metadata=details)
    db.commit()
    return result

@app.post("/api/instant-test/export")
def instant_test_export(p:dict, request:Request, db:Session=Depends(get_db)):
    kind=str(p.get("kind") or "json").lower(); result=p.get("result") or {}
    if kind not in {"json","html","txt","pdf"}: raise HTTPException(400,"Desteklenen export: JSON, HTML, TXT, PDF")
    u=db.get(User,request.state.user_id); target=str(result.get("target") or "instant-test"); now=datetime.utcnow(); safe_name=re.sub(r"[^a-zA-Z0-9._-]+","_",target)[:70] or "instant-test"
    if kind=="json":
        payload=json.dumps({"generated_at":now.isoformat(),"result":result},ensure_ascii=False,default=str,indent=2); media="application/json"
    elif kind=="txt":
        payload="Uptime Monitor Service — Anlık Test\n\n"+json.dumps(result,ensure_ascii=False,default=str,indent=2); media="text/plain"
    elif kind=="html":
        import html as _html
        payload=f"<!doctype html><html lang='tr'><meta charset='utf-8'><title>Anlık Test</title><style>body{{font:14px Arial;background:#07101d;color:#e7eef7;padding:30px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d1a2b;padding:18px;border-radius:14px}}</style><h1>Anlık Test</h1><p>{_html.escape(target)} · {_html.escape(str(result.get('test_type','-')))}</p><pre>{_html.escape(json.dumps(result,ensure_ascii=False,default=str,indent=2))}</pre></html>"; media="text/html"
    else:
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Preformatted
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.units import mm
        b=io.BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4,leftMargin=14*mm,rightMargin=14*mm,topMargin=14*mm,bottomMargin=14*mm)
        styles=getSampleStyleSheet()
        try: pdfmetrics.registerFont(TTFont("UMDejaVu","/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")); styles["Title"].fontName="UMDejaVu"; styles["Normal"].fontName="UMDejaVu"
        except Exception: pass
        story=[Paragraph("Uptime Monitor Service — Anlık Test",styles["Title"]),Paragraph(f"Hedef: {target}",styles["Normal"]),Paragraph(f"Test: {result.get('test_type','-')} · Durum: {result.get('status','-')}",styles["Normal"]),Spacer(1,10),Preformatted(json.dumps(result,ensure_ascii=False,default=str,indent=2),styles["Code"])]
        doc.build(story); return Response(b.getvalue(),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{safe_name}.pdf"'})
    details={"username":u.username if u else request.state.user_username,"target":target,"test_type":result.get("test_type"),"port":result.get("port"),"export_kind":kind,"time":now.isoformat(),"exported":True}
    # Mark the latest matching test event as exported so its history shows the complete lifecycle.
    prior=db.query(AppNotification).filter(AppNotification.event_type=="INSTANT_TEST_EXECUTED",AppNotification.target_user_id.is_(None)).order_by(AppNotification.id.desc()).limit(25).all()
    for pn in prior:
        md=jd(pn.metadata_json,"{}")
        if md.get("username")==details["username"] and md.get("target")==target and md.get("test_type")==details["test_type"] and not md.get("exported"):
            md["exported"]=True; md["export_kind"]=kind; md["export_time"]=now.isoformat(); pn.metadata_json=json.dumps(md,ensure_ascii=False,default=str); break
    db.add(AuditLog(actor=u.username if u else request.state.user_username,action="INSTANT_TEST_EXPORT",details=json.dumps(details,ensure_ascii=False,default=str)))
    app_notification(db,"system","INSTANT_TEST_EXPORTED","Anlık test dışa aktarıldı",f"{details['username']} anlık test sonucunu {kind.upper()} olarak dışa aktardı.","instant-test",metadata=details)
    db.commit()
    return Response(payload.encode("utf-8"),media_type=media,headers={"Content-Disposition":f'attachment; filename="{safe_name}.{kind}"'})

@app.get("/api/services/schema")
def service_schema():
    """Frontend'deki servis formunun kullandığı alanları ve seçenekleri makine tarafından okunabilir biçimde döndürür."""
    return {
        "description": "Service Monitor servis oluşturma API şeması",
        "monitor_type": {"type":"string", "enum":["web","http","https","ping","tcp","dns","ssl","smtp","mysql","postgresql","redis"], "default":"web"},
        "typed_create_endpoint": "POST /api/services/type/{monitor_type}",
        "monitor_types": {
            "web": {"label":"Web (HTTP/HTTPS)", "fields":["url","description","service_authorized_name","resolved_ip","status_ranges","ignore_cert_errors","certificate_monitoring","certificate_alert_enabled","certificate_alert_days","certificate_notification_group_ids","certificate_notification_subject","certificate_notification_message","content_monitoring","content_mode","content_keywords"]},
            "ping": {"label":"Ping", "fields":["host","timeout"]},
            "tcp": {"label":"TCP", "fields":["host","port","timeout"]},
            "dns": {"label":"DNS", "fields":["host","expected"]},
            "ssl": {"label":"SSL Certificate", "fields":["host","resolved_ip","port","certificate_monitoring","certificate_alert_enabled","certificate_alert_days","certificate_notification_group_ids","certificate_notification_subject","certificate_notification_message"]},
            "smtp": {"label":"SMTP", "fields":["host","port","username","password","tls","ssl"]},
            "mysql": {"label":"MySQL", "fields":["host","port","username","password","database"]},
            "postgresql": {"label":"PostgreSQL", "fields":["host","port","username","password","database"]},
            "redis": {"label":"Redis", "fields":["host","port","username","password","database"]}
        },
        "fields": {
            "name":"Servis görünen adı",
            "description":"Servis açıklaması",
            "service_authorized_name":"Servis yetkilisi adı",
            "url":"HTTP/HTTPS URL veya tipin ana hedefi",
            "interval_seconds":"Kontrol aralığı (saniye)",
            "status_ranges":"HTTP durum kodu aralıkları; örn. 200-299,301-302",
            "failure_threshold":"DOWN kabul edilmeden önce ardışık hata sayısı",
            "evaluation_window_minutes":"Değerlendirme penceresi",
            "enabled":"İzleme aktif mi",
            "maintenance":"Bakım modu",
            "maintenance_until":"Bakım bitiş zamanı (ISO-8601)",
            "maintenance_reason":"Bakım açıklaması",
            "ignore_cert_errors":"HTTPS sertifika doğrulamasını atla",
            "certificate_monitoring":"Sertifika bilgisi/ömrünü izle",
            "certificate_alert_enabled":"Sertifika alarmını etkinleştir",
            "certificate_alert_days":"Kaç gün kala alarm verileceği",
            "content_monitoring":"İçerik kontrolü",
            "content_mode":"contains | not_contains | regex",
            "content_keywords":"İçerik anahtarları/regex listesi",
            "header_monitoring":"Beklenen HTTP header kontrolü",
            "expected_headers":"{\"x-frame-options\":\"DENY\"} gibi beklenen headerlar",
            "advanced_alarm":"Latency alarm katmanını aç",
            "latency_warning_ms":"Warning latency eşiği",
            "latency_critical_ms":"Critical latency eşiği",
            "sla_enabled":"SLA hesabı",
            "sla_target":"SLA hedefi (%)",
            "protocol_options":"Seçilen protokole özel alanlar",
            "dependency_ids":"Bağımlı servis ID listesi",
            "dependency_notifications_enabled":"Bağımlılık alarmını ayrıca bildir (varsayılan false)",
            "notification_group_ids":"Servise atanacak bildirim grubu ID listesi",
            "certificate_notification_group_ids":"Sertifika süresi alarmının gideceği bildirim grubu ID listesi",
            "certificate_notification_subject":"Sertifika alarmı konusu",
            "certificate_notification_message":"Sertifika alarmı mesajı; {{SERVICE_NAME}}, {{CERT_DAYS}}, {{CERT_EXPIRY}} değişkenleri kullanılabilir",
            "custom_notification_enabled":"Servis özel mesajını etkinleştir",
            "custom_notification_message":"Servis özel bildirim mesajı",
            "custom_notification_group_ids":"Özel mesajın gideceği grup ID listesi",
            "notification_rules":"Durum kodu aralığına göre özel bildirim kuralları",
            "notification_cooldown_minutes":"Aynı alarmın tekrar gönderilmesi arasındaki minimum dakika (0=kapalı)","down_notification_subject":"DOWN bildirimi konusu","down_notification_message":"DOWN bildirimi mesajı","recovery_notification_subject":"Recovery bildirimi konusu","recovery_notification_message":"Recovery bildirimi mesajı","warning_notification_subject":"WARNING bildirimi konusu","warning_notification_message":"WARNING bildirimi mesajı","latency_notification_subject":"Latency alarmı konusu","latency_notification_message":"Latency alarmı mesajı; {{LATENCY_MS}} kullanılabilir","resolved_ip":"Hostname/URL üzerinden çözümlenen IP adresi (salt okunur)"
        },
        "notification_fields": NOTIFICATION_FIELDS,
        "notification_field_groups": {
            "service": ["SERVICE_ID","SERVICE_NAME","MONITOR_TYPE","HOST_NAME","HOST_URL","RESOLVED_IP","PORT"],
            "status_event": ["STATUS","PREVIOUS_STATUS","EVENT_TYPE","EVENT_TIME","TIME","LAST_CHECK","REASON","ERROR_MESSAGE"],
            "performance": ["LATENCY_MS","AVG_LATENCY_24H","MIN_LATENCY_24H","MAX_LATENCY_24H","CHECK_COUNT_24H","SUCCESS_COUNT_24H","FAILURE_COUNT_24H","UPTIME_24H","DOWNTIME_24H","INCIDENT_COUNT_24H","FAILURE_COUNT"],
            "http": ["HTTP_STATUS"],
            "certificate": ["CERT_STATUS","CERT_SUBJECT","CERT_ISSUER","CERT_EXPIRY","CERT_DAYS","CERT_ALERT_DAYS"],
        },
        "protocol_options_examples": {
            "ping":{"host":"10.0.0.10","timeout":5},
            "tcp":{"host":"10.0.0.10","port":443,"timeout":8},
            "dns":{"host":"example.com","expected":"1.2.3.4"},
            "ssl":{"host":"example.com","port":443},
            "smtp":{"host":"smtp.example.com","port":587,"tls":True,"ssl":False,"username":"","password":""},
            "mysql":{"host":"127.0.0.1","port":3306,"username":"monitor","password":"...","database":"app"},
            "postgresql":{"host":"127.0.0.1","port":5432,"username":"monitor","password":"...","database":"app"},
            "redis":{"host":"127.0.0.1","port":6379,"username":"","password":"","database":0}
        },
        "notification_rule_example": {
            "enabled":True,"notify":True,"range":"500-599","subject":"{{SERVICE_NAME}} HTTP 5xx","message":"{{SERVICE_NAME}} 5xx döndü. Kod: {{STATUS}}. Neden: {{REASON}}","group_ids":[]
        }
    }

@app.post("/api/services/bulk")
def services_bulk(payload:dict|list=Body(...),db:Session=Depends(get_db)):
    """Tek JSON isteğiyle birden fazla servisi oluşturur. dry_run=true yalnızca doğrulama yapar."""
    dry_run=False
    if isinstance(payload,list): items=payload
    else:
        items=payload.get("services",[]); dry_run=bool(payload.get("dry_run",False))
    if not isinstance(items,list) or not items:
        raise HTTPException(400,"services listesi boş veya hatalı")
    created=[]; errors=[]
    for idx,item in enumerate(items):
        try:
            data=ServiceIn.model_validate(item)
            x,g=prep(data)
            if dry_run:
                created.append({"index":idx,"name":data.name,"valid":True})
                continue
            svc=Service(**x)
            svc.notification_group_ids_json=json.dumps(g or [x.id for x in default_groups(db)],ensure_ascii=False)
            db.add(svc); db.flush()
            created.append(sd(svc))
        except Exception as exc:
            errors.append({"index":idx,"error":str(exc)})
    if errors:
        db.rollback()
        raise HTTPException(422,detail={"message":"Toplu ekleme doğrulama hatası","errors":errors})
    if not dry_run: db.commit()
    return {"ok":True,"dry_run":dry_run,"count":len(created),"services":created}

@app.get("/api/openapi-short")
def openapi_short():
    return {"swagger_url":"/swagger","openapi_url":"/openapi.json","bulk_create":"POST /api/services/bulk","service_schema":"GET /api/services/schema"}

@app.get("/swagger",response_class=HTMLResponse)
def swagger_page():
    return open("frontend/swagger.html",encoding="utf-8").read()

@app.get("/api/groups")
def groups(request:Request,db:Session=Depends(get_db)):
    readonly=request.state.user_role in {"read_only_admin","read_only_super_admin"}
    out=[]
    for g in db.query(NotificationGroup).order_by(NotificationGroup.id).all():
        rec=jd(g.recipients_json,"{}")
        for k in ["telegram_token","webhook_url","discord_webhook","slack_webhook"]:
            if rec.get(k): rec[k]="••••••••"
        out.append({"id":g.id,"name":g.name,"enabled":g.enabled,"auto_add_new_services":g.auto_add_new_services,"channels":jd(g.channels_json,"{}"),"recipients":rec})
    return out

@app.post("/api/groups")
def group_add(p:dict,db:Session=Depends(get_db)):
    rec=p.get("recipients",{}) or {}
    if p.get("channels",{}).get("telegram"):
        tg=db.query(Integration).filter_by(provider="telegram").first(); cfg=jd(tg.config_json,"{}") if tg else {}
        if not tg or not tg.enabled or not cfg.get("token") or not cfg.get("chat_id"):
            raise HTTPException(422,"Telegram kanalı için Ayarlar → Uygulama Entegrasyonları bölümünde Telegram entegrasyonunu etkinleştirip Bot Token ve Chat ID girin.")
    g=NotificationGroup(name=p.get("name","Yeni Bildirim Grubu"),enabled=p.get("enabled",True),auto_add_new_services=p.get("auto_add_new_services",False),channels_json=json.dumps(p.get("channels",{})),recipients_json=json.dumps(rec))
    db.add(g);db.commit();return {"id":g.id}

@app.put("/api/groups/{gid}")
def group_update(gid:int,p:dict,db:Session=Depends(get_db)):
    g=db.get(NotificationGroup,gid)
    if not g:raise HTTPException(404)
    for k in ["name","enabled","auto_add_new_services"]:
        if k in p:setattr(g,k,p[k])
    channels=p.get("channels",{}) or {}
    incoming=p.get("recipients",{}) or {}
    current=jd(g.recipients_json,"{}")
    # Secret/channel endpoints are never required to send existing secrets back.
    for secret_key in ["telegram_token","webhook_url","discord_webhook","slack_webhook"]:
        if incoming.get(secret_key) in (None,"","••••••••") and current.get(secret_key):
            incoming[secret_key]=current[secret_key]
    if channels.get("telegram"):
        tg=db.query(Integration).filter_by(provider="telegram").first(); cfg=jd(tg.config_json,"{}") if tg else {}
        if not tg or not tg.enabled or not cfg.get("token") or not cfg.get("chat_id"):
            raise HTTPException(422,"Telegram kanalı için Ayarlar → Uygulama Entegrasyonları bölümünde Telegram entegrasyonunu etkinleştirip Bot Token ve Chat ID girin.")
    g.channels_json=json.dumps(channels);g.recipients_json=json.dumps(incoming);db.commit();return {"ok":True}

@app.delete("/api/groups/{gid}")
def group_delete(gid:int,db:Session=Depends(get_db)):
    g=db.get(NotificationGroup,gid);a=db.query(AppSettings).first()
    if not g:raise HTTPException(404)
    if a.default_notification_group_id==gid:a.default_notification_group_id=None
    db.delete(g);db.commit();return {"ok":True}

@app.get("/api/settings")
def settings(db:Session=Depends(get_db)):
    a=db.query(AppSettings).first();s=db.query(SMTPSettings).first();groups= db.query(NotificationGroup).order_by(NotificationGroup.id).all()
    sec=db.query(SecurityConfig).first(); return {"app":{c.name:getattr(a,c.name) for c in AppSettings.__table__.columns},"smtp":{c.name:getattr(s,c.name) for c in SMTPSettings.__table__.columns if c.name!="password"},"groups":[{"id":g.id,"name":g.name} for g in groups],"retention":{k:getattr(a,k) for k in ["retention_enabled","retention_checks_days","retention_logs_days","retention_audit_days","retention_incidents_days","retention_cleanup_hour"]},"security":{"jwt_secret_created_at":sec.jwt_secret_created_at if sec else None,"jwt_rotation_days":20}}

@app.put("/api/settings")
def put_settings(p:dict,db:Session=Depends(get_db)):
    a=db.query(AppSettings).first();s=db.query(SMTPSettings).first()
    for k,v in p.get("app",{}).items():
        if hasattr(a,k):setattr(a,k,v)
    for k,v in p.get("smtp",{}).items():
        if hasattr(s,k):
            if k=="password" and v=="":continue
            setattr(s,k,v)
    if getattr(s,"mode", "auth") == "relay":
        s.auth_enabled=False
        s.username=""
        s.password=""
    if s.use_ssl:s.use_tls=False
    db.commit();return {"ok":True}

@app.post("/api/settings/retention/cleanup")
def retention_cleanup(db:Session=Depends(get_db)):
    return cleanup_retention_once()

@app.post("/api/telegram/test")
def telegram_test(p:dict,db:Session=Depends(get_db)):
    cfg=jd(db.query(Integration).filter_by(provider="telegram").first().config_json,"{}") if db.query(Integration).filter_by(provider="telegram").first() else {}
    token=(p.get("token") or cfg.get("token") or "").strip()
    chat_id=(p.get("chat_id") or cfg.get("chat_id") or "").strip()
    if not token or not chat_id:
        raise HTTPException(422,"Bot Token ve Chat ID zorunludur.")
    ok,info=telegram_request(token,"getMe",{})
    if not ok:
        return {"ok":False,"message":f"Telegram bot doğrulanamadı: {info}"}
    bot=(info.get("result") or {})
    test_message=("<b>Service Monitor</b>\n\n"
                  "✅ Telegram bağlantısı başarılı.\n\n"
                  "Bot: @"+str(bot.get("username") or "-")+"\n"
                  "Chat ID: "+str(chat_id))
    ok2,msg=telegram_send(token,chat_id,test_message,"HTML")
    return {"ok":ok2,"message":msg,"bot":{"id":bot.get("id"),"username":bot.get("username"),"name":bot.get("first_name")}}

@app.post("/api/smtp/test")
def smtp_test(p:dict,db:Session=Depends(get_db)):
    r=p.get("recipient") or db.query(AppSettings).first().system_email;ok,msg=email(db,[r],"Service Monitor SMTP Test","SMTP test maili başarıyla gönderildi.");return {"ok":ok,"message":msg}

def _page_args(page:int,page_size:int):
    page=max(1,int(page or 1)); page_size=min(1000,max(20,int(page_size or 50))); return page,page_size

@app.get("/api/logs")
def logs(q:str="",category:str="",page:int=1,page_size:int=50,db:Session=Depends(get_db)):
    q=(q or "").strip()[:100]; page,page_size=_page_args(page,page_size)
    query=db.query(EventLog)
    if category:query=query.filter(EventLog.category==category[:60])
    if q:
        like=f"%{q}%"
        query=query.outerjoin(Service, Service.id == EventLog.service_id).outerjoin(
            MonitorControl, MonitorControl.id == EventLog.control_id
        ).filter(or_(
            EventLog.message.ilike(like), EventLog.category.ilike(like), EventLog.level.ilike(like),
            Service.name.ilike(like), Service.url.ilike(like), Service.monitor_type.ilike(like),
            Service.description.ilike(like), Service.last_resolved_ip.ilike(like),
            MonitorControl.name.ilike(like), MonitorControl.control_type.ilike(like),
            MonitorControl.url.ilike(like), MonitorControl.last_resolved_ip.ilike(like),
            MonitorControl.config_json.ilike(like), MonitorControl.advanced_options_json.ilike(like),
        )).distinct()
    query=query.order_by(EventLog.id.desc()); total=query.count(); pages=max(1,(total+page_size-1)//page_size)
    items=query.offset((page-1)*page_size).limit(page_size).all()
    return {"items":[{"id":x.id,"time":x.created_at,"level":x.level,"category":x.category,"service_id":x.service_id,"service_name":(db.get(Service,x.service_id).name if x.service_id and db.get(Service,x.service_id) else None),"monitor_type":(db.get(Service,x.service_id).monitor_type if x.service_id and db.get(Service,x.service_id) else None),"control_id":getattr(x,"control_id",None),"message":x.message} for x in items],"page":page,"page_size":page_size,"total":total,"pages":pages}

@app.get("/api/incidents")
def incidents(q:str="",page:int=1,page_size:int=50,db:Session=Depends(get_db)):
    q=(q or "").strip()[:100]; page,page_size=_page_args(page,page_size); query=db.query(Incident)
    if q:
        like=f"%{q}%"
        query=query.outerjoin(Service, Service.id == Incident.service_id).outerjoin(
            MonitorControl, MonitorControl.id == Incident.control_id
        ).filter(or_(
            Incident.reason.ilike(like), Incident.status.ilike(like),
            Service.name.ilike(like), Service.url.ilike(like), Service.monitor_type.ilike(like),
            Service.description.ilike(like), Service.last_resolved_ip.ilike(like),
            MonitorControl.name.ilike(like), MonitorControl.control_type.ilike(like),
            MonitorControl.url.ilike(like), MonitorControl.last_resolved_ip.ilike(like),
            MonitorControl.config_json.ilike(like), MonitorControl.advanced_options_json.ilike(like),
        )).distinct()
    query=query.order_by(Incident.id.desc()); total=query.count(); pages=max(1,(total+page_size-1)//page_size); items=query.offset((page-1)*page_size).limit(page_size).all()
    return {"items":[{"id":x.id,"service_id":x.service_id,"control_id":getattr(x,"control_id",None),"status":x.status,"started":x.started_at,"resolved":x.resolved_at,"duration":x.downtime_seconds,"reason":x.reason} for x in items],"page":page,"page_size":page_size,"total":total,"pages":pages}

@app.get("/api/audit")
def audit(q:str="",page:int=1,page_size:int=50,db:Session=Depends(get_db)):
    q=(q or "").strip()[:100]; page,page_size=_page_args(page,page_size); query=db.query(AuditLog)
    if q:
        like=f"%{q}%"
        query=query.outerjoin(Service, Service.id == AuditLog.service_id).outerjoin(
            MonitorControl, MonitorControl.id == AuditLog.control_id
        ).filter(or_(
            AuditLog.action.ilike(like), AuditLog.details.ilike(like), AuditLog.actor.ilike(like),
            Service.name.ilike(like), Service.url.ilike(like), Service.monitor_type.ilike(like),
            Service.description.ilike(like), Service.last_resolved_ip.ilike(like),
            MonitorControl.name.ilike(like), MonitorControl.control_type.ilike(like),
            MonitorControl.url.ilike(like), MonitorControl.last_resolved_ip.ilike(like),
            MonitorControl.config_json.ilike(like), MonitorControl.advanced_options_json.ilike(like),
        )).distinct()
    query=query.order_by(AuditLog.id.desc()); total=query.count(); pages=max(1,(total+page_size-1)//page_size); items=query.offset((page-1)*page_size).limit(page_size).all()
    return {"items":[{"id":x.id,"time":x.created_at,"actor":x.actor,"action":x.action,"service_id":x.service_id,"control_id":getattr(x,"control_id",None),"details":x.details} for x in items],"page":page,"page_size":page_size,"total":total,"pages":pages}

@app.get("/api/audit/{audit_id}")
def audit_detail(audit_id:int,db:Session=Depends(get_db)):
    x=db.get(AuditLog,audit_id)
    if not x:raise HTTPException(404,"Denetim kaydı bulunamadı")
    service=db.get(Service,x.service_id) if x.service_id else None
    related=[]
    if service:related=[{"id":l.id,"time":l.created_at,"level":l.level,"category":l.category,"message":l.message} for l in db.query(EventLog).filter(EventLog.service_id==service.id).order_by(EventLog.id.desc()).limit(15).all()]
    return {"audit":{"id":x.id,"time":x.created_at,"actor":x.actor,"action":x.action,"service_id":x.service_id,"control_id":getattr(x,"control_id",None),"details":x.details},"service":sd(service) if service else None,"related_logs":related}

@app.get("/api/screenshots")
def screenshots(page:int=1,page_size:int=60,service_id:int|None=None,q:str="",db:Session=Depends(get_db)):
    page,page_size=_page_args(page,page_size);query=db.query(ServiceScreenshot)
    if service_id:query=query.filter(ServiceScreenshot.service_id==service_id)
    if q:
        like=f"%{q.strip()[:100]}%"
        query=query.join(Service, Service.id == ServiceScreenshot.service_id).filter(or_(
            Service.name.ilike(like), Service.url.ilike(like), Service.monitor_type.ilike(like),
            Service.last_resolved_ip.ilike(like), ServiceScreenshot.reason.ilike(like),
            ServiceScreenshot.url.ilike(like), ServiceScreenshot.status.ilike(like)
        ))
    total=query.count();items=query.order_by(ServiceScreenshot.id.desc()).offset((page-1)*page_size).limit(page_size).all()
    return {"items":[{"id":x.id,"service_id":x.service_id,"service_name":(db.get(Service,x.service_id).name if x.service_id and db.get(Service,x.service_id) else None),"monitor_type":(db.get(Service,x.service_id).monitor_type if x.service_id and db.get(Service,x.service_id) else None),"control_id":getattr(x,"control_id",None),"captured_at":x.captured_at,"status":x.status,"http_status":x.http_status,"reason":x.reason,"path":x.path,"url":x.url} for x in items],"page":page,"page_size":page_size,"total":total,"pages":max(1,(total+page_size-1)//page_size)}

@app.get("/api/branding")
def get_branding(db:Session=Depends(get_db)):
    a=db.query(AppSettings).first();return {"logo_url":getattr(a,"branding_logo_url","/static/assets/um-logo.svg") if a else "/static/assets/um-logo.svg"}

@app.post("/api/branding")
def set_branding(p:dict,db:Session=Depends(get_db)):
    import base64
    data=str(p.get("data_url") or "")
    if not data.startswith("data:image/"):raise HTTPException(400,"Geçerli bir görsel seçin.")
    parts=data.split(",",1)
    if len(parts)!=2:raise HTTPException(400,"Görsel verisi bozuk.")
    head,payload=parts
    if len(payload)>3_000_000:raise HTTPException(400,"Logo en fazla yaklaşık 2 MB olabilir.")
    ext={"data:image/png":"png","data:image/jpeg":"jpg","data:image/webp":"webp","data:image/svg+xml":"svg"}.get(head.split(";")[0])
    if not ext:raise HTTPException(400,"Desteklenen formatlar: PNG, JPG, WEBP, SVG.")
    try:raw=base64.b64decode(payload)
    except Exception:raise HTTPException(400,"Görsel kodlaması geçersiz.")
    os.makedirs("frontend/assets/branding",exist_ok=True);fp=f"frontend/assets/branding/branding-logo.{ext}"
    with open(fp,"wb") as f:f.write(raw)
    a=db.query(AppSettings).first();a.branding_logo_url=f"/static/assets/branding/branding-logo.{ext}?v={int(time.time())}";db.commit()
    return {"ok":True,"logo_url":a.branding_logo_url}

@app.get("/api/logs/{log_id}")
def log_detail(log_id:int,db:Session=Depends(get_db)):
    x=db.get(EventLog,log_id)
    if not x: raise HTTPException(404,"Log bulunamadı")
    s=db.get(Service,x.service_id) if x.service_id else None
    recent=[]; related_incidents=[]; screenshots=[]; related_logs=[]; related_audit=[]
    if s:
        recent=[{"id":r.id,"time":r.checked_at,"status":r.status,"http_status":r.http_status,"latency_ms":r.latency_ms,"error":r.error,"certificate_days":r.certificate_days,"headers":jd(r.headers_json,"{}"),"header_security":jd(r.header_security_json,"{}"),"tls_security":jd(r.tls_security_json,"{}")} for r in db.query(CheckResult).filter_by(service_id=s.id).order_by(CheckResult.id.desc()).limit(30).all()]
        related_incidents=[{"id":i.id,"status":i.status,"started":i.started_at,"resolved":i.resolved_at,"duration":i.downtime_seconds,"failure_count":i.failure_count,"reason":i.reason} for i in db.query(Incident).filter_by(service_id=s.id).order_by(Incident.id.desc()).limit(10).all()]
        screenshots=[{"id":z.id,"captured_at":z.captured_at,"status":z.status,"http_status":z.http_status,"reason":z.reason,"path":z.path} for z in db.query(ServiceScreenshot).filter_by(service_id=s.id).order_by(ServiceScreenshot.id.desc()).limit(10).all()]
        related_logs=[{"id":l.id,"time":l.created_at,"level":l.level,"category":l.category,"message":l.message} for l in db.query(EventLog).filter(EventLog.service_id==s.id).order_by(EventLog.id.desc()).limit(10).all()]
        related_audit=[{"time":a.created_at,"actor":a.actor,"action":a.action,"details":a.details} for a in db.query(AuditLog).filter(AuditLog.service_id==s.id).order_by(AuditLog.id.desc()).limit(10).all()]
    return {"log":{"id":x.id,"time":x.created_at,"level":x.level,"category":x.category,"service_id":x.service_id,"control_id":getattr(x,"control_id",None),"message":x.message},
            "service":sd(s) if s else None,"recent_checks":recent,"incidents":related_incidents,"screenshots":screenshots,"related_logs":related_logs,"audit":related_audit}

@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id:int,db:Session=Depends(get_db)):
    x=db.get(Incident,incident_id)
    if not x: raise HTTPException(404,"Olay bulunamadı")
    s=db.get(Service,x.service_id) if x.service_id else None
    checks=[]
    if s: checks=[{"time":r.checked_at,"status":r.status,"http_status":r.http_status,"latency_ms":r.latency_ms,"error":r.error} for r in db.query(CheckResult).filter_by(service_id=s.id).order_by(CheckResult.id.desc()).limit(50).all()]
    return {"incident":{"id":x.id,"status":x.status,"started":x.started_at,"resolved":x.resolved_at,"duration":x.downtime_seconds,"failure_count":x.failure_count,"reason":x.reason},
            "service":sd(s) if s else None,"checks":checks}

@app.get("/api/notification-templates")
def notification_templates(db:Session=Depends(get_db)):
    a=db.query(AppSettings).first()
    return {k:getattr(a,k) for k in ["down_notification_subject","down_notification_message","recovery_notification_subject","recovery_notification_message","warning_notification_subject","warning_notification_message","latency_notification_subject","latency_notification_message"]}

@app.put("/api/notification-templates")
def notification_templates_update(p:dict,db:Session=Depends(get_db)):
    a=db.query(AppSettings).first()
    keys=["down_notification_subject","down_notification_message","recovery_notification_subject","recovery_notification_message","warning_notification_subject","warning_notification_message","latency_notification_subject","latency_notification_message"]
    for k in keys:
        if k in p:a.__setattr__(k,p[k] or "")
    db.commit();return {"ok":True}

@app.get("/api/providers")
def providers(request:Request,db:Session=Depends(get_db)):
    readonly=request.state.user_role in {"read_only_admin","read_only_super_admin"}
    out=[]
    for x in db.query(Integration).all():
        cfg=jd(x.config_json,"{}")
        if isinstance(cfg,dict) and (readonly or x.provider=="telegram"):
            cfg={k:("••••••••" if any(secret in k.lower() for secret in ["token","secret","password","key","webhook"]) else v) for k,v in cfg.items()}
        out.append({"provider":x.provider,"enabled":x.enabled,"config":cfg})
    return out

@app.post("/api/providers")
def provider(p:dict,db:Session=Depends(get_db)):
    x=db.query(Integration).filter_by(provider=p["provider"]).first()
    if not x:x=Integration(provider=p["provider"]);db.add(x)
    cfg=p.get("config",{}) or {}; current=jd(x.config_json,"{}")
    if p.get("provider")=="telegram":
        for k in ["token"]:
            if cfg.get(k) in (None,"","••••••••") and current.get(k): cfg[k]=current[k]
        if cfg.get("enabled") is None: pass
        if p.get("enabled") and (not cfg.get("token") or not cfg.get("chat_id")):
            raise HTTPException(422,"Telegram etkinse Bot Token ve Chat ID zorunludur.")
    x.enabled=p.get("enabled",False);x.config_json=json.dumps(cfg,ensure_ascii=False);db.commit();return {"ok":True}

@app.get("/api/dashboard/analytics")
def dashboard_analytics(period:str="24h",db:Session=Depends(get_db)):
    period=(period or "24h").lower()
    configs={"24h":(timedelta(hours=24),timedelta(hours=1),24),"7d":(timedelta(days=7),timedelta(hours=6),28),"30d":(timedelta(days=30),timedelta(days=1),30)}
    horizon,bucket_size,bucket_count=configs.get(period,configs["24h"])
    now=datetime.utcnow(); since=now-horizon
    rows=db.query(CheckResult.service_id,CheckResult.checked_at,CheckResult.status,CheckResult.latency_ms).filter(CheckResult.checked_at>=since).order_by(CheckResult.checked_at.asc()).all()
    incidents=db.query(Incident.service_id,Incident.started_at,Incident.downtime_seconds,Incident.status).filter(Incident.started_at>=since).all()
    services=db.query(Service.id,Service.name,Service.monitor_type,Service.last_status,Service.last_latency_ms,Service.last_resolved_ip).all()
    buckets=[{"label":(since+bucket_size*i).strftime("%H:%M" if period=="24h" else ("%d %b" if period=="30d" else "%d %b %H:%M")),"checks":0,"up":0,"down":0,"warning":0,"uptime_pct":0,"avg_latency":0,"min_latency":0,"max_latency":0,"incidents":0,"downtime_seconds":0,"_lat":[]} for i in range(bucket_count)]
    service_stats={s.id:{"id":s.id,"service":s.name,"ip":s.last_resolved_ip or "","checks":0,"up":0,"lat":[],"incidents":0,"last_status":s.last_status} for s in services}
    status_counts={"UP":0,"WARNING":0,"DOWN":0}; all_lats=[]
    for r in rows:
        idx=int((r.checked_at-since).total_seconds()//bucket_size.total_seconds())
        if 0<=idx<bucket_count:
            b=buckets[idx]; b["checks"]+=1; b[r.status.lower() if r.status in ("UP","DOWN","WARNING") else "warning"]+=1
            if r.latency_ms is not None: b["_lat"].append(float(r.latency_ms)); all_lats.append(float(r.latency_ms))
        if r.status in status_counts: status_counts[r.status]+=1
        st=service_stats.get(r.service_id)
        if st:
            st["checks"]+=1; st["up"]+=1 if r.status=="UP" else 0
            if r.latency_ms is not None: st["lat"].append(float(r.latency_ms))
    for x in incidents:
        idx=int((x.started_at-since).total_seconds()//bucket_size.total_seconds())
        if 0<=idx<bucket_count:
            buckets[idx]["incidents"]+=1; buckets[idx]["downtime_seconds"]+=float(x.downtime_seconds or 0)
        if x.service_id in service_stats: service_stats[x.service_id]["incidents"]+=1
    for b in buckets:
        lat=b.pop("_lat")
        b["uptime_pct"]=round(b["up"]/b["checks"]*100,2) if b["checks"] else 0
        b["avg_latency"]=round(sum(lat)/len(lat),2) if lat else 0
        b["min_latency"]=round(min(lat),2) if lat else 0
        b["max_latency"]=round(max(lat),2) if lat else 0
        b["downtime_seconds"]=round(b["downtime_seconds"],1)
    type_map={}
    for svc in services:
        key=svc.monitor_type or "unknown"; t=type_map.setdefault(key,{"type":key,"count":0,"up":0,"down":0,"warning":0,"avg_latency":0,"_lat":[]}); t["count"]+=1
        if svc.last_status in {"UP","DOWN","WARNING"}: t[svc.last_status.lower()]+=1
        if svc.last_latency_ms is not None: t["_lat"].append(float(svc.last_latency_ms))
    type_stats=[]
    for t in type_map.values():
        lat=t.pop("_lat"); t["avg_latency"]=round(sum(lat)/len(lat),1) if lat else 0; type_stats.append(t)
    service_stats_out=[]
    for st in service_stats.values():
        lat=st.pop("lat"); st["uptime_percent"]=round(st["up"]/st["checks"]*100,2) if st["checks"] else 0; st["avg_latency"]=round(sum(lat)/len(lat),2) if lat else 0; st["max_latency"]=round(max(lat),2) if lat else 0; service_stats_out.append(st)
    return {"period":period,"buckets":buckets,"type_stats":sorted(type_stats,key=lambda x:x["count"],reverse=True),"service_stats":service_stats_out,
            "status_counts":status_counts,"latency":{"min":round(min(all_lats),2) if all_lats else 0,"avg":round(sum(all_lats)/len(all_lats),2) if all_lats else 0,"max":round(max(all_lats),2) if all_lats else 0},
            "incidents":{"count":len(incidents),"open":sum(i.status=="OPEN" for i in incidents),"downtime_seconds":round(sum(float(i.downtime_seconds or 0) for i in incidents),1)}}

@app.get("/api/services/{sid}/analytics")
def service_analytics(sid:int,period:str="24h",db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    period=(period or "24h").lower(); configs={"24h":(timedelta(hours=24),timedelta(hours=1),24),"7d":(timedelta(days=7),timedelta(hours=6),28),"30d":(timedelta(days=30),timedelta(days=1),30)}
    horizon,bucket_size,bucket_count=configs.get(period,configs["24h"]); now=datetime.utcnow(); since=now-horizon
    rows=db.query(CheckResult).filter(CheckResult.service_id==sid,CheckResult.checked_at>=since).order_by(CheckResult.checked_at.asc()).all()
    incidents=db.query(Incident).filter(Incident.service_id==sid,Incident.started_at>=since).order_by(Incident.started_at.asc()).all()
    buckets=[]
    for i in range(bucket_count):
        start=since+bucket_size*i; end=start+bucket_size; rr=[r for r in rows if start<=r.checked_at<end]; lat=[r.latency_ms for r in rr if r.latency_ms is not None]; up=sum(r.status=="UP" for r in rr)
        buckets.append({"label":start.strftime("%H:%M" if period=="24h" else ("%d %b" if period=="30d" else "%d %b %H:%M")),"checks":len(rr),"up":up,"down":sum(r.status=="DOWN" for r in rr),"warning":sum(r.status=="WARNING" for r in rr),"uptime_pct":round(up/len(rr)*100,2) if rr else 0,"latency":round(sum(lat)/len(lat),2) if lat else 0,"min_latency":round(min(lat),2) if lat else 0,"max_latency":round(max(lat),2) if lat else 0,"incidents":sum(1 for x in incidents if start<=x.started_at<end)})
    codes={}
    for r in rows:
        if r.http_status is not None: codes[str(r.http_status)]=codes.get(str(r.http_status),0)+1
    lats=[r.latency_ms for r in rows if r.latency_ms is not None]; total=len(rows); up=sum(r.status=="UP" for r in rows)
    return {"service":s.name,"resolved_ip":s.last_resolved_ip or "","period":period,"buckets":buckets,"status_counts":{k:sum(r.status==k for r in rows) for k in ["UP","WARNING","DOWN"]},"uptime_percent":round(up/total*100,2) if total else 0,"latency":{"min":round(min(lats),2) if lats else 0,"avg":round(sum(lats)/len(lats),2) if lats else 0,"max":round(max(lats),2) if lats else 0},"http_codes":codes,"checks":total,"incidents":{"count":len(incidents),"open":sum(i.status=="OPEN" for i in incidents),"downtime_seconds":round(sum(i.downtime_seconds or 0 for i in incidents),1)}}

@app.get("/api/daily-summary")
def daily_summary(db:Session=Depends(get_db)):
    since=datetime.utcnow()-timedelta(days=1);services=db.query(Service).all();out=[]
    for s in services:
        rows=db.query(CheckResult).filter(CheckResult.service_id==s.id,CheckResult.checked_at>=since).all();total=len(rows);up=sum(r.status=="UP" for r in rows);lat=[r.latency_ms for r in rows if r.latency_ms is not None]
        out.append({"service":s.name,"checks":total,"up":up,"uptime_percent":round(up/total*100,2) if total else 0,"avg_latency_ms":round(sum(lat)/len(lat),2) if lat else 0,"incidents":db.query(Incident).filter(Incident.service_id==s.id,Incident.started_at>=since).count(),"last_status":s.last_status})
    return {"generated_at":datetime.utcnow(),"services":out}

def _export_rows(db, sid, limit=5000):
    return db.query(CheckResult).filter_by(service_id=sid).order_by(CheckResult.id.desc()).limit(limit).all()

def _export_service_payload(db, s, limit=5000):
    rows=list(reversed(_export_rows(db,s.id,limit)))
    incidents=db.query(Incident).filter_by(service_id=s.id).order_by(Incident.id.desc()).limit(200).all()
    lat=[r.latency_ms for r in rows if r.latency_ms is not None]
    up=sum(r.status=="UP" for r in rows); total=len(rows)
    shots=db.query(ServiceScreenshot).filter_by(service_id=s.id).order_by(ServiceScreenshot.id.desc()).limit(1000).all()
    logs=db.query(EventLog).filter_by(service_id=s.id).order_by(EventLog.id.desc()).limit(5000).all()
    return {"id":s.id,"name":s.name,"monitor_type":s.monitor_type,"url":s.url,"description":s.description or "","service_authorized_name":s.service_authorized_name or "",
            "resolved_ip":s.last_resolved_ip or "","last_status":s.last_status,"last_latency_ms":s.last_latency_ms,"last_error":s.last_error or "",
            "last_http_status":s.last_http_status,"last_check_at":s.last_check_at,"checks":total,"uptime_percent":round(up/total*100,2) if total else 0,
            "latency_min":round(min(lat),2) if lat else 0,"latency_avg":round(sum(lat)/len(lat),2) if lat else 0,"latency_max":round(max(lat),2) if lat else 0,
            "incidents":len(incidents),"header_security":jd(s.last_header_security_json,"{}"),"headers":jd(s.last_headers_json,"{}"),
            "tls_security":jd(s.last_tls_security_json,"{}"),"certificate":{"subject":s.cert_subject or "","issuer":s.cert_issuer or "","expires_at":s.cert_expires_at,"remaining_days":s.last_cert_days},
            "screenshots":[{"captured_at":x.captured_at,"reason":x.reason,"status":x.status,"http_status":x.http_status,"path":x.path,"url":x.url} for x in shots],
            "incidents_detail":[{"id":x.id,"status":x.status,"started_at":x.started_at,"resolved_at":x.resolved_at,"duration":x.downtime_seconds,"failure_count":x.failure_count,"reason":x.reason} for x in incidents],
            "logs":[{"id":x.id,"time":x.created_at,"level":x.level,"category":x.category,"message":x.message} for x in logs],
            "check_rows":[{"time":r.checked_at.isoformat() if r.checked_at else "","status":r.status or "","http_status":r.http_status,"latency_ms":r.latency_ms,"certificate_days":r.certificate_days,"error":r.error or "",
                           "headers":jd(r.headers_json,"{}"),"header_security":jd(r.header_security_json,"{}"),"tls_security":jd(r.tls_security_json,"{}")} for r in rows]}

def _svg_line(points, width=900, height=260, title="Latency"):
    if not points:return "<div class='empty'>Veri yok.</div>"
    vals=[float(p[1] or 0) for p in points]; mx=max(1,max(vals)); left,top,right,bottom=52,26,18,38; iw=width-left-right; ih=height-top-bottom
    coords=[]
    for i,(label,val) in enumerate(points):
        x=left+(iw/2 if len(points)==1 else i*iw/(len(points)-1)); y=top+(mx-float(val or 0))/mx*ih; coords.append((x,y))
    grid=[]
    for n in range(5):
        y=top+ih*n/4; v=mx*(1-n/4); grid.append(f"<line x1='{left}' y1='{y:.1f}' x2='{width-right}' y2='{y:.1f}' stroke='#334155' stroke-dasharray='4 5'/><text x='{left-8}' y='{y+4:.1f}' text-anchor='end' fill='#94a3b8' font-size='10'>{v:.0f}</text>")
    path=" ".join(("M" if i==0 else "L")+f"{x:.1f} {y:.1f}" for i,(x,y) in enumerate(coords))
    area=f"{path} L {coords[-1][0]:.1f} {top+ih:.1f} L {coords[0][0]:.1f} {top+ih:.1f} Z"
    marks={0,len(coords)//2,len(coords)-1}; labels="".join(f"<text x='{coords[i][0]:.1f}' y='{height-12}' text-anchor='middle' fill='#94a3b8' font-size='9'>{str(points[i][0])[-12:]}</text>" for i in sorted(marks))
    dots="".join(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='3' fill='#0b1320' stroke='#63b3ed' stroke-width='2'><title>{str(label)} · {float(val or 0):.2f}</title></circle>" for (label,val),(x,y) in zip(points,coords))
    return f"<div class='chart-block'><div class='chart-title'>{title}</div><svg viewBox='0 0 {width} {height}' role='img' aria-label='{title}'><g>{''.join(grid)}</g><path d='{area}' fill='rgba(99,179,237,.12)'/><path d='{path}' fill='none' stroke='#63b3ed' stroke-width='2.7' stroke-linecap='round' stroke-linejoin='round'/>{dots}{labels}</svg></div>"

def _safe_export_text(v):
    return str(v if v is not None else "").replace("\r"," ").replace("\n"," ").strip()

def _safe_csv_value(v):
    x=_safe_export_text(v).replace("|","/")
    return "'"+x if x.startswith(("=","+","-","@")) else x

def _html_report(title, services_payload, generated_at):
    import html
    rows=[]; charts=[]
    for s in services_payload:
        rows.append(f"<tr><td>{html.escape(_safe_export_text(s['name']))}</td><td>{html.escape(_safe_export_text(s['monitor_type']))}</td><td>{html.escape(_safe_export_text(s['resolved_ip'] or '-'))}</td><td>{html.escape(_safe_export_text(s['last_status'] or '-'))}</td><td>{s['uptime_percent']:.2f}%</td><td>{s['latency_avg']:.2f} ms</td><td>{s['latency_max']:.2f} ms</td><td>{s['incidents']}</td></tr>")
        if s['check_rows']:
            recent=s['check_rows'][-120:]
            pts=[(r['time'][11:19] if len(r['time'])>=19 else r['time'],r['latency_ms'] or 0) for r in recent]
            uptime_pts=[(r['time'][11:19] if len(r['time'])>=19 else r['time'],100 if r['status']=='UP' else 0) for r in recent]
            charts.append(f"<section class='service-section'><h2>{html.escape(_safe_export_text(s['name']))}</h2><div class='meta'>{html.escape(_safe_export_text(s['url'] or s['monitor_type']))} · IP: {html.escape(_safe_export_text(s['resolved_ip'] or '-'))}</div>{_svg_line(uptime_pts,title='Uptime Trendi')}{_svg_line(pts,title='Latency Trendi')}</section>")
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>:root{{color-scheme:dark}}body{{margin:0;background:#07101d;color:#e7eef7;font:14px Inter,Arial,sans-serif}}.wrap{{max-width:1250px;margin:0 auto;padding:34px}}header{{padding:24px;border:1px solid #24364d;border-radius:18px;background:#0e1b2c}}h1{{margin:0 0 6px;font-size:28px}}h2{{margin:0 0 6px}}.muted,.meta{{color:#93a4b8}}.summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}.kpi{{padding:16px;border:1px solid #24364d;border-radius:14px;background:#0d1a2b}}.kpi b{{display:block;font-size:22px;margin-top:6px}}table{{width:100%;border-collapse:collapse;background:#0d1a2b;border:1px solid #24364d}}th,td{{padding:10px 12px;border-bottom:1px solid #203047;text-align:left}}th{{color:#9fb1c5;font-size:11px;text-transform:uppercase}}.service-section{{margin-top:18px;padding:18px;border:1px solid #24364d;border-radius:16px;background:#0d1a2b}}svg{{width:100%;height:260px;display:block}}.chart-title{{font-weight:700;margin-bottom:6px}}@media(max-width:800px){{.summary{{grid-template-columns:1fr 1fr}}.wrap{{padding:16px}}}}</style></head><body><div class="wrap"><header><h1>{html.escape(title)}</h1><div class="muted">Uptime Monitor Service · Oluşturulma: {html.escape(str(generated_at))}</div></header><div class="summary"><div class="kpi">Servis Sayısı<b>{len(services_payload)}</b></div><div class="kpi">UP<b>{sum(1 for x in services_payload if x['last_status']=='UP')}</b></div><div class="kpi">Ortalama Uptime<b>{(sum(x['uptime_percent'] for x in services_payload)/len(services_payload) if services_payload else 0):.2f}%</b></div><div class="kpi">Ortalama Latency<b>{(sum(x['latency_avg'] for x in services_payload)/len(services_payload) if services_payload else 0):.2f} ms</b></div></div><table><thead><tr><th>Servis</th><th>Tip</th><th>IP</th><th>Durum</th><th>Uptime</th><th>Ort. Latency</th><th>Maks. Latency</th><th>Incident</th></tr></thead><tbody>{''.join(rows)}</tbody></table>{''.join(charts)}</div></body></html>"""

def _pdf_report(title, services_payload, generated_at):
    from reportlab.platypus import SimpleDocTemplate,Table,TableStyle,Paragraph,Spacer,KeepTogether
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4,landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.units import mm
    from reportlab.graphics.shapes import Drawing,PolyLine,Line,String
    try:
        pdfmetrics.registerFont(TTFont("UMDejaVu","/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
        pdfmetrics.registerFont(TTFont("UMDejaVuBold","/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"))
        styles=getSampleStyleSheet(); styles["Title"].fontName="UMDejaVuBold"; styles["Normal"].fontName="UMDejaVu"; styles["Heading3"].fontName="UMDejaVuBold"
    except Exception:
        styles=getSampleStyleSheet()
    b=io.BytesIO(); doc=SimpleDocTemplate(b,pagesize=landscape(A4),leftMargin=10*mm,rightMargin=10*mm,topMargin=10*mm,bottomMargin=10*mm)
    story=[Paragraph(title,styles['Title']),Paragraph(f"Uptime Monitor Service · {generated_at}",styles['Normal']),Spacer(1,8)]
    table_data=[["Servis","Tip","IP","Durum","Uptime","Ort. Latency","Maks. Latency","Incident"]]+[[s['name'],s['monitor_type'],s['resolved_ip'] or '-',s['last_status'] or '-',f"{s['uptime_percent']:.2f}%",f"{s['latency_avg']:.2f} ms",f"{s['latency_max']:.2f} ms",str(s['incidents'])] for s in services_payload]
    t=Table(table_data,repeatRows=1,colWidths=[55*mm,25*mm,35*mm,22*mm,25*mm,28*mm,28*mm,22*mm]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17304d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#aab7c4')),('FONTSIZE',(0,0),(-1,-1),7),('FONTNAME',(0,0),(-1,-1),'UMDejaVu'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f2f6fa')])]))
    story += [t,Spacer(1,10)]
    for s in services_payload:
        rows=s['check_rows'][-120:]
        if not rows:continue
        d=Drawing(780,175); vals=[float(r['latency_ms'] or 0) for r in rows]; mx=max(1,max(vals)); pts=[]
        for i,v in enumerate(vals): pts.extend([20+(740*i/max(1,len(vals)-1)),20+130*(v/mx)])
        d.add(Line(20,20,760,20,strokeColor=colors.HexColor('#9aa9b8')));d.add(Line(20,20,20,150,strokeColor=colors.HexColor('#9aa9b8')));d.add(PolyLine(pts,strokeColor=colors.HexColor('#2879b9'),strokeWidth=1.7));d.add(String(20,158,f"{s['name']} · Latency Trendi",fontSize=9));d.add(String(20,5,f"Max: {s['latency_max']:.2f} ms",fontSize=7))
        u=Drawing(780,145); uppts=[]
        for i,r in enumerate(rows): uppts.extend([20+(740*i/max(1,len(rows)-1)),25+(95 if r['status']=='UP' else 10)])
        u.add(Line(20,25,760,25,strokeColor=colors.HexColor('#9aa9b8')));u.add(Line(20,25,20,125,strokeColor=colors.HexColor('#9aa9b8')));u.add(PolyLine(uppts,strokeColor=colors.HexColor('#25c2a0'),strokeWidth=1.7));u.add(String(20,130,'Uptime / Status Trendi',fontSize=9))
        story += [KeepTogether([Paragraph(str(s['name']),styles['Heading3']),Paragraph(f"IP: {s['resolved_ip'] or '-'} · Uptime: {s['uptime_percent']:.2f}%",styles['Normal']),u,d]),Spacer(1,8)]
    doc.build(story);return b.getvalue()

@app.get("/api/export/{kind}/all")
def export_all(kind:str,db:Session=Depends(get_db)):
    services=db.query(Service).order_by(Service.id.asc()).all(); payload=[_export_service_payload(db,s,5000 if kind in {"json","csv","txt"} else 1000) for s in services]; now=datetime.utcnow(); filename=f"uptime-monitor-service-all.{kind}"
    if kind in {"html","pdf"}:
        if kind=="html":return Response(_html_report("Uptime Monitor Service — Tüm Servisler",payload,now).encode("utf-8"),media_type="text/html",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
        return Response(_pdf_report("Uptime Monitor Service — Tüm Servisler",payload,now),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
    if kind=="json":content=json.dumps({"generated_at":now.isoformat(),"services":payload},ensure_ascii=False,default=str,indent=2);media="application/json"
    elif kind in {"txt","csv"}:
        fields=["record_type","service_id","service_name","monitor_type","url","description","service_authorized_name","resolved_ip","status","time","http_status","latency_ms","certificate_days","error","category","level","message"]; lines=["|".join(fields)]
        for s in payload:
            lines.append("|".join(_safe_csv_value(v) for v in ["SERVICE",s["id"],s["name"],s["monitor_type"],s["url"],s.get("description",""),s.get("service_authorized_name",""),s["resolved_ip"],s["last_status"],s.get("last_check_at"),s.get("last_http_status"),s.get("last_latency_ms"),"","","","",s.get("last_error","")]))
            for r in s["check_rows"]:
                vals=["CHECK",s["id"],s["name"],s["monitor_type"],s["url"],s.get("description",""),s.get("service_authorized_name",""),s["resolved_ip"],r["status"],r["time"],r["http_status"],r["latency_ms"],r["certificate_days"],r["error"],"","",""]; lines.append("|".join(_safe_csv_value(v) for v in vals))
            for x in s.get("incidents_detail",[]):
                vals=["INCIDENT",s["id"],s["name"],s["monitor_type"],s["url"],s.get("description",""),s.get("service_authorized_name",""),s["resolved_ip"],x["status"],x["started_at"],"", "", "",x["reason"],"","",""]; lines.append("|".join(_safe_csv_value(v) for v in vals))
            for x in s.get("logs",[]):
                vals=["LOG",s["id"],s["name"],s["monitor_type"],s["url"],s.get("description",""),s.get("service_authorized_name",""),s["resolved_ip"],"",x["time"],"","","","",x["category"],x["level"],x["message"]]; lines.append("|".join(_safe_csv_value(v) for v in vals))
        content="\n".join(lines);media="text/plain" if kind=="txt" else "text/csv"
    elif kind=="xml":
        import html
        content="<services>"+"".join(f"<service id=\"{s['id']}\"><name>{html.escape(_safe_export_text(s['name']))}</name><type>{html.escape(_safe_export_text(s['monitor_type']))}</type><ip>{html.escape(_safe_export_text(s['resolved_ip']))}</ip><status>{html.escape(_safe_export_text(s['last_status']))}</status></service>" for s in payload)+"</services>";media="application/xml"
    else:raise HTTPException(400,"Desteklenmeyen export tipi")
    return Response(content.encode("utf-8"),media_type=media,headers={"Content-Disposition":f'attachment; filename="{filename}"'})

@app.get("/api/export/{kind}/{sid}")
def export(kind:str,sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s:raise HTTPException(404,"Servis bulunamadı")
    payload=_export_service_payload(db,s,5000); data=payload["check_rows"]; filename=f"uptime-monitor-service-{sid}.{kind}"; now=datetime.utcnow()
    if kind in {"html","pdf"}:
        if kind=="html":return Response(_html_report(f"Uptime Monitor Service — {s.name}",[payload],now).encode("utf-8"),media_type="text/html",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
        return Response(_pdf_report(f"Uptime Monitor Service — {s.name}",[payload],now),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
    if kind=="json":content=json.dumps({"service":{k:v for k,v in payload.items() if k!="check_rows"},"checks":data},ensure_ascii=False,default=str,indent=2);media="application/json"
    elif kind in {"txt","csv"}:
        fields=["time","status","http_status","latency_ms","certificate_days","error","headers","header_security","tls_security"]; lines=["|".join(fields)]
        for r in data:lines.append("|".join(_safe_csv_value(r.get(k)) for k in fields))
        lines.append("")
        lines.append("# SERVICE")
        for k in ["id","name","monitor_type","url","description","service_authorized_name","resolved_ip","last_status","last_latency_ms","last_error","last_http_status","last_check_at"]:
            lines.append(f"{k}|{_safe_csv_value(payload.get(k))}")
        lines.append("# INCIDENTS")
        for x in payload.get("incidents_detail",[]): lines.append("|".join(_safe_csv_value(x.get(k)) for k in ["id","status","started_at","resolved_at","duration","failure_count","reason"]))
        lines.append("# LOGS")
        for x in payload.get("logs",[]): lines.append("|".join(_safe_csv_value(x.get(k)) for k in ["id","time","level","category","message"]))
        content="\n".join(lines);media="text/plain" if kind=="txt" else "text/csv"
    elif kind=="xml":
        import html
        content="<checks>"+"".join("<check>"+"".join(f"<{k}>{html.escape(_safe_export_text(v))}</{k}>" for k,v in r.items())+"</check>" for r in data)+"</checks>";media="application/xml"
    else:raise HTTPException(400,"Desteklenmeyen export tipi")
    return Response(content.encode("utf-8"),media_type=media,headers={"Content-Disposition":f'attachment; filename="{filename}"'})

