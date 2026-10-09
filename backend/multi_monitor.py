"""
Multi-control monitoring engine.

A Service is an operational container. Each MonitorControl is an independent
probe with its own cadence, state machine, metrics and notification policies.
"""
import json
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import (
    Service, MonitorControl, CheckResult, Incident, EventLog,
    AppNotification, AppSettings, ServiceScreenshot, NotificationGroup
)
from .checker import check, tls_security_scan
from .notifier import render, notify

EVENTS = ("UP", "DOWN", "RECOVERY", "WARNING", "LATENCY")


def jd(value, default):
    try:
        return json.loads(value or json.dumps(default))
    except Exception:
        return default


def control_config(c):
    cfg = jd(c.config_json, {})
    adv = jd(c.advanced_options_json, {})
    # checker historically reads these from Service; proxying them keeps the
    # mature checker implementation reusable while state lives on the control.
    return cfg, adv


class ControlProxy:
    def __init__(self, service, control):
        self._service = service
        self._control = control
        cfg, adv = control_config(control)

        # Service-level attributes remain available to the existing checker.
        for k in (
            "id", "name", "description", "service_authorized_name",
            "maintenance", "maintenance_until", "dependency_ids",
            "dependency_notifications_enabled", "certificate_alert_days",
            "certificate_alert_enabled", "certificate_notification_group_ids",
            "certificate_notification_subject", "certificate_notification_message",
        ):
            setattr(self, k, getattr(service, k, None))

        self.control_id = control.id
        self.service_id = service.id
        self.monitor_type = control.control_type
        self.url = control.url or ""
        self.protocol_options = json.dumps(cfg, ensure_ascii=False)
        self.interval_seconds = control.interval_seconds
        self.failure_threshold = control.failure_threshold
        self.evaluation_window_minutes = control.evaluation_window_minutes
        self.status_ranges = control.status_ranges or "200-299"
        self.ignored_http_status_codes = control.ignored_http_status_codes or "401,403"

        self.content_monitoring = bool(adv.get("content_monitoring", False))
        self.content_mode = adv.get("content_mode", "contains")
        self.content_keywords = json.dumps(adv.get("content_keywords", []), ensure_ascii=False)
        # Security headers are collected automatically for every Web control;
        # the legacy manual expected-header editor is intentionally ignored.
        self.header_monitoring = self.monitor_type == "web" or bool(adv.get("header_monitoring", False))
        self.expected_headers = "{}"
        self.certificate_monitoring = bool(adv.get("certificate_monitoring", True))
        self.ignore_cert_errors = bool(adv.get("ignore_cert_errors", False))
        self.sla_enabled = bool(adv.get("sla_enabled", False))
        self.sla_target = float(adv.get("sla_target", 99.9) or 99.9)
        # These legacy certificate settings now resolve per-control first, then
        # fall back to the service-level value for migrated deployments.
        self.certificate_alert_enabled = bool(adv.get("certificate_alert_enabled", getattr(service, "certificate_alert_enabled", False)))
        self.certificate_alert_days = int(adv.get("certificate_alert_days", getattr(service, "certificate_alert_days", 30)) or 30)
        self.certificate_notification_group_ids = adv.get("certificate_notification_group_ids", getattr(service, "certificate_notification_group_ids", []))
        self.certificate_notification_subject = adv.get("certificate_notification_subject", getattr(service, "certificate_notification_subject", ""))
        self.certificate_notification_message = adv.get("certificate_notification_message", getattr(service, "certificate_notification_message", ""))

        # Notification/context compatibility.
        self.last_status = control.last_status
        self.last_latency_ms = control.last_latency_ms
        self.last_check_at = control.last_check_at
        self.consecutive_failures = control.consecutive_failures
        self.last_error = control.last_error
        self.last_http_status = control.last_http_status
        self.last_resolved_ip = control.last_resolved_ip
        self.last_cert_days = control.last_cert_days
        self.cert_subject = control.last_cert_subject
        self.cert_issuer = control.last_cert_issuer
        self.cert_expires_at = control.last_cert_expires_at
        self.notification_groups = []

    @property
    def service(self):
        return self._service


def _policy_groups(policy):
    return [g for g in policy.groups if g.enabled]


def _log(db, control, level, category, message):
    db.add(EventLog(
        service_id=control.service_id, control_id=control.id,
        level=level, category=category, message=message
    ))


def _app_notification(db, control, event_type, title, message, metadata=None):
    db.add(AppNotification(
        category="service",
        event_type=event_type,
        title=title,
        message=message,
        link=f"service-detail:{control.service_id}",
        service_id=control.service_id,
        control_id=control.id,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False, default=str),
    ))


def _send_policy(db, proxy, policy, result, previous_status, event_type):
    if not policy.enabled:
        return []
    now = datetime.utcnow()
    if policy.cooldown_minutes and policy.last_sent_at:
        if (now - policy.last_sent_at).total_seconds() < policy.cooldown_minutes * 60:
            return []

    extra = {
        "EVENT_TYPE": event_type,
        "STATUS": proxy.last_status,
        "PREVIOUS_STATUS": previous_status or "UNKNOWN",
        "EVENT_TIME": now,
        "REASON": result.get("error") or "",
        "ERROR_MESSAGE": result.get("error") or "",
        "LATENCY_MS": result.get("latency", 0),
        "HTTP_STATUS": result.get("code"),
        "RESOLVED_IP": result.get("resolved_ip") or proxy.last_resolved_ip or "N/A",
        "HOST_NAME": result.get("host") or proxy.url,
        "PORT": result.get("port") or "N/A",
    }
    subject = render(policy.subject or f"{event_type} | {{SERVICE_NAME}}", proxy, extra, db)
    body = render(policy.message or f"{event_type}: {{SERVICE_NAME}}", proxy, extra, db)
    results = notify(db, proxy, subject, body, _policy_groups(policy))
    if any(x[2] for x in results):
        policy.last_sent_at = now
    for group_name, channel, ok, msg in results:
        _log(db, proxy._control, "INFO" if ok else "ERROR", "NOTIFICATION",
             f"{event_type} · {channel.upper()} · {group_name} · {'başarılı' if ok else 'BAŞARISIZ'} · {msg}")
    return results


def _aggregate_service(db, service_id):
    service = db.get(Service, service_id)
    if not service:
        return
    controls = db.query(MonitorControl).filter(
        MonitorControl.service_id == service_id,
        MonitorControl.enabled.is_(True)
    ).all()
    if not controls:
        service.last_status = "UNKNOWN"
        return
    statuses = [c.last_status for c in controls]
    if "DOWN" in statuses:
        aggregate = "DOWN"
    elif "WARNING" in statuses:
        aggregate = "WARNING"
    elif all(x == "UP" for x in statuses):
        aggregate = "UP"
    else:
        aggregate = "UNKNOWN"
    service.last_status = aggregate
    service.last_latency_ms = max((c.last_latency_ms or 0 for c in controls), default=0)
    latest = max((c.last_check_at for c in controls if c.last_check_at), default=None)
    service.last_check_at = latest
    service.last_error = " | ".join(
        f"{c.name or c.control_type}: {c.last_error}"
        for c in controls if c.last_error
    )[:4000]
    service.last_http_status = next(
        (c.last_http_status for c in controls if c.last_http_status is not None), None
    )
    service.last_resolved_ip = next(
        (c.last_resolved_ip for c in controls if c.last_resolved_ip), ""
    )


def _capture_screenshot(db, service, control, result, status):
    if control.control_type != "web" or not result.get("effective_url") and not control.url:
        return
    settings=db.query(AppSettings).first()
    if not settings or not getattr(settings,"screenshot_on_http_failure",True):
        return
    code=result.get("code")
    def in_codes(value, spec):
        if value is None: return False
        try:
            for part in str(spec or "").split(","):
                part=part.strip()
                if not part: continue
                if "-" in part:
                    a,b=part.split("-",1)
                    if int(a)<=int(value)<=int(b): return True
                elif int(part)==int(value): return True
        except Exception:
            pass
        return False
    last=db.query(ServiceScreenshot).filter(
        ServiceScreenshot.control_id==control.id
    ).order_by(ServiceScreenshot.id.desc()).first()
    now=datetime.utcnow()
    due=not last or (now-last.captured_at).total_seconds() >= max(1,int(getattr(settings,"screenshot_interval_seconds",900) or 900))
    trigger=in_codes(code,getattr(settings,"screenshot_trigger_codes","404,500-599"))
    transition_down=status=="DOWN" and (not last or last.status!="DOWN")
    if not (due and (trigger or transition_down or bool(getattr(settings,"screenshot_routine_enabled",True)))):
        return
    try:
        from playwright.sync_api import sync_playwright
        import os,re
        url=result.get("effective_url") or control.url
        service_name=re.sub(r"[^a-zA-Z0-9_-]+","_",service.name).strip("_")[:80] or f"service-{service.id}"
        bucket="down" if status=="DOWN" else "routine"
        filename=f"{service_name}-control-{control.id}-{now.strftime('%Y%m%d-%H%M%S')}.png"
        folder=os.path.join("screenshots",service_name,bucket);os.makedirs(folder,exist_ok=True)
        path=os.path.join(folder,filename)
        timeout=max(5,int(getattr(settings,"screenshot_timeout_seconds",30) or 30))*1000
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page(viewport={"width":1440,"height":1000},device_scale_factor=1)
            page.goto(url,wait_until="domcontentloaded",timeout=timeout)
            wait=max(0,min(300,int(getattr(settings,"screenshot_wait_seconds",2) or 2)))
            if wait: page.wait_for_timeout(wait*1000)
            page.screenshot(path=path,full_page=True);browser.close()
        rel=f"{service_name}/{bucket}/{filename}"
        db.add(ServiceScreenshot(service_id=service.id,control_id=control.id,captured_at=now,
                                 reason=f"HTTP {code}" if trigger else ("DOWN geçişi" if transition_down else "Periyodik rutin"),
                                 status=status,http_status=code,path="/screenshots/"+rel,url=url))
    except Exception as exc:
        _log(db,control,"WARNING","SCREENSHOT",f"Ekran görüntüsü alınamadı: {exc}")

def _tls_scan_due(db, service, control, proxy, now):
    if control.control_type not in {"web", "ssl"} or not control.enabled:
        return
    adv = jd(control.advanced_options_json, {})
    if not bool(adv.get("tls_tracking_enabled", True)):
        return
    unit = str(adv.get("tls_scan_interval_unit") or "days")
    value = max(1, int(adv.get("tls_scan_interval_value") or 7))
    factors = {"hours":3600, "days":86400, "weeks":604800}
    seconds = value * factors.get(unit, 86400)
    last_at = adv.get("tls_last_scan_at")
    due = not last_at
    if last_at and not due:
        try: due = (now - datetime.fromisoformat(str(last_at).replace("Z", "").split("+")[0])).total_seconds() >= seconds
        except Exception: due = True
    if not due:
        return
    cfg = jd(control.config_json, {})
    if control.control_type == "ssl":
        host = cfg.get("host") or (control.url or "").replace("ssl://", "").split(":",1)[0]
        port = int(cfg.get("port") or 443)
    else:
        from urllib.parse import urlparse
        raw = control.url or cfg.get("url") or ""
        raw = raw if "://" in raw else "https://" + raw
        u = urlparse(raw)
        if u.scheme != "https":
            adv["tls_last_scan_at"] = now.isoformat()
            control.advanced_options_json = json.dumps(adv, ensure_ascii=False)
            return
        host, port = u.hostname, int(u.port or 443)
    if not host:
        return
    try:
        result = tls_security_scan(host, port, deep=False)
        adv["tls_last_scan_at"] = now.isoformat()
        adv["tls_last_scan_result"] = result
        control.advanced_options_json = json.dumps(adv, ensure_ascii=False, default=str)
        _log(db, control, "INFO", "TLS", f"TLS güvenlik taraması tamamlandı · {host}:{port} · {result.get('grade','-')} / {result.get('score',0)}")
    except Exception as exc:
        adv["tls_last_scan_at"] = now.isoformat()
        adv["tls_last_scan_error"] = str(exc)[:1000]
        control.advanced_options_json = json.dumps(adv, ensure_ascii=False)
        _log(db, control, "WARNING", "TLS", f"TLS güvenlik taraması başarısız: {exc}")

def run_control(control_id):
    db = SessionLocal()
    try:
        control = db.get(MonitorControl, control_id)
        if not control or not control.enabled:
            return
        service = db.get(Service, control.service_id)
        if not service or not service.enabled:
            return
        if service.maintenance and (
            not service.maintenance_until or service.maintenance_until > datetime.utcnow()
        ):
            return

        proxy = ControlProxy(service, control)
        old = control.last_status or "UNKNOWN"
        result = check(proxy)
        now = datetime.utcnow()
        _tls_scan_due(db, service, control, proxy, now)

        if result.get("status") == "UP":
            control.consecutive_failures = 0
            new = "UP"
        else:
            control.consecutive_failures = int(control.consecutive_failures or 0) + 1
            new = (
                "DOWN" if control.consecutive_failures >= max(1, control.failure_threshold)
                else "WARNING"
            )

        control.last_status = new
        control.last_check_at = now
        control.last_latency_ms = float(result.get("latency") or 0)
        control.last_error = result.get("error") or ""
        control.last_http_status = result.get("code")
        control.last_resolved_ip = result.get("resolved_ip") or control.last_resolved_ip or ""
        control.last_result_json = json.dumps(result, ensure_ascii=False, default=str)

        if result.get("cert"):
            subject, issuer, expires = result["cert"]
            control.last_cert_subject = subject or ""
            control.last_cert_issuer = issuer or ""
            control.last_cert_expires_at = expires
            control.last_cert_days = max(
                0, int((expires - now).total_seconds() / 86400)
            )

            # Certificate alerts are scoped to this Web/SSL control.
            adv = jd(control.advanced_options_json, {})
            alert_enabled = bool(adv.get("certificate_alert_enabled", False))
            alert_days = max(0, int(adv.get("certificate_alert_days", 30) or 30))
            sent = bool(adv.get("certificate_alert_sent", False))
            if alert_enabled and control.last_cert_days <= alert_days:
                if not sent:
                    group_ids=[int(x) for x in (adv.get("certificate_notification_group_ids") or []) if str(x).isdigit()]
                    groups=db.query(NotificationGroup).filter(NotificationGroup.id.in_(group_ids)).all() if group_ids else []
                    subject_text=adv.get("certificate_notification_subject") or "Sertifika uyarısı - {{SERVICE_NAME}}"
                    message_text=adv.get("certificate_notification_message") or "{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor."
                    extra={"STATUS":"CERTIFICATE WARNING","CERT_DAYS":control.last_cert_days,
                           "CERT_EXPIRY":control.last_cert_expires_at,"REASON":f"Sertifika {control.last_cert_days} gün içinde sona eriyor.",
                           "EVENT_TYPE":"CERTIFICATE_WARNING","EVENT_TIME":now}
                    subject_text=render(subject_text,proxy if 'proxy' in locals() else ControlProxy(service,control),extra,db)
                    message_text=render(message_text,proxy if 'proxy' in locals() else ControlProxy(service,control),extra,db)
                    if groups:
                        results=notify(db,proxy if 'proxy' in locals() else ControlProxy(service,control),subject_text,message_text,groups)
                        for gname,channel,ok,msg in results:
                            _log(db,control,"INFO" if ok else "ERROR","NOTIFICATION",
                                 f"CERTIFICATE WARNING · {channel.upper()} · {gname} · {'başarılı' if ok else 'BAŞARISIZ'} · {msg}")
                        adv["certificate_alert_sent"]=any(x[2] for x in results)
                    else:
                        adv["certificate_alert_sent"]=False
            elif control.last_cert_days > alert_days:
                adv["certificate_alert_sent"]=False
            control.advanced_options_json=json.dumps(adv,ensure_ascii=False)

        db.add(CheckResult(
            service_id=service.id,
            control_id=control.id,
            checked_at=now,
            status=new,
            http_status=result.get("code"),
            latency_ms=control.last_latency_ms,
            error=control.last_error,
            certificate_days=control.last_cert_days,
            rule_signature=control.last_rule_signature or "",
            headers_json=json.dumps(result.get("headers") or {}, ensure_ascii=False),
            header_security_json=json.dumps(result.get("header_security") or {}, ensure_ascii=False),
            tls_security_json=json.dumps(result.get("tls_security") or {}, ensure_ascii=False, default=str),
        ))

        _capture_screenshot(db, service, control, result, new)

        # Incident lifecycle is per control, not per service.
        if old != "DOWN" and new == "DOWN":
            db.add(Incident(
                service_id=service.id, control_id=control.id,
                reason=control.last_error, failure_count=control.consecutive_failures
            ))
            _log(db, control, "ERROR", "INCIDENT", f"Olay açıldı: {service.name} / {control.name or control.control_type}")
            _app_notification(
                db, control, "CONTROL_DOWN",
                f"Kontrol DOWN: {service.name} / {control.name or control.control_type}",
                control.last_error or "Kontrol erişilemiyor.",
                {"control_type": control.control_type, "status": "DOWN"}
            )

        if old == "DOWN" and new == "UP":
            incident = db.query(Incident).filter(
                Incident.control_id == control.id, Incident.status == "OPEN"
            ).order_by(Incident.id.desc()).first()
            if incident:
                incident.status = "RESOLVED"
                incident.resolved_at = now
                incident.downtime_seconds = max(
                    0, (now - incident.started_at).total_seconds()
                )
            _log(db, control, "INFO", "RECOVERY", f"Kontrol düzeldi: {service.name} / {control.name or control.control_type}")
            _app_notification(
                db, control, "CONTROL_RECOVERY",
                f"Kontrol RECOVERY: {service.name} / {control.name or control.control_type}",
                "Kontrol yeniden erişilebilir durumda.",
                {"control_type": control.control_type, "status": "UP"}
            )

        if old not in ("WARNING", "DOWN") and new == "WARNING":
            _app_notification(
                db, control, "CONTROL_WARNING",
                f"Kontrol WARNING: {service.name} / {control.name or control.control_type}",
                control.last_error or "Kontrol uyarı durumunda.",
                {"control_type": control.control_type, "status": "WARNING"}
            )

        # Explicit per-control event toggles.
        # Notification events are edge-triggered. A routine UP check must never
        # send another UP message; recovery is a single event when DOWN/WARNING
        # returns to UP. Likewise WARNING and DOWN fire only on entry into that
        # state. This keeps a service from generating one notification per poll.
        event = ("DOWN" if new == "DOWN" and old != "DOWN" else
                 "RECOVERY" if old in ("DOWN", "WARNING") and new == "UP" else
                 "WARNING" if new == "WARNING" and old != "WARNING" else None)
        proxy.last_status = new
        proxy.last_latency_ms = control.last_latency_ms
        proxy.last_check_at = now
        proxy.last_error = control.last_error
        proxy.last_http_status = control.last_http_status
        proxy.last_resolved_ip = control.last_resolved_ip
        proxy.last_cert_days = control.last_cert_days
        proxy.cert_subject = control.last_cert_subject
        proxy.cert_issuer = control.last_cert_issuer
        proxy.cert_expires_at = control.last_cert_expires_at
        for policy in control.notification_policies:
            if event and policy.event_type == event:
                _send_policy(db, proxy, policy, result, old, event)

        # LATENCY is a normal notification policy. Its threshold lives on the
        # policy itself rather than in a separate "advanced latency alarm".
        for policy in control.notification_policies:
            if policy.event_type == "LATENCY" and policy.enabled:
                threshold = max(1, int(getattr(policy, "threshold_ms", 1000) or 1000))
                if control.last_latency_ms >= threshold:
                    # Only emit when crossing into the alarm state; recovery is
                    # represented by the next latency event after it falls below.
                    alarm_key=f"LATENCY:{policy.id}"
                    result_meta=jd(control.last_result_json,{})
                    already=result_meta.get("_latency_policy_sent",{}).get(str(policy.id), False)
                    if not already:
                        _send_policy(db, proxy, policy, result, old, "LATENCY")
                        result_meta.setdefault("_latency_policy_sent",{})[str(policy.id)]=True
                        control.last_result_json=json.dumps(result_meta,ensure_ascii=False,default=str)
                else:
                    result_meta=jd(control.last_result_json,{})
                    sent=result_meta.get("_latency_policy_sent",{})
                    if str(policy.id) in sent:
                        sent.pop(str(policy.id),None)
                        result_meta["_latency_policy_sent"]=sent
                        control.last_result_json=json.dumps(result_meta,ensure_ascii=False,default=str)

        _aggregate_service(db, service.id)
        db.commit()
    except Exception as exc:
        db.rollback()
        try:
            c = db.get(MonitorControl, control_id)
            if c:
                db.add(EventLog(
                    service_id=c.service_id, control_id=c.id,
                    level="ERROR", category="CHECK",
                    message=f"Kontrol motoru hatası #{control_id}: {exc}"
                ))
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


class ControlScheduler:
    def __init__(self, pool, lock, running):
        self.pool, self.lock, self.running = pool, lock, running
        self.due = {}

    def tick(self):
        now = datetime.utcnow()
        db = SessionLocal()
        try:
            controls = db.query(MonitorControl).join(Service).filter(
                MonitorControl.enabled.is_(True), Service.enabled.is_(True)
            ).yield_per(500)
            for c in controls:
                due_at = self.due.get(c.id)
                if due_at and now < due_at:
                    continue
                with self.lock:
                    if c.id in self.running:
                        continue
                    self.running.add(c.id)
                future = self.pool.submit(run_control, c.id)
                future.add_done_callback(lambda _, cid=c.id: self.running.discard(cid))
                self.due[c.id] = now + timedelta(seconds=max(5, int(c.interval_seconds or 30)))
        finally:
            db.close()
