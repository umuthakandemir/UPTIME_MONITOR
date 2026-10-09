"""
Version 2 API for multi-control services.

The API is deliberately self-contained so integrations can use the same
contract as the web UI. Legacy /api/services endpoints remain untouched for
backward compatibility.
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .checker import check, tls_security_scan
from .multi_monitor import ControlProxy
from .cache import get_or_compute as cache_get_or_compute

from .database import get_db
from .models import (
    Service, MonitorControl, ControlNotificationPolicy, NotificationGroup,
    CheckResult, Incident, EventLog, AuditLog, ServiceScreenshot, AppNotification, AppSettings
)

router = APIRouter(prefix="/api/v2", tags=["Multi-control monitoring"])

CONTROL_TYPES = {
    "web": {
        "label": "Web HTTP(S)",
        "fields": [
            {"name":"url","type":"url","required":True,"label":"URL"},
            {"name":"status_ranges","type":"text","required":False,"label":"UP HTTP aralıkları","default":"200-299"},
            {"name":"ignored_http_status_codes","type":"text","required":False,"label":"İstisna kodları","default":"401,403"},
        ],
    },
    "ping": {
        "label": "Ping / ICMP",
        "fields": [
            {"name":"host","type":"text","required":True,"label":"Hedef IP / Hostname / URL","placeholder":"192.168.1.10 veya monitor.example.com"},
            {"name":"timeout","type":"number","required":False,"label":"Timeout (sn)","default":5},
        ],
    },
    "postgresql": {
        "label": "PostgreSQL",
        "fields": [
            {"name":"host","type":"text","required":True,"label":"Host"},
            {"name":"port","type":"number","required":True,"label":"Port","default":5432},
            {"name":"username","type":"text","required":True,"label":"Kullanıcı"},
            {"name":"password","type":"password","required":True,"label":"Parola","secret":True},
            {"name":"database","type":"text","required":False,"label":"Veritabanı"},
        ],
    },
    "tcp": {"label":"TCP", "fields":[
        {"name":"host","type":"text","required":True,"label":"Host / IP"},
        {"name":"port","type":"number","required":True,"label":"Port","default":80},
        {"name":"timeout","type":"number","required":False,"label":"Timeout (sn)","default":8},
    ]},
    "dns": {"label":"DNS", "fields":[
        {"name":"host","type":"text","required":True,"label":"Domain"},
        {"name":"expected","type":"text","required":False,"label":"Beklenen IP"},
    ]},
    "ssl": {"label":"SSL/TLS", "fields":[
        {"name":"host","type":"text","required":True,"label":"Host / Domain"},
        {"name":"port","type":"number","required":True,"label":"TLS Portu","default":443},
    ]},
    "smtp": {"label":"SMTP", "fields":[
        {"name":"host","type":"text","required":True,"label":"SMTP Host"},
        {"name":"port","type":"number","required":True,"label":"Port","default":587},
        {"name":"username","type":"text","required":False,"label":"Kullanıcı"},
        {"name":"password","type":"password","required":False,"label":"Parola","secret":True},
        {"name":"tls","type":"boolean","required":False,"label":"STARTTLS","default":True},
        {"name":"ssl","type":"boolean","required":False,"label":"SSL","default":False},
    ]},
    "mysql": {"label":"MySQL", "fields":[
        {"name":"host","type":"text","required":True,"label":"Host"},
        {"name":"port","type":"number","required":True,"label":"Port","default":3306},
        {"name":"username","type":"text","required":True,"label":"Kullanıcı"},
        {"name":"password","type":"password","required":True,"label":"Parola","secret":True},
        {"name":"database","type":"text","required":False,"label":"Veritabanı"},
    ]},
    "redis": {"label":"Redis", "fields":[
        {"name":"host","type":"text","required":True,"label":"Host"},
        {"name":"port","type":"number","required":True,"label":"Port","default":6379},
        {"name":"username","type":"text","required":False,"label":"Kullanıcı"},
        {"name":"password","type":"password","required":False,"label":"Parola","secret":True},
        {"name":"database","type":"number","required":False,"label":"DB","default":0},
    ]},
}

EVENTS = ("UP","DOWN","RECOVERY","WARNING","LATENCY")
SECRET_KEYS = {"password","token","secret","api_key","bot_token"}


def _jd(v, default):
    try:
        return json.loads(v or json.dumps(default))
    except Exception:
        return default


def _sanitize_config(config, reveal=False):
    out=dict(config or {})
    if not reveal:
        for k in list(out):
            if k.lower() in SECRET_KEYS:
                out[k]="********" if out[k] else ""
    return out


def _validate_ids(db, ids):
    vals=[]
    for raw in ids or []:
        try: vals.append(int(raw))
        except Exception: raise HTTPException(422, "Bildirim grubu ID'leri sayı olmalıdır.")
    if vals:
        found={g.id for g in db.query(NotificationGroup).filter(NotificationGroup.id.in_(vals)).all()}
        missing=set(vals)-found
        if missing: raise HTTPException(422, f"Geçersiz bildirim grubu ID: {sorted(missing)}")
    return list(dict.fromkeys(vals))


def _validate_control_payload(db, item, old=None):
    if not isinstance(item, dict):
        raise HTTPException(422, "Her control nesne olmalıdır.")
    typ=str(item.get("control_type") or "").lower().strip()
    typ={"http":"web", "https":"web", "postgres":"postgresql", "pgsql":"postgresql"}.get(typ, typ)
    if typ not in CONTROL_TYPES:
        raise HTTPException(422, f"Desteklenmeyen kontrol tipi: {typ}")
    config=dict(item.get("config") or {})
    old_config=_jd(old.config_json, {}) if old else {}
    for field in CONTROL_TYPES[typ]["fields"]:
        name=field["name"]
        value=config.get(name)
        if field.get("secret") and value == "********" and old and old_config.get(name):
            config[name]=old_config[name]
            value=config[name]
        if field.get("required") and value in (None,""):
            # On update, omitted secret keeps the existing secret.
            if field.get("secret") and old and old_config.get(name):
                config[name]=old_config[name]
            else:
                raise HTTPException(422, f"{CONTROL_TYPES[typ]['label']}: {field['label']} zorunludur.")
        if field.get("type")=="number" and value not in (None,""):
            try: config[name]=float(value) if "." in str(value) else int(value)
            except Exception: raise HTTPException(422, f"{name} sayı olmalıdır.")
    if typ=="web":
        url=str(item.get("url") or config.get("url") or "").strip()
        if not url: raise HTTPException(422,"Web URL zorunludur.")
        if not url.lower().startswith(("http://","https://")):
            url="https://"+url
        item["url"]=url
        config["url"]=url
    elif typ=="ping":
        item["url"]="ping://"+str(config.get("host","")).strip()
    else:
        item["url"]=str(item.get("url") or config.get("host") or "").strip()

    advanced = dict(item.get("advanced_options") or {})
    if typ in {"web", "ssl"}:
        advanced.setdefault("certificate_monitoring", True)
        advanced.setdefault("tls_tracking_enabled", True)
        advanced.setdefault("tls_scan_interval_unit", "days")
        advanced.setdefault("tls_scan_interval_value", 7)
    if typ == "web":
        # Header analysis is automatic; no manual expected-header list is required.
        advanced["header_monitoring"] = True
        advanced.pop("expected_headers", None)
    item["advanced_options"] = advanced
    event_cfg=item.get("notifications") or {}
    policies=[]
    for event in EVENTS:
        raw=dict(event_cfg.get(event) or {})
        if "group_ids" in raw:
            group_ids=raw.get("group_ids") or [g.id for g in db.query(NotificationGroup).filter(NotificationGroup.name.in_(["Güvenlik Bildirim Grubu","Sistem Bildirim Grubu"]), NotificationGroup.enabled.is_(True)).all()]
        else:
            auto_ids=[g.id for g in db.query(NotificationGroup).filter(NotificationGroup.auto_add_new_services.is_(True), NotificationGroup.enabled.is_(True)).all()]
            if not auto_ids:
                app_settings=db.query(AppSettings).first()
                default_id=int(app_settings.default_notification_group_id) if app_settings and app_settings.default_notification_group_id else 0
                default_group=db.get(NotificationGroup,default_id) if default_id else None
                auto_ids=[default_group.id] if default_group and default_group.enabled else []
            group_ids=auto_ids
        policies.append({
            "event_type":event,
            "enabled":bool(raw.get("enabled", False)),
            "subject":str(raw.get("subject") or ""),
            "message":str(raw.get("message") or ""),
            "cooldown_minutes":max(0,int(raw.get("cooldown_minutes") or 0)),
            "threshold_ms":max(1,int(raw.get("threshold_ms") or 1000)),
            "group_ids":_validate_ids(db, group_ids),
        })
    return typ, config, policies, item


def _control_dict(c, include_secrets=False):
    policies={}
    for p in c.notification_policies:
        policies[p.event_type]={
            "enabled":p.enabled,
            "subject":p.subject or "",
            "message":p.message or "",
            "cooldown_minutes":p.cooldown_minutes or 0,
            "threshold_ms":p.threshold_ms or 1000,
            "group_ids":[g.id for g in p.groups],
        }
    cfg=_jd(c.config_json,{})
    return {
        "id":c.id,"name":c.name,"control_type":c.control_type,
        "label":CONTROL_TYPES.get(c.control_type,{}).get("label",c.control_type),
        "enabled":c.enabled,"url":c.url,
        "interval_seconds":c.interval_seconds,
        "failure_threshold":c.failure_threshold,
        "evaluation_window_minutes":c.evaluation_window_minutes,
        "status_ranges":c.status_ranges,
        "ignored_http_status_codes":c.ignored_http_status_codes,
        "config":_sanitize_config(cfg,include_secrets),
        "advanced_options":_jd(c.advanced_options_json,{}),
        "state":{"status":c.last_status,"latency_ms":c.last_latency_ms,
                 "last_check_at":c.last_check_at,"error":c.last_error,
                 "http_status":c.last_http_status,"resolved_ip":c.last_resolved_ip,
                 "certificate_days":c.last_cert_days},
        "notifications":policies,
    }


def _service_dict(s, include_secrets=False):
    controls=sorted(s.monitor_controls,key=lambda x:x.id)
    statuses=[c.last_status for c in controls if c.enabled]
    aggregate="DOWN" if "DOWN" in statuses else "WARNING" if "WARNING" in statuses else "UP" if statuses and all(x=="UP" for x in statuses) else "UNKNOWN"
    return {
        "id":s.id,"name":s.name,"description":s.description or "",
        "service_authorized_name":s.service_authorized_name or "",
        "enabled":s.enabled,"maintenance":s.maintenance,
        "maintenance_until":s.maintenance_until,"maintenance_reason":s.maintenance_reason or "",
        "dependency_ids":_jd(s.dependency_ids,[]) if isinstance(s.dependency_ids,str) else (s.dependency_ids or []),
        "dependency_notifications_enabled":bool(s.dependency_notifications_enabled),
        "status":aggregate,"control_count":len(controls),
        "controls":[_control_dict(c,include_secrets) for c in controls],
    }


def _dashboard_history(db, period, days):
    """Dashboard'un AĞIR ve geçmişe dönük kısmı (zaman serisi, HTTP kod dağılımı, olaylar).

    Yalnızca gereken sütunlar okunur (ORM nesnesi oluşturulmaz). Bu bölüm önbelleğe
    alınır; canlı durum (UP/DOWN sayıları, öne çıkan servisler) burada YOKTUR.
    """
    now = datetime.utcnow()
    since = now - timedelta(days=days)
    control_ids = {cid for (cid,) in db.query(MonitorControl.id).filter(MonitorControl.enabled.is_(True)).all()}
    rows = (db.query(CheckResult.control_id, CheckResult.checked_at, CheckResult.status,
                     CheckResult.latency_ms, CheckResult.http_status)
            .filter(CheckResult.checked_at >= since).order_by(CheckResult.checked_at.asc()).all())
    rows = [r for r in rows if r.control_id in control_ids]

    # Keep the series readable: hourly for 24h, daily for 7/30d.
    bucket_seconds = 3600 if period == "24h" else 86400
    def bucket(dt):
        ts = int((dt - since).total_seconds() // bucket_seconds) * bucket_seconds
        return since + timedelta(seconds=max(0, ts))
    buckets = defaultdict(list)
    for r in rows:
        buckets[bucket(r.checked_at)].append(r)
    count = int((days*86400 + bucket_seconds - 1) // bucket_seconds)
    timeline=[]
    for i in range(count):
        start=since + timedelta(seconds=i*bucket_seconds)
        rr=buckets.get(start,[])
        total=len(rr); up=sum(x.status=="UP" for x in rr); down=sum(x.status=="DOWN" for x in rr); warning=sum(x.status=="WARNING" for x in rr)
        lat=[float(x.latency_ms or 0) for x in rr]
        timeline.append({
            "time":start,"label":start.strftime("%H:%M" if period=="24h" else "%d %b"),
            "uptime":round(up/total*100,2) if total else None,
            "avg_latency":round(sum(lat)/len(lat),2) if lat else 0,
            "max_latency":round(max(lat),2) if lat else 0,
            "checks":total,"up":up,"down":down,"warning":warning,
        })
    code_counts=defaultdict(int)
    # Aggregate latency in one pass; avoid O(controls * check-history) scans.
    latency_totals = defaultdict(lambda: [0.0, 0])
    for row in rows:
        if row.http_status is not None: code_counts[str(row.http_status)]+=1
        if row.latency_ms is not None:
            acc = latency_totals[str(row.control_id)]
            acc[0] += float(row.latency_ms or 0)
            acc[1] += 1
    incidents=db.query(Incident.started_at, Incident.downtime_seconds).filter(Incident.started_at>=since).all()
    incident_buckets=defaultdict(lambda:{"count":0,"downtime":0})
    for inc in incidents:
        b=bucket(inc.started_at); incident_buckets[b]["count"]+=1; incident_buckets[b]["downtime"]+=float(inc.downtime_seconds or 0)
    for t in timeline:
        x=incident_buckets.get(t["time"],{"count":0,"downtime":0}); t["incidents"]=x["count"];t["downtime_seconds"]=round(x["downtime"],2)
    total_checks=len(rows); total_up=sum(r.status=="UP" for r in rows)
    return {
        "from":since,"to":now,"timeline":timeline,
        "http_status_counts":dict(sorted(code_counts.items(), key=lambda x:int(x[0]))),
        "latency_totals":{k:[v[0],v[1]] for k,v in latency_totals.items()},
        "checks":total_checks,
        "uptime_percent":round(total_up/total_checks*100,2) if total_checks else 0,
        "avg_latency_ms":round(sum(float(r.latency_ms or 0) for r in rows)/len(rows),2) if rows else 0,
        "incidents":len(incidents),
        "downtime_seconds":round(sum(float(i.downtime_seconds or 0) for i in incidents),2),
    }


def _aggregate_status(controls):
    statuses=[c.last_status for c in controls if c.enabled]
    return "DOWN" if "DOWN" in statuses else "WARNING" if "WARNING" in statuses else "UP" if statuses and all(x=="UP" for x in statuses) else "UNKNOWN"


@router.get("/dashboard")
def dashboard_analytics(period:str="24h", db:Session=Depends(get_db)):
    """Dashboard için zaman serisi + dağılım verilerini tek çağrıda üretir.

    Geçmiş analitik (ağır) Redis'te 60 sn tutulur; servis/kontrol eklenip silindiğinde veya
    izleme alanları değiştiğinde anında geçersiz olur. Canlı durum her istekte veritabanından
    taze okunur, böylece UP/DOWN sayıları asla bayat görünmez.
    """
    period = period if period in {"24h", "7d", "30d"} else "24h"
    days = {"24h": 1, "7d": 7, "30d": 30}[period]
    history, cache_meta = cache_get_or_compute("analytics", f"v2-dashboard:{period}", 60,
                                               lambda: _dashboard_history(db, period, days))

    # --- Canlı kısım: her istekte taze ---
    services = (db.query(Service).filter(Service.enabled.is_(True))
                .options(selectinload(Service.monitor_controls)).all())
    all_enabled_controls = db.query(MonitorControl).filter(MonitorControl.enabled.is_(True)).all()
    service_by_id = {s.id:s for s in services}
    status_by_service = {svc.id:_aggregate_status(svc.monitor_controls) for svc in services}
    status_counts={"UP":0,"WARNING":0,"DOWN":0,"UNKNOWN":0}
    for svc in services:
        status_counts[status_by_service[svc.id]] = status_counts.get(status_by_service[svc.id], 0) + 1
    type_counts=defaultdict(int)
    for c in all_enabled_controls: type_counts[c.control_type]+=1
    latency_totals = history["latency_totals"]
    top_latency=[]
    for c in all_enabled_controls:
        total_latency, samples = latency_totals.get(str(c.id), [0.0, 0])
        avg = total_latency / samples if samples else float(c.last_latency_ms or 0)
        svc = service_by_id.get(c.service_id)
        top_latency.append({"id":c.id,"service_id":c.service_id,
            "name":f"{svc.name if svc else '-'} / {c.name}",
            "latency":round(avg,2),"type":c.control_type})
    top_latency=sorted(top_latency,key=lambda x:x["latency"],reverse=True)[:8]
    tls_grades=[]
    for c in all_enabled_controls:
        adv=_jd(c.advanced_options_json,{})
        tls=adv.get("tls_last_scan_result") or {}
        if tls:
            tls_grades.append({"grade":tls.get("grade") or "Yok","score":tls.get("score",0),"control_id":c.id})
    # Yalnızca öne çıkan 8 servisin tam ayrıntısı üretilir; tüm servisler için _service_dict çağrılmaz.
    featured=sorted(services,key=lambda x:(
        {"DOWN":0,"WARNING":1,"UP":2,"UNKNOWN":3}.get(status_by_service[x.id],9),
        -max((float(c.last_latency_ms or 0) for c in x.monitor_controls if c.enabled), default=0)
    ))[:8]
    return {
        "period":period,"from":history["from"],"to":history["to"],"summary":{"services":len(services),"controls":len(all_enabled_controls),"checks":history["checks"],
            "up":status_counts.get("UP",0),"warning":status_counts.get("WARNING",0),"down":status_counts.get("DOWN",0),
            "uptime_percent":history["uptime_percent"],"avg_latency_ms":history["avg_latency_ms"],
            "incidents":history["incidents"],"downtime_seconds":history["downtime_seconds"]},
        "status_counts":status_counts,"type_counts":dict(type_counts),"http_status_counts":history["http_status_counts"],
        "timeline":history["timeline"],"top_latency":top_latency,"tls_grades":tls_grades,
        "featured_services":[_service_dict(s) for s in featured],
        "cache":cache_meta,
    }


@router.get("/control-types")
def control_types():
    return {"items":CONTROL_TYPES,"events":list(EVENTS)}


@router.get("/notification-fields")
def notification_fields():
    from .notifier import NOTIFICATION_FIELDS
    return {"items":NOTIFICATION_FIELDS}


@router.get("/services")
def list_services(
    q: str = "", page: int = 1, page_size: int = 20, status: str = "ALL",
    sort: str = "name_az", db: Session = Depends(get_db)
):
    """Paged service listing. Do not hydrate every service/control for each page."""
    from sqlalchemy.orm import selectinload
    from sqlalchemy import func

    page = max(1, page)
    page_size = max(1, min(page_size, 250))
    q = q.strip()[:100]
    base = db.query(Service.id).outerjoin(
        MonitorControl, MonitorControl.service_id == Service.id
    )
    if q:
        like = f"%{q}%"
        base = base.filter(or_(
            Service.name.ilike(like), Service.description.ilike(like),
            Service.monitor_type.ilike(like), Service.url.ilike(like),
            Service.service_authorized_name.ilike(like),
            Service.last_resolved_ip.ilike(like), Service.last_error.ilike(like),
            MonitorControl.name.ilike(like), MonitorControl.control_type.ilike(like),
            MonitorControl.url.ilike(like), MonitorControl.last_resolved_ip.ilike(like),
            MonitorControl.last_error.ilike(like), MonitorControl.config_json.ilike(like),
            MonitorControl.advanced_options_json.ilike(like),
        ))
    ids_query = base.distinct()

    # For the default/name sort, pagination and count happen in PostgreSQL.
    # Status filtering and computed status sorts need the aggregate status and
    # retain the compatibility path below.
    if status.upper() == "ALL" and sort in {"name_az", "name_za", "", None}:
        total = ids_query.count()
        direction = Service.name.desc() if sort == "name_za" else Service.name.asc()
        id_subquery = ids_query.subquery()
        ids = [row[0] for row in db.query(Service.id)
               .join(id_subquery, Service.id == id_subquery.c.id)
               .order_by(direction, Service.id.asc())
               .offset((page - 1) * page_size).limit(page_size).all()]
        if not ids:
            items = []
        else:
            services = (db.query(Service)
                .options(selectinload(Service.monitor_controls)
                         .selectinload(MonitorControl.notification_policies)
                         .selectinload(ControlNotificationPolicy.groups))
                .filter(Service.id.in_(ids)).all())
            by_id = {obj.id: obj for obj in services}
            items = [_service_dict(by_id[sid]) for sid in ids if sid in by_id]
        pages = max(1, (total + page_size - 1) // page_size)
        return {"items": items, "page": page, "page_size": page_size, "total": total, "pages": pages}

    # Compatibility path for status-dependent sorting/filtering.
    services = db.query(Service).options(
        selectinload(Service.monitor_controls)
        .selectinload(MonitorControl.notification_policies)
        .selectinload(ControlNotificationPolicy.groups)
    ).filter(Service.id.in_(ids_query)).all()
    data = [_service_dict(obj) for obj in services]
    if status.upper() != "ALL":
        data = [item for item in data if item["status"] == status.upper()]
    status_order = {"DOWN": 0, "UP": 1, "WARNING": 2, "UNKNOWN": 3}
    if sort == "name_za":
        data.sort(key=lambda x: str(x.get("name") or "").lower(), reverse=True)
    elif sort in {"up_down_warning", "down_up_warning"}:
        data.sort(key=lambda x: (status_order.get(x.get("status"), 9), str(x.get("name") or "").lower()))
    elif sort == "warning_down_up":
        data.sort(key=lambda x: ({"WARNING": 0, "DOWN": 1, "UP": 2, "UNKNOWN": 3}.get(x.get("status"), 9), str(x.get("name") or "").lower()))
    else:
        data.sort(key=lambda x: str(x.get("name") or "").lower())
    total = len(data)
    pages = max(1, (total + page_size - 1) // page_size)
    return {"items": data[(page - 1) * page_size:page * page_size],
            "page": page, "page_size": page_size, "total": total, "pages": pages}



@router.get("/services/{sid}/controls/{cid}/preview")
def preview_control(sid:int,cid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    c=db.get(MonitorControl,cid)
    if not s or not c or c.service_id != sid:
        raise HTTPException(404,"Kontrol bulunamadı")
    result=check(ControlProxy(s,c))
    return {
        "service_id":sid,"control_id":cid,"service":s.name,"control":c.name,
        "control_type":c.control_type,"status":result.get("status","DOWN"),
        "latency_ms":result.get("latency",0),"http_status":result.get("code"),
        "resolved_ip":result.get("resolved_ip") or "","host":result.get("host"),
        "port":result.get("port"),"error":result.get("error") or "",
        "certificate":result.get("cert_details"),"effective_url":result.get("effective_url")
    }

@router.post("/services/{sid}/controls/{cid}/tls-scan")
def tls_scan_control(sid:int,cid:int,db:Session=Depends(get_db)):
    c=db.get(MonitorControl,cid); s=db.get(Service,sid)
    if not s or not c or c.service_id!=sid: raise HTTPException(404,"Kontrol bulunamadı")
    if c.control_type not in {"web","ssl"}: raise HTTPException(400,"TLS taraması yalnızca Web/SSL kontrollerinde kullanılabilir.")
    from urllib.parse import urlparse
    cfg=_jd(c.config_json,{})
    if c.control_type=="ssl": host=cfg.get("host") or c.url; port=int(cfg.get("port") or 443)
    else:
        raw=c.url or cfg.get("url") or ""; raw=raw if "://" in raw else "https://"+raw; u=urlparse(raw)
        host=u.hostname;port=int(u.port or 443)
        if u.scheme not in {"https","http"}: raise HTTPException(400,"Yalnızca HTTP/HTTPS web hedefleri desteklenir.")
        # TLS assessment always probes the TLS port; a plain HTTP URL does not disable SSL scanning.
    if not host: raise HTTPException(400,"TLS host bulunamadı.")
    result=tls_security_scan(host,port,deep=True)
    adv=_jd(c.advanced_options_json,{ });adv["tls_last_scan_at"]=datetime.utcnow().isoformat();adv["tls_last_scan_result"]=result;c.advanced_options_json=json.dumps(adv,ensure_ascii=False,default=str);db.commit()
    return {"ok":True,"control_id":cid,"tls_security":result}

@router.get("/services/{sid}/detail")
def get_service_detail(sid:int, db:Session=Depends(get_db)):
    """Full multi-control detail view; preserves the legacy detail information per control."""
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    controls=sorted(s.monitor_controls,key=lambda x:x.id)
    out=[]
    for c in controls:
        checks=db.query(CheckResult).filter(CheckResult.control_id==c.id).order_by(CheckResult.checked_at.desc()).limit(120).all()
        incidents=db.query(Incident).filter(Incident.control_id==c.id).order_by(Incident.id.desc()).limit(100).all()
        shots=db.query(ServiceScreenshot).filter(ServiceScreenshot.control_id==c.id).order_by(ServiceScreenshot.captured_at.desc()).limit(24).all()
        last=checks[0] if checks else None
        adv=_jd(c.advanced_options_json,{})
        cert={
            "subject":c.last_cert_subject or "",
            "issuer":c.last_cert_issuer or "",
            "expires_at":c.last_cert_expires_at,
            "remaining_days":c.last_cert_days,
            "monitoring":bool(adv.get("certificate_monitoring",False)),
            "alert_enabled":bool(adv.get("certificate_alert_enabled",False)),
            "alert_days":int(adv.get("certificate_alert_days",30) or 30),
            "notification_group_ids":adv.get("certificate_notification_group_ids",[]),
            "notification_subject":adv.get("certificate_notification_subject",""),
            "notification_message":adv.get("certificate_notification_message",""),
        }
        out.append({
            "id":c.id,"name":c.name,"type":c.control_type,
            "label":CONTROL_TYPES.get(c.control_type,{}).get("label",c.control_type),
            "url":c.url,"config":_sanitize_config(_jd(c.config_json,{})),
            "advanced_options":adv,"state":_control_dict(c)["state"],
            "notifications":_control_dict(c)["notifications"],
            "certificate":cert,
            "header_security":_jd(last.header_security_json,{}) if last else {},
            "tls_security":adv.get("tls_last_scan_result") or (_jd(last.tls_security_json,{}) if last else {}),
            "checks":[{"time":x.checked_at,"status":x.status,"latency":x.latency_ms,"code":x.http_status,
                       "error":x.error,"certificate_days":x.certificate_days,
                       "headers":_jd(x.headers_json,{}),"header_security":_jd(x.header_security_json,{}),
                       "tls_security":_jd(x.tls_security_json,{})} for x in reversed(checks)],
            "incidents":[{"id":x.id,"status":x.status,"started":x.started_at,"resolved":x.resolved_at,
                          "duration":x.downtime_seconds,"reason":x.reason} for x in incidents],
            "screenshots":[{"id":x.id,"captured_at":x.captured_at,"reason":x.reason,"status":x.status,
                            "http_status":x.http_status,"path":x.path,"url":x.url} for x in shots],
        })
    service=_service_dict(s)
    return {"service":service,"controls":out}

@router.get("/services/{sid}")
def get_service(sid:int, db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    return {"service":_service_dict(s)}


@router.post("/services")
def create_service(payload:dict, request:Request, db:Session=Depends(get_db)):
    name=str(payload.get("name") or "").strip()
    controls=payload.get("controls") or []
    if not name: raise HTTPException(422,"Servis adı zorunludur.")
    if not controls: raise HTTPException(422,"En az bir kontrol tipi eklenmelidir.")
    if len(name)>200 or len(controls)>30: raise HTTPException(422,"Geçersiz servis boyutu.")
    maintenance_until=None
    if payload.get("maintenance_until"):
        try: maintenance_until=datetime.fromisoformat(str(payload.get("maintenance_until")).replace("Z","+00:00")).replace(tzinfo=None)
        except ValueError: raise HTTPException(422,"maintenance_until geçerli ISO-8601 olmalıdır.")
    try: dependency_ids=json.dumps([int(x) for x in (payload.get("dependency_ids") or [])])
    except Exception: raise HTTPException(422,"dependency_ids sayı listesi olmalıdır.")
    s=Service(name=name,description=str(payload.get("description") or "")[:10000],
              service_authorized_name=str(payload.get("service_authorized_name") or "")[:200],
              enabled=bool(payload.get("enabled",True)),
              maintenance=bool(payload.get("maintenance",False)),
              maintenance_until=maintenance_until,
              maintenance_reason=str(payload.get("maintenance_reason") or "")[:500],
              dependency_ids=dependency_ids,
              dependency_notifications_enabled=bool(payload.get("dependency_notifications_enabled",False)))
    db.add(s); db.flush()
    for item in controls:
        typ,config,policies,item=_validate_control_payload(db,item)
        c=MonitorControl(
            service_id=s.id,name=str(item.get("name") or CONTROL_TYPES[typ]["label"])[:200],
            control_type=typ,enabled=bool(item.get("enabled",True)),
            url=str(item.get("url") or ""),interval_seconds=max(5,min(86400,int(item.get("interval_seconds",30)))),
            failure_threshold=max(1,min(100,int(item.get("failure_threshold",3)))),
            evaluation_window_minutes=max(1,min(1440,int(item.get("evaluation_window_minutes",5)))),
            status_ranges=str(item.get("status_ranges") or "200-299")[:200],
            ignored_http_status_codes=str(item.get("ignored_http_status_codes") or "401,403")[:200],
            config_json=json.dumps(config,ensure_ascii=False),
            advanced_options_json=json.dumps(item.get("advanced_options") or {},ensure_ascii=False),
            description=str(item.get("description") or "")[:5000],
        )
        db.add(c); db.flush()
        for p in policies:
            policy=ControlNotificationPolicy(
                control_id=c.id,event_type=p["event_type"],enabled=p["enabled"],
                subject=p["subject"][:500],message=p["message"][:50000],
                cooldown_minutes=p["cooldown_minutes"],
                threshold_ms=p["threshold_ms"]
            )
            policy.groups=[db.get(NotificationGroup,gid) for gid in p["group_ids"]]
            db.add(policy)
    db.add(AuditLog(actor=getattr(request.state,"user_username","api"),action="MULTI_SERVICE_CREATE",service_id=s.id,
                    details=json.dumps({"control_count":len(controls)},ensure_ascii=False)))
    try:
        db.commit(); db.refresh(s)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, f"Servis kaydedilemedi: {str(exc.orig)[:300]}")
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(500, f"Servis kaydedilirken veritabanı hatası oluştu: {str(exc)[:300]}")
    return {"service":_service_dict(s)}


@router.put("/services/{sid}")
def update_service(sid:int,payload:dict,request:Request,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    controls=payload.get("controls")
    if controls is None: raise HTTPException(422,"controls alanı zorunludur.")
    if not controls or len(controls)>30: raise HTTPException(422,"Servis en az bir kontrol içermelidir.")
    s.name=str(payload.get("name",s.name)).strip()[:200]
    s.description=str(payload.get("description",s.description or ""))[:10000]
    s.service_authorized_name=str(payload.get("service_authorized_name",s.service_authorized_name or ""))[:200]
    s.enabled=bool(payload.get("enabled",s.enabled))
    s.maintenance=bool(payload.get("maintenance",s.maintenance))
    s.maintenance_reason=str(payload.get("maintenance_reason",s.maintenance_reason or ""))[:500]
    dep_ids=payload.get("dependency_ids")
    if dep_ids is not None:
        try: s.dependency_ids=json.dumps([int(x) for x in dep_ids])
        except Exception: raise HTTPException(422,"dependency_ids sayı listesi olmalıdır.")
    s.dependency_notifications_enabled=bool(payload.get("dependency_notifications_enabled",s.dependency_notifications_enabled))
    raw_until=payload.get("maintenance_until",s.maintenance_until)
    if isinstance(raw_until,str) and raw_until:
        try: s.maintenance_until=datetime.fromisoformat(raw_until.replace("Z","+00:00")).replace(tzinfo=None)
        except ValueError: raise HTTPException(422,"maintenance_until geçerli ISO-8601 olmalıdır.")
    elif raw_until in (None,""):
        s.maintenance_until=None

    existing={c.id:c for c in s.monitor_controls}
    keep=set()
    for item in controls:
        raw_id=item.get("id")
        try: cid=int(raw_id) if raw_id not in (None, "", 0, "0") else None
        except (TypeError, ValueError): raise HTTPException(422,"Kontrol ID geçersiz.")
        old=existing.get(cid) if cid else None
        if cid and old is None: raise HTTPException(422,"Kontrol bu servise ait değil.")
        typ,config,policies,item=_validate_control_payload(db,item,old)
        if old:
            c=old; keep.add(c.id)
        else:
            c=MonitorControl(service_id=s.id)
            db.add(c)
        c.name=str(item.get("name") or CONTROL_TYPES[typ]["label"])[:200]
        c.control_type=typ;c.enabled=bool(item.get("enabled",True))
        c.url=str(item.get("url") or "")
        c.interval_seconds=max(5,min(86400,int(item.get("interval_seconds",30))))
        c.failure_threshold=max(1,min(100,int(item.get("failure_threshold",3))))
        c.evaluation_window_minutes=max(1,min(1440,int(item.get("evaluation_window_minutes",5))))
        c.status_ranges=str(item.get("status_ranges") or "200-299")[:200]
        c.ignored_http_status_codes=str(item.get("ignored_http_status_codes") or "401,403")[:200]
        c.config_json=json.dumps(config,ensure_ascii=False)
        c.advanced_options_json=json.dumps(item.get("advanced_options") or {},ensure_ascii=False)
        c.description=str(item.get("description") or "")[:5000]
        if c.id:
            for p in list(c.notification_policies): db.delete(p)
        db.flush()
        for p in policies:
            policy=ControlNotificationPolicy(
                control_id=c.id,event_type=p["event_type"],enabled=p["enabled"],
                subject=p["subject"][:500],message=p["message"][:50000],
                cooldown_minutes=p["cooldown_minutes"],
                threshold_ms=p["threshold_ms"]
            )
            policy.groups=[db.get(NotificationGroup,gid) for gid in p["group_ids"]]
            db.add(policy)
        keep.add(c.id)
    for cid,c in existing.items():
        if cid not in keep: db.delete(c)
    db.add(AuditLog(actor=getattr(request.state,"user_username","api"),action="MULTI_SERVICE_UPDATE",service_id=s.id,
                    details=json.dumps({"control_count":len(controls)},ensure_ascii=False)))
    try:
        db.commit(); db.refresh(s)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, f"Servis güncellenemedi: {str(exc.orig)[:300]}")
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(500, f"Servis güncellenirken veritabanı hatası oluştu: {str(exc)[:300]}")
    return {"service":_service_dict(s)}




@router.delete("/services/{sid}")
def delete_service_v2(sid:int,request:Request,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    controls=db.query(MonitorControl).filter_by(service_id=sid).all()
    cids=[c.id for c in controls]
    if cids:
        db.query(ControlNotificationPolicy).filter(ControlNotificationPolicy.control_id.in_(cids)).delete(synchronize_session=False)
    for model in (CheckResult,Incident,EventLog,AuditLog,ServiceScreenshot,AppNotification):
        db.query(model).filter(model.service_id==sid).delete(synchronize_session=False)
    for c in controls: db.delete(c)
    db.add(AuditLog(actor=getattr(request.state,"user_username","api"),action="MULTI_SERVICE_DELETE",service_id=sid,details=json.dumps({"control_ids":cids},ensure_ascii=False)))
    db.delete(s)
    db.commit()
    return {"ok":True,"deleted_id":sid}

@router.get("/services/{sid}/controls/{cid}/metrics")
def control_metrics(sid:int,cid:int,days:int=7,page:int=1,page_size:int=500,db:Session=Depends(get_db)):
    c=db.get(MonitorControl,cid)
    if not c or c.service_id!=sid: raise HTTPException(404,"Kontrol bulunamadı")
    days=max(1,min(days,90)); page=max(1,page); page_size=max(1,min(page_size,2000))
    since=datetime.utcnow()-timedelta(days=days)
    q=db.query(CheckResult).filter(CheckResult.service_id==sid,CheckResult.control_id==cid,CheckResult.checked_at>=since)
    total=q.count()
    rows=q.order_by(CheckResult.checked_at.asc()).offset((page-1)*page_size).limit(page_size).all()
    return {
        "control":_control_dict(c),
        "range":{"days":days,"from":since,"to":datetime.utcnow()},
        "summary":{
            "checks":total,
            "up":q.filter(CheckResult.status=="UP").count(),
            "down":q.filter(CheckResult.status=="DOWN").count(),
            "warning":q.filter(CheckResult.status=="WARNING").count(),
            "avg_latency_ms":round(sum((r.latency_ms or 0) for r in rows)/len(rows),2) if rows else 0,
        },
        "items":[{"id":r.id,"time":r.checked_at,"status":r.status,"latency_ms":r.latency_ms,
                  "http_status":r.http_status,"error":r.error,"certificate_days":r.certificate_days}
                 for r in rows],
        "page":page,"page_size":page_size,"total":total,
        "pages":max(1,(total+page_size-1)//page_size)
    }


@router.get("/services/{sid}/events")
def service_events(sid:int,control_id:int|None=None,page:int=1,page_size:int=100,db:Session=Depends(get_db)):
    if not db.get(Service,sid): raise HTTPException(404,"Servis bulunamadı")
    page=max(1,page);page_size=max(1,min(page_size,500))
    q=db.query(EventLog).filter(EventLog.service_id==sid)
    if control_id:q=q.filter(EventLog.control_id==control_id)
    total=q.count(); rows=q.order_by(EventLog.id.desc()).offset((page-1)*page_size).limit(page_size).all()
    return {"items":[{"id":x.id,"time":x.created_at,"level":x.level,"category":x.category,
                      "control_id":x.control_id,"message":x.message} for x in rows],
            "page":page,"page_size":page_size,"total":total,
            "pages":max(1,(total+page_size-1)//page_size)}


@router.get("/reports/{sid}/weekly")
def weekly_report(sid:int,db:Session=Depends(get_db)):
    s=db.get(Service,sid)
    if not s: raise HTTPException(404,"Servis bulunamadı")
    since=datetime.utcnow()-timedelta(days=7)
    controls=[]
    for c in s.monitor_controls:
        rows=db.query(CheckResult).filter(CheckResult.control_id==c.id,CheckResult.checked_at>=since).order_by(CheckResult.checked_at.asc()).all()
        incidents=db.query(Incident).filter(Incident.control_id==c.id,Incident.started_at>=since).order_by(Incident.started_at.asc()).all()
        shots=db.query(ServiceScreenshot).filter(ServiceScreenshot.control_id==c.id,ServiceScreenshot.captured_at>=since).order_by(ServiceScreenshot.captured_at.asc()).all()
        total=len(rows); up=sum(r.status=="UP" for r in rows)
        controls.append({
            "id":c.id,"name":c.name,"type":c.control_type,"label":CONTROL_TYPES.get(c.control_type,{}).get("label",c.control_type),
            "enabled":c.enabled,"interval_seconds":c.interval_seconds,"failure_threshold":c.failure_threshold,
            "evaluation_window_minutes":c.evaluation_window_minutes,"url":c.url or "",
            "config":_sanitize_config(_jd(c.config_json,{})),
            "advanced_options":_jd(c.advanced_options_json,{}),
            "status_ranges":c.status_ranges or "","ignored_http_status_codes":c.ignored_http_status_codes or "",
            "state":{"status":c.last_status,"latency_ms":c.last_latency_ms,"last_check_at":c.last_check_at,
                      "resolved_ip":c.last_resolved_ip or "","http_status":c.last_http_status,"error":c.last_error or "",
                      "certificate_days":c.last_cert_days,"certificate_subject":c.last_cert_subject or "",
                      "certificate_issuer":c.last_cert_issuer or "","certificate_expires_at":c.last_cert_expires_at},
            "notification_groups":{p.event_type:[g.name for g in p.groups] for p in c.notification_policies},
            "notifications":{p.event_type:{"enabled":p.enabled,"subject":p.subject,"message":p.message,
                              "cooldown_minutes":p.cooldown_minutes,"threshold_ms":p.threshold_ms} for p in c.notification_policies},
            "summary":{
                "checks":total,"up":up,"down":sum(r.status=="DOWN" for r in rows),
                "warning":sum(r.status=="WARNING" for r in rows),
                "uptime_percent":round(up/total*100,2) if total else 0,
                "avg_latency_ms":round(sum(r.latency_ms or 0 for r in rows)/total,2) if total else 0,
                "min_latency_ms":min((r.latency_ms for r in rows if r.latency_ms is not None),default=0),
                "max_latency_ms":max((r.latency_ms for r in rows if r.latency_ms is not None),default=0),
            },
            "timeline":[{"time":r.checked_at,"status":r.status,"latency_ms":r.latency_ms,
                         "http_status":r.http_status,"error":r.error,"certificate_days":r.certificate_days,
                         "header_security":_jd(r.header_security_json,{}),"tls_security":_jd(r.tls_security_json,{})} for r in rows],
            "incidents":[{"id":i.id,"started_at":i.started_at,"resolved_at":i.resolved_at,
                          "duration_seconds":i.downtime_seconds,"failure_count":i.failure_count,"reason":i.reason} for i in incidents],
            "screenshots":[{"id":x.id,"captured_at":x.captured_at,"reason":x.reason,"status":x.status,
                            "http_status":x.http_status,"path":x.path,"url":x.url} for x in shots],
        })
    service_logs=db.query(EventLog).filter(EventLog.service_id==s.id,EventLog.created_at>=since).order_by(EventLog.created_at.asc()).limit(5000).all()
    service_audit=db.query(AuditLog).filter(AuditLog.service_id==s.id,AuditLog.created_at>=since).order_by(AuditLog.created_at.asc()).limit(1000).all()
    return {"generated_at":datetime.utcnow(),"period":{"from":since,"to":datetime.utcnow(),"days":7},
            "service":{"id":s.id,"name":s.name,"description":s.description or "","authorized":s.service_authorized_name or "",
                        "enabled":s.enabled,"maintenance":s.maintenance,"maintenance_until":s.maintenance_until,
                        "maintenance_reason":s.maintenance_reason or "","dependency_ids":_jd(s.dependency_ids,[]),
                        "status":s.last_status,"resolved_ip":s.last_resolved_ip or "","url":s.url or "",
                        "monitor_type":s.monitor_type or ""},
            "logs":[{"id":x.id,"time":x.created_at,"level":x.level,"category":x.category,"control_id":x.control_id,"message":x.message or ""} for x in service_logs],
            "audit":[{"id":x.id,"time":x.created_at,"actor":x.actor,"action":x.action,"control_id":x.control_id,"details":x.details or ""} for x in service_audit],
            "controls":controls}

@router.get("/screenshots")
def screenshots(
    page:int=1,page_size:int=24,q:str="",service_id:str="",
    control_id:str="",status:str="",db:Session=Depends(get_db)
):
    page=max(1,page);page_size=max(1,min(page_size,100));q=q.strip()[:100]
    try:
        service_id_int=int(service_id) if str(service_id).strip() else None
        control_id_int=int(control_id) if str(control_id).strip() else None
    except ValueError:
        raise HTTPException(422, "service_id ve control_id sayı olmalıdır.")
    query=db.query(ServiceScreenshot)
    if service_id_int: query=query.filter(ServiceScreenshot.service_id==service_id_int)
    if control_id_int:
        control=db.get(MonitorControl, control_id_int)
        if not control or (service_id_int and control.service_id != service_id_int):
            raise HTTPException(404, "Kontrol bulunamadı")
        query=query.filter(ServiceScreenshot.control_id==control_id_int)
    if status: query=query.filter(ServiceScreenshot.status==status.upper())
    if q:
        like=f"%{q}%"
        query=query.join(Service,Service.id==ServiceScreenshot.service_id).outerjoin(
            MonitorControl, MonitorControl.id == ServiceScreenshot.control_id
        ).filter(
            or_(
                Service.name.ilike(like), Service.url.ilike(like), Service.monitor_type.ilike(like),
                Service.description.ilike(like), Service.last_resolved_ip.ilike(like),
                ServiceScreenshot.reason.ilike(like), ServiceScreenshot.url.ilike(like),
                ServiceScreenshot.status.ilike(like),
                MonitorControl.name.ilike(like), MonitorControl.control_type.ilike(like),
                MonitorControl.url.ilike(like), MonitorControl.last_resolved_ip.ilike(like),
                MonitorControl.config_json.ilike(like), MonitorControl.advanced_options_json.ilike(like),
            )
        ).distinct()
    total=query.count()
    rows=query.order_by(ServiceScreenshot.captured_at.desc()).offset((page-1)*page_size).limit(page_size).all()
    service_map={s.id:s for s in db.query(Service).filter(Service.id.in_({x.service_id for x in rows})).all()} if rows else {}
    return {"items":[{"id":x.id,"service_id":x.service_id,"service_name":service_map.get(x.service_id).name if service_map.get(x.service_id) else None,
                      "control_id":x.control_id,"captured_at":x.captured_at,"status":x.status,
                      "http_status":x.http_status,"reason":x.reason,"path":x.path,"url":x.url}
                     for x in rows],
            "page":page,"page_size":page_size,"total":total,
            "pages":max(1,(total+page_size-1)//page_size)}

@router.get("/reports/{sid}/export/{kind}")
def weekly_report_export(sid:int, kind:str, db:Session=Depends(get_db)):
    kind=kind.lower()
    if kind not in {"json","xml","txt","html","pdf"}:
        raise HTTPException(400,"Desteklenmeyen export tipi.")
    data=weekly_report(sid,db)
    filename=f"uptime-monitor-weekly-{sid}.{kind}"
    import html as _html
    esc=lambda v:_html.escape(str(v if v is not None else ""))

    if kind=="json":
        content=json.dumps(data,ensure_ascii=False,default=str,indent=2)
        return Response(content.encode(),media_type="application/json",headers={"Content-Disposition":f'attachment; filename="{filename}"'})

    if kind=="xml":
        chunks=[f'<weekly_report generated_at="{esc(data["generated_at"])}"><service id="{sid}">']
        sv=data["service"]
        for key in ("name","description","authorized","url","resolved_ip","status","monitor_type"):
            chunks.append(f'<{key}>{esc(sv.get(key))}</{key}>')
        for c in data["controls"]:
            chunks.append(f'<control id="{c["id"]}" type="{esc(c["type"])}"><name>{esc(c["name"])}</name>')
            st=c.get("state",{})
            chunks.append(f'<target url="{esc(c.get("url"))}" resolved_ip="{esc(st.get("resolved_ip"))}" status="{esc(st.get("status"))}"/>')
            chunks.append(f'<settings interval_seconds="{c["interval_seconds"]}" failure_threshold="{c["failure_threshold"]}" evaluation_window_minutes="{c["evaluation_window_minutes"]}" status_ranges="{esc(c.get("status_ranges"))}" ignored_http_status_codes="{esc(c.get("ignored_http_status_codes"))}">')
            chunks.append(f'<config>{esc(json.dumps(c.get("config",{}),ensure_ascii=False,default=str))}</config>')
            chunks.append(f'<advanced>{esc(json.dumps(c.get("advanced_options",{}),ensure_ascii=False,default=str))}</advanced></settings>')
            sm=c["summary"]
            chunks.append(f'<summary uptime_percent="{sm["uptime_percent"]}" checks="{sm["checks"]}" avg_latency_ms="{sm["avg_latency_ms"]}"/>')
            for r in c["timeline"]:
                chunks.append(f'<metric time="{esc(r["time"])}" status="{esc(r["status"])}" latency_ms="{r["latency_ms"]}" http_status="{r["http_status"]}">{esc(r["error"])}</metric>')
            for i in c.get("incidents",[]):
                chunks.append(f'<incident id="{i["id"]}" started_at="{esc(i.get("started_at"))}" resolved_at="{esc(i.get("resolved_at"))}" duration_seconds="{i.get("duration_seconds") or 0}" reason="{esc(i.get("reason"))}"/>')
            for x in c.get("screenshots",[]):
                chunks.append(f'<screenshot id="{x["id"]}" captured_at="{esc(x.get("captured_at"))}" status="{esc(x.get("status"))}" http_status="{x.get("http_status")}" path="{esc(x.get("path"))}" url="{esc(x.get("url"))}" reason="{esc(x.get("reason"))}"/>')
            chunks.append('</control>')
        chunks.append('<logs>')
        for x in data.get("logs",[]):
            chunks.append(f'<log id="{x["id"]}" time="{esc(x.get("time"))}" level="{esc(x.get("level"))}" category="{esc(x.get("category"))}" control_id="{x.get("control_id") or ""}">{esc(x.get("message"))}</log>')
        chunks.append('</logs><audit>')
        for x in data.get("audit",[]):
            chunks.append(f'<audit_record id="{x["id"]}" time="{esc(x.get("time"))}" actor="{esc(x.get("actor"))}" action="{esc(x.get("action"))}" control_id="{x.get("control_id") or ""}">{esc(x.get("details"))}</audit_record>')
        chunks.append('</audit></service></weekly_report>')
        return Response("".join(chunks).encode(),media_type="application/xml",headers={"Content-Disposition":f'attachment; filename="{filename}"'})

    if kind=="txt":
        sv=data["service"]
        out=[f"UPTIME MONITOR SERVICE WEEKLY REPORT | {sv['name']}",
             f"Period: {data['period']['from']} - {data['period']['to']}",
             f"URL: {sv.get('url') or '-'} | IP: {sv.get('resolved_ip') or '-'} | Durum: {sv.get('status') or '-'}",
             f"Yetkili: {sv.get('authorized') or '-'} | Aktif: {sv.get('enabled')} | Bakım: {sv.get('maintenance')}",
             f"Bağımlı servisler: {', '.join(map(str,sv.get('dependency_ids') or [])) or '-'}",""]
        for c in data["controls"]:
            sm=c["summary"]
            groups="; ".join(f"{k}={', '.join(v) or '-'}" for k,v in c["notification_groups"].items())
            out += [f"[CONTROL] {c['name']} ({c['type']})",
                    f"Target URL/Host: {c.get('url') or '-'} | Resolved IP: {c.get('state',{}).get('resolved_ip') or '-'}",
                    f"Interval: {c['interval_seconds']} sec | Failure threshold: {c['failure_threshold']} | Window: {c['evaluation_window_minutes']} min",
                    f"Status ranges: {c.get('status_ranges') or '-'} | Ignored HTTP: {c.get('ignored_http_status_codes') or '-'}",
                    f"Config: {json.dumps(c.get('config',{}),ensure_ascii=False,default=str)}",
                    f"Advanced/TLS/Security: {json.dumps(c.get('advanced_options',{}),ensure_ascii=False,default=str)}",
                    f"Uptime: %{sm['uptime_percent']} | Checks: {sm['checks']} | UP: {sm['up']} | WARNING: {sm['warning']} | DOWN: {sm['down']}",
                    f"Latency min/avg/max: {sm['min_latency_ms']} / {sm['avg_latency_ms']} / {sm['max_latency_ms']} ms",
                    f"Notification groups: {groups}",""]
            for i in c.get("incidents",[]):
                out.append(f"INCIDENT | {i['id']} | {i.get('started_at')} | {i.get('resolved_at') or 'OPEN'} | {i.get('duration_seconds') or 0}s | {i.get('reason') or '-'}")
            for x in c.get("screenshots",[]):
                out.append(f"SCREENSHOT | {x['id']} | {x.get('captured_at')} | {x.get('status')} | {x.get('url') or x.get('path') or '-'} | {x.get('reason') or '-'}")
            for r in c["timeline"]:
                out.append("|".join(str(v if v is not None else "") for v in ["METRIC",r["time"],r["status"],r["latency_ms"],r["http_status"],r["error"]]))
            out.append("")
        out.append("[LOGS]")
        for x in data.get("logs",[]): out.append(f"{x['id']} | {x.get('time')} | {x.get('level')} | {x.get('category')} | control={x.get('control_id') or '-'} | {x.get('message') or ''}")
        out.append("")
        out.append("[AUDIT]")
        for x in data.get("audit",[]): out.append(f"{x['id']} | {x.get('time')} | {x.get('actor')} | {x.get('action')} | control={x.get('control_id') or '-'} | {x.get('details') or ''}")
        return Response("\n".join(out).encode(),media_type="text/plain",headers={"Content-Disposition":f'attachment; filename="{filename}"'})

    service_name=esc(data["service"]["name"])
    sv=data["service"]
    sections=[]
    for c in data["controls"]:
        sm=c["summary"]
        bars="".join(f'<i class="bar {str(r["status"]).lower()}"></i>' for r in c["timeline"][-168:])
        groups=" · ".join(f'{esc(k)}: {esc(", ".join(v) or "-")}' for k,v in c["notification_groups"].items())
        cfg=esc(json.dumps(c.get("config",{}),ensure_ascii=False,default=str,indent=2))
        adv=esc(json.dumps(c.get("advanced_options",{}),ensure_ascii=False,default=str,indent=2))
        rows="".join(f'<tr><td>{esc(r["time"])}</td><td>{esc(r["status"])}</td><td>{r["latency_ms"] or 0} ms</td><td>{r["http_status"] or "-"}</td><td>{esc(r["error"] or "")}</td></tr>' for r in c["timeline"][-100:])
        inc_rows="".join(f'<tr><td>#{i["id"]}</td><td>{esc(i.get("started_at"))}</td><td>{esc(i.get("resolved_at") or "OPEN")}</td><td>{i.get("duration_seconds") or 0} sn</td><td>{esc(i.get("reason") or "-")}</td></tr>' for i in c.get("incidents",[])) or '<tr><td colspan="5">Olay yok.</td></tr>'
        shot_rows="".join(f'<tr><td>#{x["id"]}</td><td>{esc(x.get("captured_at"))}</td><td>{esc(x.get("status"))}</td><td>{x.get("http_status") or "-"}</td><td>{esc(x.get("url") or x.get("path") or "-")}</td><td>{esc(x.get("reason") or "-")}</td></tr>' for x in c.get("screenshots",[])) or '<tr><td colspan="6">Ekran görüntüsü yok.</td></tr>'
        sections.append(f'''<section class="control"><h2>{esc(c["name"])} <small>{esc(c["label"])}</small></h2>
<div class="meta"><b>Hedef:</b> {esc(c.get("url") or "-")} · <b>IP:</b> {esc(c.get("state",{}).get("resolved_ip") or "-")} · <b>Son durum:</b> {esc(c.get("state",{}).get("status") or "-")}</div>
<div class="kpis"><b>Uptime<strong>%{sm["uptime_percent"]}</strong></b><b>Kontrol<strong>{sm["checks"]}</strong></b><b>Avg Latency<strong>{sm["avg_latency_ms"]} ms</strong></b><b>DOWN<strong>{sm["down"]}</strong></b></div>
<p><b>Kontrol ayarları:</b> {c["interval_seconds"]} sn · hata eşiği {c["failure_threshold"]} · pencere {c["evaluation_window_minutes"]} dk · UP HTTP: {esc(c.get("status_ranges"))} · istisna HTTP: {esc(c.get("ignored_http_status_codes"))}</p>
<div class="two"><div><h3>Config</h3><pre>{cfg}</pre></div><div><h3>Gelişmiş / TLS / Security</h3><pre>{adv}</pre></div></div>
<p><b>Bildirim ekipleri:</b> {groups or "-"}</p><div class="timeline">{bars}</div>
<h3>Kontrol ölçümleri</h3><table><tr><th>Zaman</th><th>Durum</th><th>Latency</th><th>HTTP</th><th>Hata</th></tr>{rows}</table>
<h3>Olaylar</h3><table><tr><th>ID</th><th>Başlangıç</th><th>Çözülme</th><th>Süre</th><th>Neden</th></tr>{inc_rows}</table>
<h3>Ekran görüntüleri</h3><table><tr><th>ID</th><th>Zaman</th><th>Durum</th><th>HTTP</th><th>URL/Path</th><th>Neden</th></tr>{shot_rows}</table></section>''')
    log_rows="".join(f'<tr><td>#{x["id"]}</td><td>{esc(x.get("time"))}</td><td>{esc(x.get("level"))}</td><td>{esc(x.get("category"))}</td><td>{x.get("control_id") or "-"}</td><td>{esc(x.get("message") or "")}</td></tr>' for x in data.get("logs",[])) or '<tr><td colspan="6">İşlem kaydı yok.</td></tr>'
    audit_rows="".join(f'<tr><td>#{x["id"]}</td><td>{esc(x.get("time"))}</td><td>{esc(x.get("actor"))}</td><td>{esc(x.get("action"))}</td><td>{x.get("control_id") or "-"}</td><td>{esc(x.get("details") or "")}</td></tr>' for x in data.get("audit",[])) or '<tr><td colspan="6">Denetim kaydı yok.</td></tr>'
    html_doc=f'''<!doctype html><html lang="tr"><meta charset="utf-8"><title>Uptime Monitor Service — {service_name}</title>
<style>body{{font:13px Arial;background:#f5f7fa;color:#18212b;margin:0}}main{{max-width:1300px;margin:auto;padding:28px}}header,.control,.logs{{background:white;border:1px solid #dce3ea;border-radius:16px;padding:22px;margin-bottom:18px}}h1{{margin:0}}h2 small{{font-size:12px;color:#657487}}h3{{margin:14px 0 7px}}.meta{{color:#657487;margin:8px 0}}.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}}.kpis b{{background:#f1f5f9;padding:12px;border-radius:10px;color:#657487}}.kpis strong{{display:block;font-size:20px;color:#18212b;margin-top:4px}}.timeline{{display:flex;gap:1px;height:38px;align-items:end;margin:18px 0}}.bar{{flex:1;min-width:1px;height:18px;background:#94a3b8}}.bar.up{{background:#16a34a}}.bar.down{{background:#dc2626}}.bar.warning{{background:#d97706}}table{{width:100%;border-collapse:collapse;font-size:11px}}td,th{{padding:6px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}th{{background:#eef2f6}}pre{{background:#0b1420;color:#dbe7f1;padding:10px;border-radius:9px;overflow:auto;white-space:pre-wrap;word-break:break-word}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}@media(max-width:800px){{.kpis,.two{{grid-template-columns:1fr}}}}</style>
<main><header><h1>Uptime Monitor Service — Haftalık Servis Raporu</h1><p>{service_name}</p><p>Period: {esc(data["period"]["from"])} → {esc(data["period"]["to"])}</p><p><b>URL:</b> {esc(sv.get("url") or "-")} · <b>IP:</b> {esc(sv.get("resolved_ip") or "-")} · <b>Durum:</b> {esc(sv.get("status") or "-")} · <b>Yetkili:</b> {esc(sv.get("authorized") or "-")}</p><p><b>Bakım:</b> {esc(sv.get("maintenance"))} · <b>Bağımlılıklar:</b> {esc(", ".join(map(str,sv.get("dependency_ids") or [])) or "-")}</p></header>{''.join(sections)}
<section class="logs"><h2>İşlem Kayıtları</h2><table><tr><th>ID</th><th>Zaman</th><th>Seviye</th><th>Kategori</th><th>Kontrol</th><th>Mesaj</th></tr>{log_rows}</table></section>
<section class="logs"><h2>Denetim Kayıtları</h2><table><tr><th>ID</th><th>Zaman</th><th>Kullanıcı</th><th>Aksiyon</th><th>Kontrol</th><th>Detay</th></tr>{audit_rows}</table></section></main></html>'''
    if kind=="html":
        return Response(html_doc.encode(),media_type="text/html",headers={"Content-Disposition":f'attachment; filename="{filename}"'})

    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
    from reportlab.lib.pagesizes import A4,landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    import io
    buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=landscape(A4),leftMargin=9*mm,rightMargin=9*mm,topMargin=9*mm,bottomMargin=9*mm)
    styles=getSampleStyleSheet(); story=[Paragraph(f'Uptime Monitor Service — Haftalık Servis Raporu — {data["service"]["name"]}',styles["Title"]),
        Paragraph(f'URL: {esc(sv.get("url") or "-")} · IP: {esc(sv.get("resolved_ip") or "-")} · Durum: {esc(sv.get("status") or "-")} · Yetkili: {esc(sv.get("authorized") or "-")}',styles["Normal"]),Spacer(1,8)]
    for c in data["controls"]:
        sm=c["summary"]
        story += [Paragraph(f'{esc(c["name"])} · {esc(c["label"])}',styles["Heading2"]),Paragraph(f'Hedef: {esc(c.get("url") or "-")} · IP: {esc(c.get("state",{}).get("resolved_ip") or "-")} · Interval: {c["interval_seconds"]} sn · Hata eşiği: {c["failure_threshold"]} · Pencere: {c["evaluation_window_minutes"]} dk',styles["Normal"])]
        t=Table([["Uptime","Checks","UP","WARNING","DOWN","Avg","Min","Max"],[f'%{sm["uptime_percent"]}',sm["checks"],sm["up"],sm["warning"],sm["down"],f'{sm["avg_latency_ms"]} ms',f'{sm["min_latency_ms"]} ms',f'{sm["max_latency_ms"]} ms']],repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17304d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),("FONTSIZE",(0,0),(-1,-1),7)]));story += [t,Spacer(1,5)]
        groups_txt="; ".join(f"{k}={', '.join(v) or '-'}" for k,v in c["notification_groups"].items())
        story += [Paragraph(f'Config: {esc(json.dumps(c.get("config",{}),ensure_ascii=False,default=str))}',styles["Normal"]),Paragraph(f'Gelişmiş/TLS/Security: {esc(json.dumps(c.get("advanced_options",{}),ensure_ascii=False,default=str))}',styles["Normal"]),Paragraph(f'Bildirim grupları: {esc(groups_txt)}',styles["Normal"]),Spacer(1,5)]
        rows=[["Zaman","Durum","Latency","HTTP","Hata"]]+[[str(r["time"]),r["status"],f'{r["latency_ms"] or 0} ms',str(r["http_status"] or "-"),str(r["error"] or "")[:100]] for r in c["timeline"][-100:]]
        t2=Table(rows,repeatRows=1,colWidths=[42*mm,20*mm,23*mm,18*mm,135*mm]);t2.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#334155")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.2,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story += [t2,Spacer(1,7)]
        inc=[["ID","Başlangıç","Çözülme","Süre","Neden"]]+[[f'#{i["id"]}',str(i.get("started_at")),str(i.get("resolved_at") or "OPEN"),f'{i.get("duration_seconds") or 0} sn',str(i.get("reason") or "")[:100]] for i in c.get("incidents",[])]
        ti=Table(inc,repeatRows=1,colWidths=[15*mm,38*mm,38*mm,25*mm,122*mm]);ti.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#334155")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.2,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story += [Paragraph('Olaylar',styles["Heading3"]),ti,Spacer(1,7)]
        shots=[["ID","Zaman","Durum","HTTP","URL/Path","Neden"]]+[[f'#{x["id"]}',str(x.get("captured_at")),str(x.get("status")),str(x.get("http_status") or "-"),str(x.get("url") or x.get("path") or "-")[:70],str(x.get("reason") or "")[:70]] for x in c.get("screenshots",[])]
        ts=Table(shots,repeatRows=1,colWidths=[15*mm,38*mm,22*mm,18*mm,80*mm,65*mm]);ts.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#334155")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.2,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story += [Paragraph('Ekran görüntüleri',styles["Heading3"]),ts,Spacer(1,10)]
    if data.get("logs"):
        story += [PageBreak(),Paragraph('İşlem Kayıtları',styles["Heading2"])]
        rows=[["ID","Zaman","Seviye","Kategori","Kontrol","Mesaj"]]+[[f'#{x["id"]}',str(x.get("time")),str(x.get("level")),str(x.get("category")),str(x.get("control_id") or "-"),str(x.get("message") or "")[:140]] for x in data["logs"][-1000:]]
        t=Table(rows,repeatRows=1,colWidths=[15*mm,38*mm,22*mm,30*mm,22*mm,145*mm]);t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17304d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.2,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story += [t]
    if data.get("audit"):
        story += [PageBreak(),Paragraph('Denetim Kayıtları',styles["Heading2"])]
        rows=[["ID","Zaman","Kullanıcı","Aksiyon","Kontrol","Detay"]]+[[f'#{x["id"]}',str(x.get("time")),str(x.get("actor")),str(x.get("action")),str(x.get("control_id") or "-"),str(x.get("details") or "")[:140]] for x in data["audit"][-1000:]]
        t=Table(rows,repeatRows=1,colWidths=[15*mm,38*mm,30*mm,45*mm,22*mm,122*mm]);t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17304d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.2,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),6)]));story += [t]
    doc.build(story)
    return Response(buf.getvalue(),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{filename}"'})

