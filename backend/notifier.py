import json,re,smtplib,ssl,urllib.request,urllib.parse
from email.mime.text import MIMEText
from .models import SMTPSettings, CheckResult, Incident, Integration, Service

# Şablon yer tutucularına asla sızdırılmaması gereken Service sütunları.
_SENSITIVE_COLUMN = re.compile(r"password|passwd|secret|token|credential|auth|protocol_options|headers_json|_security_json", re.I)

NOTIFICATION_FIELDS = {
    "SERVICE_ID":"Servis ID", "SERVICE_NAME":"Servis adı", "MONITOR_TYPE":"İzleme tipi",
    "HOST_NAME":"Hostname/hedef", "HOST_URL":"URL", "RESOLVED_IP":"Çözümlenen IP",
    "PORT":"Port", "STATUS":"Güncel durum", "PREVIOUS_STATUS":"Önceki durum",
    "EVENT_TYPE":"Bildirim olayı", "EVENT_TIME":"Olay zamanı", "TIME":"Bildirim/ölçüm zamanı",
    "LAST_CHECK":"Son kontrol zamanı", "INTERVAL_TIME":"Kontrol aralığı",
    "HTTP_STATUS":"HTTP durum kodu", "LATENCY_MS":"Son latency (ms)",
    "AVG_LATENCY_24H":"24 saat ortalama latency (ms)", "MIN_LATENCY_24H":"24 saat minimum latency (ms)",
    "MAX_LATENCY_24H":"24 saat maksimum latency (ms)", "CHECK_COUNT_24H":"24 saat kontrol sayısı",
    "SUCCESS_COUNT_24H":"24 saat başarılı kontrol sayısı", "FAILURE_COUNT_24H":"24 saat başarısız kontrol sayısı",
    "UPTIME_24H":"24 saat uptime (%)", "DOWNTIME_24H":"24 saat downtime (sn)",
    "INCIDENT_COUNT_24H":"24 saat olay sayısı", "FAILURE_COUNT":"Ardışık hata sayısı",
    "REASON":"Hata/olay nedeni", "ERROR_MESSAGE":"Hata mesajı",
    "CERT_STATUS":"Sertifika durumu", "CERT_SUBJECT":"Sertifika sahibi", "CERT_ISSUER":"Sertifika sağlayıcısı",
    "CERT_EXPIRY":"Sertifika bitiş zamanı", "CERT_DAYS":"Sertifika kalan gün",
    "CERT_ALERT_DAYS":"Sertifika alarm eşiği (gün)",
    "NOTIFICATION_TITLE":"Bildirim başlığı", "NOTIFICATION_TYPE":"Bildirim tipi",
}

def notification_context(db, s, extra=None):
    from datetime import datetime, timedelta
    from urllib.parse import urlparse
    since=datetime.utcnow()-timedelta(hours=24)
    q_rows=db.query(CheckResult).filter(CheckResult.service_id==s.id, CheckResult.checked_at>=since)
    q_inc=db.query(Incident).filter(Incident.service_id==s.id, Incident.started_at>=since)
    if getattr(s, "control_id", None) is not None:
        q_rows=q_rows.filter(CheckResult.control_id==s.control_id)
        q_inc=q_inc.filter(Incident.control_id==s.control_id)
    rows=q_rows.all()
    incidents=q_inc.all()
    lats=[float(r.latency_ms) for r in rows if r.latency_ms is not None]
    total=len(rows); success=sum(r.status=="UP" for r in rows); failures=max(0,total-success)
    url=(s.url or "").strip(); host=url
    try:
        if "://" in url: host=urlparse(url).hostname or url
    except Exception: pass
    opts=json.loads(getattr(s,"protocol_options","{}") or "{}")
    port=opts.get("port") or (443 if str(getattr(s,"monitor_type","")) in {"ssl","https"} else "N/A")
    cert_days=s.last_cert_days if s.last_cert_days is not None else "N/A"
    cert_status=("EXPIRED" if isinstance(cert_days,(int,float)) and cert_days<0 else "EXPIRING" if isinstance(cert_days,(int,float)) and cert_days<=getattr(s,"certificate_alert_days",30) else "VALID") if s.cert_expires_at else "N/A"
    vals={
        "SERVICE_ID":s.id,"SERVICE_NAME":s.name,"MONITOR_TYPE":getattr(s,"monitor_type","N/A"),"HOST_NAME":host,"HOST_URL":url,
        "RESOLVED_IP":getattr(s,"resolved_ip",None) or "N/A","PORT":port,"STATUS":s.last_status or "UNKNOWN",
        "PREVIOUS_STATUS":(extra or {}).get("PREVIOUS_STATUS", "N/A"),"EVENT_TYPE":(extra or {}).get("EVENT_TYPE", "N/A"),
        "EVENT_TIME":(extra or {}).get("EVENT_TIME", s.last_check_at or "N/A"),"TIME":s.last_check_at or "N/A","LAST_CHECK":s.last_check_at or "N/A",
        "INTERVAL_TIME":f"{s.interval_seconds}s","HTTP_STATUS":s.last_http_status if s.last_http_status is not None else "N/A",
        "LATENCY_MS":round(s.last_latency_ms or 0,2),"AVG_LATENCY_24H":round(sum(lats)/len(lats),2) if lats else 0,
        "MIN_LATENCY_24H":round(min(lats),2) if lats else 0,"MAX_LATENCY_24H":round(max(lats),2) if lats else 0,
        "CHECK_COUNT_24H":total,"SUCCESS_COUNT_24H":success,"FAILURE_COUNT_24H":failures,
        "UPTIME_24H":round(success/total*100,2) if total else 0,"DOWNTIME_24H":round(sum(i.downtime_seconds or 0 for i in incidents),1),
        "INCIDENT_COUNT_24H":len(incidents),"FAILURE_COUNT":s.consecutive_failures or 0,
        "REASON":s.last_error or "N/A","ERROR_MESSAGE":s.last_error or "N/A",
        "CERT_STATUS":cert_status,"CERT_SUBJECT":s.cert_subject or "N/A","CERT_ISSUER":s.cert_issuer or "N/A",
        "CERT_EXPIRY":s.cert_expires_at or "N/A","CERT_DAYS":cert_days,"CERT_ALERT_DAYS":getattr(s,"certificate_alert_days",30),
    }
    vals.update(extra or {})
    vals.setdefault("NOTIFICATION_TITLE", vals.get("EVENT_TYPE", "Service Monitor"))
    vals.setdefault("NOTIFICATION_TYPE", vals.get("EVENT_TYPE", "N/A"))
    return vals

def render(t,s,extra=None,db=None):
    vals=notification_context(db,s,extra) if db is not None else {}
    # Olay bağlamında bulunmayan yer tutucular, güncel Service satırından doldurulur.
    # Veri her zaman veritabanından okunur: bildirim metni bayat (önbellekteki) bir
    # servis anlık görüntüsünden ASLA doldurulmaz. Gizli sütunlar hariç tutulur.
    if db is not None:
        missing=[k for k in re.findall(r"{{\s*([A-Za-z0-9_.-]+)\s*}}", t) if k not in vals or vals.get(k) in (None, "", "N/A", "n/a")]
        missing=[k for k in missing if not _SENSITIVE_COLUMN.search(k)]
        if missing:
            try:
                fresh=db.get(Service, int(s.id))
            except Exception:
                fresh=None
            if fresh:
                columns={c.name for c in Service.__table__.columns if not _SENSITIVE_COLUMN.search(c.name)}
                for key in missing:
                    name=key if key in columns else (key.lower() if key.lower() in columns else None)
                    if name:
                        value=getattr(fresh,name,None)
                        if value not in (None, ""):
                            vals[key]=value

    if not vals:
        vals={"SERVICE_NAME":s.name,"STATUS":s.last_status or "UNKNOWN","HOST_URL":s.url or "N/A","HOST_NAME":s.url or "N/A"}
        vals.update(extra or {})
    # Unknown placeholders intentionally remain visible so template mistakes are easy to diagnose.
    for k,v in vals.items(): t=t.replace("{{"+k+"}}",str(v if v not in (None, "") else "N/A"))
    t=re.sub(r"{{\s*([A-Za-z0-9_.-]+)\s*}}", lambda m: str(vals.get(m.group(1), "N/A")), t)
    return t


def telegram_request(token, method, payload=None):
    if not token:
        return False, "Telegram bot token boş."
    try:
        data=json.dumps(payload or {},ensure_ascii=False).encode()
        req=urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=data,
            headers={"Content-Type":"application/json"}
        )
        with urllib.request.urlopen(req,timeout=15) as r:
            raw=r.read().decode("utf-8",errors="replace")
        obj=json.loads(raw)
        if not obj.get("ok"):
            return False, obj.get("description") or "Telegram API isteği başarısız."
        return True, obj
    except Exception as e:
        return False, str(e)

def telegram_send(token, chat_id, text, parse_mode="HTML"):
    if not token or not chat_id:
        return False, "Telegram bot token ve Chat ID zorunludur."
    payload={"chat_id":str(chat_id),"text":text,"disable_web_page_preview":True}
    if parse_mode: payload["parse_mode"]=parse_mode
    ok, result=telegram_request(token,"sendMessage",payload)
    if not ok and parse_mode:
        # Templates may contain raw <, > or Markdown characters from service errors.
        # Retry as plain text so a formatting problem never blocks an operational alert.
        ok, result=telegram_request(token,"sendMessage",{"chat_id":str(chat_id),"text":text,"disable_web_page_preview":True})
    if not ok:
        return False, result
    return True, "Telegram mesajı gönderildi."

def telegram_config(db):
    integ=db.query(Integration).filter_by(provider="telegram").first()
    if integ and integ.enabled:
        cfg=json.loads(integ.config_json or "{}")
        if cfg.get("token") and cfg.get("chat_id"):
            return cfg
    # Backward compatibility for old notification groups.
    for g in db.query(__import__(".models",fromlist=["NotificationGroup"]).NotificationGroup).all():
        r=json.loads(g.recipients_json or "{}")
        if r.get("telegram_token") and r.get("telegram_chat_id"):
            return {"token":r["telegram_token"],"chat_id":r["telegram_chat_id"],"parse_mode":r.get("telegram_parse_mode","HTML")}
    return {}

def email(db,to,subject,body):
    s=db.query(SMTPSettings).first(); to=[x.strip() for x in (to or []) if x and x.strip()]
    if not s or not s.host or not s.from_email or not to:return False,"SMTP ayarları eksik: sunucu, gönderen veya alıcı boş."
    m=MIMEText(body,"plain","utf-8");m["Subject"]=subject;m["From"]=s.from_email;m["To"]=", ".join(to)
    try:
        if s.use_ssl:
            server=smtplib.SMTP_SSL(s.host,int(s.port),timeout=20)
        else:
            server=smtplib.SMTP(s.host,int(s.port),timeout=20)
        with server:
            server.ehlo(getattr(s,"helo_name", "") or None) if getattr(s,"helo_name", "") else server.ehlo()
            if s.use_tls and not s.use_ssl:
                server.starttls(context=ssl.create_default_context());
                server.ehlo(getattr(s,"helo_name", "") or None) if getattr(s,"helo_name", "") else server.ehlo()
            if getattr(s,"mode","auth")=="auth" and s.auth_enabled and s.username:
                server.login(s.username,s.password)
            server.send_message(m)
        return True,"E-posta gönderildi."
    except smtplib.SMTPAuthenticationError as e:
        return False,f"SMTP kimlik doğrulama başarısız (kod {e.smtp_code}): {e.smtp_error.decode(errors='replace') if isinstance(e.smtp_error,bytes) else e.smtp_error}"
    except Exception as e:return False,str(e)

def webhook(url,payload):
    if not url:return False,"Webhook URL boş"
    try:
        req=urllib.request.Request(url,data=json.dumps(payload,ensure_ascii=False).encode(),headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req,timeout=15) as r:return 200<=r.status<300,"Gönderildi"
    except Exception as e:return False,str(e)

def notify(db,s,subject,body,groups=None):
    groups=groups if groups is not None else s.notification_groups
    results=[]
    for g in groups:
        if not g.enabled:continue
        c=json.loads(g.channels_json or "{}");r=json.loads(g.recipients_json or "{}")
        subject=render(subject,s,db=db); body=render(body,s,db=db)
        if c.get("email"):
            ok,msg=email(db,r.get("email",[]),subject,body);results.append((g.name,"email",ok,msg))
        if c.get("webhook"):
            ok,msg=webhook(r.get("webhook_url",""),{"service":s.name,"status":s.last_status,"message":body});results.append((g.name,"webhook",ok,msg))
        if c.get("discord"):
            ok,msg=webhook(r.get("discord_webhook",""),{"content":body});results.append((g.name,"discord",ok,msg))
        if c.get("slack"):
            ok,msg=webhook(r.get("slack_webhook",""),{"text":body});results.append((g.name,"slack",ok,msg))
        if c.get("telegram"):
            tg=telegram_config(db)
            ok,msg=telegram_send(tg.get("token"),tg.get("chat_id"),body,tg.get("parse_mode","HTML"))
            results.append((g.name,"telegram",ok,msg))
        elif c.get("telegram") is False:
            pass
    return results
