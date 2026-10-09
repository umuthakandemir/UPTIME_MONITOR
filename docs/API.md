# Uptime Monitor Service — API Ek Dokümantasyonu

## Servis arama, filtreleme ve sayfalama

`GET /api/services?q=&page=1&page_size=20&status=ALL&sort=name_az`

- `q`: servis adı, URL veya monitor tipi
- `status`: `ALL`, `UP`, `WARNING`, `DOWN`, `UNKNOWN`
- `sort`: `name_az`, `name_za`, `up_down_warning`, `down_up_warning`, `warning_down_up`, `latest`
- `page_size`: 10–250
- Yanıt: `items`, `page`, `page_size`, `total`, `pages`

## Dashboard ve analytics

- `GET /api/dashboard` — hızlı özet ve dashboard için küçük featured servis listesi.
- `GET /api/dashboard/analytics?period=24h|7d|30d` — bucket'lanmış uptime, latency, kontrol ve incident verileri.
- `GET /api/services/{service_id}/analytics?period=24h|7d|30d` — servis bazlı analytics.

Dashboard analytics geçmiş kontrol kayıtlarını tek geçişte bucket'lar; her bucket veya servis için ayrı sorgu çalıştırmaz.

## İşlem kayıtları

`GET /api/logs?q=&category=&page=1&page_size=50`

Detay:

`GET /api/logs/{log_id}`

Detay endpoint'i kayıt mesajını, servis ilişkisini ve son ilgili kontrolleri döndürür.

## Incident'lar

`GET /api/incidents?q=&page=1&page_size=50`

Detay:

`GET /api/incidents/{incident_id}`

## Denetim

`GET /api/audit?q=&page=1&page_size=50`

## Uygulama bildirimleri

Kullanıcıya özel okuma durumu:

- `GET /api/notifications?category=all&limit=60`
- `POST /api/notifications/{notification_id}/read`
- `POST /api/notifications/read-all`

Servis olayları global bildirimdir; login ve şifre değişikliği gibi kullanıcı olayları yalnızca ilgili kullanıcıya gösterilir.

## Web güvenlik header analizi

Web kontrollerinde header analizi otomatik yapılır. Kullanıcıdan ayrıca beklenen header tanımlaması istenmez.

Temel analiz HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy ve Permissions-Policy kontrollerini içerir. Sonuçlar `header_security` ve `headers` alanlarında tutulur.

## Anlık test

`POST /api/instant-test`

Desteklenen testler: `auto`, `web`, `headers`, `ssl`, `ping`, `tcp`, `dns`, `smtp`, `mysql`, `postgresql`, `redis`.

Örnek:

```json
{
  "target": "example.com",
  "test_type": "ssl"
}
```

Web/HTTP başarısız olduğunda backend ayrıca hedef hostu ping'ler ve sonucu `server_reachable` alanında döndürür. Böylece web uygulaması ile sunucu erişilebilirliği ayrıştırılır.

## TLS / SSL güvenlik analizi

`POST /api/services/{service_id}/security/tls`

Uygulama uzak bir SSL Labs API'sine ihtiyaç duymaz. Python OpenSSL ve `cryptography` kullanılarak:

- TLS 1.0 / 1.1 / 1.2 / 1.3 desteği
- modern/legacy protokol durumu
- sertifika geçerlilik süresi
- hostname doğrulaması
- güvenlik skoru ve grade
- kritik/uyarı bulguları

üretilir ve `tls_security` altında saklanır.

## Sertifika

`GET /api/services/{service_id}/certificate`

Sertifika Common Name, issuer, SAN, başlangıç/bitiş zamanı, serial, version ve cipher bilgilerini döndürür.

## Screenshot

Ayarlar → Genel bölümünde:

- `screenshot_on_http_failure`
- `screenshot_interval_seconds`
- `screenshot_wait_seconds`
- `screenshot_timeout_seconds`

alanları bulunur.

Otomatik screenshot yalnızca gerçek HTTP/server hataları için alınır:

- `404`
- `5xx`

`401` ve `403` için otomatik screenshot alınmaz.

Dosyalama:

```text
screenshots/
  <servis-adı>/
    routine/
    up/
    down/
```

Dosya adı örneği:

```text
Portal-response-404-20261007-103500.png
```

## Export

Tek servis:

- `GET /api/export/html/{service_id}`
- `GET /api/export/pdf/{service_id}`
- `GET /api/export/csv/{service_id}`
- `GET /api/export/txt/{service_id}`
- `GET /api/export/json/{service_id}`
- `GET /api/export/xml/{service_id}`

Tüm servisler için aynı endpoint'lerin `/all` varyantları bulunur.

## Veri saklama

`GET /api/settings` retention ayarlarını döndürür.

`POST /api/settings/retention/cleanup` manuel temizleme başlatır.

Otomatik retention varsayılan olarak kapalıdır. Açıldığında check/log/audit geçmişi ve çözülmüş incident'lar belirlenen saklama sürelerine göre temizlenir.


## Multi-Control API v2

`Service` is now an operational container. Monitoring is performed by one or more
independent `MonitorControl` records. Each control has its own type, target,
cadence, state, metrics, incidents and notification policies.

### Control catalog

`GET /api/v2/control-types`

Returns the dynamic field schema used by the UI. Current built-ins include:

- `web`
- `ping`
- `postgresql`
- `tcp`
- `dns`
- `ssl`
- `smtp`
- `mysql`
- `redis`

The API contract is intentionally schema-driven so new control types can be
added without changing the Service resource shape.

### Create a multi-control service

`POST /api/v2/services`

```json
{
  "name": "example",
  "description": "Example production stack",
  "controls": [
    {
      "name": "Public Web",
      "control_type": "web",
      "config": {
        "url": "https://example.com"
      },
      "interval_seconds": 30,
      "failure_threshold": 3,
      "notifications": {
        "DOWN": {
          "enabled": true,
          "group_ids": [2],
          "subject": "DOWN | {{SERVICE_NAME}} | {{MONITOR_TYPE}}",
          "message": "Kontrol={{MONITOR_TYPE}} Durum={{STATUS}} Latency={{LATENCY_MS}} ms"
        },
        "RECOVERY": {
          "enabled": true,
          "group_ids": [2],
          "subject": "RECOVERY | {{SERVICE_NAME}}",
          "message": "{{SERVICE_NAME}} tekrar UP."
        }
      }
    },
    {
      "name": "Server Ping",
      "control_type": "ping",
      "config": {
        "host": "10.0.0.10",
        "timeout": 5
      },
      "notifications": {
        "DOWN": {
          "enabled": true,
          "group_ids": [3]
        }
      }
    },
    {
      "name": "Application DB",
      "control_type": "postgresql",
      "config": {
        "host": "10.0.0.20",
        "port": 5432,
        "username": "monitor",
        "password": "********",
        "database": "app"
      },
      "notifications": {
        "DOWN": {
          "enabled": true,
          "group_ids": [4]
        }
      }
    }
  ]
}
```

### Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v2/control-types` | Dynamic control type/field catalog |
| GET | `/api/v2/notification-fields` | Template variables |
| GET | `/api/v2/services` | Paginated service list with control breakdown |
| POST | `/api/v2/services` | Create service + N controls |
| GET | `/api/v2/services/{id}` | Full service/control configuration |
| GET | `/api/v2/services/{sid}/detail` | Legacy-quality detailed view, rebuilt per control (certificate/TLS/headers/screenshots/checks/incidents) |
| GET | `/api/v2/services/{sid}/controls/{cid}/preview` | Live control test without persisting a check |
| PUT | `/api/v2/services/{id}` | Replace control set atomically |
| DELETE | `/api/v2/services/{id}` | Delete service and dependent monitoring history |
| GET | `/api/v2/services/{sid}/controls/{cid}/metrics` | Paginated control metrics |
| GET | `/api/v2/services/{sid}/events` | Control-level event log |
| GET | `/api/v2/reports/{sid}/weekly` | Seven-day detailed report model |
| GET | `/api/v2/reports/{sid}/export/{kind}` | `json`, `xml`, `txt`, `html`, `pdf` |
| GET | `/api/v2/screenshots` | Search/filter/paginated screenshots |

All v2 routes are protected by the existing authentication/permission middleware.
Secret control fields are redacted in GET responses and `"********"` preserves
the existing secret during an update.

### State model

A control is evaluated independently:

`UP → WARNING → DOWN → RECOVERY(UP)`

`Service.status` is derived:

1. Any `DOWN` control → `DOWN`
2. Otherwise any `WARNING` control → `WARNING`
3. Otherwise all enabled controls `UP` → `UP`
4. Otherwise → `UNKNOWN`

This prevents a failed PostgreSQL control from incorrectly overwriting the
independent Ping/Web state.

### Migration

Startup performs an additive migration:

1. Creates `monitor_controls`, `control_notification_policies` and their group relation.
2. Adds nullable `control_id` columns to historical result/event/incident/audit/screenshot/notification tables.
3. Converts every legacy `Service` into one `MonitorControl`.
4. Converts legacy DOWN/RECOVERY/WARNING notification settings into control policies.
5. Attaches legacy history to the migrated control.

No legacy service columns are removed.
