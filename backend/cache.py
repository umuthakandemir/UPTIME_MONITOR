"""Redis önbellek katmanı.

Tasarım ilkeleri (veri bütünlüğü ve doğruluğu için):

1. Redis YALNIZCA türetilmiş, yeniden üretilebilir ve kısa süre bayat kalması
   kabul edilebilir verilerde kullanılır (ör. geçmişe dönük analitik).
   Canlı durum (UP/DOWN), bildirimler, oturum/yetki, kontrol sonuçları ve
   yazma yolları ASLA önbelleğe alınmaz.
2. Redis kapalıysa uygulama aynen çalışır: her çağrı doğrudan hesaplamaya düşer.
   Bağlantı hatasında devre kesici açılır; her istekte tekrar bağlanmayı
   denemez (eski sürümde her çağrı 1,5 sn timeout bekleyebiliyordu).
3. Anahtarlar "namespace sürümü" ile üretilir. Veri değiştiğinde sürüm
   artırılır (bump) ve eski girdiler tek hamlede geçersiz olur; SCAN/DEL
   gerekmez. Sürüm hesaplamadan ÖNCE okunur; hesaplama sırasında gelen bir
   invalidation, sonucun yeni sürüme yazılmasını engeller (eski veri yeni
   anahtara asla yazılmaz).
4. Aynı anahtar için eşzamanlı cache-miss'lerde yalnızca bir istek hesaplar
   (tek-uçuş kilidi); diğerleri sonucu bekler (cache stampede önlenir).
5. Hem cache hit hem miss aynı JSON biçimini döndürür (jsonable_encoder),
   böylece tarih alanları iki yolda da aynı formattadır.
6. TTL her zaman üst sınırdır; invalidation kaçırılsa bile bayatlık TTL ile
   sınırlıdır.
"""
import json
import logging
import os
import random
import threading
import time
import uuid

log = logging.getLogger("uptime.cache")

_PREFIX = os.getenv("CACHE_PREFIX", "uptimemonitor")
_RETRY_AFTER = float(os.getenv("REDIS_RETRY_SECONDS", "30"))
_state_lock = threading.Lock()
_client_obj = None
_down_until = 0.0

_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


def _trip(reason):
    """Devre kesiciyi aç: bir süre Redis'e hiç gitme."""
    global _client_obj, _down_until
    with _state_lock:
        _client_obj = None
        _down_until = time.monotonic() + _RETRY_AFTER
    log.warning("Redis devre dışı (%ss): %s", int(_RETRY_AFTER), reason)


def _client():
    """Bağlı Redis istemcisini döndür; yoksa/erişilemezse None."""
    global _client_obj
    if _client_obj is not None:
        return _client_obj
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return None  # REDIS_URL tanımlı değilse önbellek kapalıdır.
    if time.monotonic() < _down_until:
        return None
    with _state_lock:
        if _client_obj is not None:
            return _client_obj
        if time.monotonic() < _down_until:
            return None
    try:
        import redis
        client = redis.Redis.from_url(
            url, socket_connect_timeout=0.5, socket_timeout=0.5,
            decode_responses=True, health_check_interval=30,
        )
        client.ping()
    except Exception as exc:
        _trip(exc)
        return None
    with _state_lock:
        _client_obj = client
    return client


def is_available():
    return _client() is not None


def _version(client, ns):
    value = client.get(f"{_PREFIX}:ver:{ns}")
    return int(value) if value else 0


def bump(ns):
    """Namespace'teki tüm girdileri geçersiz kıl. Başarılıysa True."""
    client = _client()
    if not client:
        return False
    try:
        client.incr(f"{_PREFIX}:ver:{ns}")
        return True
    except Exception as exc:
        _trip(exc)
        return False


def _data_key(ns, version, key):
    return f"{_PREFIX}:{ns}:{version}:{key}"


def _encode(value):
    from fastapi.encoders import jsonable_encoder
    return jsonable_encoder(value)


def get_or_compute(ns, key, ttl, compute, lock_ttl=20, wait_seconds=3.0):
    """Cache-aside + tek-uçuş. (değer, meta) döndürür.

    meta = {"hit": bool, "age_seconds": float|None, "backend": "redis"|"none"}
    `compute` her zaman JSON'a çevrilebilir bir değer üretmelidir.
    """
    client = _client()
    if not client:
        return _encode(compute()), {"hit": False, "age_seconds": None, "backend": "none"}

    lock_key, token, have_lock = None, None, False
    try:
        version = _version(client, ns)
        data_key = _data_key(ns, version, key)
        raw = client.get(data_key)
        if raw:
            entry = json.loads(raw)
            return entry["v"], {"hit": True, "age_seconds": round(time.time() - entry["t"], 1), "backend": "redis"}

        lock_key = f"{data_key}:lock"
        token = uuid.uuid4().hex
        have_lock = bool(client.set(lock_key, token, nx=True, ex=int(lock_ttl)))
        if not have_lock:
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                time.sleep(0.1)
                raw = client.get(data_key)
                if raw:
                    entry = json.loads(raw)
                    return entry["v"], {"hit": True, "age_seconds": round(time.time() - entry["t"], 1), "backend": "redis"}
    except Exception as exc:
        _trip(exc)
        return _encode(compute()), {"hit": False, "age_seconds": None, "backend": "none"}

    try:
        value = _encode(compute())
    except Exception:
        _release(client, lock_key, token, have_lock)
        raise
    try:
        # Sürüm hesaplamadan önce okundu: araya invalidation girdiyse bu yazı eski
        # sürüm anahtarına gider ve hiçbir zaman okunmaz.
        spread = max(1, int(ttl * 0.1))
        client.setex(data_key, max(1, int(ttl) + random.randint(0, spread)),
                     json.dumps({"v": value, "t": time.time()}, ensure_ascii=False))
    except Exception as exc:
        _trip(exc)
    finally:
        _release(client, lock_key, token, have_lock)
    return value, {"hit": False, "age_seconds": 0.0, "backend": "redis"}


def _release(client, lock_key, token, have_lock):
    if not have_lock or not lock_key or not token:
        return
    try:
        client.eval(_RELEASE_LUA, 1, lock_key, token)
    except Exception:
        pass
