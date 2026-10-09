"""Önbellek invalidation kancaları.

Servis / kontrol eklenmesi, silinmesi veya izlemeyi etkileyen alanların
(enabled, name, monitor_type/control_type) değişmesi durumunda "analytics"
namespace'i, İŞLEM COMMIT EDİLDİKTEN SONRA geçersiz kılınır. Rollback olursa
hiçbir şey yapılmaz. Her kontrol sonrası değişen alanlar (last_status,
last_latency_ms, last_check_at ...) bilinçli olarak izlenmez; bu alanlar zaten
önbelleğe alınmaz.
"""
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from .cache import bump
from .models import MonitorControl, Service

ANALYTICS_NS = "analytics"
_TRACKED = (Service, MonitorControl)
_WATCHED_ATTRS = ("enabled", "name", "monitor_type", "control_type", "service_id")


def _dirty_tracked(obj):
    state = inspect(obj)
    for attr in _WATCHED_ATTRS:
        if attr in state.attrs.keys() and state.attrs[attr].history.has_changes():
            return True
    return False


@event.listens_for(Session, "after_flush")
def _mark_dirty(session, flush_context):
    if session.info.get("analytics_dirty"):
        return
    for obj in session.new:
        if isinstance(obj, _TRACKED):
            session.info["analytics_dirty"] = True
            return
    for obj in session.deleted:
        if isinstance(obj, _TRACKED):
            session.info["analytics_dirty"] = True
            return
    for obj in session.dirty:
        if isinstance(obj, _TRACKED) and _dirty_tracked(obj):
            session.info["analytics_dirty"] = True
            return


@event.listens_for(Session, "after_commit")
def _bump_after_commit(session):
    if session.info.pop("analytics_dirty", False):
        bump(ANALYTICS_NS)


@event.listens_for(Session, "after_rollback")
def _clear_on_rollback(session):
    session.info.pop("analytics_dirty", None)


def invalidate_analytics():
    """Toplu silme/temizlik gibi ORM olayı üretmeyen yollar için açık çağrı."""
    return bump(ANALYTICS_NS)
