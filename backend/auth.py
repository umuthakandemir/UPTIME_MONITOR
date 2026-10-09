import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from .models import User, SecurityConfig

ROLES = {
    "super_admin": "Super Admin",
    "admin": "Admin",
    "read_only_super_admin": "Read Only Super Admin",
    "read_only_admin": "Read Only Admin",
    "semi_admin": "Semi Admin",
    "read_only_semi_admin": "Semi Admin Read Only",
}
READ_ROLES = set(ROLES)
WRITE_ROLES = {"super_admin", "admin", "semi_admin"}
SUPER_ROLES = {"super_admin", "read_only_super_admin"}
READ_ONLY_ROLES = {"read_only_super_admin", "read_only_admin", "read_only_semi_admin"}

def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False

def _env_secret() -> str | None:
    value = os.getenv("JWT_SECRET", "").strip()
    return value or None

def ensure_security(db: Session) -> SecurityConfig:
    """Create the persisted security row once; never rotate it on every request."""
    sec = db.query(SecurityConfig).first()
    if sec:
        return sec
    secret = _env_secret() or secrets.token_urlsafe(48)
    sec = SecurityConfig(jwt_secret_sha=secret, jwt_secret_created_at=datetime.utcnow())
    db.add(sec)
    db.commit()
    db.refresh(sec)
    return sec

def _jwt_secret(db: Session) -> str:
    return _env_secret() or ensure_security(db).jwt_secret_sha

def ensure_admin(db: Session):
    if db.query(User).count() == 0:
        ensure_security(db)
        u = User(
            username="admin", password_hash=_hash_password("admin"), role="super_admin",
            display_name="İlk Yönetici", email="", email_verified=True, is_active=True,
            is_initial_admin=True, must_change_password=True, created_at=datetime.utcnow()
        )
        db.add(u)
        db.commit()
        return u
    ensure_security(db)
    return db.query(User).filter(User.username == "admin").first()

def create_token(db: Session, user: User) -> str:
    secret = _jwt_secret(db)
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "username": user.username, "role": user.role,
               "iat": now, "exp": now + timedelta(hours=12), "jti": secrets.token_hex(12)}
    return jwt.encode(payload, secret, algorithm="HS256")

def current_user(request: Request, db: Session) -> User:
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else (request.cookies.get("um_access_token") or "")
    if not token:
        raise HTTPException(status_code=401, detail="Oturum gerekli")
    try:
        payload = jwt.decode(token, _jwt_secret(db), algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
    except Exception:
        raise HTTPException(status_code=401, detail="Oturum geçersiz veya süresi dolmuş")
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Kullanıcı pasif veya bulunamadı")
    return user
