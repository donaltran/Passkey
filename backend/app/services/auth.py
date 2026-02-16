from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import UserCreate, TokenData
import base64
import hashlib

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_auth_key(auth_key_hash: str) -> str:
    """Truncate to 72 bytes via SHA-256 before bcrypt to avoid the 72-byte limit."""
    truncated = hashlib.sha256(auth_key_hash.encode()).hexdigest()
    return pwd_context.hash(truncated)

def verify_auth_key(plain: str, hashed: str) -> bool:
    truncated = hashlib.sha256(plain.encode()).hexdigest()
    return pwd_context.verify(truncated, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> TokenData:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    user_id: str = payload.get("sub")
    if user_id is None:
        raise JWTError("Missing subject")
    return TokenData(user_id=user_id)

def register_user(db: Session, user_data: UserCreate) -> User:
    server_hash = hash_auth_key(user_data.auth_key_hash)
    salt_bytes = base64.b64decode(user_data.salt)
    db_user = User(
        email=user_data.email,
        auth_key_hash=server_hash,
        salt=user_data.salt
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, auth_key_hash: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_auth_key(auth_key_hash, user.auth_key_hash):
        return None
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def get_user_salt(db: Session, email: str) -> Optional[bytes]:
    """Return the user's salt so the client can derive the encryption key."""
    user = db.query(User).filter(User.email == email).first()
    return user.salt if user else None
