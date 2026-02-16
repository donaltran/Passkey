from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
import uuid

class UserCreate(BaseModel):
    email: EmailStr
    auth_key_hash: str   # PBKDF2/Argon2 hash of master password, done CLIENT-SIDE
    salt: str            # base64-encoded salt, generated client-side

class UserLogin(BaseModel):
    email: EmailStr
    auth_key_hash: str

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    created_at: datetime

    model_config = {"from_attributes": True}

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None
