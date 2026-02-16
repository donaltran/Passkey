from pydantic import BaseModel
from datetime import datetime
import uuid

class VaultCreate(BaseModel):
    encrypted_data: str   # AES-256-GCM ciphertext, base64 encoded
    iv: str               # Initialization vector, base64 encoded

class VaultUpdate(BaseModel):
    encrypted_data: str
    iv: str

class VaultResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    encrypted_data: str
    iv: str
    version: int
    updated_at: datetime

    model_config = {"from_attributes": True}
