from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text

from datetime import datetime
import uuid
from app.db.base import Base

class Vault(Base):
    __tablename__ = "vaults"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    encrypted_data = Column(Text, nullable=False)
    iv = Column(String, nullable=False)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)