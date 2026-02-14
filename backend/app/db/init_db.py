from app.db.base import Base, engine
from app.models.user import User
from app.models.vault import Vault

def init_db():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)
    print("Database tables created!")

if __name__ == "__main__":
    init_db()
