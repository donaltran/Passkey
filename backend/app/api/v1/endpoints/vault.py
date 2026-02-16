from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.models.vault import Vault
from app.schemas.vault import VaultCreate, VaultUpdate, VaultResponse

router = APIRouter()

@router.get("/", response_model=VaultResponse)
def get_vault(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vault = db.query(Vault).filter(Vault.user_id == current_user.id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    return vault

@router.post("/", response_model=VaultResponse, status_code=201)
def create_vault(
    vault_data: VaultCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(Vault).filter(Vault.user_id == current_user.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Vault already exists. Use PUT to update.")
    vault = Vault(
        user_id=current_user.id,
        encrypted_data=vault_data.encrypted_data,
        iv=vault_data.iv,
    )
    db.add(vault)
    db.commit()
    db.refresh(vault)
    return vault

@router.put("/", response_model=VaultResponse)
def update_vault(
    vault_data: VaultUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vault = db.query(Vault).filter(Vault.user_id == current_user.id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    vault.encrypted_data = vault_data.encrypted_data
    vault.iv = vault_data.iv
    vault.version += 1
    db.commit()
    db.refresh(vault)
    return vault

@router.delete("/", status_code=204)
def delete_vault(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vault = db.query(Vault).filter(Vault.user_id == current_user.id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    db.delete(vault)
    db.commit()
