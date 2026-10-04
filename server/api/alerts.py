from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from server.database import SessionLocal, AlertRecord

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", status_code=200)
@router.get("/", status_code=200)
def list_alerts(db: Session = Depends(get_db)):
    """Devuelve las alertas generadas ordenadas de más reciente a más antigua."""
    alerts = db.query(AlertRecord).order_by(AlertRecord.created_at.desc()).all()
    return alerts

