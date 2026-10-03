from fastapi import APIRouter, status
from server.models import SecurityEvent, EventBatch
from server.engine.engine import engine
from server.database import SessionLocal, AlertRecord

router = APIRouter(prefix="/api/v1", tags=["Ingest"])

def save_alerts(alerts: list):
    if not alerts:
        return
    db = SessionLocal()
    try:
        for a in alerts:
            record = AlertRecord(
                rule_id=a["rule_id"],
                rule_name=a["rule_name"],
                severity=a["severity"],
                entity=a["entity"],
                count=a["count"],
                description=a["description"]
            )
            db.add(record)
        db.commit()
    finally:
        db.close()

@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: SecurityEvent):

    # Procesar el evento con el motor de reglas
    alerts = engine.process_event(event)

    # Imprimir alertas si se activó alguna regla
    if alerts:
        save_alerts(alerts)
        for alert in alerts:
            print(f"\n🚨 [ALERTA GUARDADA EN DB] {alert['rule_name']} -> {alert['entity']}")

    return {
        "status": "accepted",
        "alerts_triggered": len(alerts)
    }


@router.post("/events/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_events(batch: EventBatch):
    
    total_alerts = []
    for ev in batch.events:
        alerts = engine.process_event(ev)
        if alerts:
            total_alerts.extend(alerts)

    save_alerts(total_alerts)

    return {"status": "accepted", "count": len(batch.events), "alerts_triggered": len(total_alerts)}