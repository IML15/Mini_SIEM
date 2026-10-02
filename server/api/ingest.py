from fastapi import APIRouter, status
from server.models import SecurityEvent, EventBatch
from server.engine.engine import engine

router = APIRouter(prefix="/api/v1", tags=["Ingest"])

@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: SecurityEvent):

    # Procesar el evento con el motor de reglas
    alerts = engine.process_event(event)

    # Imprimir alertas si se activó alguna regla
    if alerts:
        for alert in alerts:
            print("\n🚨 [ALERTA DISPARADA] 🚨")
            print(f"  Regla:    {alert['rule_name']} ({alert['rule_id']})")
            print(f"  Nivel:    {alert['severity']}")
            print(f"  Entidad:  {alert['entity']}")
            print(f"  Conteo:   {alert['count']} intentos")
            print(f"  Detalle:  {alert['description']}\n")

    return {
        "status": "accepted",
        "alerts_triggered": len(alerts)
    }


@router.post("/events/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_events(batch: EventBatch):
    
    total_alerts = 0
    for ev in batch.events:
        alerts = engine.process_event(ev)
        total_alerts += len(alerts)

    return {"status": "accepted", "count": len(batch.events), "alerts_triggered": total_alerts}