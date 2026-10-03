from fastapi import FastAPI
from server.api.ingest import router as ingest_router
from server.api.alerts import router as alerts_router
from server.database import init_db

# Inicializar tablas SQLite
init_db()

app = FastAPI(
    title="Mini-SIEM Server",
    version="0.1.0",
    description="Servidor de ingesta y motor de detección de seguridad"
)

# Registrar las rutas de ingesta
app.include_router(ingest_router)
app.include_router(alerts_router)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    # Ejecuta el servidor en http://localhost:8000
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)