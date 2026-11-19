from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from server.api.ingest import router as ingest_router
from server.api.alerts import router as alerts_router
from server.database import init_db
from firma_iml15 import mostrar_firma
import os
import sys

# Firma IML15: se muestra al arrancar (python -m server.main o uvicorn server.main:app).
# La variable evita que salga dos veces cuando --reload lanza el proceso hijo, y no se
# muestra al ejecutar los tests.
if os.environ.get("IML15_FIRMA_MOSTRADA") != "1" and "pytest" not in sys.modules:
    os.environ["IML15_FIRMA_MOSTRADA"] = "1"
    mostrar_firma(version="v0.1.0")

# Inicializar tablas SQLite
init_db()

app = FastAPI(
    title="Mini-SIEM Server",
    version="0.1.0",
    description="Servidor de ingesta y motor de detección de seguridad"
)

# Rutas API
app.include_router(ingest_router)
app.include_router(alerts_router)

# Montar dashboard como archivos estáticos
dashboard_path = os.path.abspath("dashboard")
if os.path.exists(dashboard_path):
    app.mount("/dashboard", StaticFiles(directory=dashboard_path), name="dashboard")

@app.get("/")
async def root():
    """Redirigir o servir directamente el frontend"""
    index_file = os.path.join(dashboard_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "ok", "docs": "/docs"}


@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    # Ejecuta el servidor en http://localhost:8000
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)