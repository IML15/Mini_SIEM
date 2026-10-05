FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias necesarias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el backend, las reglas y los archivos estáticos del panel
COPY server/ ./server/
COPY rules/ ./rules/
COPY dashboard/ ./dashboard/

# Exponer el puerto de FastAPI
EXPOSE 8000

# Arrancar la aplicación
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]