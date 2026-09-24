from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class NetworkDetails(BaseModel):
    """Detalles de red opcionales si el log involucra tráfico IP."""
    src_ip: Optional[str] = Field(None, description="IP de origen")
    dst_ip: Optional[str] = Field(None, description="IP de destino")
    src_port: Optional[int] = Field(None, ge=1, le=65535, description="Puerto de origen")
    dst_port: Optional[int] = Field(None, ge=1, le=65535, description="Puerto de destino")
    protocol: Optional[str] = Field(None, description="TCP, UDP, ICMP, etc.")


class AuthDetails(BaseModel):
    """Detalles comunes para eventos de autenticación (SSH, sudo, etc.)."""
    user: Optional[str] = Field(None, description="Usuario objetivo o que ejecuta la acción")
    success: Optional[bool] = Field(None, description="¿Fue exitosa la autenticación?")
    auth_method: Optional[str] = Field(None, description="password, publickey, etc.")


class SecurityEvent(BaseModel):
    """Contrato base para un evento procesado o ingestado."""
    # Metadatos del origen
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Marca de tiempo en formato ISO 8601 (UTC)"
    )
    hostname: str = Field(..., min_length=1, description="Nombre o identificador del host/agente")
    source_type: str = Field(..., description="Tipo de origen: 'linux_auth', 'syslog', 'auditd', etc.")
    
    # Contenido del log
    raw_message: str = Field(..., description="El log textual original sin procesar")
    
    # Campos normalizados (opcionales según el tipo de log)
    network: Optional[NetworkDetails] = Field(default=None)
    auth: Optional[AuthDetails] = Field(default=None)
    
    # Bolsa de atributos adicionales no normalizados
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Campos arbitrarios parseados no cubiertos por el esquema fijo"
    )


class EventBatch(BaseModel):
    """Esquema para envío por lotes (eficiencia de red desde el agente)."""
    events: list[SecurityEvent] = Field(..., min_length=1)