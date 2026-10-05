import pytest
from datetime import datetime, timezone
from server.engine.engine import RuleEngine
from server.models import SecurityEvent


@pytest.fixture
def rule_engine():
    """Instancia el motor cargando las reglas de la carpeta rules/."""
    return RuleEngine(rules_dir="rules")


def test_ssh_bruteforce_detection(rule_engine):
    """Verifica que se dispare la alerta tras 3 fallos de SSH desde la misma IP."""
    ip_atacante = "192.168.1.100"
    alerts = []

    # Enviamos 3 intentos fallidos consecutivos
    for i in range(3):
        event = SecurityEvent.model_validate({
            "hostname": "test-host",
            "source_type": "linux_auth",
            "raw_message": f"Failed password for user test{i}",
            "network": {"src_ip": ip_atacante},
            "auth": {"user": f"test{i}", "success": False},
            "timestamp": datetime.now(timezone.utc)
        })
        res = rule_engine.process_event(event)
        if res:
            alerts.extend(res)

    # Debe saltar exactamente 1 alerta de fuerza bruta SSH
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "linux-ssh-bruteforce"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["entity"] == ip_atacante
    assert alerts[0]["count"] == 3


def test_port_scan_detection(rule_engine):
    """Verifica que se detecte un escaneo al tocar 5 puertos diferentes."""
    ip_escaneo = "45.33.32.156"
    ports = [21, 22, 80, 443, 8080]
    alerts = []

    for port in ports:
        event = SecurityEvent.model_validate({
            "hostname": "test-host",
            "source_type": "network_flow",
            "raw_message": f"Connection attempt to port {port}",
            "network": {"src_ip": ip_escaneo, "dst_port": port},
            "timestamp": datetime.now(timezone.utc)
        })
        res = rule_engine.process_event(event)
        if res:
            alerts.extend(res)

    # Debe saltar exactamente 1 alerta de escaneo de puertos
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "network-port-scan"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["entity"] == ip_escaneo
    assert alerts[0]["count"] == 5


def test_port_scan_same_port_does_not_trigger(rule_engine):
    """Verifica que 5 peticiones al MISMO puerto no disparen el escaneo."""
    ip = "10.0.0.1"
    alerts = []

    # 5 peticiones repetidas al puerto 80 (tráfico web normal)
    for _ in range(5):
        event = SecurityEvent.model_validate({
            "hostname": "test-host",
            "source_type": "network_flow",
            "raw_message": "HTTP request to port 80",
            "network": {"src_ip": ip, "dst_port": 80},
            "timestamp": datetime.now(timezone.utc)
        })
        res = rule_engine.process_event(event)
        if res:
            alerts.extend(res)

    # No debe disparar alerta de port scan porque los puertos no son distintos
    assert len(alerts) == 0