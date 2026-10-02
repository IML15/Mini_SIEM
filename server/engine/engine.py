import os
import yaml
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from server.models import SecurityEvent


class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules: List[Dict[str, Any]] = []
        # Historial en memoria: { rule_id: { group_value: [timestamps] } }
        self.history: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self.load_rules()

    def load_rules(self):
        """Carga recursivamente todos los archivos .yaml en rules/."""
        self.rules.clear()
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        if rule and "id" in rule:
                            self.rules.append(rule)
        print(f"[*] Reglas cargadas en el motor: {len(self.rules)}")

    def _get_nested_field(self, obj: Any, key_path: str) -> Optional[Any]:
        """Permite obtener valores anidados usando puntos (ej: 'auth.success')."""
        keys = key_path.split(".")
        val = obj
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                val = getattr(val, k, None)
            if val is None:
                return None
        return val

    def _matches_filter(self, event: SecurityEvent, filters: Dict[str, Any]) -> bool:
        """Verifica si el evento cumple todos los filtros de la regla."""
        for field, expected_val in filters.items():
            actual_val = self._get_nested_field(event, field)
            if actual_val != expected_val:
                return False
        return True

    def process_event(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Evalúa un evento contra todas las reglas cargadas."""
        alerts = []
        event_time = event.timestamp or datetime.now(timezone.utc)

        for rule in self.rules:
            # 1. Validar condiciones base
            if not self._matches_filter(event, rule.get("filter", {})):
                continue

            detection = rule.get("detection", {})
            group_key_field = detection.get("group_by")
            threshold = detection.get("threshold", 1)
            time_window = detection.get("time_window", 60)

            # Obtener el valor de agrupación (ej. IP de origen)
            group_val = self._get_nested_field(event, group_key_field) if group_key_field else "global"
            if not group_val:
                continue

            rule_id = rule["id"]
            timestamps = self.history[rule_id][group_val]

            # 2. Agregar evento actual y descartar eventos fuera de la ventana
            timestamps.append(event_time)
            cutoff_time = event_time - timedelta(seconds=time_window)
            self.history[rule_id][group_val] = [t for t in timestamps if t >= cutoff_time]

            # 3. Evaluar umbral
            if len(self.history[rule_id][group_val]) >= threshold:
                alert = {
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "timestamp": event_time.isoformat(),
                    "entity": group_val,
                    "count": len(self.history[rule_id][group_val]),
                    "description": rule["description"]
                }
                alerts.append(alert)
                # Reseteamos tras disparar la alerta para evitar spam inmediato
                self.history[rule_id][group_val] = []

        return alerts


# Instancia singleton para usar en los endpoints
engine = RuleEngine()