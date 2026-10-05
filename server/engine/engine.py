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
        self.history: Dict[str, Dict[str, List[tuple]]] = defaultdict(lambda: defaultdict(list))
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
            distinct_field = detection.get("distinct")

            # Obtener el valor de agrupación (ej. IP de origen)
            group_val = self._get_nested_field(event, group_key_field) if group_key_field else "global"
            if not group_val:
                continue

            distinct_val = self._get_nested_field(event, distinct_field) if distinct_field else None

            rule_id = rule["id"]
            records = self.history[rule_id][group_val]

            # Guardar evento y descartar los que estén fuera de la ventana temporal
            records.append((event_time, distinct_val))
            cutoff_time = event_time - timedelta(seconds=time_window)
            records = [item for item in records if item[0] >= cutoff_time]
            self.history[rule_id][group_val] = records

            # Conteo normal o conteo por valores únicos
            if distinct_field:
                unique_vals = {item[1] for item in records if item[1] is not None}
                count = len(unique_vals)
                print(f"[DEBUG Rule: {rule_id}] IP: {group_val} -> Puertos vistos: {unique_vals} ({count}/{threshold})")
            else:
                count = len(records)
                print(f"[DEBUG Rule: {rule_id}] IP: {group_val} -> Conteo: {count}/{threshold}")

            if count >= threshold:
                alert = {
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "timestamp": event_time.isoformat(),
                    "entity": str(group_val),
                    "count": count,
                    "description": rule["description"]
                }
                alerts.append(alert)
                self.history[rule_id][group_val] = []

        return alerts


# Instancia singleton para usar en los endpoints
engine = RuleEngine()