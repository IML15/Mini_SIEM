async function fetchAlerts() {
  try {
    const res = await fetch('/api/v1/alerts');
    if (!res.ok) return;
    const alerts = await res.json();

    // Actualización de KPIs
    const elTotal = document.getElementById('totalAlerts');
    const elHigh = document.getElementById('highAlerts');
    const elEntities = document.getElementById('uniqueEntities');

    if (elTotal) elTotal.innerText = alerts.length;
    if (elHigh) elHigh.innerText = alerts.filter(a => a.severity === 'HIGH').length;
    if (elEntities) elEntities.innerText = new Set(alerts.map(a => a.entity)).size;

    // Actualización de la Tabla
    const tbody = document.getElementById('alertsBody');
    if (!tbody) return;

    if (alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No se han detectado incidentes de seguridad todavía.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>#${a.id}</td>
        <td>${new Date(a.created_at).toLocaleTimeString()}</td>
        <td><strong>${a.rule_name}</strong></td>
        <td><span class="severity severity-${a.severity}">${a.severity}</span></td>
        <td><code class="code-badge">${a.entity}</code></td>
        <td>${a.count}</td>
        <td>${a.description}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error("Error al obtener alertas:", err);
  }
}

// Inicializar y refrescar automáticamente cada 2 segundos
document.addEventListener('DOMContentLoaded', () => {
  fetchAlerts();
  setInterval(fetchAlerts, 2000);
});