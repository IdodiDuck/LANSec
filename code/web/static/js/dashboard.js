function fetchRealAlerts() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            const alerts = data.alerts; 
            const container = document.getElementById('alerts-container');
            if (!container) return;
            
            container.innerHTML = ''; 

            alerts.forEach(alert => {
                const alertElement = document.createElement('div');
                alertElement.className = 'alert-item';
                
                alertElement.innerHTML = `
                    <div class="alert-header">
                        <div class="alert-severity severity-high">ALERT</div>
                        <div class="alert-time">${alert.time}</div>
                    </div>
                    <div class="alert-name">Intrusion Detection System</div>
                    <div class="alert-data">
                        ${alert.content}
                    </div>
                    <div class="alert-action">
                        <div class="action-icon action-block">🛡️</div>
                        <span>Logged & Monitored</span>
                    </div>
                `;
                
                container.appendChild(alertElement);
            });
        })
        .catch(err => console.error("Error fetching alerts:", err));
}

document.addEventListener('DOMContentLoaded', () => {
    fetchRealAlerts();
    
    setInterval(fetchRealAlerts, 5000);
});