const INITIAL_ALERT_COUNT = -1;
const REFRESH_INTERVAL_MS = 3000;

let lastAlertCount = INITIAL_ALERT_COUNT;

window.unblockIP = async function(ip) {
    if (!confirm(`Are you sure you want to release the block for: ${ip}?`)) return;

    try {
        const response = await fetch(`/unblock/${ip}`);
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        if (data.status === "success") {
            console.log("IP Unblocked successfully");
            lastAlertCount = INITIAL_ALERT_COUNT; 
            fetchRealAlerts();
        }
    } catch (err) {
        console.error("Error unblocking IP:", err);
        alert("Failed to unblock IP.");
    }
};

function fetchRealAlerts() {
    fetch('/api/alerts', { cache: 'no-store' })
        .then(response => {
            if (!response.ok) throw new Error('API unreachable');
            return response.json();
        })
        .then(data => {
            const container = document.getElementById('alerts-container');
            const blockedCountElement = document.getElementById('blocked-count');
            const blockedListContainer = document.getElementById('blocked-ips-list');

            if (blockedCountElement && data.blocked_ips) {
                blockedCountElement.innerText = data.blocked_ips.length;
            }

            if (blockedListContainer && data.blocked_ips) {
                blockedListContainer.innerHTML = '';
                data.blocked_ips.forEach(ip => {
                    const div = document.createElement('div');
                    div.className = 'blocked-ip-item';
                    div.innerHTML = `
                        <span class="ip-address">${ip}</span>
                        <button class="unblock-btn" onclick="window.unblockIP('${ip}')">Unblock</button>
                    `;
                    blockedListContainer.appendChild(div);
                });
            }

            if (container && data.alerts.length !== lastAlertCount) {
                lastAlertCount = data.alerts.length;
                container.innerHTML = '';

                if (!data.alerts || data.alerts.length === 0) {
                    container.innerHTML = `<div class="alert-item"><p style="text-align: center; color: #94a3b8;">🛡️ System Secure</p></div>`;
                } else {
                    data.alerts.slice().forEach(alert => {
                        const alertElement = document.createElement('div');
                        alertElement.className = 'alert-item new-alert';
                        
                        const sevMap = { 'CRITICAL': 'high', 'DANGEROUS': 'high', 'SUSPICIOUS': 'medium', 'NORMAL': 'low' };
                        const severityClass = sevMap[alert.severity] || 'low';
                        const flowText = alert.src_ip ? `${alert.src_ip} → ${alert.dst_ip}` : 
                                        (alert.src_mac ? `${alert.src_mac} → ${alert.dst_mac}` : "System Event");

                        alertElement.innerHTML = `
                            <div class="alert-header">
                                <div class="severity-bubble sev-${severityClass}">${alert.severity}</div>
                                <div class="alert-time">${alert.time}</div>
                            </div>
                            <div class="alert-content">
                                <div class="alert-name" style="margin-top: 5px; font-weight: 600; color: #f1f5f9;">${alert.attack_type}</div>
                                <div class="alert-flow" style="font-family: 'JetBrains Mono', monospace; color: #94a3b8; font-size: 0.85rem; margin: 5px 0;">${flowText}</div>
                            </div>
                            <details class="alert-details">
                                <summary>View Technical Analysis</summary>
                                <div class="alert-data" style="white-space: pre-wrap;">${alert.details}</div>
                            </details>
                            <div class="alert-action">
                                <div class="action-icon">🛡️</div>
                                <span>Automatic IPS Block Active</span>
                            </div>
                        `;

                        container.appendChild(alertElement);
                    });
                }
            }
        })
        .catch(err => console.error("Dashboard Sync Error:", err));
}

document.addEventListener('DOMContentLoaded', () => {
    fetchRealAlerts();
    setInterval(fetchRealAlerts, REFRESH_INTERVAL_MS);
});