let lastAlertCount = -1;

window.unblockIP = async function(ip) {
    if (!confirm(`Are you sure you want to release the block for: ${ip}?`)) return;

    try {
        const response = await fetch(`/unblock/${ip}`);
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        if (data.status === "success") {
            console.log("IP Unblocked successfully");
            lastAlertCount = -1; 
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
            const blockedListContainer = document.getElementById('blocked-ips-list');
            const blockedCountElement = document.getElementById('blocked-count');

            if (blockedCountElement && data.blocked_ips) {
                blockedCountElement.innerText = data.blocked_ips.length;
            }

            if (blockedListContainer && data.blocked_ips) {
                blockedListContainer.innerHTML = '';
                if (data.blocked_ips.length === 0) {
                    blockedListContainer.innerHTML = `<div style="color: #64748b; font-size: 0.85rem; padding: 15px; text-align: center;">No active blocks</div>`;
                } else {
                    data.blocked_ips.forEach(ip => {
                        const div = document.createElement('div');
                        div.className = 'blocked-ip-item';
                        div.innerHTML = `
                            <span class="ip-address">${ip}</span>
                            <button class="unblock-btn" onclick="window.unblockIP('${ip}')">Release</button>
                        `;
                        blockedListContainer.appendChild(div);
                    });
                }
            }

            if (container && data.alerts.length !== lastAlertCount) {
                lastAlertCount = data.alerts.length;
                container.innerHTML = '';

                if (!data.alerts || data.alerts.length === 0) {
                    container.innerHTML = `<div class="alert-item"><p style="text-align: center; color: #94a3b8;">🛡️ System Secure</p></div>`;
                } else {
                    data.alerts.forEach(alert => {
                        const alertElement = document.createElement('div');
                        alertElement.className = 'alert-item new-alert';
                        const severity = (alert.severity || "NORMAL").toLowerCase();

                        alertElement.innerHTML = `
                            <div class="alert-header">
                                <div class="severity-bubble sev-${severity}">${alert.severity}</div>
                                <div class="alert-time">${alert.time}</div>
                            </div>
                            <div class="alert-name" style="margin-top: 10px; font-weight: 600; color: #f1f5f9;">
                                ${alert.attack_type}
                            </div>
                            <details class="alert-details">
                                <summary>View Technical Analysis</summary>
                                <div class="alert-data">${alert.details}</div>
                            </details>
                            <div class="alert-action">
                                <div class="action-icon action-block">🛡️</div>
                                <span>Automatic Protection Active</span>
                            </div>
                        `;
                        container.prepend(alertElement);
                    });
                }
            }
        })
        .catch(err => console.error("Dashboard Sync Error:", err));
}

document.addEventListener('DOMContentLoaded', () => {
    fetchRealAlerts();
    setInterval(fetchRealAlerts, 3000);
});