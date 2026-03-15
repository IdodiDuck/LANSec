import logging
import threading
from flask import Flask, render_template, jsonify

from prevent import iptbls
from utils.logger import recent_alerts

# Disable Flask's default console spam to keep the terminal clean for system alerts
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Constants for Server Configuration
ERROR_CODE = 500
PORT = 5000
LOCAL_HOST = '0.0.0.0'

@app.route('/')
def home():
    """
    Renders the main dashboard page.
    Passes the current list of blocked IPs to the template for initial rendering.
    """
    blocked = list(set(iptbls.blocked_ips))
    return render_template('index.html', blocked_ips=blocked)

@app.route('/api/alerts')
def get_alerts():
    """
    API Endpoint for the frontend to poll new data.
    Returns the latest security alerts and the current blacklist in JSON format.
    """
    return jsonify({
        "alerts": recent_alerts,
        "blocked_ips": list(set(iptbls.blocked_ips))
    })

@app.route('/unblock/<ip>')
def unblock_route(ip):
    """
    API Endpoint to manually unblock an IP address.
    Triggered when the user clicks the 'Unblock' button on the Dashboard.
    """
    try:
        # Compatibility check for unblock method names
        if hasattr(iptbls, 'unblock_ip'):
            iptbls.unblock_ip(ip)
        else:
            iptbls.unblock(ip) 
            
        return jsonify({"status": "success"})
    
    except Exception as e:
        print(f"Error during manual unblock action: {e}")
        return jsonify({"status": "error", "message": str(e)}), ERROR_CODE
    
def run_server():
    """ Internal helper to execute the Flask WSGI server """
    app.run(host=LOCAL_HOST, port=PORT, debug=False, use_reloader=False, threaded=True)

def start_ui():
    """
    Initializes the Web UI in a separate background thread.
    This ensures the Web Server does not block the main IDS/IPS sniffing loop.
    """
    ui_thread = threading.Thread(target=run_server, daemon=True)
    ui_thread.start()
    print(f"Web UI is running on http://localhost:{PORT}")