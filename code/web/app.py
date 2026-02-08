import logging
import threading
from flask import Flask, render_template, jsonify
from wsgiref.simple_server import make_server

from prevent import iptbls
from utils.log_parser import get_parsed_alerts

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

@app.route('/')
def home():
    blocked = list(set(iptbls.blocked_ips))
    return render_template('index.html', blocked_ips=blocked)

@app.route('/api/alerts')
def get_alerts_api():
    alerts = get_parsed_alerts('../logs/system.log')
    return jsonify({"alerts": alerts})

@app.route('/unblock/<ip>')
def unblock_ip(ip):
    iptbls.unblock(ip)
    return jsonify({"status": "success"})

def run_server():
    try:
        httpd = make_server('0.0.0.0', 5000, app)
        httpd.serve_forever()
    except Exception as e:
        print(f"Web UI Error: {e}")

def start_ui():
    ui_thread = threading.Thread(target=run_server, daemon=True)
    ui_thread.start()
    print("Web UI is running on http://localhost:5000")