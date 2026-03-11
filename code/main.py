# Python Libraries Importations - 
import os
import time
from threading import Thread
from scapy.all import sniff

# LANSec Modules Importations - 
import events
import utils.logger as logger
from web.app import start_ui
from prevent.iptbls import clear as clear_blocked_ips
from detect.anomaly_detector import AnomalyDetector
from detect.data_aggregator import DataAggregator
from configuration.config import NET_INTERFACE

# Global Objects for Anomaly-Based Detection
detector = AnomalyDetector(logger)
aggregator = DataAggregator(detector)

def run_anomaly_analysis():
    """Background thread to analyze network statistics for anomalies every 10s."""
    while True:
        time.sleep(10)
        aggregator.analyze_and_reset()

def packet_handler(pkt, monitored_events):
    """Processes each captured packet against security signatures and statistics."""
    for event in monitored_events:
        event.inspect(pkt)

    aggregator.add_packet(pkt)

def start_sniffing_threads(searched_events):
    """Groups events by filter and starts a daemon sniffing thread for each group."""

    events_by_fltr = {}
    for event in searched_events:
        if event._snf_filter not in events_by_fltr:
            events_by_fltr[event._snf_filter] = []

        events_by_fltr[event._snf_filter].append(event)

    for snf_fltr, events_list in events_by_fltr.items():
        t = Thread(target=lambda f=snf_fltr, evs=events_list: sniff(filter=f, iface=NET_INTERFACE, prn=lambda pkt: packet_handler(pkt, evs), store=0))
        t.daemon = True
        t.start()

    print(f"[!] Sniffing engines active on {NET_INTERFACE}")

def initialize_system():
    """Initializes logging, UI, and security events."""
    if os.geteuid() != 0:
        logger.error("Project requires root privileges")
        exit(1)
    
    log_obj = logger.setup_logger(to_console=False)
    logger.recent_alerts.clear()
    
    start_ui()
    time.sleep(1)
    return events.load_monitored_events(log_obj)

def main():
    try:
        monitored_events = initialize_system()

        # Start Anomaly Engine
        Thread(target=run_anomaly_analysis, daemon=True).start()

        # Start Sniffing Engines
        print("LanSec - Local Area Network Security\n" + "-" * 36)
        start_sniffing_threads(monitored_events)

        # Keep Main Thread Alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Stopping LanSec...")

    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")

    finally:
        logger.info("LanSec stopped cleanly")
        clear_blocked_ips()
        exit(0)

if __name__ == "__main__":
    main()