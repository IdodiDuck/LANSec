# Python Modules Importations - 
import os
from threading import Thread
import time
from scapy.all import sniff

# Customized Modules Importations - 
from web.app import start_ui
import utils.logger as logger
from prevent.iptbls import clear as clear_blocked_ips
from detect.anomaly_detector import AnomalyDetector
from detect.data_aggregator import DataAggregator
import events
from configuration.config import NET_INTERFACE

detector = AnomalyDetector(logger)
aggregator = DataAggregator(detector)

def anomaly_logic():
    while True:
        time.sleep(10)
        aggregator.analyze_and_reset()

def packet_handler(pkt, monitored_events):
    # Checking for security events' signatures/patterns
    for event in monitored_events:
        event.inspect(pkt)

    # Collecting statistis
    aggregator.add_packet(pkt)

def main():
    log_obj = logger.setup_logger(to_console=False)
    
    logger.recent_alerts.clear()

    if os.geteuid() != 0:
        logger.error("Project requires root privileges")
        exit(1)

    start_ui()
    time.sleep(1)
    searched_events = events.load_monitored_events(log_obj)

    # Activating anomaly behavior detection statistics collection
    timer_thread = Thread(target=anomaly_logic, daemon=True)
    timer_thread.start()

    print("LanSec - Local Area Network Security\n" + "-" * 36)
    
    # Security Events are devided by their sniffing filter
    events_by_fltr = {}
    for event in searched_events:
        if event._snf_filter not in events_by_fltr:
            events_by_fltr[event._snf_filter] = []

        events_by_fltr[event._snf_filter].append(event)

    try:
        for snf_fltr, events_list in events_by_fltr.items():
            Thread(target=lambda fltr=snf_fltr, events=events_list:
                   sniff(filter=fltr, iface=NET_INTERFACE, prn=lambda pkt: packet_handler(pkt, events), store=0)).start()
        
        while True:
            os.system(input())
            
    except KeyboardInterrupt:
        print("\nStopping LanSec...")

    except Exception as e:
        print(f"\nFatal Error: {e}")

    finally:
        logger.info("LanSec stopped cleanly")
        logger.recent_alerts.clear()
        clear_blocked_ips()
        os._exit(0)

if __name__ == "__main__":
    main()