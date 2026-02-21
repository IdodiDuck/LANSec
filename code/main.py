import os
from threading import Thread
import time
from scapy.all import sniff

from web.app import start_ui
import utils.logger as logger
from prevent.iptbls import clear as clear_blocked_ips
from detect.anomaly_detector import AnomalyDetector
from detect.data_aggregator import DataAggregator
import attacks

detector = AnomalyDetector(logger)
aggregator = DataAggregator(detector)

def anomaly_logic():
    while True:
        time.sleep(10)
        aggregator.analyze_and_reset()

def packet_handler(pkt, searched_attacks):
    # Checking for attacks signatures/patterns
    for attack in searched_attacks:
        attack.inspect(pkt)

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
    searched_attacks = attacks.load_attacks(log_obj)

    # Activating anomaly behavior detection statistics collection
    timer_thread = Thread(target=anomaly_logic, daemon=True)
    timer_thread.start()

    print("LanSec - Local Area Network Security\n" + "-" * 36)
    
    # Attacks are devided by their sniffing filter
    attacks_by_fltr = {}
    for attack in searched_attacks:
        if attack._snf_filter not in attacks_by_fltr:
            attacks_by_fltr[attack._snf_filter] = []

        attacks_by_fltr[attack._snf_filter].append(attack)

    try:
        for snf_fltr, attacks_list in attacks_by_fltr.items():
            Thread(target=lambda fltr=snf_fltr, attacks=attacks_list:
                   sniff(filter=fltr, prn=lambda pkt: packet_handler(pkt, attacks), store=0)).start()
        
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