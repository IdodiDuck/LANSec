from utils.logger import get_logger
logger = get_logger()

import attacks
from scapy.all import sniff
import os
import time
import platform

def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def packet_handler(pkt, searched_attacks):
    for attack in searched_attacks:
        attack.inspect(pkt)

def main():

    clear_screen()

    logger.info("Starting LanSec...")
    logger.info("Initializing Detection Engine...")
    
    searched_attacks = attacks.load_attacks(logger)
    logger.info("Detection Engine Initialized.")

    time.sleep(3)
    clear_screen()
    print("LanSec - Local Area Network Security\n" + "-"*36)

    sniff(prn=lambda pkt: packet_handler(pkt, searched_attacks), store=0)

if __name__ == "__main__":
    main()
