from utils.logger import get_logger
logger = get_logger()

import attacks
from scapy.all import sniff
from os import system
import time

def clear_screen():
    try:
        system("clear")
        system("cls")

    except:
        pass

def main():

    clear_screen()

    logger.info("Starting LanSec...")
    logger.info("Initializing Detection Engine...")
    
    searched_attacks = attacks.load_attacks(logger)
    logger.info("Detection Engine Initialized.")

    time.sleep(3)
    clear_screen()
    print("LanSec - Local Area Network Security\n" + "-"*36)

    def snf(pkt):
        for attack in searched_attacks:
            attack.inspect(pkt)

    sniff(prn=snf, store=0)

if __name__ == "__main__":
    main()
