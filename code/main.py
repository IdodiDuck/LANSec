from utils.logger import get_logger
logger = get_logger()

import attacks
from scapy.all import sniff

def packet_handler(pkt, searched_attacks):
    for attack in searched_attacks:
        attack.inspect(pkt)

def main():
    logger.info("Starting LanSec...")
    searched_attacks = attacks.load_attacks(logger)
    print("LanSec - Local Area Network Security\n" + "-"*36)

    sniff(prn=lambda pkt: packet_handler(pkt, searched_attacks), store=0)


if __name__ == "__main__":
    main()
