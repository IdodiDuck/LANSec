import prevent.iptbls as iptbls
from utils.logger import get_logger
from scapy.all import sniff
import attacks

logger = get_logger()

def packet_handler(pkt, searched_attacks):
    for attack in searched_attacks:
        attack.inspect(pkt)

def main():
    logger.info("Starting LanSec...")

    try:
        iptbls.init()
        
    except PermissionError as e:
        logger.error(str(e))
        return

    searched_attacks = attacks.load_attacks(logger)

    print("LanSec - Local Area Network Security\n" + "-" * 36)

    try:
        sniff(prn=lambda pkt: packet_handler(pkt, searched_attacks), store=0)

    except KeyboardInterrupt:
        print("\nStopping LanSec...")

    finally:
        iptbls.clear()
        logger.info("LanSec stopped cleanly")

if __name__ == "__main__":
    main()
