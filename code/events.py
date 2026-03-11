import time
from colorama import Fore, init as color_init
import prevent.iptbls as iptbls

color_init(autoreset=True)

from detect import (
    randomized_mac,
    syn_scan,
    dir_traversal,
    xss,
    sqli,
    arp_spoof,
    syn_flood,
    udp_flood,
    icmp_flood,
    ssh_bruteforce,
    arp_sweep,
    ping_sweep,
)

# Attacks Severities
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"
CRITICAL = "CRITICAL"

class SecurityEvent:
    def __init__(self, name, severity, inspect, logger, snf_fltr=""):
        self.name = name
        self.severity = severity
        self._inspect = inspect
        self.logger = logger
        self._snf_filter = snf_fltr
        
    def inspect(self, pkt):
        result = self._inspect(pkt)
        
        if not result: 
            return

        technical_info = ""
        if isinstance(result, (tuple, list)):
            technical_info = " | ".join(map(str, result))

        elif isinstance(result, dict):
            technical_info = ", ".join([f"{k}: {v}" for k, v in result.items()])

        else:
            technical_info = str(result)

        attacker_ip = ""
        target_ip = ""
        attacker_mac = ""
        target_mac = ""

        if pkt.haslayer("IP"):
            attacker_ip = pkt["IP"].src
            target_ip = pkt["IP"].dst
        elif pkt.haslayer("ARP"):
            attacker_ip = pkt["ARP"].psrc
            target_ip = pkt["ARP"].pdst
            attacker_mac = pkt["ARP"].hwsrc
            target_mac = pkt["ARP"].hwdst

        if attacker_ip:
            iptbls.block(attacker_ip)
            technical_info += f" | Status: IP {attacker_ip} Blocked"

        if self.logger: 
            self.logger.alert(
                severity=self.severity, 
                attack_type=self.name, 
                details=technical_info,
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_mac=attacker_mac,
                dst_mac=target_mac
            )


# 12345 for debugging
app_layer_fltr = "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345"
# SYN flag set
tcp_syn_fltr = "tcp and (tcp[13] & 2 != 0)" 
def load_monitored_events(logger):
    return [
        # SecurityEvent("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger, "ALL"),
        SecurityEvent("XSS", SUSPICIOUS, xss.inspect, logger, snf_fltr=app_layer_fltr),
        SecurityEvent("SQLi", SUSPICIOUS, sqli.inspect, logger, snf_fltr=app_layer_fltr),
        SecurityEvent("Directory Traversal", SUSPICIOUS, dir_traversal.inspect, logger, snf_fltr=app_layer_fltr),
        SecurityEvent("Brute Force SSH", SUSPICIOUS, ssh_bruteforce.inspect, logger, snf_fltr="tcp port 22"),
        SecurityEvent("TCP SYN Scan", DANGEROUS, syn_scan.inspect, logger, snf_fltr=tcp_syn_fltr),
        SecurityEvent("Ping Sweep", DANGEROUS, ping_sweep.inspect, logger, snf_fltr="icmp"),
        SecurityEvent("ARP Sweep", DANGEROUS, arp_sweep.inspect, logger, snf_fltr="arp"),
        SecurityEvent("SYN Flood", CRITICAL, syn_flood.inspect, logger, snf_fltr=tcp_syn_fltr),
        SecurityEvent("ICMP Flood", CRITICAL, icmp_flood.inspect, logger, snf_fltr="icmp"),
        SecurityEvent("UDP Flood", CRITICAL, udp_flood.inspect, logger, snf_fltr="udp"),
        SecurityEvent("ARP Spoofing", CRITICAL, arp_spoof.inspect, logger, snf_fltr="arp")
    ]
