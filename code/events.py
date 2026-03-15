from colorama import Fore, init as color_init
import prevent.iptbls as iptbls

# Initialize colorama for cross-platform colored terminal output
color_init(autoreset=True)

# Import individual security event detectors
from detect import (
    randomized_mac, syn_scan, dir_traversal, xss, sqli,
    arp_spoof, syn_flood, udp_flood, icmp_flood,
    ssh_bruteforce, arp_sweep, ping_sweep,
)

# Severity Constants
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"
CRITICAL = "CRITICAL"

class SecurityEvent:
    """
    Represents a managed security event. 
    Links detection logic with severity levels, blocking actions, and UI logging.
    """
    def __init__(self, name, severity, inspect_func, logger, snf_fltr=""):
        """
        :param name: Human-readable name of the attack type.
        :param severity: Severity level (NORMAL to CRITICAL).
        :param inspect_func: The detection function from the 'detect' package.
        :param logger: Logger instance for pushing alerts to the UI.
        :param snf_fltr: BPF filter string for the Scapy sniffer.
        """
        self.name = name
        self.severity = severity
        self._inspect = inspect_func
        self.logger = logger
        self._snf_filter = snf_fltr
        
    def inspect(self, pkt):
        """
        Analyzes a single packet. If an anomaly or threat is detected, 
        it triggers a Firewall block and reports the alert.
        """
        # Execute the specific detection logic
        result = self._inspect(pkt)
        
        # If result is None or False, no threat was detected
        if not result: 
            return

        # Process technical details returned by the detector for display
        technical_info = self._format_technical_info(result)

        # Extract network identifiers (IP/MAC) for blocking and logging
        attacker_ip, target_ip, attacker_mac, target_mac = self._get_packet_identities(pkt)

        # Active Response: Block the source IP via iptables
        if attacker_ip:
            iptbls.block(attacker_ip)
            technical_info += f" | Status: IP {attacker_ip} Blocked"

        # Report to Dashboard via the custom logger
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

    def _format_technical_info(self, result):
        """ Formats raw detection data into a readable string for the alert details. """
        if isinstance(result, (tuple, list)):
            return " | ".join(map(str, result))
        
        elif isinstance(result, dict):
            return ", ".join([f"{k}: {v}" for k, v in result.items()])
        
        return str(result)

    def _get_packet_identities(self, pkt):
        """ Extracts source and destination IP/MAC addresses from IP or ARP layers. """
        src_ip, dst_ip, src_mac, dst_mac = "", "", "", ""

        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
        elif pkt.haslayer("ARP"):
            src_ip = pkt["ARP"].psrc
            dst_ip = pkt["ARP"].pdst
            src_mac = pkt["ARP"].hwsrc
            dst_mac = pkt["ARP"].hwdst
            
        return src_ip, dst_ip, src_mac, dst_mac


# BPF Filter Definitions -
# Filters for common web ports (80, 8080, 8000) and a custom debug port (12345)
app_layer_fltr = "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345"

# Filter to capture only TCP packets with the SYN flag set (initial connection attempt)
tcp_syn_fltr = "tcp and (tcp[13] & 2 != 0)" 

def load_monitored_events(logger):
    """
    Initializes and returns a list of all security events to be monitored by the system.
    Each event maps a detection module to a specific severity level and BPF filter.
    """
    return [
        SecurityEvent("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger),
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