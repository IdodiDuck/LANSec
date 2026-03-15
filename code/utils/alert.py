from datetime import datetime

class Alert:
    """
    Data container for security alerts. 
    Standardizes the information collected during threat detection for consistent 
    """
    def __init__(self, name, severity, details, src_ip="", dst_ip="", src_mac="", dst_mac=""):
        """
        Initializes a security alert instance.
        
        :param name: The name/category of the detected attack (e.g., "SYN Flood").
        :param severity: Severity level (e.g., CRITICAL, DANGEROUS).
        :param details: Technical breakdown of why the alert was triggered.
        :param src_ip: Source IPv4 address of the attacker.
        :param dst_ip: Target IPv4 address.
        :param src_mac: Source MAC address.
        :param dst_mac: Target MAC address.
        """
        self.name = name
        self.severity = severity
        self.details = details
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        # Timestamp the alert at the moment of creation
        self.time = datetime.now().strftime("%H:%M:%S")

    def to_dict(self):
        """
        Serializes the alert object into a dictionary.
        This is primarily used for converting the alert to JSON format for the 
        Web UI API and real-time Socket communication.
        
        :return: Dictionary containing all alert metadata.
        """
        return {
            "time": self.time,
            "severity": self.severity,
            "attack_type": self.name,
            "details": self.details,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac
        }

    def __str__(self):
        """
        Generates a human-readable, formatted string representation of the alert.
        Designed for clear visibility when printing alerts directly to the system terminal.
        """
        divider = "-" * 30
        
        # Determine the network flow string based on available identifiers (IP or MAC)
        if self.src_ip:
            flow = f"{self.src_ip} -> {self.dst_ip}"
        elif self.src_mac:
            flow = f"{self.src_mac} -> {self.dst_mac}"
        else:
            flow = "Local Event"
        
        return (f"\n{divider}\n"
                f"[ALERT] {self.severity} | {self.name}\n"
                f"Flow: {flow}\n"
                f"Details: {self.details}\n"
                f"{divider}")