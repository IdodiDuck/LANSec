from datetime import datetime

class Alert:
    def __init__(self, name, severity, details, src_ip="", dst_ip="", src_mac="", dst_mac=""):
        self.name = name
        self.severity = severity
        self.details = details
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.time = datetime.now().strftime("%H:%M:%S")

    def to_dict(self):
        """Returns a dictionary for the Web UI (JSON)"""
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
        """Returns a clean, formatted string for the Terminal"""
        divider = "-" * 30
        # Determine the network flow string
        flow = f"{self.src_ip} -> {self.dst_ip}" if self.src_ip else (f"{self.src_mac} -> {self.dst_mac}" if self.src_mac else "Local Event")
        
        return (f"\n{divider}\n"
                f"[ALERT] {self.severity} | {self.name}\n"
                f"Flow: {flow}\n"
                f"Details: {self.details}\n"
                f"{divider}")