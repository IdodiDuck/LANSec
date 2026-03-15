import logging
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init as color_init
import os
import time
from utils.alert import Alert

color_init(autoreset=True)

# Global list to store the most recent alerts for Web UI retrieval
recent_alerts = []
MAX_RECENT_ALERTS = 50

# Define a custom logging level for Security Alerts
ALERT_LEVEL_NUM = 25
logging.addLevelName(ALERT_LEVEL_NUM, "ALERT")

class LanSecLogger(logging.Logger):
    """
    A specialized logger for Network Security. 
    Includes built-in alert suppression and UI integration.
    """
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        # Dictionary to track the last time a specific attack from an IP was reported
        self._last_alerts_times = {}
        # Minimum time (seconds) between duplicate alerts to avoid flooding
        self.SUPPRESSION_TIME = 20 

    def _get_severity_color(self, severity):
        """ Maps severity levels to terminal colors for better visibility. """
        colors = {
            "NORMAL": Fore.GREEN,
            "SUSPICIOUS": Fore.YELLOW,
            "DANGEROUS": Fore.LIGHTRED_EX,
            "CRITICAL": Fore.RED
        }
        return colors.get(severity, Fore.WHITE)

    def _push_to_ui(self, alert_obj):
        """ Updates the global list of recent alerts for the Web Dashboard. """
        recent_alerts.insert(0, alert_obj)
        if len(recent_alerts) > MAX_RECENT_ALERTS:
            recent_alerts.pop()

    def alert(self, severity, attack_type, details=None, *args, **kwargs):
        """
        Processes a security alert: checks for suppression, logs to file, 
        and updates the Web UI and Terminal.
        """
        src_ip = kwargs.get('src_ip', "Unknown")
        dst_ip = kwargs.get('dst_ip', "Unknown")

        # Suppression Logic - 
        current_time = time.time()
        alert_key = (src_ip, attack_type)

        if alert_key in self._last_alerts_times:
            last_time = self._last_alerts_times[alert_key]
            if current_time - last_time < self.SUPPRESSION_TIME:
                return # Skip logging if the same security event occurred recently

        self._last_alerts_times[alert_key] = current_time

        severity = severity.upper()
        details = details if details else "No additional data"

        new_alert = Alert(
            name=attack_type,
            severity=severity,
            details=details,
            src_ip=src_ip,
            dst_ip=dst_ip
        )

        # Push to UI buffer
        alert_dict = new_alert.to_dict()
        self._push_to_ui(alert_dict)

        # Print formatted alert to Terminal with appropriate color
        color = self._get_severity_color(severity)
        print(f"{color}{new_alert}{Style.RESET_ALL}")

        # Log formatted message to the system log file
        full_message = f"{severity} • {attack_type} • {details} | Flow: {src_ip}->{dst_ip}"
        self._log_to_file(full_message, args, kwargs)

    def _log_to_file(self, message, args, kwargs):
        """ Internal method to write the alert record into the physical log file. """
        for handler in self.handlers:
            if isinstance(handler, RotatingFileHandler):
                record = self.makeRecord(
                    self.name, ALERT_LEVEL_NUM, "(internal)", 0, 
                    message, args, kwargs.get('exc_info')
                )
                handler.emit(record)

# Set our custom class as the default logger class
logging.setLoggerClass(LanSecLogger)

# Filesystem Configuration - 
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "logs"))
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "system.log")
_logger = None

def setup_logger(name="LanSec", log_file=None, level=logging.INFO, to_console=False):
    """
    Configures and initializes the global logger instance.
    Uses RotatingFileHandler to manage log size (max 5MB, 3 backups).
    """
    global _logger
    if _logger: return _logger
    
    log_file = log_file or LOG_FILE
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Create a file handler that rotates when the file reaches 5MB
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

    _logger = logger
    return logger

# Global Accessor Functions -
def get_logger():
    return _logger or setup_logger()

def info(msg):
    get_logger().info(msg)

def alert(severity, attack_type, details=None, **kwargs):
    get_logger().alert(severity, attack_type, details, **kwargs)

def error(msg):
    get_logger().error(msg)