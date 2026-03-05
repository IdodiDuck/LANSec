import logging
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init as color_init
import os
import time
from utils.alert import Alert

color_init(autoreset=True)

# Alerts to be presented in UI
recent_alerts = []
MAX_RECENT_ALERTS = 50

# Adding Logging Level for representing ALERT logs
ALERT_LEVEL_NUM = 25
logging.addLevelName(ALERT_LEVEL_NUM, "ALERT")

# Creating customized logger with alerting functionality from API
class LanSecLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        self._last_alerts_times = {}
        self.SUPPRESSION_TIME = 20 # Seconds

    def _get_severity_color(self, severity):
        colors = {
            "NORMAL": Fore.GREEN,
            "SUSPICIOUS": Fore.YELLOW,
            "DANGEROUS": Fore.LIGHTRED_EX,
            "CRITICAL": Fore.RED
        }
        
        return colors.get(severity, Fore.WHITE)

    def _push_to_ui(self, alert_obj):
        recent_alerts.insert(0, alert_obj)
        if len(recent_alerts) > MAX_RECENT_ALERTS:
            recent_alerts.pop()

    def alert(self, severity, attack_type, details=None, *args, **kwargs):
        src_ip = kwargs.get('src_ip', "Unknown")
        dst_ip = kwargs.get('dst_ip', "Unknown")

        current_time = time.time()
        alert_key = (src_ip, attack_type)

        # Supression Mechanism - Avoiding duplicate detections spamming
        if alert_key in self._last_alerts_times:
            last_time = self._last_alerts_times[alert_key]

            if current_time - last_time < self.SUPPRESSION_TIME:
                return

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

        alert_dict = new_alert.to_dict()

        if 'attack_type' not in alert_dict:
             alert_dict['attack_type'] = attack_type

        self._push_to_ui(alert_dict)

        color = self._get_severity_color(severity)
        print(f"{color}{new_alert}{Style.RESET_ALL}")

        full_message = f"{severity} • {attack_type} • {details} | Flow: {src_ip}->{dst_ip}"
        self._log_to_file(full_message, args, kwargs)

    def _log_to_file(self, message, args, kwargs):
        for handler in self.handlers:
            if isinstance(handler, RotatingFileHandler):
                record = self.makeRecord(
                    self.name, ALERT_LEVEL_NUM, "(internal)", 0, 
                    message, args, kwargs.get('exc_info')
                )
                handler.emit(record)

logging.setLoggerClass(LanSecLogger)

# Define the logs folder (relative to project root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")
LOGS_DIR = os.path.abspath(LOGS_DIR)  # Normalize path
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "system.log")

_logger = None

def setup_logger(name="LanSec", log_file=None, level=logging.INFO, to_console=False):
    global _logger

    if _logger:
        return _logger
    
    if log_file is None:
        log_file = LOG_FILE

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Prevent duplicated handlers
    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        file_handler = RotatingFileHandler(log_file or LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

    _logger = logger
    return logger

# Globals Functions - 
def get_logger():
    return _logger or setup_logger()

def info(msg):
    get_logger().info(msg)

def alert(severity, attack_type, details=None, **kwargs):
    get_logger().alert(severity, attack_type, details, **kwargs)

def error(msg):
    get_logger().error(msg)
