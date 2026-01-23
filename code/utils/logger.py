import logging
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init as color_init
import os

color_init(autoreset=True)

# Adding Logging Level for representing ALERT logs
ALERT_LEVEL_NUM = 25
logging.addLevelName(ALERT_LEVEL_NUM, "ALERT")

# Creating customized logger with alerting functionality from API
class LanSecLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)

    def alert(self, msg, *args, **kwargs):
        print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
        self.log(ALERT_LEVEL_NUM, msg, *args, **kwargs)

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

def alert(msg):
    get_logger().alert(msg)

def error(msg):
    get_logger().error(msg)
