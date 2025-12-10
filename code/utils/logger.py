import logging
from logging.handlers import RotatingFileHandler
import os

# Define the logs folder (relative to project root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")
LOGS_DIR = os.path.abspath(LOGS_DIR)  # Normalize path
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "system.log")

_initialized = False
_logger = None

def setup_logger(name="LanSec", log_file=None, level=logging.INFO, to_console=False):
    global _initialized, _logger

    if _initialized:
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

        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

    _logger = logger
    _initialized = True
    return logger


def get_logger():
    global _logger
    if not _initialized:
        setup_logger()
        
    return _logger

def info(msg):
    get_logger().info(msg)

def error(msg):
    get_logger().error(msg)
