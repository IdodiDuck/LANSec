import logging
from logging.handlers import RotatingFileHandler
import os
import atexit

# Define the logs folder (relative to project root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")
LOGS_DIR = os.path.abspath(LOGS_DIR)  # Normalize path
os.makedirs(LOGS_DIR, exist_ok=True)

# Define log file path
LOG_FILE = os.path.join(LOGS_DIR, "system.log")

def setup_logger(name="LanSec", log_file=None, level=logging.INFO, to_console=True):
    if log_file is None:
        log_file = LOG_FILE

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if to_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Ensure handlers close on exit
    def _close_handlers():
        for handler in list(logger.handlers):
            try:
                handler.flush()
                handler.close()
            except Exception:
                pass
            try:
                logger.removeHandler(handler)
            except Exception:
                pass

    atexit.register(_close_handlers)
    return logger

# Loging Functions - 
def info(msg: str):
    logging.getLogger("LanSec").info(msg)

def error(msg: str):
    logging.getLogger("LanSec").error(msg)
