import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(name="phishguard", log_file="logs/phishguard.log", level=logging.INFO):
    """
    Sets up a rotating logger that writes to 'logs/phishguard.log'.

    Returns:
        logging.Logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger
