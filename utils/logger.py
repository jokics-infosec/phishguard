import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(
    name="phishguard",
    log_file="logs/phishguard.log",
    level=logging.INFO,
    max_bytes=1_000_000,
    backup_count=5
):
    """
    Sets up a rotating logger that writes to 'logs/phishguard.log'.
    Returns: logging.Logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Always get the absolute path to the log file based on the repo root
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_file_path = os.path.join(repo_root, log_file)

    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    handler = RotatingFileHandler(log_file_path, maxBytes=max_bytes, backupCount=backup_count)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(module)s | %(message)s')
    handler.setFormatter(formatter)

    # Prevent adding multiple handlers if setup_logger() is called more than once
    if not any(isinstance(h, RotatingFileHandler) and h.baseFilename == handler.baseFilename for h in logger.handlers):
        logger.addHandler(handler)

    return logger
