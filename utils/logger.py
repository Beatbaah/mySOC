"""
utils/logger.py — Centralized rotating file logger for MY SOC
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path

import config


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger configured with:
    - Rotating file handler  (LOG_DIR/LOG_FILE, max 10 MB × 5 backups)
    - Colored console handler (INFO+)
    - ISO-8601 timestamps
    """
    logger = logging.getLogger(name)

    if logger.handlers:          # already initialised – just return
        return logger

    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    # ── Formatter ─────────────────────────────────────────────────────────────
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # ── File handler (rotating) ────────────────────────────────────────────────
    log_dir = Path(config.LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / config.LOG_FILE

    file_handler = logging.handlers.RotatingFileHandler(
        filename=str(log_path),
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)

    # ── Console handler (with ANSI colour) ────────────────────────────────────
    class _ColorFormatter(logging.Formatter):
        COLORS = {
            logging.DEBUG:    "\033[36m",   # cyan
            logging.INFO:     "\033[32m",   # green
            logging.WARNING:  "\033[33m",   # yellow
            logging.ERROR:    "\033[31m",   # red
            logging.CRITICAL: "\033[35m",   # magenta
        }
        RESET = "\033[0m"

        def format(self, record):
            color = self.COLORS.get(record.levelno, "")
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)

    console_fmt = _ColorFormatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_fmt)
    console_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    return logger
