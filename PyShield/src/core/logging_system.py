from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "time": self.formatTime(record, self.datefmt),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            payload.update(getattr(record, "extra"))
        return json.dumps(payload, ensure_ascii=False)


class LoggerFactory:
    @staticmethod
    def get_logger(name: str, *, level: str = "INFO", json_mode: bool = False,
                   log_dir: str = "logs", file_name: str = "pyshield.log",
                   max_mb: int = 10, backups: int = 5) -> logging.Logger:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        logger = logging.getLogger(name)
        if logger.handlers:
            return logger

        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        file_path = os.path.join(log_dir, file_name)
        handler = RotatingFileHandler(file_path, maxBytes=max_mb * 1024 * 1024, backupCount=backups)

        if json_mode:
            fmt = JsonFormatter()
        else:
            fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        handler.setFormatter(fmt)

        console = logging.StreamHandler()
        console.setFormatter(fmt)

        logger.addHandler(handler)
        logger.addHandler(console)
        return logger
