"""Structured JSON logging so packet-filter events can feed the log stack."""
import json
import logging
import sys
from datetime import datetime, timezone

_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}

_LEVEL_COLORS = {
    "DEBUG": "\033[36m",
    "INFO": "\033[32m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[97m\033[41m",
}
_RESET = "\033[0m"


class JsonFormatter(logging.Formatter):
    def __init__(self, colorize: bool = False):
        super().__init__()
        self.colorize = colorize

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        line = json.dumps(payload, default=str)
        if self.colorize:
            color = _LEVEL_COLORS.get(record.levelname, "")
            if color:
                line = f"{color}{line}{_RESET}"
        return line


def setup_logging(level: str = "INFO", colorize: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(colorize=colorize))
    root.addHandler(handler)

    # uvicorn installs its own handlers with propagate=False, which bypasses
    # the root handler above and drops the timestamp from its log lines.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True
