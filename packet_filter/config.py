"""Service configuration, sourced entirely from environment variables."""
import os


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    # NFQUEUE / kernel handoff
    NFQUEUE_NUM = _int_env("NFQUEUE_NUM", 5)

    # Userspace queue + worker pool
    WORKER_POOL_SIZE = _int_env("WORKER_POOL_SIZE", 3)
    INTERNAL_QUEUE_MAXSIZE = _int_env("INTERNAL_QUEUE_MAXSIZE", 20000)

    # SQLite (management plane only, never on the packet path)
    DB_PATH = os.environ.get("PACKET_FILTER_DB_PATH", "/data/packet_filter.db")
    DB_BUSY_TIMEOUT_MS = _int_env("DB_BUSY_TIMEOUT_MS", 5000)

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    # Off by default: tty:true in compose makes isatty() unreliable for
    # auto-detection, and coloring would corrupt JSON for log shippers.
    LOG_COLOR = os.environ.get("LOG_COLOR", "false").lower() in ("1", "true", "yes")

    # API
    API_HOST = os.environ.get("API_HOST", "0.0.0.0")
    API_PORT = _int_env("API_PORT", 8000)

    # Periodic stats logging
    STATS_LOG_INTERVAL_SEC = _int_env("STATS_LOG_INTERVAL_SEC", 30)


config = Config()
