"""In-memory whitelist cache used on the packet-processing hot path.

Reads never lock and never touch the database: `contains()` only checks a
frozenset reference, which is swapped atomically (a single reference
assignment under the GIL) on reload.
"""
import logging
import time
from typing import Iterable, Optional

logger = logging.getLogger("packet_filter.whitelist_cache")


class WhitelistCache:
    def __init__(self):
        self._ips: frozenset = frozenset()
        self._version = 0
        self._loaded_at: Optional[float] = None

    def reload(self, ips: Iterable[str]) -> int:
        new_ips = frozenset(ips)
        self._ips = new_ips
        self._version += 1
        self._loaded_at = time.time()
        logger.info(
            "whitelist cache reloaded",
            extra={"event": "cache_reload", "size": len(new_ips), "version": self._version},
        )
        return len(new_ips)

    def contains(self, ip: str) -> bool:
        return ip in self._ips

    @property
    def size(self) -> int:
        return len(self._ips)

    @property
    def version(self) -> int:
        return self._version

    @property
    def loaded_at(self) -> Optional[float]:
        return self._loaded_at
