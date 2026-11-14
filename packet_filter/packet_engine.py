"""NFQUEUE reader -> bounded asyncio queue -> async worker pool -> verdict.

NFQUEUE / DoS protection.
"""
import asyncio
import logging
import socket
import threading
from dataclasses import dataclass
from typing import List, Optional

from .config import config
from .whitelist_cache import WhitelistCache

logger = logging.getLogger("packet_filter.packet_engine")


@dataclass
class Counters:
    received_total: int = 0
    accepted_total: int = 0
    dropped_total: int = 0
    dropped_queue_full: int = 0
    dropped_invalid_packet: int = 0
    errors_total: int = 0
    queue_high_watermark: int = 0
    cache_miss_total: int = 0
    cache_miss_db_hit_total: int = 0

    def as_dict(self) -> dict:
        return {
            "received_total": self.received_total,
            "accepted_total": self.accepted_total,
            "dropped_total": self.dropped_total,
            "dropped_queue_full": self.dropped_queue_full,
            "dropped_invalid_packet": self.dropped_invalid_packet,
            "errors_total": self.errors_total,
            "queue_high_watermark": self.queue_high_watermark,
            "cache_miss_total": self.cache_miss_total,
            "cache_miss_db_hit_total": self.cache_miss_db_hit_total,
        }


def extract_ipv4_dst(payload: bytes) -> Optional[str]:
    """Read the destination address directly out of the raw IPv4 header."""
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    if version != 4:
        return None
    return socket.inet_ntoa(payload[16:20])


def extract_ipv4_src(payload: bytes) -> Optional[str]:
    """Read the source address directly out of the raw IPv4 header."""
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    if version != 4:
        return None
    return socket.inet_ntoa(payload[12:16])


class PacketFilterEngine:
    def __init__(self, cache: WhitelistCache, db):
        self.cache = cache
        self.db = db
        self.counters = Counters()
        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._nfqueue = None
        self._nfqueue_thread: Optional[threading.Thread] = None
        self._workers: List[asyncio.Task] = []
        self._running = False

    async def start(self) -> None:
        from netfilterqueue import NetfilterQueue  # Linux-only C extension; imported lazily

        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=config.INTERNAL_QUEUE_MAXSIZE)
        self._running = True

        self._nfqueue = NetfilterQueue()
        self._nfqueue.bind(config.NFQUEUE_NUM, self._on_packet)

        self._nfqueue_thread = threading.Thread(
            target=self._run_nfqueue, name="nfqueue-reader", daemon=True
        )
        self._nfqueue_thread.start()

        self._workers = [
            asyncio.create_task(self._worker_loop(worker_id=i))
            for i in range(config.WORKER_POOL_SIZE)
        ]

        logger.info(
            "packet filter engine started",
            extra={
                "event": "engine_start",
                "queue_num": config.NFQUEUE_NUM,
                "worker_pool_size": config.WORKER_POOL_SIZE,
                "queue_maxsize": config.INTERNAL_QUEUE_MAXSIZE,
            },
        )

    def _run_nfqueue(self) -> None:
        try:
            self._nfqueue.run()
        except Exception:
            logger.exception("nfqueue reader loop terminated", extra={"event": "nfqueue_crash"})

    def _on_packet(self, pkt) -> None:
        """Runs on the nfqueue reader thread; must never block on it."""
        if self._loop is None:
            pkt.drop()
            return
        # retain() copies the payload out of the kernel-owned buffer, which
        # is freed once this callback returns; without it, get_payload()
        # in the deferred async _process() raises RuntimeError.
        pkt.retain()
        try:
            self._loop.call_soon_threadsafe(self._enqueue, pkt)
        except RuntimeError:
            pkt.drop()

    def _enqueue(self, pkt) -> None:
        """Runs on the event loop thread: non-blocking, bounded ingestion."""
        self.counters.received_total += 1
        try:
            self._queue.put_nowait(pkt)
            depth = self._queue.qsize()
            if depth > self.counters.queue_high_watermark:
                self.counters.queue_high_watermark = depth
        except asyncio.QueueFull:
            self.counters.dropped_queue_full += 1
            self.counters.dropped_total += 1
            pkt.drop()
            logger.warning("internal queue full, dropping packet", extra={"event": "queue_full"})

    async def _worker_loop(self, worker_id: int) -> None:
        while self._running:
            try:
                pkt = await self._queue.get()
            except asyncio.CancelledError:
                break
            try:
                await self._process(pkt)
            except Exception:
                self.counters.errors_total += 1
                logger.exception(
                    "error processing packet",
                    extra={"event": "processing_error", "worker_id": worker_id},
                )
                try:
                    pkt.drop()
                except Exception:
                    pass

    async def _process(self, pkt) -> None:
        payload = pkt.get_payload()
        dst_ip = extract_ipv4_dst(payload)
        src_ip = extract_ipv4_src(payload)
        logger.info(
            "packet received",
            extra={"event": "packet_received", "src_ip": src_ip, "dst_ip": dst_ip},
        )
        if dst_ip is None:
            self.counters.dropped_invalid_packet += 1
            self.counters.dropped_total += 1
            pkt.drop()
            return

        if self.cache.contains(dst_ip):
            self.counters.accepted_total += 1
            pkt.accept()
            logger.info(
                "accepted whitelisted destination",
                extra={"event": "verdict_accept", "src_ip": src_ip, "dst_ip": dst_ip},
            )
            return

        # Cache miss: fall back to a direct DB lookup (e.g. entry added but
        # cache not yet reloaded) before dropping. Runs off the event loop
        # thread so a slow query can't stall other packets.
        self.counters.cache_miss_total += 1
        if await asyncio.to_thread(self.db.is_active_ip, dst_ip):
            self.counters.cache_miss_db_hit_total += 1
            self.counters.accepted_total += 1
            pkt.accept()
            logger.warning(
                "cache miss but DB has active entry, accepting and cache is stale",
                extra={"event": "cache_miss_db_hit", "src_ip": src_ip, "dst_ip": dst_ip},
            )
            return

        self.counters.dropped_total += 1
        pkt.drop()
        logger.info(
            "dropped non-whitelisted destination",
            extra={"event": "verdict_drop", "src_ip": src_ip, "dst_ip": dst_ip},
        )

    async def stop(self) -> None:
        self._running = False
        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        if self._nfqueue is not None:
            try:
                self._nfqueue.unbind()
            except Exception:
                logger.exception("error unbinding nfqueue", extra={"event": "nfqueue_unbind_error"})
        logger.info("packet filter engine stopped", extra={"event": "engine_stop"})

    def stats(self) -> dict:
        data = self.counters.as_dict()
        data["queue_depth"] = self._queue.qsize() if self._queue else 0
        data["queue_maxsize"] = config.INTERNAL_QUEUE_MAXSIZE
        data["worker_pool_size"] = config.WORKER_POOL_SIZE
        data["cache_size"] = self.cache.size
        data["cache_version"] = self.cache.version
        return data
