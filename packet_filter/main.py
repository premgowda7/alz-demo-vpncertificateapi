"""FastAPI service: whitelist management API + packet-filter engine lifecycle."""
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import config
from .database import Database, DuplicateIPError, WhitelistNotFoundError
from .logging_config import setup_logging
from .packet_engine import PacketFilterEngine
from .whitelist_cache import WhitelistCache

setup_logging(config.LOG_LEVEL, colorize=config.LOG_COLOR)
logger = logging.getLogger("packet_filter.main")

db = Database()
cache = WhitelistCache()
engine = PacketFilterEngine(cache, db)


def reload_cache() -> int:
    return cache.reload(db.get_active_ips())


@asynccontextmanager
async def lifespan(_: FastAPI):
    reload_cache()
    await engine.start()
    logger.info("packet filter service ready", extra={"event": "service_ready"})
    try:
        yield
    finally:
        await engine.stop()


app = FastAPI(title="VPN Packet Filter Service", lifespan=lifespan)


class WhitelistCreate(BaseModel):
    destination_ip: str = Field(..., description="IPv4 destination address to whitelist")
    label: Optional[str] = None


class WhitelistUpdate(BaseModel):
    destination_ip: str = Field(..., description="IPv4 destination address to update")
    active: bool


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "cache_size": cache.size,
        "cache_version": cache.version,
        "cache_loaded_at": cache.loaded_at,
    }


@app.get("/api/v1/whitelist")
def list_whitelist():
    return db.list_entries()


@app.post("/api/v1/whitelist", status_code=201)
def create_whitelist_entry(payload: WhitelistCreate):
    try:
        entry = db.add_entry(payload.destination_ip, payload.label)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid IPv4 address: {payload.destination_ip}") from exc
    except DuplicateIPError as exc:
        raise HTTPException(status_code=409, detail=f"{exc} already whitelisted") from exc
    reload_cache()
    return entry


@app.put("/api/v1/whitelist")
def update_whitelist_entry(payload: WhitelistUpdate):
    try:
        entry = db.set_active_by_ip(payload.destination_ip, payload.active)
    except WhitelistNotFoundError as exc:
        raise HTTPException(status_code=404, detail="whitelist entry not found") from exc
    reload_cache()
    return entry

@app.post("/api/v1/cache/reload")
def force_reload():
    size = reload_cache()
    return {"reloaded": True, "cache_size": size}
