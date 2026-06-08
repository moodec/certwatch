"""Poll RFC 6962 CT logs concurrently and yield certstream-shaped messages."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .config import CTLog
from .ct_parse import ParsedCert, parse_entry

logger = logging.getLogger(__name__)

POLL_INTERVAL = 30.0
BATCH_SIZE = 256
MIN_BACKOFF = 2.0
MAX_BACKOFF = 300.0
HTTP_TIMEOUT = 30.0
QUEUE_MAX = 10_000


async def stream_ct_logs(logs: tuple[CTLog, ...]) -> AsyncIterator[dict[str, Any]]:
    """Poll each log on its own task; yield parsed cert messages from a shared queue."""
    if not logs:
        return

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_MAX)
    tasks = [asyncio.create_task(_poll_log(log, queue), name=f"poll-{log.name}") for log in logs]

    try:
        while True:
            yield await queue.get()
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass


async def _poll_log(log: CTLog, queue: asyncio.Queue[dict[str, Any]]) -> None:
    base = log.url.rstrip("/")
    last_size: int | None = None
    backoff = MIN_BACKOFF

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": "certwatch/0.1"}) as client:
        while True:
            try:
                tree_size = await _get_tree_size(client, base)

                if last_size is None:
                    last_size = tree_size
                    logger.info("[%s] starting at tree_size=%d", log.name, tree_size)
                elif tree_size > last_size:
                    new = tree_size - last_size
                    logger.debug("[%s] %d new entries (%d -> %d)", log.name, new, last_size, tree_size)
                    last_size = await _drain_range(client, base, log, last_size, tree_size, queue)

                backoff = MIN_BACKOFF
                await asyncio.sleep(POLL_INTERVAL)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("[%s] poll error: %s; retry in %.1fs", log.name, exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)


async def _get_tree_size(client: httpx.AsyncClient, base: str) -> int:
    r = await client.get(f"{base}/ct/v1/get-sth")
    r.raise_for_status()
    return int(r.json()["tree_size"])


async def _drain_range(
    client: httpx.AsyncClient,
    base: str,
    log: CTLog,
    start: int,
    tree_size: int,
    queue: asyncio.Queue[dict[str, Any]],
) -> int:
    """Fetch entries [start, tree_size) and enqueue parsed messages.

    Returns the next index to resume from (the first index NOT yet consumed).
    Logs cap responses at their server-side limit, so we loop until done or
    the server returns zero entries (which we treat as a transient failure).
    """
    cur = start
    while cur < tree_size:
        end = min(cur + BATCH_SIZE - 1, tree_size - 1)
        r = await client.get(f"{base}/ct/v1/get-entries", params={"start": cur, "end": end})
        r.raise_for_status()
        entries = r.json().get("entries") or []
        if not entries:
            logger.warning("[%s] empty entries response at %d; will retry", log.name, cur)
            return cur
        for offset, entry in enumerate(entries):
            parsed = parse_entry(entry.get("leaf_input"), entry.get("extra_data"))
            if parsed is None:
                continue
            await queue.put(_to_message(parsed, log, cur + offset))
        cur += len(entries)
    return cur


def _to_message(parsed: ParsedCert, log: CTLog, index: int) -> dict[str, Any]:
    return {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": list(parsed.domains),
                "issuer": {"O": parsed.issuer_o, "CN": parsed.issuer_cn},
                "not_before": parsed.not_before,
                "not_after": parsed.not_after,
                "serial_number": parsed.serial,
                "fingerprint": parsed.fingerprint,
            },
            "cert_index": index,
            "cert_link": f"{log.url.rstrip('/')}/ct/v1/get-entries?start={index}&end={index}",
            "source": {"name": log.name, "url": log.url, "entry_type": parsed.entry_type},
        },
    }
