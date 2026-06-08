"""Discord webhook sink. Best-effort: failures log + drop, never block the pipeline."""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BATCH_WINDOW = 5.0
DEFAULT_BATCH_MAX = 10
MAX_EMBEDS_PER_MESSAGE = 5      # Discord allows 10; 5 keeps total payload well under 6000 chars
QUEUE_MAX = 1000
HTTP_TIMEOUT = 15.0
MAX_SEND_ATTEMPTS = 5
DEFAULT_BACKOFF = 1.0
MAX_BACKOFF = 30.0


@dataclass(frozen=True)
class DiscordConfig:
    webhook_url: str
    batch_window_seconds: float = DEFAULT_BATCH_WINDOW
    batch_max: int = DEFAULT_BATCH_MAX
    rule_filter: tuple[str, ...] = ()  # empty == all rules


def discord_config_from_dict(
    raw: dict[str, Any] | None,
    env: dict[str, str] | None = None,
) -> DiscordConfig | None:
    """Parse a [notify.discord] table; returns None if not configured."""
    if not raw:
        return None
    env = env if env is not None else dict(os.environ)
    url = raw.get("webhook_url")
    env_var = raw.get("webhook_url_env")
    if env_var:
        env_url = env.get(env_var)
        if env_url:
            url = env_url
    if not url:
        raise ValueError(
            "notify.discord requires 'webhook_url' or 'webhook_url_env' "
            "(and the env var must be set)"
        )
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        raise ValueError("notify.discord.webhook_url must be an http(s):// URL")
    if url.startswith("http://") and not url.startswith(("http://localhost", "http://127.")):
        raise ValueError("notify.discord.webhook_url: plain http:// only allowed for localhost/127.* (test fixtures)")
    rules = raw.get("rules", [])
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ValueError("notify.discord.rules must be a list of strings")
    try:
        window = float(raw.get("batch_window_seconds", DEFAULT_BATCH_WINDOW))
        batch_max = int(raw.get("batch_max", DEFAULT_BATCH_MAX))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"notify.discord: invalid batch settings: {exc}") from exc
    if window <= 0 or batch_max <= 0:
        raise ValueError("notify.discord: batch_window_seconds and batch_max must be positive")
    return DiscordConfig(
        webhook_url=url,
        batch_window_seconds=window,
        batch_max=batch_max,
        rule_filter=tuple(rules),
    )


class DiscordNotifier:
    """Async background sink. Use:

        async with notifier:
            notifier.push(record)
    """

    def __init__(self, cfg: DiscordConfig) -> None:
        self._cfg = cfg
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_MAX)
        self._task: asyncio.Task | None = None

    async def __aenter__(self) -> "DiscordNotifier":
        self._task = asyncio.create_task(self._run(), name="discord-notifier")
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def push(self, record: dict[str, Any]) -> None:
        if self._cfg.rule_filter and record.get("rule") not in self._cfg.rule_filter:
            return
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("discord queue full; dropping match for rule %s", record.get("rule"))

    async def _run(self) -> None:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            while True:
                batch = await self._collect_batch()
                for i in range(0, len(batch), MAX_EMBEDS_PER_MESSAGE):
                    chunk = batch[i:i + MAX_EMBEDS_PER_MESSAGE]
                    await self._send(client, chunk)

    async def _collect_batch(self) -> list[dict[str, Any]]:
        first = await self._queue.get()
        batch = [first]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._cfg.batch_window_seconds
        while len(batch) < self._cfg.batch_max:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(self._queue.get(), timeout=remaining))
            except asyncio.TimeoutError:
                break
        return batch

    async def _send(self, client: httpx.AsyncClient, records: list[dict[str, Any]]) -> None:
        payload = {"embeds": [_record_to_embed(r) for r in records]}
        backoff = DEFAULT_BACKOFF
        for attempt in range(1, MAX_SEND_ATTEMPTS + 1):
            try:
                resp = await client.post(self._cfg.webhook_url, json=payload)
            except httpx.HTTPError as exc:
                logger.warning("discord post network error (attempt %d/%d): %s",
                               attempt, MAX_SEND_ATTEMPTS, exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
                continue

            if resp.status_code == 429:
                # Discord rate-limit: prefer JSON retry_after, fall back to header.
                retry_after = backoff
                try:
                    retry_after = float((resp.json() or {}).get("retry_after", backoff))
                except ValueError:
                    pass
                hdr = resp.headers.get("retry-after")
                if hdr:
                    try:
                        retry_after = max(retry_after, float(hdr))
                    except ValueError:
                        pass
                logger.warning("discord rate-limited; sleeping %.2fs", retry_after)
                await asyncio.sleep(retry_after)
                continue

            if 200 <= resp.status_code < 300:
                logger.debug("discord delivered %d embed(s)", len(records))
                return

            logger.warning("discord post HTTP %d (attempt %d/%d): %s",
                           resp.status_code, attempt, MAX_SEND_ATTEMPTS, resp.text[:200])
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)

        logger.error("discord post abandoned after %d attempts (%d records dropped)",
                     MAX_SEND_ATTEMPTS, len(records))


def _record_to_embed(r: dict[str, Any]) -> dict[str, Any]:
    rule = r.get("rule", "unknown")
    domains = r.get("matched_domains") or []
    primary = domains[0] if domains else "(no domain)"
    extras = domains[1:6]

    fields: list[dict[str, Any]] = []
    if extras:
        fields.append({
            "name": "Other matched",
            "value": "\n".join(f"`{d}`" for d in extras)[:1024],
        })
    issuer_bits = [b for b in (r.get("issuer_o"), r.get("issuer_cn")) if b]
    if issuer_bits:
        fields.append({"name": "Issuer", "value": " · ".join(issuer_bits)[:1024], "inline": True})
    src_name = (r.get("source") or {}).get("name")
    if src_name:
        fields.append({"name": "Log", "value": src_name, "inline": True})
    if r.get("cert_link"):
        fields.append({"name": "Cert", "value": r["cert_link"][:1024]})

    return {
        "title": f"[{rule}] {primary}"[:256],
        "color": _stable_color(rule),
        "fields": fields[:25],
        "timestamp": r.get("timestamp"),
        "footer": {"text": ", ".join(r.get("tags") or []) or "certwatch"},
    }


def _stable_color(name: str) -> int:
    h = 0
    for c in name:
        h = (h * 31 + ord(c)) & 0xFFFFFF
    return h or 0x5865F2  # fallback: Discord blurple
