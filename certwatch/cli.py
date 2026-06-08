from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import urllib.request
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, TextIO

from . import __version__
from . import config as config_mod
from . import ct_log
from . import matcher
from . import notify as notify_mod
from . import output as output_mod
from . import seenstore as seenstore_mod

DEFAULT_CONFIG = Path.home() / ".config" / "certwatch" / "config.toml"
GOOGLE_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

logger = logging.getLogger("certwatch")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    handlers = {
        "run": _cmd_run,
        "validate": _cmd_validate,
        "test": _cmd_test,
        "logs": _cmd_logs,
        "test-notify": _cmd_test_notify,
        "seed": _cmd_seed,
    }
    return handlers[args.command](args)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certwatch",
        description="Poll Certificate Transparency logs and emit matches against domain rules.",
    )
    p.add_argument("--version", action="version", version=f"certwatch {__version__}")
    p.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="logger verbosity (default: info)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="poll CT logs and emit matches")
    run.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG,
                     help=f"config file (default: {DEFAULT_CONFIG})")
    run.add_argument("-o", "--output", type=Path,
                     help="append output to this file instead of stdout")
    run.add_argument("-f", "--format", choices=["jsonl", "text"], default="jsonl",
                     help="output format (default: jsonl)")
    run.add_argument("--seen-db", type=Path, default=seenstore_mod.DEFAULT_SEEN_DB,
                     metavar="PATH",
                     help="path to seen-domains store (default: %(default)s)")
    run.add_argument("--no-dedup", action="store_true",
                     help="disable seen-domain filtering; emit all matches including renewals")

    val = sub.add_parser("validate", help="parse and validate a config file")
    val.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)

    test = sub.add_parser("test", help="check whether a single domain matches any rule")
    test.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    test.add_argument("domain")

    logs = sub.add_parser("logs", help="print [[logs]] blocks for currently usable CT logs")
    logs.add_argument("--operator", help="filter by operator name (substring match)")
    logs.add_argument("--limit", type=int, default=0, help="max logs to emit (0 = all)")

    tn = sub.add_parser("test-notify", help="send a synthetic match to the configured Discord webhook")
    tn.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)

    seed = sub.add_parser(
        "seed",
        help="pre-populate the seen-domains store from stdin (one domain per line)",
    )
    seed.add_argument("--seen-db", type=Path, default=seenstore_mod.DEFAULT_SEEN_DB,
                      metavar="PATH",
                      help="path to seen-domains store (default: %(default)s)")

    return p


def _load_config_or_exit(path: Path) -> config_mod.Config:
    try:
        return config_mod.load(path)
    except config_mod.ConfigError as exc:
        print(f"certwatch: {exc}", file=sys.stderr)
        sys.exit(2)


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg = _load_config_or_exit(args.config)
    print(f"OK: {len(cfg.rules)} rule(s), {len(cfg.logs)} log(s) loaded from {args.config}")
    for log in cfg.logs:
        print(f"  log: {log.name}  {log.url}")
    for r in cfg.rules:
        print(f"  rule: {r.name}  patterns={len(r.patterns)} exclude={len(r.exclude)} tags={list(r.tags)}")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    cfg = _load_config_or_exit(args.config)
    matches = matcher.match_domains([args.domain], cfg.rules)
    if not matches:
        print(f"no match for {args.domain}")
        return 1
    for m in matches:
        print(f"MATCH: {m.rule.name}  tags={list(m.rule.tags)}")
    return 0


def _cmd_logs(args: argparse.Namespace) -> int:
    try:
        with urllib.request.urlopen(GOOGLE_LOG_LIST_URL, timeout=15) as r:
            data = json.load(r)
    except Exception as exc:
        print(f"certwatch: failed to fetch log list: {exc}", file=sys.stderr)
        return 1

    emitted = 0
    op_filter = (args.operator or "").lower()
    for op in data.get("operators", []):
        op_name = op.get("name", "")
        if op_filter and op_filter not in op_name.lower():
            continue
        for log in op.get("logs", []):
            if "usable" not in (log.get("state") or {}):
                continue
            url = log.get("url") or ""
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            desc = log.get("description") or url
            slug = "".join(c if c.isalnum() else "-" for c in desc).strip("-").lower()
            print(f"# {desc}  (operator: {op_name})")
            print("[[logs]]")
            print(f'name = "{slug}"')
            print(f'url = "{url}"')
            print()
            emitted += 1
            if args.limit and emitted >= args.limit:
                return 0
    if emitted == 0:
        print("# (no logs matched)", file=sys.stderr)
        return 1
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    cfg = _load_config_or_exit(args.config)
    writer = output_mod.write_jsonl if args.format == "jsonl" else output_mod.write_text

    store: seenstore_mod.SeenDomains | None = None
    if not args.no_dedup:
        store = seenstore_mod.SeenDomains(args.seen_db)
        logger.info("seen-domains store: %d known domains from %s", len(store), args.seen_db)

    out_stream: TextIO
    out_owned = False
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        out_stream = args.output.open("a", buffering=1, encoding="utf-8")
        out_owned = True
    else:
        out_stream = sys.stdout

    try:
        asyncio.run(_run_loop(cfg, writer, out_stream, store))
    except KeyboardInterrupt:
        pass
    finally:
        if out_owned:
            out_stream.close()
    return 0


async def _run_loop(
    cfg: config_mod.Config,
    writer: Callable,
    out_stream: TextIO,
    store: seenstore_mod.SeenDomains | None,
) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    consumer = asyncio.create_task(_consume(cfg, writer, out_stream, store))
    stopper = asyncio.create_task(stop.wait())

    _, pending = await asyncio.wait({consumer, stopper}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _consume(
    cfg: config_mod.Config,
    writer: Callable,
    out_stream: TextIO,
    store: seenstore_mod.SeenDomains | None,
) -> None:
    async with _maybe_notifier(cfg.discord) as notifier:
        async for msg in ct_log.stream_ct_logs(cfg.logs):
            leaf = (msg.get("data") or {}).get("leaf_cert") or {}
            domains = leaf.get("all_domains") or []
            matches = matcher.match_domains(domains, cfg.rules)
            for m in matches:
                if store is not None:
                    new_domains = store.filter_new(list(m.matched_domains))
                    if not new_domains:
                        continue
                    store.mark_seen(new_domains)
                    m = matcher.Match(rule=m.rule, matched_domains=tuple(new_domains))
                record = output_mod.render_record(msg, m)
                writer(record, out_stream)
                if notifier is not None:
                    notifier.push(record)


class _NullNotifier:
    async def __aenter__(self): return None
    async def __aexit__(self, *exc): return None


def _maybe_notifier(cfg: notify_mod.DiscordConfig | None):
    if cfg is None:
        return _NullNotifier()
    return notify_mod.DiscordNotifier(cfg)


def _cmd_seed(args: argparse.Namespace) -> int:
    store = seenstore_mod.SeenDomains(args.seen_db)
    before = len(store)
    domains = []
    for line in sys.stdin:
        domain = line.strip().lower()
        if domain and not domain.startswith("#"):
            domains.append(domain)
    store.mark_seen(domains)
    added = len(store) - before
    print(f"read {len(domains)} domain(s) from stdin — {added} new, {len(store)} total in {args.seen_db}")
    return 0


def _cmd_test_notify(args: argparse.Namespace) -> int:
    cfg = _load_config_or_exit(args.config)
    if cfg.discord is None:
        print("certwatch: no [notify.discord] section in config", file=sys.stderr)
        return 2
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "rule": "test-notify",
        "tags": ["test"],
        "matched_domains": ["test.example.com", "alt.example.com"],
        "all_domains": ["test.example.com", "alt.example.com"],
        "issuer_o": "certwatch",
        "issuer_cn": "Synthetic Test",
        "not_before": None,
        "not_after": None,
        "serial": "deadbeef",
        "fingerprint": "0" * 64,
        "cert_index": 0,
        "cert_link": "https://example.com/test",
        "source": {"name": "synthetic", "url": "https://example.com/", "entry_type": "x509"},
    }

    async def _go() -> None:
        async with notify_mod.DiscordNotifier(cfg.discord) as notifier:
            notifier.push(record)
            # Wait for batch window + send round-trip with margin.
            await asyncio.sleep(cfg.discord.batch_window_seconds + 5)

    asyncio.run(_go())
    print("test-notify sent (check Discord; check stderr for delivery errors)")
    return 0
