from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, TextIO

from .matcher import Match


def render_record(msg: dict[str, Any], match: Match) -> dict[str, Any]:
    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    issuer = leaf.get("issuer") or {}
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "rule": match.rule.name,
        "tags": list(match.rule.tags),
        "matched_domains": list(match.matched_domains),
        "all_domains": list(leaf.get("all_domains") or []),
        "issuer_o": issuer.get("O"),
        "issuer_cn": issuer.get("CN"),
        "not_before": leaf.get("not_before"),
        "not_after": leaf.get("not_after"),
        "serial": leaf.get("serial_number"),
        "fingerprint": leaf.get("fingerprint"),
        "cert_index": data.get("cert_index"),
        "cert_link": data.get("cert_link"),
        "source": data.get("source") or {},
    }


def write_jsonl(record: dict[str, Any], stream: TextIO) -> None:
    stream.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
    stream.write("\n")
    stream.flush()


def write_text(record: dict[str, Any], stream: TextIO) -> None:
    domains = ", ".join(record["matched_domains"])
    tags = ",".join(record["tags"])
    tag_part = f" {{{tags}}}" if tags else ""
    stream.write(
        f"{record['timestamp']}  [{record['rule']}]{tag_part}  {domains}\n"
    )
    stream.flush()
