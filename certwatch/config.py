from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .notify import DiscordConfig, discord_config_from_dict


@dataclass(frozen=True)
class Rule:
    name: str
    patterns: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CTLog:
    name: str
    url: str


@dataclass(frozen=True)
class Config:
    logs: tuple[CTLog, ...]
    rules: tuple[Rule, ...]
    discord: DiscordConfig | None = None


class ConfigError(ValueError):
    pass


def load(path: Path) -> Config:
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    with path.open("rb") as f:
        raw = tomllib.load(f)

    logs = _parse_logs(raw.get("logs") or [])
    if not logs:
        raise ConfigError("config must define at least one [[logs]] entry")

    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ConfigError("config must define at least one [[rules]] entry")

    seen: set[str] = set()
    rules: list[Rule] = []
    for i, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise ConfigError(f"[[rules]] entry #{i} must be a table")
        rule = _parse_rule(item, i)
        if rule.name in seen:
            raise ConfigError(f"duplicate rule name: {rule.name!r}")
        seen.add(rule.name)
        rules.append(rule)

    discord_raw = (raw.get("notify") or {}).get("discord")
    try:
        discord = discord_config_from_dict(discord_raw)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    if discord and discord.rule_filter:
        unknown = set(discord.rule_filter) - {r.name for r in rules}
        if unknown:
            raise ConfigError(
                f"notify.discord.rules references undefined rule(s): {sorted(unknown)}"
            )

    return Config(logs=logs, rules=tuple(rules), discord=discord)


def _parse_logs(raw_logs: object) -> tuple[CTLog, ...]:
    if not isinstance(raw_logs, list):
        raise ConfigError("'logs' must be an array of tables")
    out: list[CTLog] = []
    seen: set[str] = set()
    for i, item in enumerate(raw_logs):
        if not isinstance(item, dict):
            raise ConfigError(f"[[logs]] entry #{i} must be a table")
        name = item.get("name")
        url = item.get("url")
        if not isinstance(name, str) or not name:
            raise ConfigError(f"[[logs]] entry #{i} missing 'name'")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ConfigError(f"log {name!r}: 'url' must be http(s)://...")
        if name in seen:
            raise ConfigError(f"duplicate log name: {name!r}")
        seen.add(name)
        out.append(CTLog(name=name, url=url))
    return tuple(out)


def _parse_rule(raw: dict, index: int) -> Rule:
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"[[rules]] entry #{index} missing 'name'")

    patterns = raw.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ConfigError(f"rule {name!r}: 'patterns' must be a non-empty list")
    if not all(isinstance(p, str) and p for p in patterns):
        raise ConfigError(f"rule {name!r}: every pattern must be a non-empty string")

    exclude = raw.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(p, str) for p in exclude):
        raise ConfigError(f"rule {name!r}: 'exclude' must be a list of strings")

    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise ConfigError(f"rule {name!r}: 'tags' must be a list of strings")

    return Rule(
        name=name,
        patterns=tuple(patterns),
        exclude=tuple(exclude),
        tags=tuple(tags),
    )
