from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from .config import Rule


@dataclass(frozen=True)
class Match:
    rule: Rule
    matched_domains: tuple[str, ...]


def match_domains(domains: list[str], rules: tuple[Rule, ...]) -> list[Match]:
    if not domains:
        return []
    normalised = [d.lower() for d in domains if isinstance(d, str) and d]
    out: list[Match] = []
    for rule in rules:
        hits = tuple(d for d in normalised if _rule_matches(d, rule))
        if hits:
            out.append(Match(rule=rule, matched_domains=hits))
    return out


def _rule_matches(domain: str, rule: Rule) -> bool:
    if not any(fnmatchcase(domain, p.lower()) for p in rule.patterns):
        return False
    if any(fnmatchcase(domain, p.lower()) for p in rule.exclude):
        return False
    return True
