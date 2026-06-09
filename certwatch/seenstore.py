from __future__ import annotations

from pathlib import Path

DEFAULT_SEEN_DB = Path.home() / ".local" / "share" / "certwatch" / "seen_domains.txt"


class SeenDomains:
    """Persistent set of domains already observed.

    Backed by a plain text file (one domain per line). New domains are
    appended in a single write per batch so the store survives crashes.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._seen: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        self._seen = {
            line
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

    def filter_new(self, domains: list[str]) -> list[str]:
        return [d for d in domains if d not in self._seen]

    def mark_seen(self, domains: list[str]) -> None:
        new = [d for d in domains if d not in self._seen]
        if not new:
            return
        self._seen.update(new)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            for d in new:
                f.write(d + "\n")

    def __len__(self) -> int:
        return len(self._seen)
