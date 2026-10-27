"""Tamper-evident audit log.

Every entry stores the hash of the entry before it, so editing or deleting
a past entry breaks the chain and `verify()` reports where.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def record(self, **event) -> dict:
        entries = self._entries()
        entry = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **event,
            "prev": entries[-1]["hash"] if entries else GENESIS,
        }
        entry["hash"] = _digest(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (True, None) if intact, or (False, line_number) of the first broken entry."""
        prev = GENESIS
        for number, entry in enumerate(self._entries(), start=1):
            if entry.get("prev") != prev or entry.get("hash") != _digest(entry):
                return False, number
            prev = entry["hash"]
        return True, None
