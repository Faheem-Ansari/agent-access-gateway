"""Human approval for sensitive agent actions.

An approval is tied to one agent, tool and resource, and can be used once.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path


class ApprovalStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def _save(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def request(self, agent_id: str, tool: str, resource: str) -> str:
        data = self._load()
        request_id = "apr_" + secrets.token_hex(4)
        data[request_id] = {
            "agent": agent_id,
            "tool": tool,
            "resource": resource,
            "status": "pending",
            "requested": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._save(data)
        return request_id

    def pending(self) -> dict:
        return {k: v for k, v in self._load().items() if v["status"] == "pending"}

    def approve(self, request_id: str, approver: str) -> bool:
        data = self._load()
        item = data.get(request_id)
        if not item or item["status"] != "pending":
            return False
        item.update(status="approved", approver=approver)
        self._save(data)
        return True

    def consume(self, request_id: str, agent_id: str, tool: str, resource: str) -> bool:
        """Use an approval once. It must match the exact agent, tool and resource."""
        data = self._load()
        item = data.get(request_id)
        if not item or item["status"] != "approved":
            return False
        if (item["agent"], item["tool"], item["resource"]) != (agent_id, tool, resource):
            return False
        item["status"] = "used"
        self._save(data)
        return True
