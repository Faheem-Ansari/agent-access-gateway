"""The gateway: every tool call is authenticated, checked against policy and audited."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .approvals import ApprovalStore
from .audit import AuditLog
from .policy import Decision, Policy


class AccessDenied(Exception):
    pass


@dataclass
class Gateway:
    policy: Policy
    audit: AuditLog
    approvals: ApprovalStore
    workspace: Path
    secrets_file: Path

    def authorize(self, agent_id: str, token: str, tool: str, resource: str, approval_id: str | None = None) -> None:
        """Raise AccessDenied unless the call is allowed. Records every decision."""
        agent = self.policy.authenticate(agent_id, token)
        if agent is None:
            self.audit.record(agent=agent_id, tool=tool, resource=resource, decision="deny", reason="Authentication failed.")
            raise AccessDenied("Authentication failed: unknown agent or wrong token.")

        result = self.policy.evaluate(agent, tool, resource)

        if result.decision is Decision.NEEDS_APPROVAL:
            if approval_id and self.approvals.consume(approval_id, agent_id, tool, resource):
                self.audit.record(agent=agent_id, tool=tool, resource=resource, decision="allow",
                                  reason=f"Approved by a person ({approval_id}).")
                return
            request_id = self.approvals.request(agent_id, tool, resource)
            self.audit.record(agent=agent_id, tool=tool, resource=resource, decision="needs_approval",
                              reason=result.reason, approval_id=request_id)
            raise AccessDenied(
                f"This action needs a person's approval. Request {request_id} is waiting. "
                f"Once approved, call again with approval_id='{request_id}'."
            )

        self.audit.record(agent=agent_id, tool=tool, resource=resource, decision=result.decision.value, reason=result.reason)
        if result.decision is Decision.DENY:
            raise AccessDenied(f"Denied: {result.reason}")

    # Resource helpers -------------------------------------------------

    def workspace_path(self, agent_id: str, tool: str, relative: str) -> tuple[Path, str]:
        """Resolve a path inside the workspace. Anything that escapes it is rejected and audited."""
        clean = PurePosixPath(relative.strip().lstrip("/"))
        target = (self.workspace / clean).resolve()
        root = self.workspace.resolve()
        if target != root and root not in target.parents:
            self.audit.record(agent=agent_id, tool=tool, resource=relative, decision="deny",
                              reason="Path is outside the agent workspace.")
            raise AccessDenied("Denied: the path is outside the agent workspace.")
        return target, target.relative_to(root).as_posix() if target != root else "."

    # Tools ------------------------------------------------------------

    def list_files(self, agent_id: str, token: str, folder: str = ".") -> str:
        path, resource = self.workspace_path(agent_id, "list_files", folder)
        self.authorize(agent_id, token, "list_files", resource)
        if not path.is_dir():
            return f"No folder named {resource}."
        names = sorted(p.relative_to(self.workspace.resolve()).as_posix() + ("/" if p.is_dir() else "") for p in path.iterdir())
        return "\n".join(names) or "The folder is empty."

    def read_file(self, agent_id: str, token: str, path: str) -> str:
        target, resource = self.workspace_path(agent_id, "read_file", path)
        self.authorize(agent_id, token, "read_file", resource)
        if not target.is_file():
            return f"No file named {resource}."
        return target.read_text(encoding="utf-8")

    def get_secret(self, agent_id: str, token: str, name: str, approval_id: str | None = None) -> str:
        resource = f"secrets/{name}"
        self.authorize(agent_id, token, "get_secret", resource, approval_id)
        vault = json.loads(self.secrets_file.read_text(encoding="utf-8"))
        if name not in vault:
            return f"No secret named {name}."
        return vault[name]

    def deploy(self, agent_id: str, token: str, service: str, environment: str, approval_id: str | None = None) -> str:
        resource = f"{environment}/{service}"
        self.authorize(agent_id, token, "deploy", resource, approval_id)
        return f"Deployed {service} to {environment} (simulated)."
