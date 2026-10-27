"""MCP server. Each agent runs its own connection with its own credentials.

Set these environment variables in your MCP client configuration:
  AAG_AGENT_ID     the agent's identity, for example deploy-bot
  AAG_AGENT_TOKEN  the agent's token
  AAG_HOME         folder holding policy.toml, workspace/ and secrets.json (defaults to ./demo)
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .approvals import ApprovalStore
from .audit import AuditLog
from .gateway import AccessDenied, Gateway
from .policy import Policy


def build_gateway(home: Path) -> Gateway:
    return Gateway(
        policy=Policy.load(home / "policy.toml"),
        audit=AuditLog(home / "state" / "audit.log"),
        approvals=ApprovalStore(home / "state" / "approvals.json"),
        workspace=home / "workspace",
        secrets_file=home / "secrets.json",
    )


HOME = Path(os.environ.get("AAG_HOME", "demo")).resolve()
AGENT_ID = os.environ.get("AAG_AGENT_ID", "")
AGENT_TOKEN = os.environ.get("AAG_AGENT_TOKEN", "")
gateway = build_gateway(HOME)

mcp = MCPServer(
    "Agent Access Gateway",
    instructions="Every call is checked against this agent's access policy and written to an audit log. "
    "If a call needs approval, ask a person to approve the request, then call again with the approval_id.",
)


def _guard(fn, *args, **kwargs) -> str:
    try:
        return fn(AGENT_ID, AGENT_TOKEN, *args, **kwargs)
    except AccessDenied as exc:
        return str(exc)


@mcp.tool()
def list_files(folder: str = ".") -> str:
    """List files in a workspace folder the agent is allowed to see."""
    return _guard(gateway.list_files, folder)


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace, if the agent's policy allows it."""
    return _guard(gateway.read_file, path)


@mcp.tool()
def get_secret(name: str, approval_id: str | None = None) -> str:
    """Fetch a secret. Sensitive secrets need a person's approval first."""
    return _guard(gateway.get_secret, name, approval_id=approval_id)


@mcp.tool()
def deploy(service: str, environment: str, approval_id: str | None = None) -> str:
    """Deploy a service (simulated). Production deployments need a person's approval."""
    return _guard(gateway.deploy, service, environment, approval_id=approval_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
