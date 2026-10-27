"""Access policy: who an agent is, and what it may do.

Rules are evaluated per agent. Deny beats approval, approval beats allow,
and anything not explicitly allowed is denied.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_DUMMY_DIGEST = "0" * 64


class Decision(str, Enum):
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


@dataclass(frozen=True)
class Rule:
    tool: str
    resource: str
    effect: Decision
    reason: str = ""

    def matches(self, tool: str, resource: str) -> bool:
        return fnmatch.fnmatchcase(tool, self.tool) and fnmatch.fnmatchcase(resource, self.resource)


@dataclass(frozen=True)
class Agent:
    id: str
    token_sha256: str
    description: str = ""
    rules: tuple[Rule, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Result:
    decision: Decision
    reason: str
    rule: Rule | None = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Policy:
    def __init__(self, agents: dict[str, Agent]):
        self.agents = agents

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        agents: dict[str, Agent] = {}
        for agent_id, spec in data.get("agents", {}).items():
            rules = tuple(
                Rule(
                    tool=r["tool"],
                    resource=r.get("resource", "*"),
                    effect=Decision(r["effect"]),
                    reason=r.get("reason", ""),
                )
                for r in spec.get("rules", [])
            )
            agents[agent_id] = Agent(
                id=agent_id,
                token_sha256=spec["token_sha256"],
                description=spec.get("description", ""),
                rules=rules,
            )
        return cls(agents)

    def authenticate(self, agent_id: str, token: str) -> Agent | None:
        """Return the agent if the token matches, using a constant-time comparison."""
        agent = self.agents.get(agent_id)
        digest = hash_token(token or "")
        expected = agent.token_sha256 if agent else _DUMMY_DIGEST
        valid = hmac.compare_digest(digest, expected)
        return agent if (agent and valid) else None

    def evaluate(self, agent: Agent, tool: str, resource: str) -> Result:
        matches = [r for r in agent.rules if r.matches(tool, resource)]
        for effect in (Decision.DENY, Decision.NEEDS_APPROVAL, Decision.ALLOW):
            for rule in matches:
                if rule.effect is effect:
                    return Result(effect, rule.reason or f"Matched rule for {rule.tool} on {rule.resource}.", rule)
        return Result(Decision.DENY, "No rule allows this, so it is denied by default.")
