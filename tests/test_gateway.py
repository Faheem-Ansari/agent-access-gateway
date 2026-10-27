import json
import shutil
from pathlib import Path

import pytest

from agent_access_gateway.approvals import ApprovalStore
from agent_access_gateway.audit import AuditLog
from agent_access_gateway.gateway import AccessDenied, Gateway
from agent_access_gateway.policy import Decision, Policy

DEMO = Path(__file__).resolve().parents[1] / "demo"
RESEARCH = ("research-bot", "demo-research-token")
DEPLOY = ("deploy-bot", "demo-deploy-token")


@pytest.fixture
def gw(tmp_path):
    home = tmp_path / "demo"
    shutil.copytree(DEMO, home, ignore=shutil.ignore_patterns("state"))
    return Gateway(
        policy=Policy.load(home / "policy.toml"),
        audit=AuditLog(home / "state" / "audit.log"),
        approvals=ApprovalStore(home / "state" / "approvals.json"),
        workspace=home / "workspace",
        secrets_file=home / "secrets.json",
    )


def test_wrong_token_is_rejected(gw):
    with pytest.raises(AccessDenied, match="Authentication failed"):
        gw.read_file("research-bot", "wrong-token", "docs/architecture.md")


def test_unknown_agent_is_rejected(gw):
    with pytest.raises(AccessDenied, match="Authentication failed"):
        gw.read_file("nobody", "demo-research-token", "docs/architecture.md")


def test_allowed_read(gw):
    assert "architecture" in gw.read_file(*RESEARCH, "docs/architecture.md")


def test_default_deny(gw):
    with pytest.raises(AccessDenied, match="denied by default"):
        gw.read_file(*RESEARCH, "reports/release-notes.md")


def test_explicit_deny_on_secrets(gw):
    with pytest.raises(AccessDenied, match="never receive credentials"):
        gw.get_secret(*RESEARCH, "staging-db-password")


def test_path_traversal_is_blocked(gw):
    with pytest.raises(AccessDenied, match="outside the agent workspace"):
        gw.read_file(*RESEARCH, "docs/../../secrets.json")
    assert gw.audit._entries()[-1]["decision"] == "deny"


def test_deny_beats_allow():
    from agent_access_gateway.policy import Agent, Rule
    agent = Agent("a", "x", rules=(Rule("read_file", "*", Decision.ALLOW), Rule("read_file", "docs/*", Decision.DENY)))
    assert Policy({"a": agent}).evaluate(agent, "read_file", "docs/x").decision is Decision.DENY


def test_staging_deploy_is_allowed(gw):
    assert "staging" in gw.deploy(*DEPLOY, "api", "staging")


def test_production_deploy_needs_one_time_approval(gw):
    with pytest.raises(AccessDenied, match="needs a person's approval") as exc:
        gw.deploy(*DEPLOY, "api", "production")
    request_id = str(exc.value).split("Request ")[1].split(" ")[0]

    with pytest.raises(AccessDenied):  # not approved yet
        gw.deploy(*DEPLOY, "api", "production", approval_id=request_id)

    assert gw.approvals.approve(request_id, approver="faheem")
    assert "production" in gw.deploy(*DEPLOY, "api", "production", approval_id=request_id)

    with pytest.raises(AccessDenied):  # approvals work once
        gw.deploy(*DEPLOY, "api", "production", approval_id=request_id)


def test_approval_cannot_be_reused_for_a_different_resource(gw):
    with pytest.raises(AccessDenied) as exc:
        gw.deploy(*DEPLOY, "api", "production")
    request_id = str(exc.value).split("Request ")[1].split(" ")[0]
    gw.approvals.approve(request_id, approver="faheem")
    with pytest.raises(AccessDenied):
        gw.deploy(*DEPLOY, "billing", "production", approval_id=request_id)


def test_every_decision_is_audited_and_tamper_evident(gw):
    gw.read_file(*RESEARCH, "docs/architecture.md")
    with pytest.raises(AccessDenied):
        gw.get_secret(*RESEARCH, "prod-db-password")
    assert gw.audit.verify() == (True, None)
    assert len(gw.audit._entries()) == 2

    lines = gw.audit.path.read_text().splitlines()
    first = json.loads(lines[0])
    first["decision"] = "deny"
    lines[0] = json.dumps(first, sort_keys=True)
    gw.audit.path.write_text("\n".join(lines) + "\n")
    assert gw.audit.verify() == (False, 1)
