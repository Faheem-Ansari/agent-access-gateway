# Agent Access Gateway

[![tests](https://github.com/Faheem-Ansari/agent-access-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/Faheem-Ansari/agent-access-gateway/actions/workflows/tests.yml)

An MCP server that gives AI agents **least-privilege access to tools**, asks a **person to approve** sensitive actions, and records **every decision** in a tamper-evident audit log.

AI agents are getting credentials and access to real systems faster than teams can decide what those agents should be allowed to do. This project is a small, working answer to three questions every team adopting agents has to settle:

1. **Who is this agent?** Each agent has its own identity and token. Tokens are stored only as SHA-256 hashes and compared in constant time.
2. **What may it do?** A per-agent policy decides each call: allow, deny, or needs approval. Anything not explicitly allowed is denied.
3. **What did it do?** Every decision is written to a hash-chained log, so editing or deleting a past entry is detectable.

## How a decision is made

| Step | What happens |
| --- | --- |
| Authenticate | Unknown agents and wrong tokens are rejected and logged. |
| Match rules | The agent's rules are matched on tool and resource, for example `deploy` on `production/*`. |
| Decide | Deny beats approval, approval beats allow, and no match means deny. |
| Approve | A sensitive action creates a request. A person approves it, and the approval works **once**, for that exact agent, tool and resource. |
| Record | The decision, reason and approver go into the audit log. |

Paths are resolved inside the agent's workspace, so attempts like `../secrets.json` are denied and logged.

## The demo policy

Two agents ship in [`demo/policy.toml`](demo/policy.toml):

| Agent | Can do on its own | Needs a person | Never |
| --- | --- | --- | --- |
| `research-bot` | Read `docs/`, list files | | Any secret |
| `deploy-bot` | Deploy to staging, use staging secrets, read `reports/` | Deploy to production, use production secrets | Everything not listed |

The demo tokens are `demo-research-token` and `demo-deploy-token`. They exist only for this demo.

## Quick start

Requires Python 3.11 or later.

```bash
git clone https://github.com/Faheem-Ansari/agent-access-gateway.git
cd agent-access-gateway
pip install -e ".[dev]"
pytest
```

## Connect it to an MCP client

Add a server entry to your MCP client's configuration (for example, Claude Desktop). Each agent gets its own entry with its own credentials:

```json
{
  "mcpServers": {
    "deploy-bot": {
      "command": "agent-access-gateway",
      "env": {
        "AAG_HOME": "/path/to/agent-access-gateway/demo",
        "AAG_AGENT_ID": "deploy-bot",
        "AAG_AGENT_TOKEN": "demo-deploy-token"
      }
    }
  }
}
```

Then ask the agent to deploy `api` to production. It will get back an approval request instead of a deployment.

## Be the person in the loop

```bash
aag --home demo pending                       # see what is waiting
aag --home demo approve apr_1a2b3c4d --by you # approve one request
aag --home demo log                           # see every decision
aag --home demo verify                        # check nothing was altered
aag hash-token "a-new-token"                  # hash a token for policy.toml
```

## Design choices

- **Default deny.** Forgetting a rule should fail closed, not open.
- **One-time, scoped approvals.** An approval for `production/api` can't be replayed, and can't be reused for `production/billing`.
- **Secrets never live in the policy.** Only token hashes do.
- **Explain every decision.** Each result carries a plain-language reason, so agents and people can see why.

## What's next

- Rate limits and quotas per agent, so one busy agent can't crowd out the rest
- OAuth-based agent authentication, in line with the MCP authorization specification
- Passkey-confirmed approvals, so approving a sensitive action needs a person, not just a command
- Policy tests that fail the build when a rule grants more than intended

## Status

A reference project for exploring agent access control. It is not hardened for production use. See [SECURITY.md](SECURITY.md).

Built by [Faheem Ansari](https://www.linkedin.com/in/faheem-ansari-b9362047/).
