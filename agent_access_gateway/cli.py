"""Command line for the person in the loop."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .approvals import ApprovalStore
from .audit import AuditLog
from .policy import hash_token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aag", description="Approve agent requests and check the audit log.")
    parser.add_argument("--home", default="demo", help="folder holding policy.toml and state/ (default: demo)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("pending", help="list requests waiting for approval")
    approve = sub.add_parser("approve", help="approve a waiting request")
    approve.add_argument("request_id")
    approve.add_argument("--by", required=True, help="who is approving")
    sub.add_parser("log", help="show the audit log")
    sub.add_parser("verify", help="check the audit log has not been altered")
    token = sub.add_parser("hash-token", help="print the SHA-256 hash to store in policy.toml")
    token.add_argument("token")
    args = parser.parse_args(argv)

    home = Path(args.home)
    approvals = ApprovalStore(home / "state" / "approvals.json")
    audit = AuditLog(home / "state" / "audit.log")

    if args.command == "pending":
        items = approvals.pending()
        print(json.dumps(items, indent=2) if items else "Nothing is waiting for approval.")
    elif args.command == "approve":
        ok = approvals.approve(args.request_id, args.by)
        print(f"Approved {args.request_id}." if ok else f"No pending request named {args.request_id}.")
        return 0 if ok else 1
    elif args.command == "log":
        for entry in audit._entries():
            print(f"{entry['time']}  {entry['agent']:<14} {entry['decision']:<15} {entry['tool']} {entry['resource']}")
    elif args.command == "verify":
        ok, line = audit.verify()
        print("The audit log is intact." if ok else f"The audit log was altered at entry {line}.")
        return 0 if ok else 1
    elif args.command == "hash-token":
        print(hash_token(args.token))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
