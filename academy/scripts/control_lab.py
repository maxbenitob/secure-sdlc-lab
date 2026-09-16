#!/usr/bin/env python3
"""Safe local helper for Secure SDLC Control Lab scenario state.

This script never changes GitHub repository settings, branch protection, cloud resources,
secrets, or application code. It only records a local learning state file under academy/.
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "scenarios.json"
STATE = ROOT / ".scenario-state.json"
VALID_STATES = ["BASELINE", "WEAK", "CONTROL_L1", "CONTROL_L2", "CONTROL_L3", "CONTROL_L4", "VERIFIED", "RESET"]


def load_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def load_state():
    if not STATE.exists():
        return {}
    return json.loads(STATE.read_text(encoding="utf-8"))


def save_state(state):
    STATE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def find_scenario(sid):
    for s in load_catalog()["scenarios"]:
        if s["id"] == sid:
            return s
    raise SystemExit(f"Unknown scenario: {sid}")


def cmd_list(_):
    state = load_state()
    for s in load_catalog()["scenarios"]:
        print(f"{s['id']:12} {state.get(s['id'], 'BASELINE'):12} {s['title']}")


def cmd_show(args):
    s = find_scenario(args.id)
    current = load_state().get(args.id, "BASELINE")
    print(json.dumps({**s, "current_state": current, "lifecycle": VALID_STATES}, indent=2, ensure_ascii=False))


def cmd_set(args):
    find_scenario(args.id)
    if args.state not in VALID_STATES:
        raise SystemExit(f"Invalid state. Choose one of: {', '.join(VALID_STATES)}")
    state = load_state()
    state[args.id] = args.state
    save_state(state)
    print(f"{args.id} -> {args.state}")
    print("State recorded locally only. No GitHub or application configuration was changed.")


def cmd_reset(args):
    state = load_state()
    if args.id:
        find_scenario(args.id)
        state.pop(args.id, None)
    else:
        state = {}
    save_state(state)
    print("Local scenario state reset.")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("list")
    a.set_defaults(func=cmd_list)
    a = sub.add_parser("show")
    a.add_argument("id")
    a.set_defaults(func=cmd_show)
    a = sub.add_parser("set-state")
    a.add_argument("id")
    a.add_argument("state")
    a.set_defaults(func=cmd_set)
    a = sub.add_parser("reset")
    a.add_argument("id", nargs="?")
    a.set_defaults(func=cmd_reset)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
