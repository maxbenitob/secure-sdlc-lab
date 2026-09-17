#!/usr/bin/env python3
"""Safe local state engine for Secure SDLC Academy scenarios.

This script never changes GitHub settings, cloud resources, secrets, branch protection,
or application code. It only manages a local JSON state file under academy/.state.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
CATALOG = BASE / "scenarios.json"
STATE_DIR = BASE / ".state"
STATE_FILE = STATE_DIR / "scenario-state.json"
VALID = ["BASELINE","WEAK","CONTROL_L1","CONTROL_L2","CONTROL_L3","CONTROL_L4","VERIFIED","RESET"]


def load_catalog():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "scenarios" in data:
        return data["scenarios"]
    if isinstance(data, list):
        return data
    return data.get("items", [])


def ids(items):
    out=[]
    for x in items:
        if isinstance(x,str): out.append(x)
        elif isinstance(x,dict): out.append(x.get("id") or x.get("qsus"))
    return [x for x in out if x]


def load_state():
    if not STATE_FILE.exists():
        return {}
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save_state(state):
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    scenarios = load_catalog()
    known = ids(scenarios)
    if len(sys.argv) < 2:
        print("Commands: list | show <id> | set <id> <state> | reset <id> | status")
        raise SystemExit(2)
    cmd=sys.argv[1]
    state=load_state()
    if cmd=="list":
        for sid in known: print(sid)
    elif cmd=="status":
        if not state: print("No local scenario state recorded.")
        for sid,val in sorted(state.items()): print(f"{sid}: {val}")
    elif cmd=="show":
        sid=sys.argv[2]
        if sid not in known: raise SystemExit(f"Unknown scenario: {sid}")
        print(json.dumps({"id":sid,"state":state.get(sid,"BASELINE")},indent=2))
    elif cmd=="set":
        sid,target=sys.argv[2],sys.argv[3].upper()
        if sid not in known: raise SystemExit(f"Unknown scenario: {sid}")
        if target not in VALID: raise SystemExit(f"Invalid state. Use: {', '.join(VALID)}")
        state[sid]=target
        save_state(state)
        print(f"{sid} -> {target}")
        print("State recorded locally only. No external control was changed.")
    elif cmd=="reset":
        sid=sys.argv[2]
        if sid not in known: raise SystemExit(f"Unknown scenario: {sid}")
        state[sid]="BASELINE"
        save_state(state)
        print(f"{sid} -> BASELINE")
    else:
        raise SystemExit("Unknown command")

if __name__ == "__main__":
    main()
