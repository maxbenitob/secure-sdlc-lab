#!/usr/bin/env python3
"""Generate synthetic evidence snapshots for Academy threat-control scenarios.

The simulator is intentionally local-only. It does not call GitHub APIs, cloud APIs,
registries, Kubernetes, or the application. Its purpose is to provide a reversible
evidence surface for audit practice when a live control cannot safely be changed.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
CATALOG = BASE / "scenarios.json"
OUT = BASE / ".state" / "evidence"
VALID = ["BASELINE","WEAK","CONTROL_L1","CONTROL_L2","CONTROL_L3","CONTROL_L4","VERIFIED"]

FAMILY_EVIDENCE = {
    "DEV": ["endpoint_posture","auth_event","pr_review"],
    "SRC": ["ruleset","pr_history","commit_history","audit_event"],
    "DEP": ["dependency_manifest","lockfile","sca_result","sbom"],
    "CIC": ["workflow","runner_inventory","job_log","exception_record"],
    "IDN": ["oidc_trust","iam_policy","token_event","cloud_audit"],
    "BLD": ["build_config","builder_identity","digest","provenance"],
    "ART": ["artifact_digest","signature","provenance","admission_event"],
    "REG": ["registry_policy","push_event","digest_history","quarantine_record"],
    "REL": ["iac_plan","policy_result","deployment_event","rollback_record"],
    "DAT": ["data_classification","masking_evidence","access_event"],
    "OBS": ["audit_log","siem_event","alert","retention_config"],
    "INT": ["oauth_scope","integration_inventory","webhook_event","token_lifecycle"],
    "AI": ["agent_policy","tool_call","pr_evidence","workflow_diff"],
    "RES": ["incident_timeline","rotation_record","rebuild_record","validation_test"],
    "GOV": ["role_matrix","exception_record","audit_event","review_record"],
    "APP": ["source_diff","sast_result","security_test","pipeline_status"],
}


def load_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))["scenarios"]


def find(sid):
    for item in load_catalog():
        if item["id"] == sid:
            return item
    raise SystemExit(f"Unknown scenario: {sid}")


def status_for(state, index):
    # Synthetic maturity signal only; never presented as proof of a live control.
    order={"BASELINE":1,"WEAK":0,"CONTROL_L1":2,"CONTROL_L2":3,"CONTROL_L3":4,"CONTROL_L4":5,"VERIFIED":5}
    score=order[state]
    if index >= score:
        return "missing_or_weak"
    return "present"


def build_snapshot(scenario, state):
    evidence=FAMILY_EVIDENCE.get(scenario["family"],["configuration","operation_log"])
    return {
        "synthetic": True,
        "scenario_id": scenario["id"],
        "family": scenario["family"],
        "title": scenario["title"],
        "qsus": scenario.get("qsus",[]),
        "state": state,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning": "Synthetic training evidence. Not evidence of the live GitHub repository or any real environment.",
        "evidence": [
            {"ref":f"EV-{i+1:02d}","type":name,"status":status_for(state,i),"source":"academy synthetic fixture"}
            for i,name in enumerate(evidence)
        ],
        "auditor_prompts": [
            "What does this evidence demonstrate?",
            "What does it not demonstrate?",
            "Who can change or bypass the control?",
            "What negative test would you perform?",
            "Is residual risk acceptable after this state?"
        ]
    }


def main():
    if len(sys.argv) < 3:
        raise SystemExit("Usage: evidence_simulator.py <scenario-id> <state>")
    sid,state=sys.argv[1],sys.argv[2].upper()
    if state not in VALID:
        raise SystemExit(f"State must be one of: {', '.join(VALID)}")
    scenario=find(sid)
    snapshot=build_snapshot(scenario,state)
    OUT.mkdir(parents=True,exist_ok=True)
    path=OUT/f"{sid}-{state}.json"
    path.write_text(json.dumps(snapshot,indent=2,ensure_ascii=False),encoding="utf-8")
    print(path)
    print(json.dumps(snapshot,indent=2,ensure_ascii=False))

if __name__ == "__main__":
    main()
