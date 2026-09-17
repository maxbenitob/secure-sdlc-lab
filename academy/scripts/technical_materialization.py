#!/usr/bin/env python3
"""Safe local materializer for Secure SDLC Academy threat scenarios.

This script never changes GitHub settings, secrets, cloud IAM, Kubernetes or any
external system. It writes disposable fixtures under academy/runtime/ only.
"""
from pathlib import Path
import json, shutil, sys

BASE = Path(__file__).resolve().parents[1]
SCENARIOS = json.loads((BASE / "scenarios.json").read_text(encoding="utf-8"))["scenarios"]
RUNTIME = BASE / "runtime"

ARTIFACT = {
    "DEV":"endpoint-posture.json","SRC":"repository-rules.json","DEP":"dependency-policy.json",
    "CIC":"ci-control-plane.json","IDN":"workload-identity.json","BLD":"build-policy.json",
    "ART":"artifact-trust.json","REG":"registry-policy.json","REL":"release-policy.json",
    "DAT":"data-environment-policy.json","OBS":"observability-policy.json","INT":"integration-trust.json",
    "AI":"agent-policy.json","RES":"recovery-readiness.json","GOV":"governance-policy.json",
    "APP":"application-security.json"
}

# Five-state technical progression by family. The values are intentionally
# synthetic and local: they model control maturity without mutating a live system.
LEVELS = {
"DEV":[
 {"managed":False,"mfa":"password","device_trust":False,"edr":"absent"},
 {"managed":True,"mfa":"totp","device_trust":False,"edr":"monitor"},
 {"managed":True,"mfa":"phishing-resistant","device_trust":True,"edr":"enforce"},
 {"managed":True,"mfa":"phishing-resistant","device_trust":True,"edr":"enforce","session_risk":"block-high"},
 {"managed":True,"mfa":"phishing-resistant","device_trust":True,"edr":"enforce","session_risk":"block-high","forensic_retention_days":180}],
"SRC":[
 {"require_pr":False,"approvals":0,"codeowners":False,"enforce_admins":False,"bypass_alerting":False},
 {"require_pr":True,"approvals":1,"codeowners":False,"enforce_admins":False,"bypass_alerting":False},
 {"require_pr":True,"approvals":2,"codeowners":True,"enforce_admins":True,"bypass_alerting":False},
 {"require_pr":True,"approvals":2,"codeowners":True,"enforce_admins":True,"bypass_alerting":True,"workflow_paths_protected":True},
 {"require_pr":True,"approvals":2,"codeowners":True,"enforce_admins":True,"bypass_alerting":True,"workflow_paths_protected":True,"audit_retention_days":365}],
"DEP":[
 {"pinning":"floating","lockfile":False,"publisher_review":False,"sca_gate":"off","sbom":False},
 {"pinning":"major-minor","lockfile":True,"publisher_review":False,"sca_gate":"report","sbom":False},
 {"pinning":"exact","lockfile":True,"publisher_review":True,"sca_gate":"block-critical","sbom":True},
 {"pinning":"exact","lockfile":True,"publisher_review":True,"sca_gate":"block-policy","sbom":True,"third_party_ci_sha_pin":True},
 {"pinning":"exact","lockfile":True,"publisher_review":True,"sca_gate":"block-policy","sbom":True,"third_party_ci_sha_pin":True,"rapid_recall_ready":True}],
"CIC":[
 {"workflow_review":False,"runner":"persistent-shared","permissions":"write-all","egress":"open","gate":"advisory","exceptions":"unbounded"},
 {"workflow_review":True,"runner":"persistent-shared","permissions":"read-mostly","egress":"open","gate":"report","exceptions":"manual"},
 {"workflow_review":True,"runner":"ephemeral","permissions":"least-privilege","egress":"allowlist","gate":"blocking","exceptions":"time-bound"},
 {"workflow_review":True,"runner":"ephemeral","permissions":"least-privilege","egress":"allowlist","gate":"blocking","exceptions":"time-bound","override_alerting":True},
 {"workflow_review":True,"runner":"ephemeral","permissions":"least-privilege","egress":"allowlist","gate":"blocking","exceptions":"time-bound","override_alerting":True,"runner_rebuild_tested":True}],
"IDN":[
 {"credential":"static-secret","subject":"repo:*","role_scope":"admin","ttl_minutes":1440,"monitoring":False},
 {"credential":"oidc","subject":"repo:org/*","role_scope":"broad","ttl_minutes":60,"monitoring":False},
 {"credential":"oidc","subject":"repo:org/app:ref:refs/heads/main","role_scope":"deploy-only","ttl_minutes":15,"monitoring":False},
 {"credential":"oidc","subject":"repo:org/app:environment:prod","role_scope":"deploy-only","ttl_minutes":10,"monitoring":True},
 {"credential":"oidc","subject":"repo:org/app:environment:prod","role_scope":"deploy-only","ttl_minutes":10,"monitoring":True,"revoke_and_reissue_tested":True}],
"BLD":[
 {"inputs":"mutable","builder":"shared","network":"open","reproducible":False,"provenance":False},
 {"inputs":"partially-pinned","builder":"shared","network":"open","reproducible":False,"provenance":False},
 {"inputs":"pinned","builder":"isolated","network":"restricted","reproducible":True,"provenance":False},
 {"inputs":"pinned","builder":"isolated","network":"restricted","reproducible":True,"provenance":True},
 {"inputs":"pinned","builder":"isolated","network":"restricted","reproducible":True,"provenance":True,"trusted_rebuild":True}],
"ART":[
 {"reference":"tag","immutable":False,"signed":False,"provenance_verified":False,"admission":"none"},
 {"reference":"digest","immutable":False,"signed":False,"provenance_verified":False,"admission":"none"},
 {"reference":"digest","immutable":True,"signed":True,"provenance_verified":False,"admission":"audit"},
 {"reference":"digest","immutable":True,"signed":True,"provenance_verified":True,"admission":"enforce"},
 {"reference":"digest","immutable":True,"signed":True,"provenance_verified":True,"admission":"enforce","quarantine_and_rebuild":True}],
"REG":[
 {"pushers":"broad","tag_overwrite":True,"delete":True,"promotion":"tag","audit":False},
 {"pushers":"ci-only","tag_overwrite":True,"delete":True,"promotion":"tag","audit":False},
 {"pushers":"ci-only","tag_overwrite":False,"delete":False,"promotion":"digest","audit":True},
 {"pushers":"ci-only","tag_overwrite":False,"delete":False,"promotion":"digest","audit":True,"two_stage_promotion":True},
 {"pushers":"ci-only","tag_overwrite":False,"delete":False,"promotion":"digest","audit":True,"two_stage_promotion":True,"quarantine":True}],
"REL":[
 {"iac_review":False,"policy_as_code":"off","config_changes":"direct","rollout":"all-at-once","rollback":"manual"},
 {"iac_review":True,"policy_as_code":"report","config_changes":"tracked","rollout":"all-at-once","rollback":"manual"},
 {"iac_review":True,"policy_as_code":"block","config_changes":"tracked","rollout":"canary","rollback":"tested"},
 {"iac_review":True,"policy_as_code":"block","config_changes":"approved","rollout":"progressive","rollback":"automatic-threshold"},
 {"iac_review":True,"policy_as_code":"block","config_changes":"approved","rollout":"progressive","rollback":"automatic-threshold","anti_downgrade":True}],
"DAT":[
 {"lower_env_data":"production-copy","masking":False,"prod_connectivity":True,"retention":"unbounded"},
 {"lower_env_data":"masked-copy","masking":True,"prod_connectivity":True,"retention":"90d"},
 {"lower_env_data":"synthetic","masking":True,"prod_connectivity":False,"retention":"30d"},
 {"lower_env_data":"synthetic","masking":True,"prod_connectivity":False,"retention":"30d","access_monitoring":True},
 {"lower_env_data":"synthetic","masking":True,"prod_connectivity":False,"retention":"30d","access_monitoring":True,"deletion_tested":True}],
"OBS":[
 {"sources":[],"centralized":False,"correlation":False,"alerting":False,"retention_days":7},
 {"sources":["repo","ci"],"centralized":True,"correlation":False,"alerting":False,"retention_days":30},
 {"sources":["repo","ci","cloud","registry"],"centralized":True,"correlation":True,"alerting":False,"retention_days":90},
 {"sources":["repo","ci","cloud","registry","runtime"],"centralized":True,"correlation":True,"alerting":True,"retention_days":180},
 {"sources":["repo","ci","cloud","registry","runtime"],"centralized":True,"correlation":True,"alerting":True,"retention_days":365,"reconstruction_drill":True}],
"INT":[
 {"oauth_scope":"admin","webhook_verify":False,"token_ttl":"long","app_allowlist":False,"revocation_tested":False},
 {"oauth_scope":"write","webhook_verify":True,"token_ttl":"long","app_allowlist":False,"revocation_tested":False},
 {"oauth_scope":"least-privilege","webhook_verify":True,"token_ttl":"short","app_allowlist":True,"revocation_tested":False},
 {"oauth_scope":"least-privilege","webhook_verify":True,"token_ttl":"short","app_allowlist":True,"revocation_tested":True},
 {"oauth_scope":"least-privilege","webhook_verify":True,"token_ttl":"short","app_allowlist":True,"revocation_tested":True,"trust_graph_review":True}],
"AI":[
 {"untrusted_context":"direct","tools":"broad","workflow_write":True,"human_gate":"merge-only","tool_logging":False},
 {"untrusted_context":"labelled","tools":"broad","workflow_write":True,"human_gate":"merge-only","tool_logging":True},
 {"untrusted_context":"isolated","tools":"allowlist","workflow_write":False,"human_gate":"privileged-action","tool_logging":True},
 {"untrusted_context":"isolated","tools":"allowlist","workflow_write":False,"human_gate":"risk-based","tool_logging":True,"sandbox":True},
 {"untrusted_context":"isolated","tools":"allowlist","workflow_write":False,"human_gate":"risk-based","tool_logging":True,"sandbox":True,"incident_replay":True}],
"RES":[
 {"containment":False,"rotation":False,"quarantine":False,"trusted_rebuild":False,"validation":False},
 {"containment":True,"rotation":False,"quarantine":False,"trusted_rebuild":False,"validation":False},
 {"containment":True,"rotation":True,"quarantine":True,"trusted_rebuild":False,"validation":False},
 {"containment":True,"rotation":True,"quarantine":True,"trusted_rebuild":True,"validation":False},
 {"containment":True,"rotation":True,"quarantine":True,"trusted_rebuild":True,"validation":True}],
"GOV":[
 {"control_owner":"delivery","sod":False,"exceptions":"permanent","expiry":False,"independent_review":False},
 {"control_owner":"delivery","sod":True,"exceptions":"manual","expiry":False,"independent_review":False},
 {"control_owner":"independent","sod":True,"exceptions":"time-bound","expiry":True,"independent_review":False},
 {"control_owner":"independent","sod":True,"exceptions":"time-bound","expiry":True,"independent_review":True},
 {"control_owner":"independent","sod":True,"exceptions":"time-bound","expiry":True,"independent_review":True,"control_failure_drill":True}],
"APP":[
 {"secure_pattern":False,"sast":"off","security_tests":False,"gate":"off","abuse_cases":False},
 {"secure_pattern":True,"sast":"report","security_tests":False,"gate":"off","abuse_cases":False},
 {"secure_pattern":True,"sast":"report","security_tests":True,"gate":"block-critical","abuse_cases":False},
 {"secure_pattern":True,"sast":"block-policy","security_tests":True,"gate":"block-policy","abuse_cases":True},
 {"secure_pattern":True,"sast":"block-policy","security_tests":True,"gate":"block-policy","abuse_cases":True,"regression_monitoring":True}]
}

TEST_INTENT = {
 "DEV":"endpoint posture, authentication strength, device trust and telemetry",
 "SRC":"pull-request enforcement, independent approval, admin bypass and protected paths",
 "DEP":"pinning, publisher trust, third-party automation and SBOM operational use",
 "CIC":"workflow governance, runner isolation, permissions, egress, gates and exceptions",
 "IDN":"OIDC claim binding, least privilege, token lifetime and monitoring",
 "BLD":"build input mutability, builder isolation, reproducibility and provenance",
 "ART":"digest continuity, immutability, signing, provenance verification and admission",
 "REG":"publisher authorization, overwrite/delete controls, digest promotion and auditability",
 "REL":"IaC review, policy enforcement, runtime configuration, blast radius and rollback",
 "DAT":"lower-environment data, masking, connectivity, retention and monitoring",
 "OBS":"source coverage, centralization, correlation, alerting and retention",
 "INT":"OAuth scopes, webhook verification, app trust and revocation",
 "AI":"untrusted context, tool least privilege, privileged paths, human approval and telemetry",
 "RES":"containment, rotation, quarantine, trusted rebuild and recovery validation",
 "GOV":"control ownership, segregation of duties, exception expiry and independent review",
 "APP":"secure coding, SAST, security tests, blocking gates and abuse cases"
}


def scenario(sid):
    for s in SCENARIOS:
        if s["id"] == sid:
            return s
    raise SystemExit(f"Unknown scenario: {sid}")


def materialize(sid, level, root=None):
    s = scenario(sid)
    idx = int(level[1:]) if level.startswith("L") and level[1:].isdigit() else -1
    if idx not in range(5):
        raise SystemExit("level must be L0..L4")
    root = Path(root) if root else RUNTIME
    out = root / sid / level
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    family = s["family"]
    artifact = ARTIFACT[family]
    config = LEVELS[family][idx]
    (out / artifact).write_text(json.dumps(config, indent=2), encoding="utf-8")
    manifest = {
        "scenario": sid, "title": s["title"], "family": family, "qsus": s.get("qsus", []),
        "level": level, "artifact": artifact,
        "expectedControlStrength": ["exposed","basic","strengthened","assured","resilient"][idx],
        "safeFixture": True
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    result = {"scenario":sid,"level":level,"testIntent":TEST_INTENT[family],"status":"MATERIALIZED","safeFixture":True}
    (out / "test-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "audit-note.md").write_text(
        f"# {sid} / {level}\n\nTechnical fixture materialized locally.\n\n"
        f"Test intent: {TEST_INTENT[family]}\n", encoding="utf-8")
    return out


def verify_all():
    expected = len(SCENARIOS) * 5
    created = 0
    for s in SCENARIOS:
        for i in range(5):
            p = materialize(s["id"], f"L{i}")
            if not (p / "manifest.json").exists() or not (p / "test-result.json").exists():
                raise SystemExit(f"verification failed: {s['id']} L{i}")
            created += 1
    print(f"verified {created}/{expected} technical states")


def compare(sid, left, right):
    import difflib
    a = materialize(sid, left)
    b = materialize(sid, right)
    s = scenario(sid); artifact = ARTIFACT[s["family"]]
    la = (a / artifact).read_text().splitlines(True)
    lb = (b / artifact).read_text().splitlines(True)
    print("".join(difflib.unified_diff(la, lb, fromfile=left, tofile=right)))


def main():
    if len(sys.argv) < 2:
        raise SystemExit("commands: materialize <scenario> <L0-L4> | inspect <scenario> <level> | compare <scenario> <left> <right> | materialize-all | verify-all")
    cmd = sys.argv[1]
    if cmd == "materialize":
        print(materialize(sys.argv[2], sys.argv[3]))
    elif cmd == "inspect":
        p = materialize(sys.argv[2], sys.argv[3]); print((p / "manifest.json").read_text()); print((p / ARTIFACT[scenario(sys.argv[2])["family"]]).read_text())
    elif cmd == "compare":
        compare(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd in ("materialize-all", "verify-all"):
        verify_all()
    else:
        raise SystemExit("unknown command")

if __name__ == "__main__":
    main()
