# Wave 01 — Source Control & CI/CD Control Experiments

This first wave implements the Academy → Repository bridge using controls that are already close to the current repository state. The goal is not to break `main`; scenarios should run on a dedicated training branch, exported configuration, or a local clone.

## SRC-02 — Protected Source Changes

### Threat
Unauthorized or insufficiently reviewed source changes reach `main`.

### L0 — Exposure
- Direct change path is possible or branch governance is not evidenced.
- Audit task: inspect ruleset/branch protection, commit history and pull-request history.

### L1 — Basic
- Pull request required.
- Negative test: attempt a direct push in a controlled scenario branch.

### L2 — Reinforced
- Independent approvals and required checks.
- Re-test direct push and merge without required review.

### L3 — Assurance
- Admin enforcement / monitored bypass / CODEOWNERS for sensitive paths.
- Evidence: ruleset export + audit event + PR review history.

### L4 — Resilience
- Alert on bypass/control changes, retained audit history and periodic reperformance.

## SRC-03 — Repository Control Plane Protection

### Threat
The subject being controlled can alter or bypass the repository control itself.

### Audit focus
- Who can modify rulesets?
- Who can administer the repository?
- Are workflow paths protected?
- Are bypasses visible and independently reviewed?

### Evidence
Repository roles, ruleset JSON/export, audit events, PR history.

## SRC-04 — Secrets in Source / History

The repository already has a Gitleaks job in `.github/workflows/ci.yml`, so this scenario can build on an existing control rather than inventing a parallel mechanism.

### L0
Introduce a **fake training secret only** in a scenario branch or fixture.

### L1
Run Gitleaks and capture detection evidence.

### L2
Verify the pipeline blocks the change rather than merely producing a report.

### L3
Simulate removal and verify whether the value still exists in Git history; document required rotation even after deletion.

### L4
Add incident handling: detection → revoke/rotate → history analysis → evidence retention.

## CIC-01 — Pipeline-as-Code Change Control

### Threat
A workflow change can alter security gates, privileges, execution steps or secret exposure.

### Current repository anchor
`.github/workflows/ci.yml`

### Progressive control path
- L1: workflow changes require PR.
- L2: CODEOWNERS / independent review for `.github/workflows/**`.
- L3: monitor workflow permission changes and security-gate removal.
- L4: reconstruct who changed the workflow, when, which jobs ran and what release was affected.

## CIC-07 — Security Gate Integrity & Exceptions

### Threat
A security tool is present but its result is not enforced, or an exception silently bypasses the gate.

### Required audit distinction
`scan executed != result reviewed != threshold defined != release blocked`

### Experiments
1. Make a controlled finding detectable by the gate.
2. Observe whether CI fails or merely reports.
3. Add an explicit threshold or blocking condition.
4. Re-test.
5. Introduce a documented, time-bound training exception.
6. Verify that the exception is independently approved and visible.

## DEP-03 — Third-Party CI Automation

The current workflow uses third-party actions such as `actions/checkout`, `actions/setup-python` and `gitleaks/gitleaks-action`.

### Threat
A mutable action reference or compromised publisher changes code executed inside the trusted CI context.

### Progressive controls
- L1: inventory third-party actions.
- L2: pin sensitive actions to immutable commit SHA where appropriate.
- L3: action allowlist + minimal job permissions.
- L4: monitor action changes and maintain replacement/recovery procedures.

## Workpaper requirement for every scenario

Document:
- risk scenario;
- control objective;
- current level L0-L4;
- procedure and negative test;
- evidence references;
- result;
- residual risk;
- additional control if risk remains unacceptable;
- final conclusion and limitations.
