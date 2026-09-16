# Full Threat-to-Control Catalog

This catalog closes the design loop for the Secure SDLC Control Lab. It covers every threat family represented in the Academy and provides a consistent experiment pattern.

## Standard experiment loop

For every scenario:

1. **LEARN** — understand the threat, asset, actor, weakness, trust boundary and impact.
2. **BASELINE** — inspect the current or known-good state.
3. **WEAK** — activate or observe a controlled weakness.
4. **TEST** — execute the audit procedure, including a negative test.
5. **CONTROL L1** — apply the first control.
6. **RE-TEST** — verify what changed.
7. **RESIDUAL RISK** — decide whether the remaining risk is acceptable.
8. **L2/L3/L4** — strengthen when necessary.
9. **EVIDENCE** — capture design/configuration and operating evidence.
10. **DOCUMENT** — complete the workpaper and conclusion.
11. **RESET** — return to a known state.

## Families covered

- DEV — developer endpoint / IDE / session security
- SRC — source control, pull requests, rulesets and history
- DEP — dependencies, publishers, CI components and SBOM
- CIC — workflows, runners, cache, egress, secrets and gates
- IDN — workload identities, OIDC and runtime secrets
- BLD — build isolation, hermeticity and reproducibility
- ART — digests, signing, provenance and verification
- REG — registry authorization, immutability and promotion
- REL — non-prod isolation, IaC, runtime config, progressive release and rollback
- DAT — lower-environment data protection
- OBS — audit logging, correlation and anomaly detection
- INT — SaaS, OAuth, webhooks and cross-service trust
- AI — AI-generated code and agentic-development security
- RES — containment, trusted reconstitution and recovery validation
- GOV — segregation of duties, exceptions and control-of-controls
- APP — application vulnerabilities and business-logic abuse cases

## Maturity ladder

### L0 — Exposure
Control absent, declarative or easily bypassed.

### L1 — Basic
First preventive or detective mechanism.

### L2 — Reinforced
Obvious bypass paths reduced.

### L3 — Assurance
Enforcement, monitored exceptions and operational evidence.

### L4 — Resilience
Failure detection, forensic readiness, trusted recovery and recurring validation.

## Evidence rule

A scenario is not considered verified merely because a configuration file looks correct. The auditor should seek evidence of:

- **DESIGN** — what the control is intended to prevent;
- **CONFIGURATION** — how it is implemented;
- **AUTHORITY** — who or what can change or bypass it;
- **OPERATION** — what actually happened during the test;
- **EVIDENCE** — whether activity and bypass can be reconstructed;
- **FAILURE** — what happens if the control fails.

## Completion rule

A scenario is complete only when the student can support all of the following:

- the threat and risk scenario are correctly articulated;
- at least one negative test was performed or evidenced;
- residual risk is explicitly justified;
- any additional control is tied to the remaining attack path;
- evidence references are traceable;
- the conclusion does not exceed what the evidence demonstrates.

This catalog is a specification layer. Scenarios that need live GitHub rulesets, OIDC, cloud, registry or Kubernetes remain clearly separated from local fixture-based simulations so `main` is never intentionally broken for training.