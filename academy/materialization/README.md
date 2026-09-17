# Technical Materialization — v2.7

This directory turns the 31 Academy threat scenarios into disposable technical states that an auditor can inspect and compare.

## Objective

For every scenario in `academy/scenarios.json`, the lab supports five control states:

`L0 -> L1 -> L2 -> L3 -> L4`

- **L0 — Exposure:** weak or absent control.
- **L1 — Basic control:** first meaningful safeguard.
- **L2 — Strengthened:** obvious bypasses reduced.
- **L3 — Assurance:** enforcement, monitoring and governed exceptions.
- **L4 — Resilience:** failure detection, recovery and reconstitution evidence.

## Safe operating model

The materializer never changes repository rulesets, secrets, cloud IAM, Kubernetes, OAuth applications, runners or production infrastructure. It writes only to `academy/runtime/`, which is disposable and should not be committed.

No real credentials, exploit payloads, external callbacks or customer data are used.

## Run one state

```bash
python academy/scripts/technical_materialization.py materialize SRC-01-T L0
python academy/scripts/technical_materialization.py inspect SRC-01-T L0
python academy/scripts/technical_materialization.py materialize SRC-01-T L3
python academy/scripts/technical_materialization.py compare SRC-01-T L0 L3
```

## Materialize the complete catalog

```bash
python academy/scripts/technical_materialization.py materialize-all
python academy/scripts/technical_materialization.py verify-all
```

The complete run covers **31 scenarios x 5 levels = 155 technical states**.

## Evidence generated

Every materialized state contains:

- one technical configuration artifact specific to the threat family;
- `test-result.json` describing the audit test intent;
- `audit-note.md` giving the auditor a traceable evidence reference;
- `manifest.json` identifying scenario, level, QSUS and expected control strength.

## Audit loop

1. Read the threat and risk scenario in the Academy.
2. Materialize L0.
3. Inspect the technical artifact.
4. Perform the negative test conceptually or against the disposable fixture.
5. Collect evidence.
6. Materialize L1 and re-test.
7. Continue through L2/L3/L4 only while residual risk remains unacceptable.
8. Document evidence, limitations and conclusion in the Academy workpaper.

## Families covered

DEV, SRC, DEP, CIC, IDN, BLD, ART, REG, REL, DAT, OBS, INT, AI, RES, GOV and APP.

The materialization layer is deliberately separate from the real GitHub control plane. Later live-lab exercises may bind selected scenarios to actual GitHub settings, OIDC, cloud or Kubernetes, but only through explicit sandboxed exercises.