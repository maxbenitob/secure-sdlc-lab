# Secure SDLC Control Lab

This directory integrates `secure-sdlc-lab` with the Secure SDLC Audit Academy without changing the existing application or CI behavior.

## Purpose

The repository is treated as a **control experiment environment**, not merely as a vulnerable application.

For every threat or QSUS, the learning loop is:

1. LEARN — understand the threat and risk scenario in the Academy.
2. MAP — identify asset, actor, weakness, trust boundary and attack path.
3. BASELINE — observe the known-good or current state.
4. WEAK — materialize or inspect a controlled weakness.
5. TEST — execute the audit procedure and collect evidence.
6. CONTROL L1 — apply a first control and re-test.
7. RESIDUAL RISK — decide whether the remaining risk is acceptable.
8. CONTROL L2/L3/L4 — strengthen when necessary.
9. VERIFY — collect evidence that the control actually operates.
10. DOCUMENT — complete the workpaper and conclusion.
11. RESET — return the lab to a known state.

## Anti-regression rules

- Do not intentionally break `main` to create an exercise.
- Prefer scenario branches, exported configuration, fixtures or local sandboxes.
- Every weakness must be reversible.
- Never use real secrets, production credentials or sensitive data.
- GitHub Rulesets, OIDC, cloud and Kubernetes scenarios must be clearly identified as external-configuration scenarios.
- Existing application behavior and the existing CI pipeline remain the baseline unless a scenario explicitly runs on a dedicated branch.

## Control maturity model

- **L0 — Exposure:** absent, declarative or easily bypassed control.
- **L1 — Basic:** first preventive or detective mechanism.
- **L2 — Reinforced:** obvious bypasses reduced.
- **L3 — Assurance:** enforcement, monitored exceptions and operational evidence.
- **L4 — Resilience:** failure detection, forensic readiness and trusted recovery.

## Files

- `scenarios.json` — threat/QSUS catalogue and lifecycle.
- `scenarios/SRC-CIC-wave-01.md` — first implementation wave.
- `scripts/control_lab.py` — safe local scenario-state helper; it does not modify GitHub settings or the application.
- `templates/workpaper.md` — audit documentation template.

The Academy remains the source of theory, scoring, residual-risk assessment and review. This repository provides the technical target and evidence surface.
