# Wave 02 — Dependencies, Build, Artifacts, Registry & Release

This wave extends the Secure SDLC Control Lab beyond source/CI governance. It is intentionally non-destructive and can be implemented through fixtures, local branches, exported configuration and simulated evidence before any real cloud or registry integration.

## Scope

### DEP-01 — Dependency selection and pinning
- **Threat:** compromised, mutable or unexpected dependency.
- **L0:** floating dependency / no lock discipline.
- **L1:** explicit version constraints.
- **L2:** lockfile + controlled source.
- **L3:** policy enforcement + maintainer/source trust review.
- **L4:** SBOM linkage + rapid impact analysis and replacement readiness.
- **Evidence:** requirements, lockfile, dependency graph, SCA output, SBOM.

### DEP-02 — Maintainer / project trust
- **Threat:** trusted package compromised without a known CVE.
- **L0:** CVE-only decision model.
- **L1:** package ownership and source reviewed.
- **L2:** provenance / publisher validation.
- **L3:** policy for high-risk packages and restricted introduction.
- **L4:** emergency package replacement and impact identification.

### DEP-03 — Third-party CI automation
- **Threat:** mutable action or publisher compromise.
- **L0:** tag-based reference.
- **L1:** known publisher.
- **L2:** SHA pinning.
- **L3:** allowlist + least privilege + review of workflow changes.
- **L4:** monitoring and rapid revocation of compromised components.

### DEP-04 — SBOM quality and operational use
- **Threat:** SBOM exists but cannot support incident response.
- **L0:** no SBOM.
- **L1:** generated SBOM.
- **L2:** SBOM tied to exact artifact digest.
- **L3:** quality checks and searchable inventory.
- **L4:** incident exercise proving rapid affected-artifact identification.

### ART-01 / ART-04 — Immutability and source-to-production continuity
- **Threat:** approved artifact replaced after build.
- **L0:** mutable tags.
- **L1:** digest recorded.
- **L2:** digest-pinned promotion and immutable release identifiers.
- **L3:** deployment verifies expected digest.
- **L4:** quarantine / rollback to previously trusted digest.

### ART-02 / ART-03 — Signing and provenance verification
- **Threat:** signed but malicious artifact, or attestation not actually enforced.
- **L0:** no trusted provenance.
- **L1:** signature created.
- **L2:** provenance includes builder/source/digest.
- **L3:** admission verifies signer and provenance policy.
- **L4:** signer compromise / key rotation / trusted rebuild exercise.

### REL-02 — IaC / policy-as-code assurance
- **Threat:** infrastructure or policy changes weaken production security.
- **L0:** manual or unreviewed IaC.
- **L1:** IaC review.
- **L2:** static checks and policy-as-code.
- **L3:** blocking policy and protected policy changes.
- **L4:** drift detection and trusted rollback.

### REL-03 / REL-04 / REL-05 — Runtime config, progressive release and rollback
- **Threat:** a change bypasses code governance, has excessive blast radius or cannot be safely reversed.
- **L0:** global immediate rollout / mutable runtime config.
- **L1:** config change logging or manual staged release.
- **L2:** canary + approval gates.
- **L3:** automatic health gates + rollback criteria.
- **L4:** anti-downgrade, recovery testing and verified known-good rollback.

## Safe implementation strategy

Use local fixtures under `academy/fixtures/` first. Do not require a live cloud account or production registry. Each scenario should contain:
1. baseline evidence;
2. weak-state evidence;
3. L1/L2/L3/L4 evidence;
4. expected negative test;
5. workpaper references;
6. reset instructions.

The Academy remains responsible for theory, residual-risk scoring and reviewer logic. The repository provides the technical evidence surface.