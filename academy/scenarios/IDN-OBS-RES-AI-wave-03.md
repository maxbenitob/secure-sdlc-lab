# Wave 03 — Identity, Observability, Recovery, Integrations & AI

This wave completes the control-lab architecture for the remaining modern software-factory threat families. It is additive and should be implemented with local fixtures or dedicated scenario branches before any real cloud or SaaS changes.

## IDN-01 — Workload identity / OIDC
- **Threat:** an unexpected repository or workflow obtains production credentials through a broad trust policy.
- **L0:** static credentials or broad subject conditions.
- **L1:** short-lived workload identity.
- **L2:** strict subject/audience claims and repository/branch binding.
- **L3:** least-privilege target role, environment approval and monitored token use.
- **L4:** revocation/recovery playbook and periodic reperformance.
- **Evidence:** OIDC trust policy, IAM policy, token events, deployment logs.

## IDN-02 — Runtime secret exposure
- **Threat:** a secret is printed, reused or exposed to an unauthorized job.
- **L0:** long-lived secret available broadly.
- **L1:** masking and reduced scope.
- **L2:** short-lived credentials / OIDC.
- **L3:** job isolation and secret-access monitoring.
- **L4:** rotation and incident exercise.

## OBS-01 / OBS-02 — Logging and anomaly detection
- **Threat:** critical factory activity cannot be reconstructed or suspicious changes are not detected.
- **L0:** fragmented logs / short retention.
- **L1:** collect Git, CI and deployment events.
- **L2:** centralize and correlate identities, commits, workflows and deployments.
- **L3:** alert on control changes, bypasses and unusual release activity.
- **L4:** forensic retention and incident reconstruction exercise.

## INT-01 — SaaS / OAuth / webhook trust graph
- **Threat:** a compromised integration pivots into the repository, pipeline or cloud.
- **L0:** broad scopes and unmanaged apps.
- **L1:** inventory and minimum scopes.
- **L2:** allowlist, webhook verification and token lifecycle.
- **L3:** monitored app/permission changes.
- **L4:** rapid revocation and dependency recovery.

## AI-01 — AI-generated code assurance
- **Threat:** AI-generated changes are accepted faster than normal controls can evaluate them.
- **L0:** direct acceptance / no differentiation.
- **L1:** normal PR, testing and SAST still apply.
- **L2:** sensitive-path review and provenance/metadata indicating AI-generated work.
- **L3:** policy enforcement for high-risk changes.
- **L4:** audit analytics and recurring challenge of AI-generated changes.

## AI-02 — Agentic development / prompt injection
- **Threat:** untrusted issue/document text influences an agent with privileged tools.
- **L0:** broad tool access and workflow-write capability.
- **L1:** human merge approval.
- **L2:** tool least privilege and privileged-path protection.
- **L3:** untrusted-context isolation, approval for high-risk tool calls and complete tool-call logging.
- **L4:** containment/revocation/reconstruction exercise after simulated agent compromise.

## RES-01 / RES-02 — Incident containment and trusted reconstitution
- **Threat:** CI is restored without rebuilding trust after compromise.
- **L0:** reboot/restart only.
- **L1:** containment and artifact quarantine.
- **L2:** key/token rotation and runner rebuild.
- **L3:** rebuild from known-good baseline, review OIDC/permissions and regenerate affected artifacts.
- **L4:** recovery validation, evidence package and periodic exercise.

## Safe evidence-first implementation

For every scenario, store only synthetic or exported evidence under `academy/fixtures/`. Keep the scenario state independent from real production credentials. The auditor should be able to compare BASELINE → WEAK → L1/L2/L3/L4 → VERIFIED without changing `main`.