# Zekvar Product Plan

**Security at every interaction.**  
The unified security platform for browsers, endpoints, and AI.

## Product strategy

Zekvar helps security teams see where employees use AI, apply company policy to sensitive actions, and investigate policy decisions. Start with managed browsers, where the team can ship both visibility and enforcement in one deployment. Use Zekvar Control as the shared administration layer as the platform expands to endpoints and autonomous agents.

The first buyer is an IT or security lead at a company that manages Chrome and wants employees to use approved AI tools safely. The daily users are security administrators who configure policy and review events, and employees who need a clear explanation when an action is interrupted. Design partners should already have a managed Chrome fleet and an active AI usage policy. MSPs become a distribution channel once delegated administration and tenant isolation are ready.

| Product | Role | Direction |
| --- | --- | --- |
| Zekvar Control | Core platform | Central administration, versioned policies, security analytics, audit history, and multi-tenant MSP management |
| Zekvar Browser | Initial commercial product | Managed browser enrollment, URL filtering, credential protection, and malicious extension detection |
| Zekvar AI | Initial commercial product | Shadow AI discovery, sensitive-data protection, and AI application governance |
| Zekvar Endpoint | Expansion product | Device security, endpoint monitoring, and policy enforcement outside the browser |
| Zekvar Agent | Expansion product | AI-agent permissions, tool-call monitoring, runtime policies, and autonomous action controls |

## First commercial release

Ship Browser and AI through a single Chrome extension with Control included. Lead with a workflow that a security team can deploy and verify during a pilot.

1. An administrator enrolls a managed Chrome browser in Control and publishes a policy to a pilot group.
2. An employee attempts to submit a prompt on a supported AI site. The extension evaluates the text locally at submission time.
3. If a detector matches, the extension monitors, warns, or blocks according to policy. A warning lets the employee edit the prompt or explicitly continue. A block lets the employee edit and try again.
4. Control records the app, time, detector category, policy version, and action taken. The administrator can inspect the decision and adjust the policy.

| Area | Pilot scope | After the pilot |
| --- | --- | --- |
| Browser | Managed Chrome enrollment, health status, and administrator-defined URL rules for selected domains | Edge, credential protection across websites, extension inventory and risk detection |
| AI | Observed use of cataloged AI domains in managed Chrome, approved or unapproved app labels, and text-submit protection on one supported ChatGPT web flow | More AI sites and submission paths, selected file uploads, and richer data classification |
| Control | Tenant-scoped admin login, policy creation and publishing, monitor/warn/block modes, event review, enrollment status, and publish audit history | Enterprise SSO and provisioning, policy exceptions, SIEM export, and MSP administration |
| Detection | Locally evaluated structured secrets and administrator-defined exact phrases, tested with synthetic data | Evaluate customer record detectors and document classification against labeled samples |

Start every pilot in monitor mode. Move high-confidence detections to warn or block once the customer has reviewed the results. Document the tested site flows, Chrome versions, and app coverage for each release. Treat discovery of cataloged domains and pre-submit protection as distinct capabilities in the product UI.

## Platform and implementation

Use a TypeScript Chrome Manifest V3 extension, a Next.js and Tailwind CSS dashboard, an ASP.NET Core API, and PostgreSQL. Start with one backend deployment and one database. Keep cloud and identity provider selection open until pilot requirements are known. Use a managed OpenID Connect provider for Control admin authentication and separate credentials for browser enrollment.

- **Extension** — Use domain rules for URL filtering and a site-specific adapter for supported prompt submissions. Evaluate local detectors and show the decision in the page. Track adapter health so a site change can be surfaced in Control. Chrome's declarative rules handle request conditions such as destination URLs. Prompt inspection depends on the supported page flow. Chrome reserves blocking `webRequest` listeners for policy-installed extensions in Manifest V3. [Chrome declarativeNetRequest API](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) · [Chrome webRequest API](https://developer.chrome.com/docs/extensions/reference/api/webRequest)
- **Policy** — Begin with an immutable version per publish. Each rule identifies its target group, app or domain, detector if applicable, and action. Resolve matches deterministically using the most restrictive action and record the rule that determined it. Roll back by publishing an earlier configuration as a new version. Keep the last applied policy across restarts and outages, and expose stale policy status in Control.
- **Enrollment and tenancy** — Use short-lived enrollment grants and revocable per-installation credentials. Scope policies, installations, audit entries, and events to an organization. Derive the organization from authenticated credentials and exercise cross-tenant access checks before external pilot use. Chrome managed storage is available for administrator-provided bootstrap configuration. [Chrome managed storage manifest](https://developer.chrome.com/docs/extensions/reference/manifest/storage)
- **Events** — Use a stable event ID across retries and deduplicate it server-side. Store the app or domain, event and receipt timestamps, detector category, policy version, decision, and pseudonymous installation ID. Keep a bounded offline queue for event metadata. Report degraded status when delivery or enforcement coverage drops.
- **Privacy** — Keep prompt text, matched secret values, and file contents on the device. Keep raw content out of logs and analytics. Collect sanctioned app usage and policy events with hostname or app identifiers, excluding URL query strings and general browsing history. Start with a proposed 30-day event retention period and confirm it with design partners.

The initial data model covers organizations, admin memberships, enrollment grants, browser installations, policy versions, security events, and audit entries. Browser and AI share enrollment, policy delivery, and event ingestion. Endpoint and Agent can reuse those services while defining their own runtime enforcement and event fields.

## Delivery milestones

| Milestone | Deliverable | Exit criteria |
| --- | --- | --- |
| 1. Local proof | Chrome extension and a controlled test page with a synthetic secret rule | A clean prompt submits normally. A matching prompt is held, a clear message appears, and an edited prompt can be submitted. The result contains metadata only. |
| 2. End-to-end demo | Connected Control, API, and browser with one supported ChatGPT flow | An admin publishes a policy, the enrolled browser applies it, and Control displays one deduplicated event per policy action. Verify button and keyboard submission, warning override, and offline recovery. |
| 3. Design-partner pilot | Managed Chrome deployment, monitor-first rollout, and weekly event review | A customer admin can enroll a pilot group, review real usage, publish and roll back policies, and identify browsers with stale policy or degraded coverage. Verify cross-tenant access controls, retention, and metadata-only telemetry before rollout. |
| 4. Commercial launch | A supported Browser and AI offering with Control, onboarding, support, and incident response | Pilot evidence supports the claims made at launch. Installation, updates, backups, recovery, and escalation have been exercised. Domain and trademark checks are complete. |
| 5. Platform expansion | Broader browser coverage, MSP administration, Endpoint, and Agent | Sequence work by buyer demand and integration readiness. Validate delegated administration before MSP deployment. Pilot Endpoint and Agent separately before expanding their enforcement coverage. |

## Pilot success and commercial assumptions

- Recruit two or three design partners with managed Chrome and an existing AI policy. Test whether they can identify AI usage and investigate a policy event without engineering support.
- Measure enrolled and reporting browsers as a share of eligible browsers, policy freshness, and adapter health. Proposed targets are 95% reporting coverage and policy delivery within five minutes for 95% of online installations.
- Measure detector accuracy against labeled synthetic examples and review misclassified pilot decisions with administrators. Proposed target is at least 95% precision for rules promoted to block mode. Track recall and unsupported submission paths separately.
- Compare monitor, warn, and block activity, warning overrides, false blocks, and support requests. Use those results to decide which rules can ship with enforcement enabled.
- Test per-managed-user pricing for a Browser and AI bundle with Control included. Use pilot interviews to test demand for separate SKUs, annual commitments, and MSP pricing before setting public prices.

## Brand and launch readiness

- **Working brand** — Zekvar. Use the five product names in this plan across product interfaces and documentation.
- **Identity** — Midnight navy `#101927`, electric mint `#59E6B5`, and clean, bold, technical typography. Use confident, precise copy and state what each deployment actually covers.
- **Public launch gate** — Verify `zekvar.com` and `zekvar.ai`, and complete trademark clearance in the intended markets. These checks are pending.

## First build slice

Start with the local proof. Build a minimal MV3 extension and a controlled prompt composer. Use an inert synthetic marker and exercise ordinary submit, keyboard submit, warning override, blocking, and edit-and-retry. Emit the same metadata fields planned for Control so the demo can connect to the API in the next milestone. Once the flow passes, adapt it to the first supported ChatGPT submission path and record the exact coverage in the release checklist.
