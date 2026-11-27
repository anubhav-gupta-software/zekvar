# HIPAA readiness checklist

This is a working checklist for the founder. It prepares Zekvar to talk with healthcare buyers. It is not legal advice and it is not a compliance claim. Items marked **[TO CONFIRM]** are decisions or commitments that have not been made.

Status on 2026-11-25: Browser v0.45.0 ships opt-in **Health identifiers** detection. Zekvar has no HIPAA attestation, no executed business associate agreement (BAA), no completed risk analysis, and no independent assessment. Do not describe Zekvar as "HIPAA compliant" or "HIPAA certified". HHS does not certify products.

## Keep capability and compliance status separate

| Topic | What the product can do today | Compliance status |
| --- | --- | --- |
| Health identifier detection | Browser checks prompts, clipboard paste, and supported attachments locally for labeled U.S. National Provider Identifiers, labeled DEA registration numbers, Medicare Beneficiary Identifiers, and organization-defined medical record number formats. Administrators choose Off, Monitor, Warn, or Block. See [Browser guide](../apps/browser-extension/README.md#protect-health-identifiers). | A detection control. It does not make a customer or Zekvar compliant. It covers four identifier types, not all 18 HIPAA identifiers or free-text clinical content. |
| Metadata-only reporting | Control receives the rule ID, category `health`, app, decision, time, and policy version. Control rejects events with extra fields. See [What is sent](security-and-privacy.md#sent-to-control). | A design property verified by automated tests with synthetic data. It is not an audited claim. |
| Business associate status | None. | **[TO CONFIRM]** Not determined. See the first section below. |
| BAA | None. | **[TO CONFIRM]** No template and no signed agreement. |
| Risk analysis (45 CFR 164.308(a)(1)) | None. | **[TO CONFIRM]** Not started. |

Approved phrasing for sales until these change: "Zekvar can detect and block common U.S. health identifiers before they reach an AI app, and reports only which rule fired. We have not completed a HIPAA risk analysis or signed BAAs yet." **[TO CONFIRM]** with counsel.

## 1. Business associate determination

A vendor is generally a business associate when it creates, receives, maintains, or transmits protected health information (PHI) on behalf of a covered entity or another business associate. [HHS business associate guidance](https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/business-associates/index.html) · [HHS cloud computing guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html)

- [ ] Map each offering: self-hosted Control run by the customer, Control hosted by Zekvar, and Browser alone. **[TO CONFIRM]** which offerings healthcare customers will buy.
- [ ] For hosted Control, decide whether stored metadata can be PHI. Event rows hold an installation ID, app, rule, and time, not names or values. However, an installation ID can be linked to a device and therefore to an employee, and the fact that a "health" rule fired at a given time is information about a workforce member's activity, not about a patient. Ask counsel whether that metadata, combined with customer context, is PHI. **[TO CONFIRM]**
- [ ] Decide whether Zekvar staff will ever see PHI during support, for example in a screenshot, a ticket, or a shared screen. If yes, Zekvar is more likely a business associate even when the product never transmits PHI. **[TO CONFIRM]**
- [ ] Note that HHS states that a cloud provider that stores encrypted ePHI without the key is still a business associate. "We can't read it" does not settle the question.
- [ ] Record the decision and reasoning for each offering in this file.

## 2. BAA template

- [ ] Engage counsel to draft a BAA based on the [HHS sample business associate agreement provisions](https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html). **[TO CONFIRM]** budget and timing.
- [ ] Decide the breach notification window Zekvar can commit to. HIPAA allows up to 60 days after discovery. Customers often ask for less. **[TO CONFIRM]**
- [ ] List subcontractors that could touch customer data: hosting provider, object storage for backups, email and ticketing, and any error-reporting service. Each one that handles PHI needs its own BAA. **[TO CONFIRM]** the list.
- [ ] Decide on return or destruction of data at termination. Today, retention windows cover events, observations, and audit history, but policy versions and installation records have no window (see [Retention and deletion](security-and-privacy.md#retention-and-deletion)). **[TO CONFIRM]**
- [ ] Decide whether to sign customer BAA paper or only Zekvar's own. **[TO CONFIRM]**

## 3. Risk analysis

Required for covered entities and business associates by the Security Rule. Use the [HHS risk analysis guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis/index.html) and the free [HHS Security Risk Assessment tool](https://www.healthit.gov/topic/privacy-security-and-hipaa/security-risk-assessment-tool) as a starting structure.

- [ ] Inventory where ePHI could exist: the employee's browser tab (always local), Browser's offline event queue (metadata only), Control's PostgreSQL database, off-host backups, API and reverse-proxy logs, support tickets, screenshots, and the event feed and webhook receivers.
- [ ] Rate the likelihood and impact of each threat, including a detector regression that sends a matched value to Control, a misconfigured log, and a compromised administrator account.
- [ ] Record the owner, the date, and the review interval. **[TO CONFIRM]** annual plus on every major release.

## 4. Safeguards mapped to existing product controls

These are product features that support a customer's safeguards. Mapping them does not mean the safeguard is satisfied. Each needs evidence and review.

| Safeguard (45 CFR) | Product control today | Gap |
| --- | --- | --- |
| Access control, unique user identification (164.312(a)) | Named Control credentials with roles and expiry, and optional OIDC single sign-on per organization. [Delegate Control access](../apps/control-web/README.md#delegate-control-access) · [SSO](../deploy/pilot/README.md#configure-control-single-sign-on) | MFA depends on the customer's identity provider. Break-glass and offboarding drills are not documented. |
| Audit controls (164.312(b)) | Organization audit log with actor, action, and subject, and JSON export. [Audit log](../apps/control-web/README.md#review-and-export-the-audit-log) | No tamper-evident storage. Zekvar operator access to the database is not itself audited. |
| Integrity (164.312(c)) | Versioned, append-only policy history with review and rollback. [Require policy reviews](../apps/control-web/README.md#require-policy-reviews) | No signed audit records. |
| Transmission security (164.312(e)) | TLS between Browser and Control through Caddy in the pilot deployment. [Encryption](security-and-privacy.md#encryption) | Production TLS settings and certificate management are **[TO CONFIRM]**. |
| Encryption at rest (addressable) | Encrypted off-host backups. [Back up and recover Control](../deploy/pilot/README.md#back-up-and-recover-control) | Database volume encryption depends on the host. **[TO CONFIRM]** |
| Minimum necessary (164.502(b)) | Health identifiers run in the browser. Events carry only rule metadata. Redaction lets an employee remove the value and continue. [Protect health identifiers](../apps/control-web/README.md#protect-health-identifiers) | Free-text clinical notes without one of the four identifiers are not detected. |
| Workforce training, sanctions (164.308(a)(5), (a)(1)) | Warn and Block notices explain the rule to the employee. Monitor mode supports a baseline before enforcement. [Onboarding](onboarding.md#run-the-monitor-mode-baseline) | Training content and acceptable-use acknowledgment are not in the product. |
| Contingency plan (164.308(a)(7)) | Backup, restore drill in a disposable environment, offline enforcement with a 100-event queue. [Backup and recovery](security-and-privacy.md#backup-and-recovery) | RTO, RPO, and a timed staging restore are open. |
| Incident procedures (164.308(a)(6)) | Severity levels and the "sensitive content in telemetry or logs" runbook. [Blocker 2](support-and-incident-response.md#blocker-2-sensitive-content-in-telemetry-or-logs) | Breach notification timeline and contacts are **[TO CONFIRM]**. |
| Data retention and disposal (164.310(d)) | Per-organization retention windows and on-demand cleanup. [Set data retention](../apps/control-web/README.md#set-data-retention) | No window for policy versions or installations. Backup retention is **[TO CONFIRM]**. |

## 5. What "no PHI reaches Control" means, and what still might

**What it means.** Matching runs inside the employee's browser. When a health rule fires, Browser sends Control an event with the rule ID (for example `us-national-provider-identifier`), category `health`, app, decision, time, and policy version. The matched value, the prompt, the file name, and the file contents stay in the tab. Control rejects events that carry any other field. Automated tests with synthetic identifiers check this at the API and end to end: `apps/control-api/test/control.test.mjs` ("versions health identifier rules…") and `apps/browser-extension/test/health-identifiers-connected.test.mjs`.

**What still might reach Zekvar or the customer's Control:**

- [ ] **Configuration typed by an administrator.** Medical record number prefixes, classification labels, and prompt exception reasons are stored as policy. An administrator could type a real patient's MRN as a prefix. Tell customers not to, and consider a warning in the form. **[TO CONFIRM]**
- [ ] **Network and server logs.** The API and reverse proxy see source IP addresses and request paths, never prompt text. The pilot Caddyfile has no access log. Production logging configuration is **[TO CONFIRM]**. Any error logging must never log request bodies.
- [ ] **Support access.** Screenshots, screen shares, and pasted text in tickets can carry PHI. Add a support intake rule that asks customers to remove patient data first, and decide whether support staff need HIPAA training. **[TO CONFIRM]**
- [ ] **Backups.** Backups copy whatever Control holds, including administrator-entered configuration. Deletions reach backups only when old snapshots expire. **[TO CONFIRM]** backup retention.
- [ ] **Event feed, webhooks, and SIEM copies.** These carry the same metadata as events. Once delivered, they are under the receiver's retention.
- [ ] **A detector or protocol regression.** A future change could add a field. The API's strict event schema and the metadata tests are the guard. Keep them in the release gate.
- [ ] **The AI app itself.** If an employee overrides a Warn, uses Monitor mode, or the identifier is not one of the four types, the content goes to the AI provider. That provider relationship is the customer's, and its BAA status is outside Zekvar's control.

## 6. Detection scope and known gaps

- Detected: labeled NPIs (Luhn check digit with the 80840 prefix), labeled DEA numbers (DEA checksum), MBIs (CMS position rules), and organization-defined MRN formats. Unlabeled NPIs and DEA numbers are deliberately ignored, because about one random number in ten passes each check digit.
- Not detected: patient names, dates of birth, addresses, health plan member IDs other than the MBI, ICD-10 or CPT codes, and free-text clinical notes. ICD-10 codes were left out because a code alone identifies no one, and short codes such as `E11.9` collide with version and part numbers. Use classification rules for document labels such as "PHI" or "Patient confidential".
- Precision and recall come from a synthetic labeled corpus, not from customer data. Run Monitor with a design partner before turning on Block.

## 7. Before the first healthcare pilot

- [ ] Business associate decision recorded for the offering in use.
- [ ] BAA signed if required, or a written determination that it is not.
- [ ] Risk analysis completed for the pilot deployment.
- [ ] Production logging reviewed so that no request body is logged.
- [ ] Support intake updated to exclude PHI.
- [ ] Pilot runs Health identifiers in Monitor first, with synthetic data during setup.
- [ ] Sales and marketing copy reviewed against the approved phrasing above.
