# Customer onboarding and pilot guide

This guide covers a design-partner pilot from kickoff to the decision to expand, adjust, or stop. It follows [3. Design-partner pilot](../product_plan.md#3-design-partner-pilot) and [Pilot success and commercial assumptions](../product_plan.md#pilot-success-and-commercial-assumptions) in the product plan. The observation period and targets below are proposals, not commitments.

Rule for every pilot: start in Monitor. Move a rule to Warn or Block only after you have reviewed results and signed off.

## Who does what

| Role | Responsibility |
| --- | --- |
| Customer sponsor | Owns the buying decision and the policy. |
| Customer IT administrator | Deploys the extension through your device manager and owns Chrome policy. |
| Customer security lead | Reviews events, decides which rules move to Warn or Block. |
| Zekvar pilot owner | Runs the pilot cadence, collects measurements, and is the escalation contact. [TO CONFIRM: named owner.] |
| Zekvar support | Handles tickets. See [support and incident response](support-and-incident-response.md). |

## Kickoff checklist

Agree these before inviting any employee. Write the answers down.

- [ ] Pilot group: who, how many, which Chrome profiles and devices. See [Pick the pilot group](#pick-the-pilot-group).
- [ ] Data collection: confirm what Control records and what it does not (see [what is sent](security-and-privacy.md#what-is-processed-locally-and-what-is-sent)). Agree retention windows. A new organization has no expiry until you set one.
- [ ] Supported app flows: which AI apps and which actions you need covered (type and Send, paste, file attach). Read the coverage matrix [forthcoming] and the stated limits. Live signed-in coverage is not yet verified, so list the layouts and account types you use.
- [ ] Allowed actions: for each detector, the intended end state (Monitor, Warn, Block) and who approves the change.
- [ ] Escalation contact on each side, and how to reach them. Support intake and severity targets: [support document](support-and-incident-response.md#support-intake).
- [ ] One buying decision: the concrete use case and the person who decides.
- [ ] Employee notice: who tells the pilot group that AI prompt metadata is recorded, and what the group can expect when a prompt is warned or blocked.
- [ ] Identity: owner credential holder, named administrators and auditors, and whether to use SSO. Customer identity providers have not yet been verified. Plan an access review. See [Delegate Control access](../apps/control-web/README.md#delegate-control-access).
- [ ] Policy review: decide whether to require a second administrator to approve changes ([Require policy reviews](../apps/control-web/README.md#require-policy-reviews)).
- [ ] Deployment: device manager, Chrome version, extension ID, update URL, Control origin. See [install and remove](install-and-remove.md).
- [ ] Security review: send [security and privacy answers](security-and-privacy.md) and resolve [TO CONFIRM] items the customer cares about.
- [ ] Alerts and exports: webhook, SIEM, or manual review. See [Send alerts to a webhook](../deploy/pilot/README.md#send-alerts-to-a-webhook) and [Collect security events in a SIEM](../deploy/pilot/README.md#collect-security-events-in-a-siem).

## Pick the pilot group

- Start with an internal deployment, then a small managed group. Use 10 to 25 profiles for the first wave. [TO CONFIRM: recommended size.]
- Choose people who use ChatGPT, Gemini, or Claude daily and who can tell you when something breaks.
- Include at least one profile on each device type and Chrome version you manage.
- Include at least one person in each workflow you care about: pasting text, attaching files, and each AI app.
- Keep the group's Chrome policy unique so you can roll back for the group only.
- Put the group in a Control rollout group. A group follows the baseline until you publish its first scoped policy. See [Roll out policies to a pilot group](../apps/control-web/README.md#roll-out-policies-to-a-pilot-group).

## Deploy and verify

1. Deploy and enroll with the [install and remove guide](install-and-remove.md). Record the extension version and Chrome versions.
2. Confirm every pilot profile shows **Reporting** in **Browser health** with the current policy applied.
3. Check composer readiness for each app. Record which composers show Detected, Unsupported, or Unobserved.
4. Run a Monitor test with the synthetic marker `ZEKVAR_TEST_SECRET` in each app and each input path you plan to rely on: Send by click, Send by Enter, paste, and file attach. Record the Browser version, page layout, account type, and observed result for each. The plan requires this record for each partner workflow.
5. Rehearse one policy rollback and one extension rollback on a canary. See [Roll back](install-and-remove.md#roll-back).

## Run the monitor-mode baseline

Run Monitor for a baseline period. The plan proposes 2 to 4 weeks. [TO CONFIRM: agreed length for each partner.]

Set up:

- Enable only the detectors the customer wants to learn about. Each starts Off. Set them to Monitor and publish to the pilot group.
- Turn on **App discovery** to see which AI apps are in use ([App discovery](../apps/browser-extension/README.md#app-discovery)). Classify each app as Approved, Unapproved, or Unreviewed in **App inventory**.
- Use **Policy preview** and the starter pack to compare outcomes before you publish ([Preview a policy](../apps/control-web/README.md#preview-a-policy), [Test a policy with a reusable pack](../apps/control-web/README.md#test-a-policy-with-a-reusable-pack)).

Weekly routine:

1. Check **Browser health**: reporting, stale, and policy status.
2. Review **Events**. Triage each as Needs review, Investigating, or Resolved, with a disposition: confirmed violation, false positive, expected activity, or insufficient evidence ([Investigate and export security events](../apps/control-web/README.md#investigate-and-export-security-events)).
3. Open the **AI enforcement report** for the last 7 days ([Review AI enforcement](../apps/control-web/README.md#review-ai-enforcement)).
4. Export composer readiness and keep it with the report ([Review composer readiness](../apps/control-web/README.md#review-composer-readiness-before-switching-a-group-to-block)).
5. Log support requests, the time to resolve each, and employee and admin feedback.

## Review results with the customer

Hold a review at the end of week one, mid-pilot, and the end of the baseline. Bring:

- Reporting coverage: enrolled and reporting browsers as a share of eligible browsers.
- Policy freshness: share of online installations on the current policy within five minutes.
- Composer readiness by app and extension version, and any unsupported layouts.
- Detections by app, rule, and rollout group.
- Triage results: confirmed violations, false positives, expected activity.
- AI apps found by discovery and their classifications.
- Support requests and time to resolve.

Validate detector precision on labeled synthetic fixtures. Review each misclassified pilot decision with the administrator. Measure recall and unsupported submission paths separately.

Note on privacy: Control holds no prompt text, so the customer cannot see why a detection was a false positive from the event alone. Use the employee's account of the prompt, the detector category, and the policy preview samples. Employees can use **Request policy review** from a Warn or Block. See [Review employee prompt exception requests](../apps/control-web/README.md#review-employee-prompt-exception-requests).

## Move a rule to Warn or Block

Move one rule and one group at a time. Only promote a rule when all of these are true:

- [ ] The customer's security lead has reviewed the Monitor results and signed off in writing.
- [ ] Precision for that rule is at least 95% on labeled fixtures. This is the plan's proposed target for rules promoted to block.
- [ ] The false positives seen in Monitor have a documented cause and a fix or an exception.
- [ ] Composer readiness is Detected and fresh for the apps in scope. Control can enforce this at publish time ([Require composer readiness before publishing](../apps/control-web/README.md#require-composer-readiness-before-publishing)).
- [ ] For file protection, you tested a clean file and a blocked file through each file path the group uses. Clean files must reach the app.
- [ ] Employees have been told. A Warn lets them edit or continue. A Block holds the prompt until it is edited. Redaction is offered for review before a separate Send.
- [ ] The support route and the false-block recovery steps are known. See [false block](support-and-incident-response.md#false-block).
- [ ] The rollback is ready. Restore the previous policy version if Block causes harm.

Order of promotion we suggest:

1. Warn for one detector in one group.
2. Review for a week. Count overrides and false positives.
3. Block for high-confidence detectors only.
4. Repeat for the next detector, then widen to more groups.

Use temporary prompt exceptions with an expiry and a reason for known cases. See [Grant a temporary prompt exception](../apps/control-web/README.md#grant-a-temporary-prompt-exception).

After each policy change, review the AI enforcement report and the support queue again.

## Success criteria

Targets are proposed, from the product plan. Agree your own with the customer at kickoff.

| Measure | Proposed target |
| --- | --- |
| Reporting coverage | At least 95% of eligible browsers enrolled and reporting. |
| Policy freshness | Policy delivered within five minutes for 95% of online installations. |
| Detector precision | At least 95% for rules promoted to Block. |
| Admin independence | The customer can identify AI usage and investigate a policy event without engineering support. |
| Latency and task completion | Recorded for clean, warned, redacted, and blocked submissions. |
| Monitor, Warn, and Block activity | Warning overrides, false blocks, and support requests compared, then used to decide which rules ship with enforcement. |
| Time to resolve a false block | Measured in the pilot. |
| Coverage | The app-by-action matrix is re-run when the extension or an adapter changes. Keyboard, click, paste, and attachment paths are covered wherever advertised. |

## Wrap up

At the end, write a short report with:

- Measured outcomes against the targets above.
- Coverage gaps and unsupported layouts found.
- Support burden: tickets, severity, and time to resolve.
- What the customer would pay for and the buying decision.
- An explicit decision to expand, adjust, or stop.

Zekvar uses the results to confirm launch app order and the cases in its benchmark. [TO CONFIRM: what pilot data Zekvar may keep and for how long. Agree this at kickoff.]

If the pilot stops, follow [Remove](install-and-remove.md#remove) and agree data deletion in writing.
