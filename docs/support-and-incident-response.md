# Support and incident response

This document is the support process and incident runbook for Zekvar Browser and Control. It is written for the support team, on-call engineers, and the customer administrators who work with them. It also contains tabletop drill scripts. The product plan requires a support and incident-response drill before direct commercial release ([4. Direct commercial release](../product_plan.md#4-direct-commercial-release), step 2).

Every response target, contact, and notice period below marked **[TO CONFIRM]** is not yet a company commitment.

The plan names three release blockers. Treat each as a Severity 1 incident:

1. A cross-tenant data exposure.
2. Sensitive content in telemetry or logs.
3. Evidence that supported enforcement is falling short of advertised coverage.

Assign an owner and verify recovery before expanding a rollout ([How to run the work](../product_plan.md#how-to-run-the-work)).

## Support intake

**Channels.** [TO CONFIRM: support email or portal, urgent phone or pager route, support hours and time zone, languages.]

**Ticket template.** Ask the customer for:

| Field | Where to find it |
| --- | --- |
| Organization slug | Control sign-in |
| Installation ID | Control **Browser health**, **Browser fleet**, or the event detail |
| Rollout group | Control **Browser health** |
| Extension version and Chrome version | `chrome://extensions` and `chrome://version`. Control shows the last reported extension version. |
| Policy version and mode | Extension popup, Control **Policy history** |
| Popup status text | Extension popup. Copy the text. |
| App and page type | For example ChatGPT home, ChatGPT conversation, Gemini `/app`, Claude `/new` |
| Account type | For example signed out, personal, workspace |
| Time of the issue, with time zone | |
| Event ID and installation ID, if an event exists | Control **Events** detail |
| Composer diagnostics | The popup or banner **Copy composer diagnostics**. It contains only the extension version, route category, and structural counts and flags. |
| What the employee expected and what happened | |

**What not to send.** Do not paste prompts, file contents, matched values, enrollment grants, Control tokens, event feed keys, SSO secrets, or screenshots that show prompt content. Use the synthetic marker `ZEKVAR_TEST_SECRET` when reproducing. If a customer sends sensitive content by mistake, treat it as a Blocker 2 report: delete it from the ticket system and record the deletion.

**Support access to customer data.** Support works from the ticket, the customer's screen share, and Control views that the customer's administrator grants. [TO CONFIRM: whether Zekvar staff can read production data, how access is approved, and how it is logged.]

## Severity levels

| Level | Definition | Examples | First response | Update cadence | Target resolution or mitigation |
| --- | --- | --- | --- | --- | --- |
| Sev 1 | A release blocker, a security incident, or an outage that stops all protection or reporting for a customer | Cross-tenant exposure. Sensitive content in telemetry or logs. Enforcement shown not to work where advertised. Control unavailable. Widespread false blocks halting work. | [TO CONFIRM] | [TO CONFIRM] | [TO CONFIRM] |
| Sev 2 | Major degradation for part of the fleet, with a workaround | One app adapter broken after an app change. Enrollment failing for a group. Many browsers stale. | [TO CONFIRM] | [TO CONFIRM] | [TO CONFIRM] |
| Sev 3 | A single user or a minor feature problem | One unsupported composer layout. One false block with an exception available. | [TO CONFIRM] | [TO CONFIRM] | [TO CONFIRM] |
| Sev 4 | Question or request | How to export, how to configure retention | [TO CONFIRM] | [TO CONFIRM] | [TO CONFIRM] |

Raise the severity if more than one organization is affected or if sensitive content is involved. Never lower a release blocker without the incident owner's written agreement.

## Triage for common issues

Start with **Browser health** in Control. **Reporting** means Control heard from the browser in the last 90 seconds. **Stale** means it did not. See [Run the dashboard](../apps/control-web/README.md#run-the-dashboard).

### Unsupported composer

Signs: the extension banner on the AI page shows **Unsupported composer**, **Unsupported ChatGPT page**, or **ChatGPT policy unavailable**. Control shows **Unsupported** in the app's composer column. Or an employee sent a prompt and no event appeared.

1. In Control, open **Browser health** and filter to the installation or group. Read the composer status: Detected, Unsupported, Unobserved, Policy pending, Off, or Stale. [What each means.](../apps/control-web/README.md#review-composer-readiness-before-switching-a-group-to-block)
2. Unobserved: confirm Browser v0.22.0 or later, and that the employee opened the app in that profile.
3. Policy pending: wait for the browser to sync, or ask the employee to select **Sync now** in the popup.
4. Off for Claude: Claude prompt protection is disabled in the assigned policy. This is by design.
5. Unsupported: collect **Copy composer diagnostics**, the page route, and the account type. Check the supported scope in the [browser README](../apps/browser-extension/README.md). Supported paths are native click and plain Enter on a recognized editor and Send control. Voice, programmatic submits, and other surfaces are outside coverage.
6. If the layout should be supported, escalate as a possible [Blocker 3](#blocker-3-enforcement-falls-short-of-advertised-coverage). Meanwhile, tell the customer the group has no protection on that layout. Offer to publish an AI site access block for that host for affected groups.

### False block

Signs: an employee says a clean prompt or file was held, or an event shows a detector the employee did not expect.

1. Find the event in Control **Events**. Note the app, detector, decision, policy version, and rollout. The event holds no prompt text.
2. Ask the employee for what they typed, outside the ticket if sensitive. Test it with the policy preview ([Preview a policy](../apps/control-web/README.md#preview-a-policy)) using synthetic text of the same shape.
3. Decide with the customer's security lead: allow once, grant a temporary exception, change the detector, or accept the block.
   - The employee can select **Request policy review** from the Warn or Block ([Review employee prompt exception requests](../apps/control-web/README.md#review-employee-prompt-exception-requests)).
   - An administrator can publish a temporary exception with an expiry and reason ([Grant a temporary prompt exception](../apps/control-web/README.md#grant-a-temporary-prompt-exception)). It applies to everyone in that scope.
   - To stop the harm quickly, set the detector to Monitor for the group, or restore the previous policy version.
4. Mark the event triage as resolved with the disposition `false_positive` ([Investigate and export security events](../apps/control-web/README.md#investigate-and-export-security-events)).
5. After the next sync, retest with a clean prompt and a synthetic sensitive prompt.
6. Record the time from report to resolution. The pilot measures it.
7. If several customers hit the same false block, file it as a detector defect. If a Block stopped required work for many people, treat it as Sev 1.

File-specific: **File check unavailable** means Block stopped a file the browser could not finish checking (for example password-protected, beyond scan limits, or checked slower than three seconds). It is not a content match. The limits are in the [browser README](../apps/browser-extension/README.md#monitor-file-contents).

### Enrollment failure

Signs: the popup does not show Connected to Control, or the profile is missing from **Browser health**.

1. Read the popup message and use the [message table](install-and-remove.md#enroll-browsers).
2. Expired or already used: grants are single-use and last 10 minutes. Issue a fresh grant. Check **Enrollment batches** for redemption and cancellation counts.
3. Origin mismatch: `ControlOrigin` in managed storage must equal the origin built into the extension. Fix the policy and issue a fresh grant.
4. Manual enrollment required: Chrome is too old, or managed storage is not available to trusted contexts. Use a current Chrome and check `chrome://policy`.
5. Check the policy reached the device: `chrome://policy`, then `chrome://extensions`.
6. From the device's network, request `https://<browser-host>/health`. A failure points to network, proxy, TLS inspection, or an operator outage.
7. Check the group grant requirement: group grants need Browser v0.21.0 or later.
8. If an operator outage is suspected, check the deployment's readiness and re-run the [deployment preflight](../deploy/pilot/README.md#verify-the-deployment).

### Extension not reporting

Signs: **Stale** in **Browser health**, **Control offline** in the popup, or events missing.

1. Is the browser running? Chrome syncs about every 30 seconds while it runs. A stopped browser shows Stale after 90 seconds. A restarted browser catches up on its own.
2. Popup status: Control offline means the extension cannot reach Control. It keeps enforcing the last saved policy and queues up to 100 events. If the queue fills it discards the oldest and shows the count.
3. Control access revoked: the installation was revoked. Enroll again with a fresh grant.
4. Compare the reported extension version with the deployed one in **Review browser rollout**. Relaunch the browser if the version looks old after an upgrade.
5. If the extension is missing from `chrome://extensions`, check the device policy, update URL, and CRX hosting.
6. If many browsers are stale at once, suspect the Control deployment or a network change. Check the browser API `/health` and operator monitoring. See [Verify the deployment](../deploy/pilot/README.md#verify-the-deployment).
7. If only decisions are missing but the browser reports, check the composer status and policy status in Control.

### Policy shows as not applied

Control keeps a policy version unacknowledged when the browser's build cannot apply a capability in it. Check the extension version in **Review browser rollout** and upgrade. See [Upgrade](install-and-remove.md#upgrade).

## Respond to a broken app adapter

An adapter breaks when an AI site changes its page and Zekvar Browser can no longer recognize the composer, the Send control, or a file intake path. Treat it as Sev 2, or as [Blocker 3](#blocker-3-enforcement-falls-short-of-advertised-coverage) if the app is advertised as covered in the [coverage matrix](coverage.md).

Control has a dedicated **Adapter controls** page (Browser v0.42.0 or later). For one app and one scope (the organization baseline or a rollout group), an administrator can:

- **Disable attachments**: Browser stops holding and inspecting files from the picker, drag and drop, and clipboard file paste on that app. Typed prompts and text paste stay protected.
- **Disable the whole adapter**: Browser stops intercepting the app entirely. Its panel reads "protection disabled by your administrator", and Control shows the app as **Disabled by administrator**, not Unsupported.
- Choose a fallback:
  - **Fail open**: the app stays usable without that protection.
  - **Fail closed**: Control also adds the app's hosts to the AI app access block for that scope, so users cannot open the app at all. This works on every Browser release that supports AI app access, including releases older than v0.42.0.

Each change is a normal versioned policy. It can be reviewed, restored, and rolled out through an automated rollout plan. An intentionally disabled app passes composer readiness gates. Auditors can see the state but cannot change it.

**Older Browser releases.** A release before v0.42.0 does not request adapter controls. It keeps intercepting the app, which may be broken, and stays **Policy pending** for that version in Control. Fail closed still blocks its access to the app. Upgrade those browsers, or use fail closed when the broken behavior is unacceptable.

### Runbook

1. **Detect.** Watch **Composer readiness** on the dashboard (Browsers section) and the **Adapter controls** page. A broken adapter shows as a rise in **Unsupported** for one app, often for one Browser release or right after the app changed. The Adapter controls page marks the app **Possible broken adapter** when any browser in the scope reports Unsupported. A customer report of prompts or files getting through without a decision is another signal.
2. **Confirm.** Reproduce with the synthetic marker on a test profile. Record the Browser version, page route, account type, which action fails (Send click, Enter, paste, picker, drop, clipboard file, or one attachment type), and the result. Use **Copy composer diagnostics** in the page panel. Compare with the [coverage matrix](coverage.md).
3. **Decide the fallback with the customer administrator.** Fail open keeps the app usable without protection. Fail closed blocks the app. If only files break, disable attachments rather than the whole adapter.
4. **Disable.** In Control, open **Adapter controls**, choose the scope, set the app's interception to **Attachments disabled** or **Whole adapter disabled**, choose the fallback, and publish. Start with a rollout group if only part of the fleet is affected. With policy reviews on, a second administrator approves it. The API equivalent is `POST /v1/admin/policies` (or a group's policies) with `adapterControls`, for example `{ "chatgpt": { "scope": "attachments", "fallback": "open" } }`.
5. **Verify the switch.** In Adapter controls, the app's browsers move to **Disabled by administrator** (whole adapter) or the **Attachments disabled** count rises. Browsers still on **Policy pending** are older releases or offline.
6. **Notify affected customers' administrators** with the template below.
7. **Fix.** Engineering ships a new Browser release. Stage it on a test tenant and a canary group first. See [Upgrade](install-and-remove.md#upgrade).
8. **Re-enable.** Set the app back to **Active (protected)** for the canary group first. Confirm the app returns to **Detected** in composer readiness and the controlled tests for that app pass. Then re-enable the baseline and other groups. Restoring an earlier policy version also restores its adapter controls, so check the Adapter controls page after any restore.
9. **Close.** Send the restoration notice, and record the incident and its regression test in the product plan's decision log.

### Customer notice template

> Subject: Zekvar Browser protection change for [App] ([scope])
>
> On [date, time UTC], we found that [App] changed its page in a way that stops Zekvar Browser from reliably checking [prompts / file attachments / all actions] on [Browser version or "all versions"].
>
> To avoid a false sense of coverage, your administrator has [disabled Zekvar protection for [App] attachments / disabled the Zekvar [App] adapter] for [scope]. While this is in place, [App] is [still available without Zekvar checks for this action (fail open) / blocked in managed Chrome (fail closed)]. Other apps and actions are unaffected.
>
> What you should do: [avoid sharing sensitive files in [App] / use [approved alternative]]. We will tell you when protection is restored.
>
> Next update: [time UTC]. Contact: [support contact].

Restoration notice: "Zekvar Browser protection for [App] [action] is restored as of [time UTC] on Browser [version] and later. No action is needed beyond keeping Chrome updated."

## Run an incident

Applies to any Sev 1.

1. **Declare.** Name an incident owner, a communications lead, and a scribe. Open an incident record with the start time in UTC.
2. **Contain** following the blocker runbook below.
3. **Assess** which organizations, installations, and data are affected. Use Control audit logs and database queries by the operator.
4. **Notify.** Customers: [TO CONFIRM: notice time, contact method, content]. Regulators and partners: [TO CONFIRM].
5. **Recover** and verify with synthetic data. Record the time to contain and the time to recover.
6. **Review** within [TO CONFIRM] days. Add regression tests for what the existing suites missed. Record the incident and its resolution in the product plan's decision log.

Keep the record factual and free of customer content.

## Blocker 1: Cross-tenant data exposure

**Definition.** One organization's data (policies, installations, events, audit entries, exports, cases, alerts, feed output, or webhooks) was readable or changeable by another organization's credential, installation, or collector.

**Signals.** A customer reports seeing records that are not theirs. An export holds unknown installation or group names. A feed key reads another tenant's events. A support or test check fails an isolation assertion.

**Contain (first hour).**

1. Declare Sev 1 and name an owner.
2. Stop expanding rollouts. Pause policy and enrollment changes.
3. If the exposure is ongoing and the path is known, close it: take the affected route offline at the edge, or stop the API. Extensions keep enforcing their last saved policy and queue up to 100 events while Control is offline.
4. Revoke credentials that may have seen the data: named Control credentials, SSO identities, and event feed keys for the affected organizations (Control access page). Rotating an organization's OIDC exchange token invalidates its SSO sessions. Restarting the dashboard clears its sessions.
5. Preserve evidence: copy the audit log, the API and edge logs, and the request time range, before any cleanup.

**Investigate.**

- Identify the route, query, and code change responsible. Reproduce on a test pair of tenants with synthetic data.
- Determine which organizations and which datasets were read, by whom, and when. The audit log records named actions. The audit action list contains no entries for read-only views or event exports. [TO CONFIRM: what read-access evidence exists. Request logs may be the only source.]
- List affected customers.

**Recover.**

1. Ship the fix. Add a regression test that would have caught it, in the tenant-isolation suites ([`control.test.mjs`](../apps/control-api/test/control.test.mjs)).
2. Verify on a disposable pair of organizations: policies, events, history, export, cases, alerts, webhooks, feed, and fleet routes, using one tenant's credential against the other's IDs. Expected results are 404 or 403 and no data.
3. Re-issue credentials for affected organizations. Restore access in stages.
4. Notify affected customers under the notice terms. [TO CONFIRM]
5. Record the verification before any rollout resumes.

**Tabletop drill 1: A feed key reads another tenant.**

*Roles:* incident owner, support lead, engineer, communications lead, scribe, and a facilitator who plays the customer and the clock. *Time:* 45 minutes.

| Time | Inject | Questions to answer |
| --- | --- | --- |
| 0:00 | Customer A's collector shows events with installation IDs that Customer A does not own. | Who declares? What severity? Who is the owner? |
| 0:05 | Support finds the events carry organization B's rollout group names. | What do we preserve? Which logs exist? |
| 0:10 | An engineer finds a feed endpoint query that is missing the organization filter in a code path added last week. | How do we stop reading right now? Which keys do we revoke? |
| 0:20 | Customer B asks if their data was read. | What do we know? What do we not know? What can we say? |
| 0:30 | A fix is ready. | How do we prove it on two disposable tenants? What regression test is added? |
| 0:40 | Facilitator asks for the notification draft. | Who gets notified, by when, saying what? [TO CONFIRM: notice terms] |

*Pass criteria:* owner named within five minutes. Containment action chosen and recorded. Evidence preserved before changes. Affected tenants and datasets listed. A notification draft produced. The verification steps listed above are written down. The scribe has times for declare, contain, recover.

## Blocker 2: Sensitive content in telemetry or logs

**Definition.** Prompt text, file names or contents, matched values, clipboard contents, URLs visited, or credentials appear in an event, Control database field, API or edge log, webhook payload, SIEM feed, export, or support ticket.

**Signals.** A synthetic marker string shows in a stored event, an export, or a log line. An engineer finds a new field in an event. A customer reports content in a ticket or screenshot.

**Contain (first hour).**

1. Declare Sev 1 and name an owner.
2. Find the source: extension payload, API handling, dashboard, edge, or a log.
3. Stop the flow:
   - If the extension sends the data, ship a rollback or fix. Until it is installed, consider blocking the ingestion route at the edge, which makes extensions queue up to 100 events and then drop the oldest. Weigh the loss of event visibility against exposure.
   - If a log carries it, change the log configuration and remove the log source.
4. Do not copy the content into tickets or chat.

**Investigate.**

- Identify the field, the version range, and the time window. Use synthetic strings to reproduce.
- List every place the data may have reached: the `security_events` table and its exports, SIEM copies from the event feed, webhook receivers, container and host logs, off-host backups, support tickets, screenshots, and dashboards.
- Confirm that the API accepts only the listed event fields. The API rejects clipboard evidence that includes inspected text. Check whether the same protection exists for the path in question.

**Recover.**

1. Fix the leak. Add a regression test with a synthetic marker that must not appear in event transport, storage, export, feed, or logs. The demo runner already checks this for the GitHub token path ([Verify the scenarios](../apps/browser-extension/README.md#verify-the-scenarios)). Extend it for the new path.
2. Purge in Control. Export evidence first if the customer needs it. To delete retained events and observations, set the retention window to 1 day and select **Run cleanup** until the counts reach zero ([Set data retention](../apps/control-web/README.md#set-data-retention)). Audit entries follow their own window and carry no prompt content by design. If the leak is in another table, use an operator database procedure. [TO CONFIRM: approved procedure and approver.]
3. Purge logs and SIEM copies. Ask the customer to delete the copies they collected through their SIEM and webhook receivers.
4. Backups: encrypted snapshots made during the window still hold the data. Delete or let them expire by the lifecycle, and document the date. [TO CONFIRM: backup deletion procedure.]
5. Rotate any credentials found in content.
6. Notify affected customers. [TO CONFIRM]
7. Verify on a disposable organization with synthetic data in each path.

**Tabletop drill 2: A synthetic marker appears in the event feed.**

*Roles:* as in drill 1, plus a customer security contact. *Time:* 45 minutes.

| Time | Inject | Questions to answer |
| --- | --- | --- |
| 0:00 | The customer's SIEM shows an event field that contains the string `ZEKVAR_TEST_SECRET` from a test prompt. | Is this a leak? What severity? |
| 0:05 | The field arrived in a new extension build that was deployed to the pilot ring yesterday. | Which versions? Which organizations run it? |
| 0:10 | An engineer confirms the extension adds the matched text to a new optional field. | What do we do about the build now? Roll back? Block ingestion? |
| 0:20 | The customer asks where else the string lives. | List every location. |
| 0:30 | The customer asks for deletion. | How do we purge events, copies, logs, and backups? What do we tell them about backups? |
| 0:40 | Fix and regression test proposed. | Which test fails on the old build and passes on the new one? |

*Pass criteria:* the data locations list includes the database, exports, SIEM, webhook, logs, backups, and tickets. A containment decision is recorded with its tradeoff. A purge plan exists. A regression test is defined. Time to contain and time to recover are recorded.

## Blocker 3: Enforcement falls short of advertised coverage

**Definition.** A control that Zekvar documents as supported fails to hold or release as stated in the coverage matrix, in a supported app flow. Examples: a Block prompt reaches the app on a supported composer; a clean file is held and never released; a documented input path (click, Enter, paste, drop, picker) bypasses a rule.

**Signals.** An employee or administrator reports a bypass. Composer readiness shows Unsupported or Unobserved after an app update. The weekly matrix run fails. Events stop for a covered flow.

**Contain (first hour).**

1. Declare Sev 1 if the flow is advertised as covered. Name an owner.
2. Reproduce with the synthetic marker. Record Browser version, Chrome version, page layout, account type, and observed result.
3. Stop relying on it. Tell affected administrators that the flow is not protected as stated.
4. Compensate if needed: in Control **Adapter controls**, disable the affected app's attachments or whole adapter for the affected scope, with fail closed to block the app or fail open to keep it usable without that protection. See [Respond to a broken app adapter](#respond-to-a-broken-app-adapter).
5. If a recent release caused it, roll back the extension release ([Roll back](install-and-remove.md#roll-back)). If an adapter break caused it, follow [Respond to a broken app adapter](#respond-to-a-broken-app-adapter).
6. Pause promotions to Warn and Block and pause marketing and documentation claims for that flow.

**Investigate.**

- Which flows, versions, and layouts. Which customers. When it started. Whether queued decisions and events were lost.
- Whether the matrix was out of date, a test was missing, or the app changed.

**Recover.**

1. Fix and add a test case to the app-by-action matrix.
2. Stage the fix on a test tenant, then a pilot ring, then wider. Verify clean and blocked paths. Confirm composer readiness returns to Detected.
3. Update the coverage statement before the fix is announced. Only claim what a release test shows.
4. Notify customers: which flows were affected, the period, what to do.
5. Record the version, layout, account type, and result for each retested flow.

**Tabletop drill 3: Claude changes its composer.**

*Roles:* as in drill 1, plus a pilot customer administrator. *Time:* 45 minutes.

| Time | Inject | Questions to answer |
| --- | --- | --- |
| 0:00 | A customer reports that a Block prompt with the synthetic marker was sent in Claude. | Is Claude advertised as covered? What is the severity? |
| 0:05 | Control shows Unsupported for Claude in 40 percent of the pilot group, with Browser v0.40.0. | What do we tell the customer now? |
| 0:10 | Support collects composer diagnostics. They show a changed structure. | What do we ask the customer to avoid sending? |
| 0:15 | The customer asks to keep using Claude for the sales team. | What containment options exist? What do we apply for which groups? |
| 0:25 | An engineer proposes a fix. | How is it staged? What is the rollback? What proves it? |
| 0:35 | Marketing wants to keep the coverage matrix unchanged. | What changes in the coverage statement and when? |
| 0:40 | The fix passes the controlled fixtures. | What live check is required before we call it covered? |

*Pass criteria:* the containment action is applied or specified for each group. The customer is told what is unprotected. The coverage statement is corrected before announcing a fix. The fix path includes canary, widen, and rollback. The retest record names version, layout, account type, and result.

## Drill record

Complete after each drill and file the result in the product plan's decision log.

| Field | Value |
| --- | --- |
| Drill and date | |
| Participants and roles | |
| Declared at (UTC) | |
| Owner named at | |
| Contained at | |
| Recovered and verified at | |
| Customer notice drafted at | |
| What worked | |
| Gaps found | |
| Fixes and owners | |
| Tests added | |
| Scenarios not exercised | |

Also record what was simulated. A tabletop drill does not test live restore, live revocation, or a live rollback. Run those separately: a timed restore on a staging deployment ([Back up and recover Control](../deploy/pilot/README.md#back-up-and-recover-control)), a credential revocation, and an extension rollback on a canary ([Roll back a signed Browser release](../deploy/pilot/README.md#roll-back-a-signed-browser-release)).
