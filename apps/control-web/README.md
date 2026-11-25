# Zekvar Control dashboard

Control is a local dashboard for publishing browser policies, issuing enrollment grants, reviewing policy versions and browser health, and filtering security events. It reads and changes real data through the [Control API](../control-api/README.md).

## Run the dashboard

1. Start PostgreSQL and the Control API using the [API instructions](../control-api/README.md#start-the-api). Keep the generated admin token available to paste into the sign-in form.
2. Open a second terminal, `cd` into your `zekvar` checkout, and verify that `pwd` ends in `/zekvar`. Install dependencies and start the dashboard with Node.js 22 or newer.

   ```sh
   npm --prefix apps/control-web ci
   npm --prefix apps/control-web run dev
   ```

3. Open [Control on localhost](http://localhost:3000) and sign in with the API's `Control__Organizations__0__AdminToken` value.
4. Set **Test marker** and **GitHub classic PAT** independently under **Publish a policy**. The GitHub rule defaults to **Off** with **Monitor**, **Warn**, and **Block** available. To revert the policy settings, restore an earlier version. Control publishes the restored configuration as a new version.
5. Create an enrollment grant and paste it into the Zekvar Browser popup. After testing a prompt, refresh the dashboard to see the installation and its decision metadata. **Security events** names the rule responsible for each decision. [Run the browser demo](../browser-extension/README.md#run-the-demo)
6. For the [experimental ChatGPT adapter](../browser-extension/README.md#try-the-experimental-chatgpt-adapter), filter **Application** to **ChatGPT**, and check the **ChatGPT composer** column under **Browser health**. The timestamp shows when Control last received a coverage observation.
7. Publish **App discovery** as **On** to populate **App inventory** from enrolled browsers. The inventory shows the latest observation and distinct browser count over 30 days. Classify each app from its row and click **Save**. [Try app discovery](../browser-extension/README.md#app-discovery)
8. Open **Navigation rules** to publish allowed and blocked hostnames or paths. Policy history shows the lists for each version. Browser health shows whether Chrome has applied the latest policy. [Try navigation rules](../browser-extension/README.md#domain-rules)

In **Browser health**, **Reporting** indicates Control heard from the installation within the last 90 seconds. **Stale** indicates the reporting window elapsed. **Policy status** shows whether the browser’s last applied version matches the current policy. Use **Refresh** to update the table. The [two-profile pilot lab](../browser-extension/README.md#run-the-two-profile-chrome-pilot-lab) demonstrates both states.

**Extension rollout** counts active installations by the last extension version they reported. Filter **Rollout group** in **Browser health**, or open **Review browser rollout** from a group’s settings. Choose **Organization baseline** for unassigned installations. Compare the cohort’s active count with **Version reported in last 90 seconds** before widening an update. The eight most common releases have individual rows. Less common releases appear under **Other versions**, and browsers that have never reported a version appear under **Unreported**.

Select a version or **Unreported** in the summary to find matching installations. You can also enter an exact version in **Reported extension version**, including versions grouped under **Other versions**. The installation table shows up to 100 matches and includes the last version and receipt time alongside the applied policy. The summary continues to count all active installations in the selected group. Security event filters retain their own selection. Browser v0.20.0 and later reports its manifest version when it fetches policy. Use `chrome://extensions` or device management for independent confirmation of the installed package. [Signed Browser distribution](../../deploy/pilot/README.md#distribute-signed-browser-releases)

The organization baseline applies to unassigned browsers and groups that follow it. The dashboard keeps Control tokens in server memory and gives the browser a short-lived HTTP-only session cookie. Restarting the dashboard clears those sessions. Keep both services on loopback and use synthetic demo data.

To pilot Claude attachments, choose a test rollout group under **Policy preview**. Enable **Draft Claude prompt protection**, then choose a file-type rule or file content mode. The preview rows show how the draft handles synthetic Claude attachments. After publication, confirm that enrolled Browser v0.40.0 profiles acknowledge the version. Filter **Security events** to **Claude** and review the file decision and intake method. [Test Claude attachment protection](../browser-extension/README.md#try-experimental-claude-prompt-protection)

### Review composer readiness before switching a group to Block

Open **Browser health** and choose the rollout group and, if needed, a reported extension version. **Composer readiness** counts all matching active browsers for ChatGPT, Gemini, and Claude. Each matching installation shows the same status in its app column. Compare the readiness table with the **AI enforcement report** before promoting a group.

- **Detected** or **Unsupported** reflects the latest recent observation for the browser's applied policy and assignment. Test the intended compose workflows in your own pilot.
- **Unobserved** means no matching observation has arrived. Install Browser v0.22.0 or later and open the app in that profile.
- **Policy pending** means Control is waiting for acknowledgment of the assigned policy. **Off** means that policy disables Claude prompt protection.
- **Stale** means the observation is at least 24 hours old or the browser has missed 90 seconds of heartbeats. Ask the user to reopen the app and refresh Browser health.

Select **Export composer readiness (JSON)** to save a fresh snapshot for those Browser health filters. The download includes the capture time, selected group and extension version, current target policy for a specific group or the baseline, and counts for every matching active browser. Keep that file with the pilot's enforcement report and hands-on workflow checks. A composer detected under the current policy is a coverage signal. Exercise the actual submit and attachment paths before enabling enforcement for the cohort.

### Require composer readiness before publishing

In **Policy preview**, choose the destination scope, make the draft changes, and select **Run preview**. Under **Require fresh composer checks**, select the apps to verify before you publish or request review. Control checks every active browser affected by the draft. A baseline draft reaches unassigned browsers and inheriting groups. A group draft checks only that group's browsers.

Each selected app needs a detected composer on the browser's current policy and assignment. The observation must be less than 24 hours old and the browser must have checked in within 90 seconds. The scope needs at least one active browser. If a check fails, open **Review rollout impact**, resolve the missing coverage, and retry the same draft. To check Claude, first enable its adapter and gather observations on the current policy.

For a two-person review, the request shows the selected apps and Control checks them again at approval. When coverage changes, the request stays pending until coverage recovers or the review expires. A successful publication records the app names, reference version, and browser count in **Audit log**. Continue testing the intended text submission and file workflows on the pilot profiles. [Control API contract](../control-api/README.md#require-composer-readiness-for-publication)

## Reuse a published policy

1. Open **Policy templates**. If a template is already open, select **New template**. Choose the source rollout group or organization baseline and select **Load source policies**. Name the template, select a published version, and select **Create template**.
2. Open the template, choose its revision and destination, and select **Compare settings**. Review the configuration changes, including any removed rules. Temporary prompt exceptions stay with their destination and keep their original expiration.
3. Apply the revision or request approval, depending on the organization's review setting. If another administrator changes the destination before publication, compare again. When independent review is required, a second administrator approves the pinned revision in **Policy reviews**.
4. Verify the resulting policy in the destination's history and confirm that enrolled browsers have synced. Use the destination's normal rollback workflow to restore a previous version.

Save a new revision to reuse a different published policy. Archiving stops future applications and makes pending applications ineligible for approval. Previously published policies remain in place. Auditors can inspect templates and comparisons. [Policy template API](../control-api/README.md#policy-templates)

## Manage browser fleet batches

1. Open **Browser fleet**. Filter by a rollout group or the organization baseline, or use **Older browsers** to page through active installations. Select up to 25 browsers on the current page.
2. Choose **Assign to rollout group** or **Revoke browser access**, then select **Review browser batch**. An assignment review shows the destination and its current policy version. Check the selected installation IDs before confirming.
3. After confirmation, Control shows how many browsers changed and records the batch in **Audit log**. Assigned browsers receive the reviewed destination policy on their next sync, or its latest version if it has since been published. Revoked browsers need fresh enrollment to reconnect.

If a selected installation moves or the destination policy changes during review, refresh and review a new batch. The whole operation must pass these checks. Earlier Browser builds must sync with assignment support before moving. Auditors can inspect the fleet and audit log. [Fleet API and retry behavior](../control-api/README.md#browser-fleet-batches)

## Enroll a rollout group

1. Publish or verify the group's policy in **Rollout groups**, then open **Enroll browsers in group**. **Enrollment batches** also lets you choose the group or organization baseline directly.
2. Issue one grant per profile, up to 25 at a time. Copy the codes as soon as the batch is created. Give each browser its own code through your device manager. Coordinate delivery within the 10-minute lifetime. For a hosted build, set the exact `ControlOrigin` alongside `EnrollmentGrant`.
3. Use Browser v0.21.0 or later for a group grant. Check **Browser health** after enrollment to confirm the group and its applied policy. Remove each grant from managed settings after redemption.
4. Use **Cancel unused grants** if a batch was misdelivered or the rollout is delayed. Browsers that already redeemed a grant keep their existing access. Use **Browser health** to revoke an enrolled browser separately.

Recent batches and the audit log show counts and group names. The grant codes appear only in the response that creates the batch. [Distribute signed Browser releases](../../deploy/pilot/README.md#distribute-signed-browser-releases)

## Review browser extension inventory

Publish **Extension inventory** on the organization baseline or a rollout group. The enrolled profile needs Browser v0.14.0 or later and Chrome’s optional management permission. The setting starts Off. Use policy preview and a policy review when those are part of your rollout.

Open **Browser extensions** to see reporting status and select an installation. **Permission needed** means the profile must grant the optional permission in the extension popup. **Awaiting report** means no current snapshot has arrived. The per-browser view shows extension details and flags entries for review based on install source, broad site access, or selected permissions. A Review flag identifies a condition for inspection.

Control keeps the latest snapshot per browser and labels counts when Chrome reports more than 100 extensions. A new policy or group assignment hides the old snapshot until the browser reports again. Revocation removes the snapshot immediately. The scheduled cleanup clears snapshots older than 30 days and snapshots for browsers whose current policy is Off. [Browser instructions](../browser-extension/README.md#report-browser-extensions)

On the same page, open **Extension change history** to compare reported versions, enabled states, install sources, site access, and selected permissions. **Review access** marks newly enabled or expanded risk signals. Names shown in the history come from the current inventory. Removed extensions can be identified by ID.

Control shows up to 20 reports with changes from the last 30 days while inventory stays enabled in the current rollout assignment. The first usable report establishes a baseline. When a report is truncated, Control compares extensions present in both reports. After a permission or collection gap, the next report establishes a fresh baseline. [Extension inventory API](../control-api/README.md#extension-inventory)

## Delegate Control access

1. Sign in with the configured owner token and open **Control access**.
2. Enter the recipient’s name, choose a role and a lifetime, and select **Issue token**. Copy the token from the issuance panel before hiding it or leaving. The credential list shows its status and expiration.
3. Sign in as the recipient with the issued **Control token**. Administrators can manage the organization’s browser policies, enrollment, and retention. Auditors can review settings, run local policy comparisons, and export events and audit records.
4. To end access early, sign in as the owner and select **Revoke** on that credential. Its next request to Control will be rejected, including requests from a dashboard session already open.

**Audit log** records issuance, revocation, and changes made with a named administrator credential. Use a distinct token per recipient for attribution.

Hosted pilots can also use **Single sign-on access** on this page. Add an identity by its exact OIDC subject and assign the Administrator or Auditor role. On a deployment with organization-specific sign-in, enter the organization slug to open its identity provider. Revoke an identity from the access list to end its active Control sessions. [Configure hosted single sign-on](../../deploy/pilot/README.md#configure-control-single-sign-on)

## Connect a security event collector

1. Sign in as the organization owner and open **Control access → Security event feed**.
2. Enter a name and the number of days the collector can read the feed. Choose **Issue event feed key** and copy the key into your collector's secret store before hiding it or leaving the page.
3. Configure the collector to poll `/v1/integrations/events` on the Control dashboard hostname over HTTPS. Use a source network allowed by the pilot deployment. Save its checkpoint only after storing each page of events.
4. To rotate a key, issue a replacement, configure the collector with the replacement, and verify it can resume from its saved checkpoint. Revoke the old key from its row. Review issuance and revocation under **Audit log**. [Event feed API and checkpoint rules](../control-api/README.md#security-event-feed)

## Require policy reviews

1. Issue named administrator credentials to two reviewers, then sign in as the owner and choose **Require policy reviews** under **Policy reviews**. The requirement applies to the organization baseline and rollout groups.
2. Sign in as a named administrator. Submit a policy, navigation rule change, previewed draft, restore, or group promotion for review. Enrolled browsers keep their current policies while the request is pending.
3. Sign in as a different named administrator, open **Policy reviews**, and compare the proposed settings with the reference version. Choose **Approve and publish** or **Reject request**. The requesting administrator can withdraw the request.
4. Check **Policy history** and **Browser health** after approval. **Audit log** records the request, decision, and published version.

Requests expire after 24 hours. A change to the reference policy, promotion source, or requesting credential can make a request stale. Submit a fresh request in that case. Owners can disable the requirement, which cancels pending requests. The requirement covers policy publication, restoration, and promotion. Browser assignments continue to use the rollout-group controls. [Policy reviews API](../control-api/README.md#policy-reviews)

## Roll out policies to a pilot group

1. Update enrolled browsers to Zekvar Browser v0.8.0 or later and let them sync. Open **Rollout groups** and create a group.
2. In **Browser assignments**, select the group for a recent active installation and save. Each browser belongs to at most one rollout group. A new group follows the organization baseline.
3. Publish the group's prompt, discovery, or navigation settings. Its first publish copies the current baseline and applies the changes to that copy. Subsequent publishes update the group's own policy. Use **Browser health** to check the policy status against the browser's assigned version.
4. Restore a version from **Group policy history** to roll back that group. Assign the browser to **Organization baseline** to return it to the current baseline. After validating the group, open **Review baseline impact** and use **Promote group policy** to copy the reviewed version into a new baseline version. If either reviewed version changes before confirmation, reload and review the current policies. Other groups with their own policies continue to use their group settings.

Control records group creation, assignment, publication, rollback, and promotion in the audit log. [Policy groups API](../control-api/README.md#policy-groups)

## Review policy rollout impact

Open **Review rollout impact** from a draft, template comparison, rollout group, or pending policy review. The report opens in a separate tab so you can return to the draft. You can also find **Policy rollout impact** under **Reports** and choose a destination.

- A baseline report includes unassigned browsers and every group that inherits the baseline. A group report includes only browsers assigned to that group. **Browsers outside scope** counts active installations that would keep their current policy scope.
- Compare **Reporting and current** with **Stale or pending**. The cohort table separates recent check-ins from acknowledgments of the current destination version. Composer counts describe observations on that version and assignment. Run a managed canary with the proposed policy to check actual enforcement.
- Choose **Export fresh snapshot (JSON)** for an aggregate snapshot of the same destination version. The export excludes browser IDs and inspected content. A changed policy version invalidates a pinned report and its export. Open the current report and reload the draft or promotion page to review the new version.

## Preview a policy

1. Open **Policy preview** for the organization baseline, or select **Preview group policy** from a rollout group. Use **Load draft from** to start with a version from the available history.
2. Edit detector settings, file upload modes and types, or navigation rules. Choose **Run preview** to see how the current policy and the draft handle the same built-in and optional custom samples. Custom prompts, navigation URLs, and sample file names and media types stay in the browser tab.
3. Review the outcomes and setting changes. Choose **Publish previewed policy** and confirm to publish the draft to the selected scope. If the current version changed while you were editing, reload the page and run the comparison again.

The preview evaluates the supported text detectors, file metadata, and individual top-level HTTP and HTTPS URLs. Choose **Prompt sample destination** to compare app-specific settings such as **Claude prompt protection** and temporary exceptions. A blank **File types** field applies the upload mode to all files for ChatGPT or Gemini. Enter types such as `.pdf` or `image/*` for selected files. Use a pilot group to test native browser actions before promotion. [File upload test guide](../browser-extension/README.md#test-file-upload-policies)

Use **Draft ChatGPT file content protection** or **Draft Gemini file content protection** to preview Off, Monitor, and Block. The preview includes matching and clean synthetic text and an unsupported file sample. Browser v0.27.0 can hold a file selection, release a clean scan, and stop a batch when it finds a match or cannot finish the check. Use Browser health to confirm the installed release across the rollout group. **Security events** shows the detector or **File check unavailable**, along with the intake method. **Reports → By activity** includes these decisions under **File content inspection**. [Block sensitive file contents](../browser-extension/README.md#block-sensitive-file-contents)

For OpenDocument uploads, use Browser v0.35.0 or later and test synthetic `.odt`, `.ods`, and `.odp` files through the enrolled browser. Policy preview scores supplied sample text. The native upload test verifies which text Browser can extract from the file. [Monitor file contents](../browser-extension/README.md#monitor-file-contents)

For PDF uploads, use Browser v0.36.0 and test a clean text PDF, one with a synthetic detector match, and one that requires a password. Check the Browser release and reported decisions before expanding the rollout. [Block sensitive file contents](../browser-extension/README.md#block-sensitive-file-contents)

## Set prompt modes by AI app

1. Open **Policy preview** for the baseline or a rollout group.
2. Under **Prompt modes by AI app**, choose **Monitor**, **Warn**, or **Block** for each destination. **Inherit detector modes** uses the action configured on each detector. An override applies to enabled detectors. Enable **Claude prompt protection** to use the Claude adapter.
3. Choose a **Prompt sample destination** or import a test pack with cases for several apps. Run the preview, then publish or request review. Browser v0.34.0 can acknowledge the override after its next policy sync.

These settings apply when a user sends text. Clipboard and file protection use their own settings.

## Test a policy with a reusable pack

1. Open **Policy preview** for the baseline or a rollout group. Under **Test samples**, select **Download starter pack**.
2. Edit the JSON with synthetic cases and expected decisions. Import the file and select **Run preview** to compare the published version and the draft.
3. Review **Regression** for an expectation met only by the current policy, **Fixed** for one met only by the draft, **Mismatch** when both miss it, and **Pass** when both meet it. Rerun after editing the draft.
4. Select **Download test results** to save the scope, current version, draft source version, capture time, case IDs, and decisions. Use non-sensitive IDs. The report excludes sample text, URLs, and file details. The imported cases stay in the tab until you clear the pack, change scope, or reload.

Use `{"version":1,"cases":[...]}`. A pack can contain 1–100 cases and be up to 256 KiB. Each case needs a unique `id` of 1–64 ASCII letters, digits, hyphens, or underscores, starting with a letter or digit, plus `kind` and `expect`.

| Kind | Case fields | Expected decisions |
| --- | --- | --- |
| `prompt` | `app` of `chatgpt`, `gemini`, or `claude`, plus `text`. | `allow`, `monitor`, `warn`, `block`, `exception_applied` |
| `clipboard` | Same app choices. Omit `text` to simulate a paste without inspectable text. | `allow`, `monitor`, `block` |
| `navigation` | Complete HTTP or HTTPS `url`. | `allow`, `block` |
| `upload` | `app` of `chatgpt` or `gemini`, `file` with `name` and `type`, and optional simulated extracted `text`. Omit `text` to test an unavailable content check. | `allow`, `monitor`, `block` |

The pack scores policy decisions locally. Exercise native prompt submission, paste, file parsing, and navigation in a managed rollout group before promoting the policy.

## Protect organization identifiers

1. Open **Policy preview** and choose a scope. Under **Organization identifier detection**, select **Monitor**, **Warn**, or **Block**. Enter one prefix and digit count per line in **Identifier formats**, such as `CUST- 8` or `CASE_ 6`. Use prefixes that distinguish your identifiers from ordinary text.
2. Select **Run preview** to see a generated prompt and file sample for each format. Use a synthetic value in **Custom prompt** to check expected matches and near misses. The sample stays in the browser tab. Publish the draft or request independent approval and check **Browser health** for v0.28.0 and the applied policy.
3. Look for **Organization identifier** under **Security events** and in the report's rule breakdown. All configured formats share this reporting label. Use **Policy history** or a review request to see the formats that were in effect for a version. Restore a previous version to roll back the setting.

The detector uses exact ASCII digit counts and compares the prefix without case sensitivity. A letter, number, combining mark, dash, or connector next to the candidate makes it part of a larger token. A temporary prompt exception applies to every configured identifier format for the chosen app. Other matching detectors and the app's file content policy still apply. [Try organization identifier protection](../browser-extension/README.md#test-organization-identifier-protection)

## Protect cloud credentials and classified labels

1. Open **Policy preview** and choose a test rollout group. Set **Draft cloud and API credentials** to **Monitor**. Under **Classification rules**, choose a mode and enter up to 16 labels or phrases, one per line. Each entry uses 3 to 64 letters, digits, spaces, or `- – — _ . & / : '` and needs at least three letters or digits.
2. Select **Run preview**. Rows show synthetic keys for each provider beside AWS documentation and Stripe test-mode near misses, plus a prompt and file sample for each label. Publish the draft or request a review. In **Browser health**, confirm that the group runs Browser v0.41.0 and has applied the policy.
3. Review **Security events** by provider rule or **Organization classification rule**. Control stores the rule and category, but never the matched key or text. Enable enforcement for a wider group after you review false blocks in Monitor. Use **Restore** in **Policy history** to roll back both settings.

Older browsers keep their other detectors and remain pending while a version enables either setting. Temporary prompt exceptions and employee review requests do not cover these rules. [Try the rules in Browser](../browser-extension/README.md#protect-cloud-and-api-credentials)

## Pilot Claude prompt protection

Enable **Claude prompt protection** in a rollout group and sync Browser v0.19.0 or later. **Browser health** shows **Off** when the assigned policy disables the adapter, **Unobserved** before a composer check for the assigned version, and the last observed **Detected** or **Unsupported** status. Filter **Security events** to Claude to review metadata-only decisions. [Experimental Claude test guide](../browser-extension/README.md#try-experimental-claude-prompt-protection)

## Configure app inventory

Choose **App inventory → Edit app catalog** for the baseline or **Preview group policy** for a rollout group. Enable **App discovery** and enter custom sites in the form `workspace.example.test, Example Workspace`. Run the preview, review the catalog changes, then publish or request approval. Enrolled Chrome browsers with the discovery permission report visits to the exact configured HTTPS sites. Use **App inventory** to inspect observed browser counts and classify each app. [Browser permission and test guide](../browser-extension/README.md#app-discovery)

## Block access to AI sites

1. Open **App inventory → Manage AI app access**. Choose the baseline or a rollout group in **Policy preview**. Select the exact hostnames to block. The list includes preset AI sites and the draft scope's custom app catalog.
2. Select **Run preview**. Review the app access rows or try a URL in **Custom navigation URL**. AI app blocks take precedence over hostname and path rules. Classifications in **App inventory** can inform which rules you publish.
3. Publish or request approval. In a managed Chrome profile on Browser v0.26.0 or later, select **Sync now** and check the blocked host count. Try a new top-level visit and confirm that the expected version is applied in **Browser health**. To restore access, clear the relevant block and publish a new version or restore the prior policy. [Browser verification](../browser-extension/README.md#ai-app-access)

## Grant a temporary prompt exception

Open **Policy preview** for the intended scope and add an entry under **Temporary prompt exceptions**. Choose the app, detector, UTC expiry, and reason. Compare outcomes for that destination, then publish or request review. Edit or remove an entry through the same workflow. **Policy history** records the scope's configured entries. Filter **Security events** to **Exception applied** for observed uses. [Browser test guide](../browser-extension/README.md#test-temporary-prompt-exceptions)

## Review employee prompt exception requests

1. Open **Prompt exception requests** in Control. Each pending request links to the original detection and shows the browser's rollout scope, policy version, AI app, and detector. The inspector can work through the oldest pending requests first.
2. Choose **Decline request** or open **Open scoped policy preview** and add a time-limited exception for the request's app and detector. Review and publish through the organization's normal policy approval workflow. An exception affects the destination scope, including other browsers assigned there.
3. Return to the inbox and select **Record published exception**. Control checks that the browser still belongs to the scope and that its policy contains a matching active exception. The **Decided** view records the decision, the administrator, and the published version when applicable.

Auditors can read the queue and the linked detections. Request metadata follows security event retention. The resulting policy and its publication audit follow their own retention. [Employee workflow](../browser-extension/README.md#request-review-of-a-blocked-prompt)

## Deploy Chrome extension rules

1. Open **Browser extensions → Manage Chrome deployment**. Choose the organization baseline or a rollout group. Copy an ID from **Browser extensions**, enter the rule, and select **Review changes**. The plan accepts up to 100 exact IDs. Use `ID, allow`, `ID, block`, or `ID, force, https://updates.example.test/channel/update.xml`. Use the approved update manifest for the extension. [Chrome ExtensionSettings](https://support.google.com/chrome/a/answer/9867568)
2. Publish or request approval. The published plan follows Control's policy history, including promotion and restore. A group inherits the baseline until its first scoped publication. After publishing, the device group's native settings still come from its device manager.
3. Paste the target device group's current **ExtensionSettings** JSON. Control merges it locally and retains the original for rollback. If you select **Block unlisted**, enter the pinned Zekvar Browser ID and keep its existing force-install rule in the source. The wildcard default applies alongside explicit settings for listed extensions. Review **Chrome policy changes** and **Review merged JSON** before downloading.
4. Download the Chrome policy and the rollback file. Apply the Chrome policy's `ExtensionSettings` through the target group's device manager. Keep enrollment and other device policy settings in place. On a canary browser, reload policies at `chrome://policy` and verify installation behavior at `chrome://extensions`. Apply the saved rollback file's `ExtensionSettings` through the device manager if needed. Compare Chrome's effective configuration if other extension policies are present.

## Configure clipboard paste protection

Use **Clipboard paste protection** in the baseline or a rollout group's publish form. Start in **Monitor** to see detections while allowing paste. **Block** holds matching clipboard text and supported text pastes that cannot be inspected. **Policy preview** shows what happens at Paste and Send, including a clean paste and a check-unavailable sample. Review and restore work through the existing policy lifecycle.

In **Security events**, look for **Clipboard paste** below the detector. The event, related case, JSON export, and SIEM feed include that source without the clipboard contents. Older Browser builds cannot acknowledge an enabled clipboard policy as fully applied. [Test clipboard protection](../browser-extension/README.md#protect-text-pasted-into-ai-composers)

## Deploy a Chrome hardening plan

1. Open **Chrome hardening** and select an organization baseline or rollout group. Choose minimum Safe Browsing and download protections, whether users can proceed from a Safe Browsing warning, and whether to disable Guest, Incognito, built-in password saving, or Chrome Sync. Review the change and publish it or request independent approval.
2. Paste the effective flat Chrome policy JSON from the target group into **Export Chrome settings**. Enter `{}` for a group with no existing managed settings. Control keeps that JSON in the dashboard tab. The merge keeps unrelated settings, including the existing `ExtensionSettings` dictionary. A stricter Safe Browsing or download value already in the source takes precedence. The export rejects conflicts with enforced Guest, forced Incognito, or an Incognito allowlist and reports when a requested warning or download restriction needs Safe Browsing enabled.
3. Download the merged policy and its rollback copy. Apply the merged settings through your device manager to a small cohort and verify the managed values and status in `chrome://policy`. Restart Chrome if required. Reapply the original settings to roll back the device change, removing keys that were added if your management tool merges assignments. Restore the earlier Control version to roll back the published plan as well. [Chrome enterprise policy catalog](https://chromeenterprise.google/intl/en_us/policies/)

Enhanced Safe Browsing can send more data to Google. Download restrictions depend on Chrome's supported download paths and verdicts. Saving the current page and printing to PDF are outside the native restriction. Validate inherited exceptions and policy precedence in the target management system. [Safe Browsing protection levels](https://chromeenterprise.google/policies/safe-browsing-protection-level/) · [Chromium DownloadRestrictions](https://chromium.googlesource.com/chromium/src/+/HEAD/components/policy/resources/templates/policy_definitions/Miscellaneous/DownloadRestrictions.yaml)

## Investigate and export security events

Open **Events** in the sidebar. Filter by application, decision, time range, browser installation ID, recorded rollout group, triage status, or assignee, then select **Apply filters**. Select an installation, rollout, or assignee in a result to narrow the current view. Use **Older events** and **Newest events** to review the matching records.

The **Recorded rollout** column shows the assignment associated with the event, including when a group inherits the baseline policy. **Organization baseline** means the browser was outside a group for that event. **Unattributed** means the earlier record lacks enough information to determine its assignment. Use **Browser health** to check a browser's current assignment.

Select **Needs review**, **Investigating**, or **Resolved** in a row to open the event. Owners and administrators can assign it to an active named administrator, set the status, and select a resolution when closing it. Use **Assigned to me** in the assignee filter to find your queue. An inactive assignment remains visible until someone changes it. If another administrator saves first, reload and review their update before trying again. Auditors can read triage and activity.

**Triage activity** shows up to 50 retained changes with the actor and before-and-after values. Use **Audit log → Security event triaged** for organization-wide review. Event data and audit history follow their respective retention windows.

**Export security events (JSON)** downloads all retained records matching the applied filters, even when you are viewing an older page. Both the view and the download use the same cutoff for relative time filters. The file includes organization, filter, decision, and any saved triage metadata. Prompt text, matched values, and tokens stay out of the download. Treat installation IDs, assignment names, and decision history as organization data.

## Review AI enforcement

Open **Reports** in Control. Choose the last 7 or 30 UTC calendar days, an AI application, and a recorded rollout group, then select **Apply report filters**. Use **Investigate security events** to open individual records for the selected rollout. Review the trend, totals by app and rule, and counts for monitor, warn, block, warning override, and exception use. A warning and its override each contribute one policy event. The current UTC day shows activity through the displayed time. The local prompt fixture is excluded. Safe test markers used on supported AI sites still count.

**Export report (JSON)** downloads the same time window and filters using current retention. It contains aggregate counts and excludes individual events and browser identifiers. Reload the report if its download link is more than 24 hours old. Owners, administrators, and auditors can read and export the report. [AI enforcement API](../control-api/README.md#ai-enforcement-report)

## Review repeated AI block alerts

1. In **Alerts**, set **Alert rule** to **On**, enter a threshold from 2 to 100 blocked events, and save. Start with a threshold that fits the pilot cohort's volume.
2. Enrolled browsers report new blocks through their usual policy workflow. Control opens a single alert when one AI app and recorded rollout group reach the threshold in a 15-minute UTC reception window. Refresh **Alert inbox** to see new alerts. The rule starts Off.
3. Open an alert to review its retained blocked events. Use an event's detail page to start or link an incident case. **Acknowledge alert** moves the item to the acknowledged view, where auditors can review it and the audit log. Counts can continue to increase in the same window after acknowledgment.

Alert settings apply to newly received decisions. Turning the rule off stops new counting and keeps existing alerts visible under their retention window. A change to the threshold starts a fresh count. Alert summaries are available for up to 30 days, subject to the organization's security-event retention policy. The evidence table follows individual event retention.

If the deployment operator configured a webhook, open the alert's **Webhook delivery** section to see whether it was delivered, when Control will retry, or why an attempt failed. Refresh delivery status to check the latest attempt. [Configure alert delivery](../../deploy/pilot/README.md#send-alerts-to-a-webhook)

## Review extension access alerts

1. Open **Alerts → Extension access alerts**. Turn **Alert on expanded access** on and save. The rule starts Off and uses browsers with extension inventory enabled and Chrome permission granted.
2. Refresh the extension inbox after a browser reports. Control opens one alert per report with new risk signals. These include broader site access, newly granted privileged permissions, and newly enabled extensions with broad access, privileged permissions, or an unpacked or sideloaded install source.
3. Open the alert to compare the before and after states or follow the link to the browser's current inventory. Select **Acknowledge alert** when reviewed. The acknowledged view and audit log preserve the review while the records are retained.

The rule starts with the next change report. Turning it off stops new alerts. Each alert follows the underlying inventory report, with up to 20 changed reports per browser from the last 30 days. The inbox uses the current rollout assignment and inventory policy. Auditors can review the evidence and acknowledgment log. [Extension access alert API](../control-api/README.md#extension-access-alerts)

## Investigate an incident case

1. Open a detection from **Events**. Under **Incident case**, choose a category and select **Open new case**. To add another detection, open that event, choose **Link to an existing case**, and select the case from the list.
2. In **Case triage**, set the shared status and assign an active named administrator. Review the related detections under **Linked security events**. Case triage and individual event triage can have different statuses and resolutions.
3. Select a resolution when closing the case. Reopen it to link or unlink events later. Each event belongs to one case at a time, and each case holds up to 100 retained events.
4. Review changes under **Case activity** or filter **Audit log** to **Incident case changed**. **Export case (JSON)** includes the case, its retained linked event metadata, and up to 50 retained case changes. Auditors can read and export cases.

Events keep their own retention windows when linked. Resolved cases use the audit window, measured from their last case update. Open cases stay available if their original events expire. Each change records an actor and structured metadata. [Incident cases API](../control-api/README.md#incident-cases)

## Review and export the audit log

Open **Audit log** from the Control sidebar. The log shows policy publishes and restores, enrollment grant issuance, browser enrollment and revocation, and changes to AI app classifications. Filter by action and UTC date range, or select **Older entries** to see more history.

**Export JSON** downloads up to 1,000 matching entries in newest-first order with the organization, export timestamp, and API cursor when more entries are available. The export includes names and credential IDs for attributed actions and access changes. Actions performed with the configured owner token appear under the organization-admin category. [Audit API](../control-api/README.md#audit-log)

## Set data retention

Open **Data retention** to set independent windows for security events, AI observations, and audit history. Enter a whole number from 1 to 3,650 days or leave a field blank for no expiry. Saving requires confirmation because shortening a window immediately expires records from views and exports and makes them eligible for permanent deletion. Widening or clearing a window applies to records that have yet to expire.

Control checks for expired records at startup and hourly by default. Use **Run cleanup** to delete up to 1,000 expired records per dataset immediately. **Audit log** displays changes to retention settings and counts from cleanup runs. The cleanup scope is the active PostgreSQL database. [Retention API and expiry rules](../control-api/README.md#data-retention)

## Verify in Chrome

With both services running against a disposable organization, run the production build or type check separately as needed. The browser test publishes and restores policy versions, enrolls and revokes a test installation, and posts one synthetic event.

```sh
cd apps/control-web
npx playwright install chromium --no-shell
ZEKVAR_TEST_ADMIN_TOKEN="$Control__Organizations__0__AdminToken" npm run test:browser
```
