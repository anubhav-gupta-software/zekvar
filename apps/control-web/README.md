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

## Delegate Control access

1. Sign in with the configured owner token and open **Control access**.
2. Enter the recipient’s name, choose a role and a lifetime, and select **Issue token**. Copy the token from the issuance panel before hiding it or leaving. The credential list shows its status and expiration.
3. Sign in as the recipient with the issued **Control token**. Administrators can manage the organization’s browser policies, enrollment, and retention. Auditors can review settings, run local policy comparisons, and export events and audit records.
4. To end access early, sign in as the owner and select **Revoke** on that credential. Its next request to Control will be rejected, including requests from a dashboard session already open.

**Audit log** records issuance, revocation, and changes made with a named administrator credential. Use a distinct token per recipient for attribution.

Hosted pilots can also use **Single sign-on access** on this page. Add an identity by its exact OIDC subject and assign the Administrator or Auditor role. Revoke it from the same list to end active Control sessions. [Configure hosted single sign-on](../../deploy/pilot/README.md#configure-control-single-sign-on)

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
4. Restore a version from **Group policy history** to roll back that group. Assign the browser to **Organization baseline** to return it to the current baseline. After validating the group, **Promote group policy** copies the reviewed version into a new baseline version. If the group policy changes before confirmation, reload and review the new version. Other groups with their own policies continue to use their group settings.

Control records group creation, assignment, publication, rollback, and promotion in the audit log. [Policy groups API](../control-api/README.md#policy-groups)

## Preview a policy

1. Open **Policy preview** for the organization baseline, or select **Preview group policy** from a rollout group. Use **Load draft from** to start with a version from the available history.
2. Edit detector settings, file upload modes and types, or navigation rules. Choose **Run preview** to see how the current policy and the draft handle the same built-in and optional custom samples. Custom prompts, navigation URLs, and sample file names and media types stay in the browser tab.
3. Review the outcomes and setting changes. Choose **Publish previewed policy** and confirm to publish the draft to the selected scope. If the current version changed while you were editing, reload the page and run the comparison again.

The preview evaluates the supported text detectors, file metadata, and individual top-level HTTP and HTTPS URLs. Choose **Prompt sample destination** to compare app-specific settings such as **Claude prompt protection** and temporary exceptions. A blank **File types** field applies the upload mode to all files for ChatGPT or Gemini. Enter types such as `.pdf` or `image/*` for selected files. Use a pilot group to test native browser actions before promotion. [File upload test guide](../browser-extension/README.md#test-file-upload-policies)

## Pilot Claude prompt protection

Enable **Claude prompt protection** in a rollout group and sync Browser v0.19.0 or later. **Browser health** shows **Off** when the assigned policy disables the adapter, **Unobserved** before a composer check for the assigned version, and the last observed **Detected** or **Unsupported** status. Filter **Security events** to Claude to review metadata-only decisions. [Experimental Claude test guide](../browser-extension/README.md#try-experimental-claude-prompt-protection)

## Configure app inventory

Choose **App inventory → Edit app catalog** for the baseline or **Preview group policy** for a rollout group. Enable **App discovery** and enter custom sites in the form `workspace.example.test, Example Workspace`. Run the preview, review the catalog changes, then publish or request approval. Enrolled Chrome browsers with the discovery permission report visits to the exact configured HTTPS sites. Use **App inventory** to inspect observed browser counts and classify each app. [Browser permission and test guide](../browser-extension/README.md#app-discovery)

## Grant a temporary prompt exception

Open **Policy preview** for the intended scope and add an entry under **Temporary prompt exceptions**. Choose the app, detector, UTC expiry, and reason. Compare outcomes for that destination, then publish or request review. Edit or remove an entry through the same workflow. **Policy history** records the scope's configured entries. Filter **Security events** to **Exception applied** for observed uses. [Browser test guide](../browser-extension/README.md#test-temporary-prompt-exceptions)

## Investigate and export security events

Open **Events** in the sidebar. Filter by application, decision, time range, or browser installation ID, then select **Apply filters**. Select an installation ID in a result to narrow the current view to that browser. Use **Older events** and **Newest events** to review the matching records.

**Export security events (JSON)** downloads all retained records matching the applied filters, even when you are viewing an older page. Both the view and the download use the same cutoff for relative time filters. The file includes organization, filter, and decision metadata. Prompt text, matched values, and tokens stay out of the download. Treat installation IDs and decision history as organization data.

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
