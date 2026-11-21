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
7. Publish **AI app discovery** as **On** to populate **AI apps** from enrolled browsers. The inventory shows the latest observation and distinct browser count over 30 days. Classify each app from its row and click **Save**. [Try app discovery](../browser-extension/README.md#ai-app-discovery)
8. Open **Domain rules** to publish allowed and blocked hostnames. Policy history shows both lists for each version. Browser health shows whether Chrome has applied the latest policy. [Try domain rules](../browser-extension/README.md#domain-rules)

In **Browser health**, **Reporting** indicates Control heard from the installation within the last 90 seconds. **Stale** indicates the reporting window elapsed. **Policy status** shows whether the browser’s last applied version matches the current policy. Use **Refresh** to update the table. The [two-profile pilot lab](../browser-extension/README.md#run-the-two-profile-chrome-pilot-lab) demonstrates both states.

The organization baseline applies to unassigned browsers and groups that follow it. The dashboard keeps admin tokens in server memory and gives the browser a short-lived HTTP-only session cookie. Restarting the dashboard clears those sessions. Keep both services on loopback and use synthetic demo data.

## Roll out policies to a pilot group

1. Update enrolled browsers to Zekvar Browser v0.8.0 or later and let them sync. Open **Rollout groups** and create a group.
2. In **Browser assignments**, select the group for a recent active installation and save. Each browser belongs to at most one rollout group. A new group follows the organization baseline.
3. Publish the group's prompt, discovery, or domain settings. Its first publish copies the current baseline and applies the changes to that copy. Subsequent publishes update the group's own policy. Use **Browser health** to check the policy status against the browser's assigned version.
4. Restore a version from **Group policy history** to roll back that group. Assign the browser to **Organization baseline** to return it to the current baseline. After validating the group, **Promote group policy** copies the reviewed version into a new baseline version. If the group policy changes before confirmation, reload and review the new version. Other groups with their own policies continue to use their group settings.

Control records group creation, assignment, publication, rollback, and promotion in the audit log. [Policy groups API](../control-api/README.md#policy-groups)

## Preview a policy

1. Open **Policy preview** for the organization baseline, or select **Preview group policy** from a rollout group. Use **Load draft from** to start with a version from the available history.
2. Edit the detector settings and domain rules. Choose **Run preview** to see how the current policy and the draft handle the same built-in and optional custom samples. Custom prompts and navigation URLs stay in the browser tab.
3. Review the outcomes and setting changes. Choose **Publish previewed policy** and confirm to publish the draft to the selected scope. If the current version changed while you were editing, reload the page and run the comparison again.

The preview evaluates the supported text detectors and individual top-level HTTP and HTTPS URLs. Test live app coverage, redirect chains, and the installed Chrome rules in a pilot group before promoting a policy.

## Review and export the audit log

Open **Audit log** from the Control sidebar. The log shows policy publishes and restores, enrollment grant issuance, browser enrollment and revocation, and changes to AI app classifications. Filter by action and UTC date range, or select **Older entries** to see more history.

**Export JSON** downloads up to 1,000 matching entries in newest-first order with the organization, export timestamp, and API cursor when more entries are available. The export contains timestamps, action and actor categories, and relevant version, installation, or app identifiers. The local admin token identifies an organization rather than an individual administrator. [Audit API](../control-api/README.md#audit-log)

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
