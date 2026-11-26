# Install, upgrade, roll back, and remove Zekvar Browser

This guide is for the IT administrator who manages Chrome for your organization. It covers deploying Zekvar Browser through Chrome enterprise policy, enrolling browsers in Control, checking the result, upgrading, rolling back, and removing it.

Zekvar Browser is a Chrome extension (Manifest V3). Control is the admin dashboard and API. Operators build and host the signed releases. For the operator steps, see the [TLS pilot README](../deploy/pilot/README.md#distribute-signed-browser-releases).

**What has been tested.** Signed install, upgrade, rollback, and removal by policy were verified on managed Linux Chromium in a Zekvar lab. They have not been verified on Windows or macOS, or through Google Admin console, Microsoft Intune, or Jamf. The product plan lists a partner-managed canary as outstanding evidence ([release readiness checkpoint](../product_plan.md#release-readiness-checkpoint)). Treat the device manager notes below as general guidance. Run a canary first.

## Before you start

You need:

| Item | Detail |
| --- | --- |
| Chrome | Version 120 or later. This is `minimum_chrome_version` in the [extension manifest](../apps/browser-extension/manifest.json). Automatic enrollment needs a Chrome release that can restrict managed storage to trusted extension contexts. Use a current stable release. If it is missing, the popup asks for a pasted grant. |
| Management | A way to push Chrome policy: Google Admin console, Microsoft Intune, Jamf, Group Policy, or the Linux managed-policy directory. Chrome only force-installs a self-hosted extension on a managed browser. Windows needs a domain or Chrome Enterprise Core. macOS needs MDM, domain management, or Chrome Enterprise Core. |
| Extension ID | The pinned ID of the signed Zekvar Browser release. Zekvar gives it to you. It stays the same across versions. |
| Update URL | The HTTPS address of `updates.xml` for your release channel. Managed Chrome must reach it without cookies or interactive sign-in. |
| Control origin | The exact HTTPS origin of the browser API, for example `https://browser.example.com`. The extension is built for this one origin. |
| Control access | An owner or administrator credential for Control. |
| Network | Managed devices must reach the Control origin and the update origin over HTTPS. The hosted build declares only the Control origin as a host permission. |

Zekvar provides, per release: `chrome-policy.json`, `release.json` (extension ID, version, channel, URLs, SHA-256 of the package), and the hosted `public/` directory with the versioned CRX and `updates.xml`. [TO CONFIRM: whether Zekvar or the customer hosts the update channel and Control.]

## What the extension does on a device

Knowing this helps you scope a canary. Details are in the [security and privacy answers](security-and-privacy.md).

- It runs in each managed Chrome profile.
- It requests `storage`, `alarms`, `declarativeNetRequest`, and `offscreen`. It has two optional permissions, `management` and `webNavigation`, that an employee grants from the popup only if you turn on the matching Control setting.
- It injects content scripts on `chatgpt.com`, `gemini.google.com`, and `claude.ai`.
- It talks only to your Control browser API origin.

## Deploy with Chrome enterprise policy

### The policy

The packager writes `chrome-policy.json` with two parts. Merge both into the policy for your pilot device group.

```json
{
  "ExtensionSettings": {
    "<extension-id>": {
      "installation_mode": "force_installed",
      "update_url": "https://updates.example.com/pilot/updates.xml",
      "override_update_url": true
    }
  },
  "3rdparty": {
    "extensions": {
      "<extension-id>": { "ControlOrigin": "https://browser.example.com" }
    }
  }
}
```

- `ExtensionSettings` force-installs the pinned ID from your update URL and keeps later updates on that channel.
- `3rdparty.extensions.<id>.ControlOrigin` is managed storage for the extension. It must equal the origin built into the package. The schema is [`managed-schema.json`](../apps/browser-extension/managed-schema.json).
- The same force-install can be written with the older `ExtensionInstallForcelist` policy (`<id>;<update_url>`). The packager emits `ExtensionSettings`. Use that unless your management tool requires the list form.

If your device group already has `ExtensionSettings`, merge instead of replacing. Keep the Zekvar entry. Control's **Chrome extension deployment** page can merge additional extension rules against your current JSON and give you a rollback file. See [Deploy Chrome extension rules](../apps/control-web/README.md#deploy-chrome-extension-rules). For Safe Browsing, download, and profile settings see [Deploy a Chrome hardening plan](../apps/control-web/README.md#deploy-a-chrome-hardening-plan).

### Device manager notes

These are starting points. Check your vendor's current documentation.

- **Google Admin console.** Under Chrome browser or user settings for the target organizational unit, add the extension by ID with the custom update URL, set it to force install, and paste the extension policy JSON (`ControlOrigin`, and `EnrollmentGrant` for the profile). Per-user unique grants are hard to set through one OU-wide JSON. Plan the grant delivery before you start. See [Enroll browsers](#enroll-browsers).
- **Microsoft Intune.** On Windows, use a settings catalog or imported Chrome ADMX policy for Chrome extension settings, or a custom configuration. Provide the `ExtensionSettings` JSON and the managed-storage values. On macOS, deploy a configuration profile for the `com.google.Chrome` preferences domain.
- **Jamf.** Deploy a configuration profile for the `com.google.Chrome` preferences domain that carries `ExtensionSettings` and the extension's managed-storage values. Jamf's custom settings payload accepts a preference domain and a plist.
- **Linux.** Put the JSON in the managed-policy directory for Chrome or Chromium.

[TO CONFIRM: tested procedures for each device manager. None has been exercised by Zekvar.]

### Check the policy reached the device

1. Open `chrome://policy` and select **Reload policies**. Confirm the extension policy shows no errors.
2. Open `chrome://extensions`. Zekvar Browser should be installed and marked as managed by your organization. Confirm the version.
3. Open the Zekvar Browser popup from the Extensions menu. It should show the configured HTTPS destination.

## Enroll browsers

Enrollment ties each Chrome profile to your Control organization. A grant is single-use and expires after 10 minutes.

1. In Control, create the pilot's rollout group and publish its policy. Start in Monitor. See the [onboarding guide](onboarding.md).
2. Open **Enroll browsers in group**. Issue one grant per profile, up to 25 at a time. Copy the codes right away. Control shows them only once. Group grants need Browser v0.21.0 or later. See [Enroll a rollout group](../apps/control-web/README.md#enroll-a-rollout-group).
3. Deliver each grant to its profile through the device manager as the managed-storage value `EnrollmentGrant`, next to `ControlOrigin`. Deliver within 10 minutes of issue.
4. After enrollment, remove the grant value from managed settings. Enrolled browsers keep their credential across restarts.
5. If a batch was misdelivered, choose **Cancel unused grants**. Browsers that already redeemed keep access.

If automatic enrollment is not available, the popup asks for a pasted grant. Give the operator a fresh grant to enter in the popup.

Popup messages and what they mean:

| Message | Meaning |
| --- | --- |
| Enrolled by Chrome policy | Enrollment through managed storage worked. |
| Connected to Control | The browser is enrolled and reaching Control. |
| Waiting for Control to redeem the Chrome policy grant | Redemption is retrying. |
| Chrome policy grant expired or was already used | Issue a fresh grant. |
| Chrome policy contains an invalid enrollment grant | Check the value was pasted whole. |
| Chrome policy must specify this build's Control origin | `ControlOrigin` is missing or does not match the build. |
| Paste an enrollment grant to connect | Chrome cannot restrict managed storage here. Enroll by hand. |
| Control changed. Enroll with a new grant from this destination | The build points at a different Control origin. The extension clears the old enrollment, queued data, and cached enforcement. Update the origin and grant together. |

## Verify in Control

1. Open **Browser health**. Each enrolled profile should appear. **Reporting** means Control heard from it in the last 90 seconds. **Stale** means it did not.
2. Check **Policy status**. The applied version should match the current policy for the browser's group.
3. Open **Review browser rollout**. The reported extension version should match what you deployed. Control learns the version when the browser fetches policy. If it still shows an old version after Chrome shows the upgrade, relaunch the browser and check again.
4. Open a supported AI site in an enrolled profile and check the composer status in **Browser health**. The states are Detected, Unsupported, Unobserved, Policy pending, Off, and Stale. See [Review composer readiness](../apps/control-web/README.md#review-composer-readiness-before-switching-a-group-to-block).
5. With a Monitor policy and the synthetic test marker `ZEKVAR_TEST_SECRET`, send a test prompt. A Monitor row should appear under **Events**. Do not use real data.

Coverage by app and action is in the [coverage matrix](coverage.md). Live signed-in app coverage is not yet verified. Test your own workflows before moving a group past Monitor.

## Upgrade

Chrome installs an update only when its version is higher than the installed one.

1. The operator packages the new version with the same signing key, extension ID, channel, and HTTPS origins, then publishes the CRX before `updates.xml`.
2. Upgrade a test device first. Reload any AI tabs that were open. Confirm the active policy before testing submissions.
3. Check **Review browser rollout** in Control for the new version on the canary. Then let the wider channel update.
4. If the signing key is lost or compromised, remove the extension, switch keys, and enroll devices again under a new extension ID.

Some policy settings need a newer browser. Control keeps a setting unacknowledged until a capable build applies it. Compare the rollout summary with your device manager before widening.

## Roll back

Roll back when a release causes a regression.

1. Ask the operator for a rollback package. They rebuild the known-good source with a version above the highest one served to the group, for example `0.37.1.1` to restore `0.37.0` code. Signing key, extension ID, channel, and origins stay the same. Details: [Roll back a signed Browser release](../deploy/pilot/README.md#roll-back-a-signed-browser-release).
2. Test the rollback build on a canary. Confirm the same installation and policy in Control, and that queued decisions arrive after reconnection.
3. Publish it to the affected group.
4. If the older code lacks a protection your group needs, the operator keeps that app out of reach during rollback. For Claude attachments, publish an AI site access block for `claude.ai` and close open Claude tabs first. See [Block access to AI sites](../apps/control-web/README.md#block-access-to-ai-sites).
5. Record how long it took to restore protection.

From v0.37.0 the extension keeps its enrollment, policy, and queued events in a private browser database. When you roll back from v0.37.0 or later, the rollback build must keep support for that database. Otherwise enrolled browsers lose their credentials, cached policy, and queued events. The operator checks this when packaging.

To roll back a policy rather than the extension, restore an earlier policy version in Control. Restoring publishes the old settings as a new version.

## Remove

### Remove the extension from devices

1. In the device group's policy, set `installation_mode` to `removed` for the pinned extension ID. Remove its managed configuration, including any `EnrollmentGrant` and `ControlOrigin` values.
2. Reload policy on a canary. Confirm in `chrome://extensions` that Zekvar Browser is gone.
3. Apply to the rest of the group.
4. Revoke each installation in Control (see below).

### Revoke in Control

1. Open **Browser health** and revoke the installation, or use **Browser fleet** to revoke up to 25 at a time. Revoked browsers need a fresh grant to reconnect. See [Manage browser fleet batches](../apps/control-web/README.md#manage-browser-fleet-batches).
2. Revocation deletes that browser's extension inventory snapshots, change reports, and composer observations. Revoke after the device removal, or at the same time. A browser that is offline learns of revocation when it next reaches Control.
3. Delete any unused grants with **Cancel unused grants**.

The Control web guide notes that navigation rules are removed on a revoked browser once it receives confirmation from Control. Removing the extension removes its rules in any case.

### What remains after removal

| Where | What remains | How to delete |
| --- | --- | --- |
| Device | The extension, its private database (enrollment credential, cached policy, up to 100 queued events), and its Chrome rules are part of the extension's profile data. Chrome removes extension data when it uninstalls the extension. [TO CONFIRM: verify on a canary profile after removal.] | Removal by policy. |
| Control: installations | The revoked installation record. | [TO CONFIRM: no self-service deletion of installation records was found in the Control API.] |
| Control: security events | Decision metadata (see the [data inventory](security-and-privacy.md#what-control-stores)). | Shorten the retention window and run cleanup. See below. |
| Control: AI observations | App ID, time, policy and assignment versions. | Same as events. |
| Control: audit log | Policy, enrollment, access, and retention changes. | Same as events, using the audit window. |
| Control: policy history | Versioned policies for the baseline and groups. | [TO CONFIRM: no self-service deletion of policy history was found.] |
| Backups | Encrypted database snapshots kept by the operator. | Follow the operator's storage lifecycle. Deleting a record in Control does not alter existing snapshots. |
| Your SIEM or webhook receiver | Copies you collected. | You manage retention there. |

### Delete retained Control data

Retention covers security events, AI observations, and audit history. See [Set data retention](../apps/control-web/README.md#set-data-retention).

1. As an administrator, open **Data retention**. Windows are whole numbers from 1 to 3,650 days. A blank field means no expiry. A new organization starts with no expiry.
2. Set the window to 1 day. Confirm. Expired records disappear from views and exports immediately.
3. Select **Run cleanup**. It deletes up to 1,000 expired records per dataset per run. Repeat until counts reach zero. Control also sweeps at startup and hourly by default.
4. Check the **Audit log** for the cleanup counts.

Shortened windows delete permanently. Widening a window later does not revive deleted or expired records.

[TO CONFIRM: customer offboarding process, including deletion of the whole organization, the timeline for deleting backups, and written confirmation of deletion.]
