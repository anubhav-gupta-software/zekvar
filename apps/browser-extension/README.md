# Zekvar Browser and Control demo

Zekvar Browser enforces domain rules, evaluates prompts locally, and controls native file intake on supported ChatGPT and Gemini routes. It also supports the loopback prompt fixture and opt-in experimental Claude text protection. Managed browsers send decision metadata to Control and can report visits to cataloged apps when discovery is enabled.

For the [TLS pilot](../../deploy/pilot/README.md#build-and-enroll-browser), build v0.18.0 or later with a fixed HTTPS browser API origin. Managed enrollment includes that origin and its short-lived grant. A change of origin clears the previous enrollment, queued data, and cached enforcement before enrollment at the new destination.

## Run the demo

From `apps/browser-extension`, using Node.js 22 or newer:

```sh
npm ci
npm run build
npm run fixture
```

1. In a test Chrome profile, open `chrome://extensions` and enable **Developer mode**. Use **Load unpacked** and select `apps/browser-extension/dist`. If the extension is already loaded, click its reload button.
2. In [Control](http://localhost:3000), open **Browser enrollment** and choose **Create enrollment grant**. Copy the grant.
3. In Chrome’s **Extensions** menu, open **Zekvar Browser**. Paste the grant and click **Enroll this browser**. The popup should show **Connected to Control** with the active policy mode and version.
4. Set **Test marker** to **Block** and publish the policy in Control. Open the [prompt fixture](http://127.0.0.1:4173/zekvar-fixture/) and click **Sync policy** if needed. The fixture should show the published version.
5. Send `Hello`. The fixture counter increases. Then send `ZEKVAR_TEST_SECRET`. The counter stays put and the page shows **Submission blocked**. Refresh Control and look for a **Block** row under **Security events** and the applied version under **Browser health**.

When Control is temporarily unreachable, the extension keeps enforcing the last saved policy. It queues up to 100 metadata events and retries during periodic or manual sync. If the queue fills, it discards the oldest item and reports the count in the popup. On revocation it retains the last policy for this test fixture, clears the credential and queued events, and prompts for a fresh grant. Before enrollment, the fixture's local mode selector remains available for standalone testing.

## Try the experimental ChatGPT adapter

1. Run the current [Control API and dashboard](../control-web/README.md#run-the-dashboard), reload Zekvar Browser in `chrome://extensions`, and enroll if needed. Set **Test marker** to **Block**, publish, then click **Sync now** in the extension popup.
2. Open or refresh [ChatGPT](https://chatgpt.com/) in the same Chrome profile. Look for **Zekvar · BLOCK v…**. If it also says **Waiting for Send control**, type only the test marker and wait for the Send control to appear before trying to submit. If Zekvar shows **Unsupported composer**, **Unsupported ChatGPT page**, or **ChatGPT policy unavailable**, use **Copy composer diagnostics** and use the loopback fixture for the demo.
3. With the status on **Block**, try `Reply with OK. Example: ZEKVAR_TEST_SECRET` once using **Send** and once using **Enter**. The adapter should hold both attempts. Choose **Redact detected values**, check that the draft now contains `[REDACTED]`, and send it when ready. In Control, refresh **Security events** and filter **Application** to **ChatGPT**.

The experimental scope is a recognized visible text editor on the homepage, a standard `/c/…` conversation, or a signed-out `/uc/…` conversation. The adapter pairs the editor with an explicitly identified **Send** control in its form or in a nearby container. The English **Ask ChatGPT** textarea can be recognized by its placeholder or accessible label when the editor IDs are absent. The adapter handles native click and plain Enter for that pair. Uploads, voice, other compose surfaces, and programmatic submissions are outside its coverage. In Control, **Detected** or **Unsupported** reflects the last observed composer signature. **Copy composer diagnostics** includes only the extension version, the route category, and structural counts and flags. The copy stays local until you share it.

Chrome for Testing `159.0.8154.6` passed the click, Enter, edit-and-retry, warning override, and coverage-loss checks against controlled composer fixtures. The guest-route case verified in-tab navigation from the homepage, direct load, and event delivery. The labeled-textarea case verified Send appearing after the first input and confirmed that an unrelated form remained outside coverage. A separate headed Chrome run verified Send and Enter blocks and a clean retry on the live signed-out ChatGPT homepage. The user also confirmed v0.3.3 works on their live layout. Other live layouts remain unverified. [ChatGPT guest access](https://help.openai.com/en/articles/9125172-the-chatgpt-home-page)

### Review a redacted draft

Browser v0.9.0 introduced **Redact detected values** after a warning or block in a supported ChatGPT text composer. The current Browser build replaces matches from enabled detectors with `[REDACTED]` in supported ChatGPT and Gemini composers. You can review the draft, undo the edit, or change the text before choosing **Send**.

The action is available for supported textareas and plain-text contenteditable layouts. Use **Edit prompt** if the draft includes rich content that needs to be preserved. Control records the original warning or block as decision metadata. The original and redacted drafts stay out of Control.

The verification runner exercises redaction in the controlled marked editor and guest textarea. With `--live`, it shows the redacted draft in the public signed-out composer, then sends that draft in a separate step.

## Try the Gemini text adapter

1. Start the updated Control API and dashboard. Build and reload Browser v0.10.0, then click **Sync now**. Gemini uses the same detector policy as ChatGPT for that browser's baseline or rollout group.
2. Open [Gemini](https://gemini.google.com/app) in the enrolled profile. In a supported English composer, type `Reply with OK. Example: ZEKVAR_TEST_SECRET`. With **Test marker** in **Block**, try **Send** or **Enter**. Choose **Redact detected values**, review the edited draft, and submit it when ready.
3. In Control, use **Gemini composer** under **Browser health** to see the last pairing check. Filter **Security events** to **Gemini** to review or export decision metadata.

The adapter matches a single visible text editor and Send control in the same Gemini composer. An empty draft may show **Waiting for Send control**. The supported paths are native click and plain Enter with the recognized English editor. Signed-in Workspace layouts, files, voice, and other compose surfaces require separate verification. [Gemini web app access](https://support.google.com/gemini/answer/13275745?hl=en)

## Try experimental Claude prompt protection

1. In Control, assign a browser to a test rollout group. Set **Claude prompt protection** to **On · experimental** for that group and start with the Test marker in **Monitor** mode. Sync Browser v0.19.0 or later.
2. On an authorized Claude account, try `ZEKVAR_TEST_SECRET` in a fresh chat and an existing chat. Check **Claude composer** in Browser health and filter Security events to Claude. Use **Copy composer diagnostics** if the banner reports an unsupported layout. The diagnostics include structure and route type.
3. After confirming the layout and Monitor events, use the same synthetic marker to check **Warn** and **Block**, including click, Enter, and the separate Send after reviewing a redaction.

The pilot recognizes a visible ProseMirror editor paired with one visible Send control in a marked composer on `/new` or `/chat/<conversation-id>`. The automated suite covers two controlled composer layouts, typed and pasted text on Send, warnings, redaction, and temporary exceptions. Signed-in Claude is pending live verification. Claude file attachments, voice, and other app surfaces have separate coverage requirements. [Claude web chat and sign-in](https://support.claude.com/en/articles/8114491-get-started-with-claude)

## Try the GitHub classic PAT rule

Set **GitHub classic PAT** under **Publish a policy** in Control, publish, and use **Sync now** in the Zekvar Browser popup. The rule starts **Off** and has its own setting. In **Monitor**, it records a matching attempt and allows Send. **Warn** asks the user to edit or continue. **Block** holds the attempt until the prompt is edited. When both rules match, Zekvar applies the stricter action and reports the rule that determined it. A tie is attributed to the GitHub rule.

Use `ghp_000000000000000000000000000000000000` in the local prompt fixture to test each setting. Refresh **Security events** in Control and look for **GitHub classic PAT** under **Detector**. The extension matches the classic token format locally. Control receives the decision and its metadata. Automated credential checks use a controlled composer and a synthetic token-shaped string. [Open the local fixture](http://127.0.0.1:4173/zekvar-fixture/)

## Test payment card detection

1. Start the updated Control services and build and reload Browser v0.11.0. In Control, set **Payment card number** to **Monitor**, **Warn**, or **Block** in the baseline or a rollout group. The detector starts **Off**. Use **Policy preview** to compare the built-in valid and invalid examples before publishing.
2. Click **Sync now**, then open or refresh your test composer. In the local fixture or a supported ChatGPT or Gemini text composer, use the sandbox number `4242-4242-4242-4242`. On supported ChatGPT and Gemini editors, choose **Redact detected values** after a warning or block and review the draft before sending it. [Stripe sandbox cards](https://docs.stripe.com/testing)
3. Open **Security events** in Control and look for **Payment card number**. Control receives the decision and rule metadata. Inspection and redaction take place in the browser.

The detector combines supported issuer ranges and lengths with the Luhn checksum. It covers standalone ASCII card numbers and common groupings with consistent spaces or hyphens. Supported formats include Visa, Mastercard, American Express, Discover, JCB, and Diners Club. The browser applies the strictest matching mode. On a tie, payment card takes precedence over GitHub PAT, followed by the test marker. [PCI SSC checksum guidance](https://www.pcisecuritystandards.org/faqs/1137/) · [Cybersource card formats](https://developer.cybersource.com/docs/cybs/en-us/test-data/developer/all/so/test-data/best_practices_intro/card_type_id.html)

Use **Monitor** to measure false positives before enforcing the rule. Browser health shows a payment policy as current after an updated browser acknowledges the detector. Coverage of card numbers in files, unsupported separators and issuer formats, CVVs, and expiry dates remains open.

## Test file upload policies

1. Start the updated Control services and load Browser v0.15.0. In the baseline or a rollout group, choose **Off**, **Monitor**, or **Block** separately for **ChatGPT file uploads** and **Gemini file uploads**. Leave **File types** blank to apply the selected action to all files. Enter suffixes such as `.pdf` or `.tar.gz`, media types such as `application/pdf`, or media groups such as `image/*` to scope the action. **Policy preview** also accepts synthetic names and media types.
2. Publish and click **Sync now**. Open or refresh a supported chat page. Zekvar shows **File uploads block (selected types)** for a scoped Block policy. Try a matching synthetic file and a nonmatching file. A matching file in a multi-file selection blocks the entire attempt. Text-only paste remains available.
3. Under **Security events**, look for **File upload** with **File picker**, **Drag and drop**, or **Clipboard file**. Control receives the app, decision, method, and usual policy metadata. Names, paths, individual file types, sizes, and contents stay out of telemetry.

The upload policy covers the supported top-level ChatGPT home and conversation routes and the Gemini `/app` chat routes. Scoped rules compare the filename and the media type Chrome provides. Chrome can supply an empty media type. File content inspection and enforcement against renamed or mislabeled data require separate controls. The browser suite tests all three native methods on controlled pages. The live signed-out check covers blocked drops. Signed-in attachment menus, cloud pickers, and programmatic uploads require separate coverage. [File API](https://w3c.github.io/FileAPI/#file-section)

Update enrolled Chrome profiles to v0.15.0 before publishing scoped file types. Older builds skip the scoped portion and Control leaves the policy version unacknowledged. Other enabled controls and any unscoped upload mode continue to apply.

## Test temporary prompt exceptions

1. Start the updated Control services and load Browser v0.17.0. In **Policy preview**, choose the baseline or a rollout group. Set the detector to **Warn** or **Block** and choose **Add prompt exception**. Select the AI app and detector, enter a reason, and set an expiry (UTC) within 24 hours.
2. Pick a **Prompt sample destination** and run the preview. Check the relevant detection and a mixed sample. Publish or request independent approval. Click **Sync now** on the assigned browser.
3. Try the test marker on the controlled guest ChatGPT, Gemini, or enabled Claude pilot composer. The exception applies to its selected app and detector. A different matching Warn or Block rule still applies. Control reports **Exception applied** on the Security events page when the exception allows a send.

Chrome uses the server deadline and a grant that can be used for up to 45 seconds after a policy fetch. It resumes standard enforcement after expiry, clock discontinuity, confirmed disconnection, or a browser restart before the next successful sync. Removing an exception takes effect at the next sync or when the local grant expires. Rollback and promotion preserve the target scope's exception list. A rollout group that inherits the baseline uses its regular rules and has its own exception list. [Chrome extension alarms](https://developer.chrome.com/docs/extensions/reference/api/alarms) · [High Resolution Time](https://www.w3.org/TR/hr-time-3/)

## App discovery

1. Load Browser v0.16.0, start Control, and enroll the test browser. Set **App discovery** to **On** under **Publish a policy**. Publish, then click **Sync now** in the Zekvar popup.
2. Open `chatgpt.com`, `claude.ai`, or `gemini.google.com` in a top-level tab. Go to **App inventory** in Control and choose **Refresh app inventory**. The app row shows distinct browsers seen in the past 30 days and the latest observation time.
3. Use the row’s classification selector and **Save** to mark the app **Approved**, **Unapproved**, or **Unreviewed**. Classification helps admins review usage. Enforcement uses the separate prompt and navigation policy settings.

To discover a custom SaaS or AI app, open **App inventory → Edit app catalog** or **Preview group policy** for a rollout group. Enter one exact hostname and display name per line in **Custom app catalog**, such as `workspace.example.test, Example Workspace`. Turn on app discovery and publish or request review. Click **Sync now** and then **Allow custom app discovery** in the extension, and accept the Chrome permission prompt. Open the configured HTTPS site in a top-level tab and refresh Control. When permission is missing, Control leaves a policy with an active custom catalog pending. Chrome can remove the permission from the Zekvar popup.

Custom discovery uses Chrome's navigation permission and checks only top-level committed HTTPS pages on exact configured domains using the default port. Reports contain the app ID, observation time, policy version and assignment. The extension queues the latest unsent observation per app. URLs, query strings, page contents and account details stay out of observation reports. Remove a site to stop collection while preserving the inventory retention window. [Chrome navigation API](https://developer.chrome.com/docs/extensions/reference/api/webNavigation#event-onCommitted) · [Chrome optional permissions](https://developer.chrome.com/docs/extensions/reference/api/permissions)

## Domain rules

1. Load Browser v0.13.0 or later, start Control, and enroll the Chrome profile you want to test. Open **Navigation rules** on the overview or in a rollout group.
2. Enter a hostname such as `example.com` in **Blocked domains** and enter `example.com/work` in **Allowed paths** to keep that section accessible. Choose **Publish navigation rules**, then **Sync now** in the extension popup. The popup shows the active counts.
3. Open the site root and the allowed path in new tabs. Chrome should block the root and allow `/work` and its matching descendants. Restore a previous version in **Policy history**, or clear the four lists and publish to remove the rules.

Enter one rule per line. Control accepts up to 50 rules across the four lists, normalizes hostname case and a trailing dot, and accepts internationalized hostnames in Punycode. A hostname or hostname/path can belong to one action list. Rules include subdomains. The most specific hostname wins first, then the longest matching path. Unmatched URLs remain accessible.

Enter paths as `hostname/path` with up to 64 characters after the hostname, including the leading slash. Use letters, digits, periods, hyphens, underscores, tildes, and slash-separated segments. Rules match literal, case-sensitive path prefixes as Chrome sends them. Query strings and fragments don’t affect the decision. If a site uses URL aliases or rewrites, test the application’s URLs in a pilot. For an allow exception on a blocked domain, the path and its descendants must use the supported literal characters.

Chrome enforces the rules on top-level HTTP and HTTPS network requests and checks redirect destinations. In-page route changes and pages served directly by a site’s service worker fall outside this coverage. The extension applies the rules locally without sending visited URLs or navigation events to Control. [Chrome declarative network rules](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)

Chrome keeps the last applied navigation rules during connection interruptions. Control shows a version with path rules as applied after Browser v0.13.0 or later acknowledges the update. Revoking enrollment removes the rules when the browser receives confirmation from Control.

## Test rollout groups

With Browser v0.8.0, use the two-profile lab to enroll two managed Chrome profiles. Assign one to a rollout group in Control, publish its prompt or domain policy, and sync both browsers. The assigned browser uses the group policy while the other follows the baseline. Return the browser to the baseline through **Browser assignments**, or promote the verified group policy to the entire baseline. [Rollout group workflow](../control-web/README.md#roll-out-policies-to-a-pilot-group)

## Report browser extensions

1. Use Browser v0.14.0 or later. Enroll the Chrome profile and publish a policy with **Extension inventory** set to **On** for its baseline or rollout group.
2. Select **Sync now** in the popup. Select **Allow extension inventory** and confirm Chrome’s optional permission prompt when shown.
3. In Control, open **Browser extensions** and select the installation. For each extension Chrome exposes, Control shows the identifier, name, version, enabled state, installation type, broad or selected site access, and selected API permissions.
4. To stop reporting, remove the permission in the popup or turn the assigned setting Off. The permission removal takes effect in Control on the next successful sync.

Zekvar reads extension metadata and keeps literal host patterns, descriptions, and links out of its reports. It excludes its own extension from the list. Review flags identify certain permissions and install sources. Publisher verification, reputation checks, and extension allow or block enforcement are separate roadmap items. [Chrome management API](https://developer.chrome.com/docs/extensions/reference/api/management) · [Chrome optional permissions](https://developer.chrome.com/docs/extensions/reference/api/permissions)

## Verify the scenarios

The full demo uses Node.js 22+, the .NET 10 SDK, and a running Docker daemon. From `apps/browser-extension`, run:

```sh
npm run verify:demo -- --headed --live --artifacts /tmp/zekvar-demo
```

From the repository root, run:

```sh
node scripts/verify-demo.mjs --headed --live --artifacts /tmp/zekvar-demo
```

The command builds in a temporary directory and starts its own PostgreSQL, Control API, dashboard, and Chrome profile. It generates a temporary admin token, signs in, creates an enrollment grant, and redeems it in the extension. It publishes and restores policy, verifies the displayed events, and checks that an event retry after a lost acknowledgment stores a single record. It exercises all four GitHub rule settings and checks that the candidate value stays out of event transport and storage. It enables app discovery, visits the controlled catalog origins, saves app classifications, and verifies privacy and recovery. It also checks allowed and blocked navigation against a local HTTP server, including while Control is unavailable and after rollback and revocation. API, dashboard, and extension regression suites run against isolated organizations. The command tears down its services at the end. On the first run, it downloads Chrome for Testing before opening the browser.

`--headed` opens Chrome during the demo. `--artifacts` saves screenshots from the workflow. `--live` separately attempts the public ChatGPT and Gemini composers using the isolated profile and synthetic text. The runner reports a skip if a site blocks access or its supported composer is unavailable. The experimental Claude workflow uses two controlled composer fixtures and the real loopback API and database.

To run the standalone extension tests from `apps/browser-extension`:

```sh
npx playwright install chromium --no-shell
npm test
```

The suite loads the compiled extension into Playwright's bundled browser and serves the fixture within its temporary browser profile. It can run while the manual demo is open. It checks click and keyboard submission, warning edit and override, retry, event fields and privacy, and extension scope.

To run the connected tests, point them at a disposable Control organization. They publish policies, enroll and revoke test installations, and write synthetic decisions. The suite isolates the extension build and Chrome profile, simulates intermittent network responses, and serves a controlled composer at the ChatGPT origin in the test profile. Event delivery uses the real API and PostgreSQL.

```sh
ZEKVAR_EXTENSION_TEST_API=http://127.0.0.1:5187 \
ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN="$Control__Organizations__0__AdminToken" \
npm run test:control
```

## Run the two-profile Chrome pilot lab

From `apps/browser-extension`, with Docker running:

```sh
npm run verify:demo -- --pilot --headed --artifacts /tmp/zekvar-pilot
```

The runner opens two temporary Chrome for Testing profiles with the unpacked Zekvar extension. It applies one grant per profile through Chrome’s policy test UI, then checks that the profiles enroll and receive a Block policy in the background. It closes one browser, restores Monitor, waits for the stopped browser to show **Stale** in Control, and reopens it to verify the same installation catches up. Allow about 90 seconds for the stale check after the browser closes. Screenshots are saved when `--artifacts` is provided.

### Apply a grant manually in a test profile

1. Build and load the extension into a dedicated Chrome for Testing profile using the [local demo instructions](#run-the-demo). Start the local Control API and dashboard.
2. In Control, create an unused enrollment grant for this profile. Open `chrome://policy/test`, select the Zekvar extension ID in the policy row, choose **Local machine**, enter `EnrollmentGrant` as the name, and paste the grant into the value. Click **Apply policies**. Chrome supplies the value through its managed storage. [Chrome managed storage](https://developer.chrome.com/docs/extensions/reference/manifest/storage)
3. Check for **Enrolled by Chrome policy** in the Zekvar popup and a new installation under **Browser health**. Use a separate grant for the second profile. Remove the grant value from the policy after enrollment. Existing installations keep their browser credentials across restarts.
4. Publish **Block** in Control. Use **Refresh** in **Browser health** to check the applied version and reporting status. When testing recovery, restore an earlier Monitor version and check that the browser applies the newly published version. Revoke a browser in Control to stop that credential from reporting. Clear the test policy and remove the unpacked extension when the lab is over.

The lab uses unpacked installation and Chrome test policy. An external pilot needs a hosted Control service, an approved extension distribution method, and an administrator-managed pilot group. Chrome Enterprise uses the extension ID and update URL for force installation. [Chrome Enterprise installation settings](https://support.google.com/chrome/a/answer/9867568)

See the [product plan](../../product_plan.md#first-build) for the acceptance matrix.
