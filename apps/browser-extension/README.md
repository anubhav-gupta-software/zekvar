# Zekvar Browser and Control demo

Zekvar Browser applies the policy published in Control to the loopback fixture and the experimental ChatGPT composer adapter. The fixture simulates a submission by incrementing a counter. Zekvar evaluates draft text locally and reports decision metadata to Control.

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
3. With the status on **Block**, try `ZEKVAR_TEST_SECRET` once using **Send** and once using **Enter**. The adapter should hold both attempts. Replace the text with `Reply with OK.` and send it. In Control, refresh **Security events** and filter **Application** to **ChatGPT**.

The experimental scope is a recognized visible text editor on the homepage, a standard `/c/…` conversation, or a signed-out `/uc/…` conversation. The adapter pairs the editor with an explicitly identified **Send** control in its form or in a nearby container. The English **Ask ChatGPT** textarea can be recognized by its placeholder or accessible label when the editor IDs are absent. The adapter handles native click and plain Enter for that pair. Uploads, voice, other compose surfaces, and programmatic submissions are outside its coverage. In Control, **Detected** or **Unsupported** reflects the last observed composer signature. **Copy composer diagnostics** includes only the extension version, the route category, and structural counts and flags. The copy stays local until you share it.

Chrome for Testing `159.0.8154.6` passed the click, Enter, edit-and-retry, warning override, and coverage-loss checks against controlled composer fixtures. The guest-route case verified in-tab navigation from the homepage, direct load, and event delivery. The labeled-textarea case verified Send appearing after the first input and confirmed that an unrelated form remained outside coverage. A separate headed Chrome run verified Send and Enter blocks and a clean retry on the live signed-out ChatGPT homepage. The user also confirmed v0.3.3 works on their live layout. Other live layouts remain unverified. [ChatGPT guest access](https://help.openai.com/en/articles/9125172-the-chatgpt-home-page)

## Try the GitHub classic PAT rule

Set **GitHub classic PAT** under **Publish a policy** in Control, publish, and use **Sync now** in the Zekvar Browser popup. The rule starts **Off** and has its own setting. In **Monitor**, it records a matching attempt and allows Send. **Warn** asks the user to edit or continue. **Block** holds the attempt until the prompt is edited. When both rules match, Zekvar applies the stricter action and reports the rule that determined it. A tie is attributed to the GitHub rule.

Use `ghp_000000000000000000000000000000000000` in the local prompt fixture to test each setting. Refresh **Security events** in Control and look for **GitHub classic PAT** under **Detector**. The extension matches the classic token format locally. Control receives the decision and its metadata. Automated credential checks use a controlled composer and a synthetic token-shaped string. [Open the local fixture](http://127.0.0.1:4173/zekvar-fixture/)

## Verify the scenarios

The full demo uses Node.js 22+, the .NET 10 SDK, and a running Docker daemon. From `apps/browser-extension`, run:

```sh
npm run verify:demo -- --headed --live --artifacts /tmp/zekvar-demo
```

From the repository root, run:

```sh
node scripts/verify-demo.mjs --headed --live --artifacts /tmp/zekvar-demo
```

The command builds in a temporary directory and starts its own PostgreSQL, Control API, dashboard, and Chrome profile. It generates a temporary admin token, signs in, creates an enrollment grant, and redeems it in the extension. It publishes and restores policy, verifies the displayed events, and checks that an event retry after a lost acknowledgment stores a single record. It exercises all four GitHub rule settings and checks that the candidate value stays out of event transport and storage. API, dashboard, and extension regression suites run against isolated organizations. The command tears down its services at the end. On the first run, it downloads Chrome for Testing before opening the browser.

`--headed` opens Chrome during the demo. `--artifacts` saves screenshots of the controlled workflow. `--live` separately attempts the public ChatGPT composer using the isolated profile and synthetic text. The runner reports a skip if the site blocks access or the supported composer is unavailable. The controlled workflow uses a local response for the ChatGPT page and the real loopback API for its events.

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
