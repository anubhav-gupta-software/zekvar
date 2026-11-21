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
4. Publish a **Block** policy in Control. Open the [prompt fixture](http://127.0.0.1:4173/zekvar-fixture/) and click **Sync policy** if needed. The fixture should show the published version.
5. Send `Hello`. The fixture counter increases. Then send `ZEKVAR_TEST_SECRET`. The counter stays put and the page shows **Submission blocked**. Refresh Control and look for a **Block** row under **Security events** and the applied version under **Browser health**.

When Control is temporarily unreachable, the extension keeps enforcing the last saved policy. It queues up to 100 metadata events and retries during periodic or manual sync. If the queue fills, it discards the oldest item and reports the count in the popup. On revocation it retains the last policy for this test fixture, clears the credential and queued events, and prompts for a fresh grant. Before enrollment, the fixture's local mode selector remains available for standalone testing.

## Try the experimental ChatGPT adapter

1. Run the current [Control API and dashboard](../control-web/README.md#run-the-dashboard), reload Zekvar Browser in `chrome://extensions`, and enroll if needed. Publish **Block**, then click **Sync now** in the extension popup.
2. Open or refresh [ChatGPT](https://chatgpt.com/) in the same Chrome profile. Look for **Zekvar · BLOCK v…**. If it also says **Waiting for Send control**, type only the test marker and wait for the Send control to appear before trying to submit. If Zekvar shows **Unsupported composer**, **Unsupported ChatGPT page**, or **ChatGPT policy unavailable**, use **Copy composer diagnostics** and use the loopback fixture for the demo.
3. With the status on **Block**, try `ZEKVAR_TEST_SECRET` once using **Send** and once using **Enter**. The adapter should hold both attempts. Replace the text with `Reply with OK.` and send it. In Control, refresh **Security events** and filter **Application** to **ChatGPT**.

The experimental scope is a recognized visible text editor on the homepage, a standard `/c/…` conversation, or a signed-out `/uc/…` conversation. The adapter pairs the editor with an explicitly identified **Send** control in its form or in a nearby container. The English **Ask ChatGPT** textarea can be recognized by its placeholder or accessible label when the editor IDs are absent. The adapter handles native click and plain Enter for that pair. The experiment uses the synthetic marker only. Uploads, voice, other compose surfaces, and programmatic submissions are outside its coverage. In Control, **Detected** or **Unsupported** reflects the last observed composer signature. **Copy composer diagnostics** includes only the extension version, the route category, and structural counts and flags. The copy stays local until you share it.

Chrome for Testing `159.0.8154.6` passed the click, Enter, edit-and-retry, warning override, and coverage-loss checks against controlled composer fixtures. The guest-route case verified in-tab navigation from the homepage, direct load, and event delivery. The labeled-textarea case verified Send appearing after the first input and confirmed that an unrelated form remained outside coverage. The user confirmed v0.3.3 works on their live ChatGPT layout. Other live layouts remain unverified. [ChatGPT guest access](https://help.openai.com/en/articles/9125172-the-chatgpt-home-page)

## Verify the scenarios

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

See the [product plan](../../product_plan.md#first-build) for the acceptance matrix.
