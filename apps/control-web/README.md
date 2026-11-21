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
4. Set **Test marker** and **GitHub classic PAT** independently under **Publish a policy**. The GitHub rule defaults to **Off** with **Monitor**, **Warn**, and **Block** available. To revert both settings, restore an earlier version. Control publishes the restored configuration as a new version.
5. Create an enrollment grant and paste it into the Zekvar Browser popup. After testing a prompt, refresh the dashboard to see the installation and its decision metadata. **Security events** names the rule responsible for each decision. [Run the browser demo](../browser-extension/README.md#run-the-demo)
6. For the [experimental ChatGPT adapter](../browser-extension/README.md#try-the-experimental-chatgpt-adapter), filter **Application** to **ChatGPT**, and check the **ChatGPT composer** column under **Browser health**. The timestamp shows when Control last received a coverage observation.

In **Browser health**, **Reporting** indicates Control heard from the installation within the last 90 seconds. **Stale** indicates the reporting window elapsed. **Policy status** shows whether the browser’s last applied version matches the current policy. Use **Refresh** to update the table. The [two-profile pilot lab](../browser-extension/README.md#run-the-two-profile-chrome-pilot-lab) demonstrates both states.

The demo applies one policy per organization. The dashboard keeps admin tokens in server memory and gives the browser a short-lived HTTP-only session cookie. Restarting the dashboard clears those sessions. Keep both services on loopback and use synthetic demo data.

## Verify in Chrome

With both services running against a disposable organization, run the production build or type check separately as needed. The browser test publishes and restores policy versions, enrolls and revokes a test installation, and posts one synthetic event.

```sh
cd apps/control-web
npx playwright install chromium --no-shell
ZEKVAR_TEST_ADMIN_TOKEN="$Control__Organizations__0__AdminToken" npm run test:browser
```
