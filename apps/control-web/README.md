# Zekvar Control dashboard

Control is a local dashboard for publishing browser policies, issuing enrollment grants, reviewing policy versions and browser health, and filtering security events. It reads and changes real data through the [Control API](../control-api/README.md).

## Run the dashboard

1. Start PostgreSQL and the Control API using the [API instructions](../control-api/README.md#start-the-api). Keep the generated admin token available to paste into the sign-in form.
2. From the repository root, install dependencies and start the dashboard with Node.js 22 or newer.

   ```sh
   npm --prefix apps/control-web ci
   npm --prefix apps/control-web run dev
   ```

3. Open [Control on localhost](http://localhost:3000) and sign in with the API's `Control__Organizations__0__AdminToken` value.
4. Choose **Monitor**, **Warn**, or **Block** under **Publish a policy**. To revert, choose **Restore** next to an earlier version. Control publishes the restored configuration as a new version.
5. Create an enrollment grant. The [manual API workflow](../control-api/README.md#exercise-the-workflow) can redeem it, report an applied policy version, and post a synthetic decision. Refresh the dashboard to see the installation and event. Extension enrollment and automatic reporting are the next roadmap task.

The demo applies one policy per organization. The dashboard keeps admin tokens in server memory and gives the browser a short-lived HTTP-only session cookie. Restarting the dashboard clears those sessions. Keep both services on loopback and use synthetic demo data.

## Verify in Chrome

With both services running against a disposable organization, run the production build or type check separately as needed. The browser test publishes and restores policy versions, enrolls and revokes a test installation, and posts one synthetic event.

```sh
cd apps/control-web
npx playwright install chromium --no-shell
ZEKVAR_TEST_ADMIN_TOKEN="$Control__Organizations__0__AdminToken" npm run test:browser
```
