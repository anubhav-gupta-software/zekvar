# Zekvar Browser local proof

This Manifest V3 extension evaluates an inert test marker on a single loopback fixture. The fixture simulates prompt submission by incrementing a counter. The extension logs decision metadata to the browser console. The build covers `http://127.0.0.1:4173/zekvar-fixture/`.

## Run the demo

From `apps/browser-extension`, using Node.js 22 or newer:

```sh
npm ci
npm run build
npm run fixture
```

1. In a test Chrome profile, open `chrome://extensions`, enable Developer mode, and load `apps/browser-extension/dist` with **Load unpacked**.
2. Open `http://127.0.0.1:4173/zekvar-fixture/`. Use a clean prompt and then `ZEKVAR_TEST_SECRET` in each policy mode. Check the submission counter and look for `Zekvar decision` in DevTools Console.
3. Reload the unpacked extension and refresh the fixture after rebuilding.

## Verify the scenarios

```sh
npx playwright install chromium --no-shell
npm test
```

The suite loads the compiled extension into Playwright's bundled browser and serves the fixture within its temporary browser profile. It can run while the manual demo is open. It checks click and keyboard submission, warning edit and override, retry, event fields and privacy, and extension scope.

See the [product plan](../../product_plan.md#first-build) for the acceptance matrix.
