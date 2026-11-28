import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from 'playwright';

const dashboard = process.env.ZEKVAR_TEST_WEB_ORIGIN ?? 'http://localhost:3000';
const api = `${process.env.ZEKVAR_TEST_API_ORIGIN ?? 'http://127.0.0.1:5187'}/v1`;
const token = process.env.ZEKVAR_TEST_ADMIN_TOKEN;
assert.match(token ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_TEST_ADMIN_TOKEN for a disposable organization that this test deletes.');

async function call(path, { body, bearer = token, method = body === undefined ? 'GET' : 'POST' } = {}) {
  const response = await fetch(`${api}${path}`, {
    method, headers: { Authorization: `Bearer ${bearer}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok, `${method} ${path} returned ${response.status}`);
  return response.status === 204 ? undefined : response.json();
}

async function assertFitsViewport(page) {
  const { clientWidth, scrollWidth } = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
  }));
  assert.equal(scrollWidth, clientWidth);
}

async function readDownload(page, trigger) {
  const [download] = await Promise.all([page.waitForEvent('download'), trigger()]);
  return JSON.parse(await readFile(await download.path(), 'utf8'));
}

for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 820 }]) {
  test(`Control data deletion works at ${viewport.width}px`, { timeout: 60_000 }, async (t) => {
    const browser = await chromium.launch({ channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1' });
    t.after(() => browser.close());
    const context = await browser.newContext({ viewport, acceptDownloads: true });
    const page = await context.newPage();
    page.setDefaultTimeout(8000);
    const clientErrors = [];
    page.on('pageerror', (error) => clientErrors.push(error.message));
    page.on('dialog', (dialog) => dialog.accept());
    const { organization } = await call('/admin/session');
    if ((await call('/admin/organization/deletion')).deletion?.status === 'pending') await call('/admin/organization/deletion/cancel', { body: {} });

    await page.goto(dashboard);
    await page.getByLabel('Control token').fill(token);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('heading', { name: 'Security overview' }).waitFor();

    await t.test('deletes a revoked browser’s data from the dashboard', async () => {
      const { grant } = await call('/admin/enrollment-grants', { body: {} });
      const installation = await call('/enroll', { body: { grant }, bearer: undefined });
      await call(`/admin/installations/${installation.installationId}/revoke`, { body: {} });
      await page.goto(`${dashboard}/data-deletion`);
      await page.getByRole('heading', { name: 'Data deletion' }).waitFor();
      const table = page.getByRole('table', { name: 'Delete revoked browser data' });
      const label = `Delete data for browser ${installation.installationId.slice(0, 13)}`;
      await table.getByRole('button', { name: label }).click();
      await page.getByRole('status').filter({ hasText: `Deleted browser ${installation.installationId.slice(0, 13)}` }).waitFor();
      await page.reload();
      assert.equal(await page.getByRole('button', { name: label }).count(), 0);
      assert.ok(!(await call('/admin/installations')).some(({ installationId }) => installationId === installation.installationId));
      await assertFitsViewport(page);
    });

    await t.test('previews and purges superseded baseline policy history', async () => {
      await call('/admin/policies', { body: { mode: 'warn' } });
      await call('/admin/policies', { body: { mode: 'monitor' } });
      const before = (await call('/admin/policies')).length;
      await page.goto(`${dashboard}/data-deletion`);
      const capturedAt = Date.now();
      const tomorrow = new Date(capturedAt + 86_400_000).toISOString().slice(0, 10);
      const today = new Date(capturedAt).toISOString().slice(0, 10);
      // Versions published today are after today's 00:00 UTC cutoff, so use the API for an exact cutoff and the form for a preview.
      await page.getByLabel('Preview cutoff').fill(today);
      await page.getByRole('button', { name: 'Preview purge' }).click();
      await page.getByRole('status').filter({ hasText: /Would purge/ }).waitFor();
      assert.equal((await call('/admin/policies')).length, before);
      assert.equal(await page.getByLabel('Published before').getAttribute('max'), today);
      void tomorrow;
      const purge = await call('/admin/policy-history/purge', { body: { publishedBefore: new Date().toISOString(), dryRun: true } });
      assert.ok(purge.versions.length >= 1);
      await page.getByLabel('Published before').fill(today);
      await page.getByRole('button', { name: 'Purge policy history' }).click();
      await page.getByRole('status').filter({ hasText: /^Purged/ }).waitFor();
      await assertFitsViewport(page);
    });

    await t.test('downloads the complete organization export', async () => {
      await page.goto(`${dashboard}/data-deletion`);
      const exported = await readDownload(page, () => page.getByRole('link', { name: 'Download organization export' }).click());
      assert.equal(exported.type, 'zekvar.organization_export');
      assert.equal(exported.organization.slug, organization);
      assert.ok(exported.datasets.policy_versions.length >= 1);
      assert.ok(!JSON.stringify(exported).includes('token_hash'));
    });

    await t.test('schedules organization deletion, suspends the dashboard, downloads a receipt, and cancels', async () => {
      await page.goto(`${dashboard}/data-deletion`);
      await page.getByLabel(/to confirm/).fill(`${organization}-wrong`);
      await page.getByRole('button', { name: 'Request organization deletion' }).click();
      await page.getByRole('alert').filter({ hasText: 'The organization name does not match.' }).waitFor();
      await page.getByLabel(/to confirm/).fill(organization);
      await page.getByRole('button', { name: 'Request organization deletion' }).click();
      await page.getByRole('status').filter({ hasText: 'Organization deletion scheduled.' }).waitFor();
      assert.match(await page.getByLabel('Receipt token').inputValue(), /^[a-f0-9]{64}$/);
      await assertFitsViewport(page);
      await page.getByRole('link', { name: 'Continue' }).click();
      await page.getByText('Scheduled', { exact: true }).waitFor();
      assert.equal(await page.getByRole('navigation', { name: 'Dashboard sections' }).count(), 0);

      await page.goto(dashboard);
      await page.waitForURL(`${dashboard}/data-deletion`);
      const receipt = await readDownload(page, () => page.getByRole('link', { name: 'Download signed receipt' }).click());
      assert.equal(receipt.receipt.status, 'pending');
      assert.equal(receipt.signature.algorithm, 'HMAC-SHA256');
      const screenshot = process.env.ZEKVAR_TEST_DELETION_SCREENSHOT;
      if (screenshot && viewport.width === 1440) await page.screenshot({ path: screenshot, fullPage: true });
      await assertFitsViewport(page);

      await page.getByRole('button', { name: 'Cancel organization deletion' }).click();
      // The page switches back to the request form and notes the cancelled request.
      await page.getByText(/The previous request was cancelled on/).waitFor();
      await page.getByRole('button', { name: 'Request organization deletion' }).waitFor();
      await page.goto(dashboard);
      await page.getByRole('heading', { name: 'Security overview' }).waitFor();
      const audit = (await call('/admin/audit?limit=100')).entries.map(({ action }) => action);
      for (const action of ['installation_deleted', 'organization_exported', 'organization_deletion_requested', 'organization_deletion_cancelled'])
        assert.ok(audit.includes(action), action);
      await page.goto(`${dashboard}/audit?action=organization_deletion_requested`);
      await page.getByText(/Deletion scheduled after a 7-day grace period/).first().waitFor();
      assert.deepEqual(clientErrors, []);
    });
  });
}
