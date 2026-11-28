import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { chromium } from 'playwright';

const web = process.env.ZEKVAR_TEST_WEB_ORIGIN;
const api = process.env.ZEKVAR_TEST_API_ORIGIN;
const owner = process.env.ZEKVAR_TEST_ADMIN_TOKEN;
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body, expected = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET', signal: AbortSignal.timeout(5000), body: body && JSON.stringify(body),
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
  });
  assert.equal(response.status, expected, path);
  return response.json();
}

test('an owner quotes, accepts, and opens the resulting invoice; auditors read only and administrators see no billing', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-billing-ui-'));
  const context = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 1000 }, acceptDownloads: true,
  });
  t.after(async () => {
    await context.close();
    await rm(root, { recursive: true, force: true });
  });
  context.setDefaultTimeout(10_000);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));

  async function signIn(token) {
    await page.goto(web);
    await page.getByLabel('Control token').fill(token);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Security overview' }).waitFor();
  }
  async function signOut() {
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  }
  async function noHorizontalScroll(label) {
    const { clientWidth, scrollWidth } = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }));
    assert.ok(scrollWidth <= clientWidth, `${label}: ${scrollWidth} > ${clientWidth}`);
  }
  async function acceptQuote(seats) {
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: `Accept quote for ${seats} seats`, exact: true }).first().click();
    // Accepting a quote that issues an invoice opens that invoice.
    const status = page.getByRole('status').filter({ hasText: /Quote accepted\. Invoice \S+ was issued\./ });
    await status.waitFor();
    return status.textContent();
  }
  async function createQuote(seats) {
    await page.getByLabel('Committed seats', { exact: true }).fill(String(seats));
    await page.getByLabel('Customer name', { exact: true }).fill('Example Customer (synthetic)');
    await page.getByLabel('Billing email', { exact: true }).fill('billing@example.test');
    await page.getByRole('button', { name: 'Create quote', exact: true }).click();
    await page.getByRole('status').filter({ hasText: `Quote created for ${seats} seats` }).waitFor();
    await page.getByRole('button', { name: `Accept quote for ${seats} seats`, exact: true }).first().waitFor();
  }

  // Owner at desktop width: quote, accept, and open the first invoice.
  await signIn(owner);
  await page.getByRole('link', { name: 'Billing', exact: true }).click();
  await page.getByRole('heading', { name: 'Billing', level: 1 }).waitFor();
  await page.getByText('This organization has no subscription.').waitFor();
  await createQuote(3);
  const accepted = await acceptQuote(3);
  const number = /Invoice (\S+) was issued/.exec(accepted)?.[1];
  assert.ok(number, accepted);
  await page.getByRole('heading', { name: number, level: 1 }).waitFor();
  await page.getByText('Awaiting payment').first().waitFor();
  const overview = await admin('billing');
  const invoice = overview.invoices.find((entry) => entry.number === number);
  assert.equal(overview.subscription.committedSeats, 3);
  await page.goto(`${web}/billing`);
  await page.getByRole('heading', { name: 'Upcoming invoice estimate' }).waitFor();
  await noHorizontalScroll('billing at 1440');
  await page.getByRole('link', { name: `View ${number}`, exact: true }).click();
  await page.getByRole('heading', { name: number, level: 1 }).waitFor();
  await noHorizontalScroll('invoice at 1440');
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: 'Download JSON' }).click()]);
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  assert.equal(exported.invoice.number, number);
  assert.equal(exported.invoice.total, invoice.total);
  await page.getByLabel('Bank transfer reference').fill('SYNTHETIC-REF-1');
  await page.getByRole('button', { name: 'Record payment', exact: true }).click();
  // Recording the payment removes the form, so the paid state is the confirmation.
  await page.getByText('Reference SYNTHETIC-REF-1').waitFor();
  await page.goto(`${web}/billing/invoices/${invoice.id}`);
  await page.getByText('Reference SYNTHETIC-REF-1').waitFor();

  // Owner at phone width: an increase is prorated into a new invoice.
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto(`${web}/billing`);
  await page.getByRole('heading', { name: 'Quote a seat change' }).waitFor();
  await noHorizontalScroll('billing at 390');
  await createQuote(5);
  const amended = await acceptQuote(5);
  const amendment = /Invoice (\S+) was issued/.exec(amended)?.[1];
  assert.ok(amendment && amendment !== number, amended);
  await page.getByRole('heading', { name: amendment, level: 1 }).waitFor();
  await page.getByRole('table').getByText(/^Unused .* commitment of 3 seats/).waitFor();
  await noHorizontalScroll('invoice at 390');
  await page.setViewportSize({ width: 1440, height: 1000 });

  // Auditor: read only.
  const auditor = (await admin('access', { name: 'Billing auditor', role: 'auditor', hours: 1 })).token;
  const administrator = (await admin('access', { name: 'Billing administrator', role: 'administrator', hours: 1 })).token;
  await page.goto(`${web}/billing`);
  await signOut();
  await signIn(auditor);
  await page.getByRole('link', { name: 'Billing', exact: true }).click();
  await page.getByRole('heading', { name: 'Upcoming invoice estimate' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Create quote' }).count(), 0);
  assert.equal(await page.getByRole('button', { name: /^Accept quote/ }).count(), 0);
  await page.getByRole('link', { name: `View ${amendment}`, exact: true }).click();
  await page.getByRole('heading', { name: amendment, level: 1 }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Corrections and payment' }).count(), 0);

  // Administrator: no billing link, and the page refuses.
  await page.goto(web);
  await signOut();
  await signIn(administrator);
  assert.equal(await page.getByRole('link', { name: 'Billing', exact: true }).count(), 0);
  await page.goto(`${web}/billing`);
  await page.getByText('Only the organization owner and auditors can view billing.').waitFor();
  assert.deepEqual(errors, []);
});
