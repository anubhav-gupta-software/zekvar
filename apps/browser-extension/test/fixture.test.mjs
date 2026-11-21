import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { fixtureUrl, startFixture } from '../fixture/server.mjs';

const marker = 'ZEKVAR_TEST_SECRET';
const prefix = 'Zekvar decision ';
const extension = fileURLToPath(new URL('../dist', import.meta.url));
let server;
let browser;

before(async () => {
  server = await startFixture();
  browser = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
});

after(async () => {
  try {
    await browser?.close();
  } finally {
    await new Promise((resolve) => server ? server.close(resolve) : resolve());
  }
});

async function openFixture(t) {
  const page = await browser.newPage();
  t.after(() => page.close());
  const logs = [];
  const requests = [];
  page.on('console', (message) => logs.push(message.text()));
  page.on('request', (request) => requests.push([request.method(), request.url()]));
  await page.goto(fixtureUrl);
  await page.locator('form[data-zekvar-ready="true"]').waitFor();
  return {
    page,
    prompt: page.getByLabel('Prompt', { exact: true }),
    mode: page.getByLabel('Policy mode'),
    send: page.getByRole('button', { name: 'Send prompt' }),
    edit: page.getByRole('button', { name: 'Edit prompt' }),
    proceed: page.getByRole('button', { name: 'Continue anyway' }),
    count: () => page.locator('#submission-count').textContent(),
    events: () => logs.filter((line) => line.startsWith(prefix)).map((line) => JSON.parse(line.slice(prefix.length))),
    logs,
    requests,
  };
}

test('clean submissions reach the handler once by click and by Enter', async (t) => {
  const fixture = await openFixture(t);
  await fixture.prompt.fill('Draft a meeting agenda');
  await fixture.send.click();
  assert.equal(await fixture.count(), '1');
  await fixture.prompt.press('Enter');
  assert.equal(await fixture.count(), '2');
  assert.deepEqual(fixture.events(), []);
});

test('monitor mode submits once and emits only decision metadata', async (t) => {
  const fixture = await openFixture(t);
  await fixture.mode.selectOption('monitor');
  const prompt = `Private text ${marker} should stay local`;
  await fixture.prompt.fill(prompt);
  await fixture.send.click();
  assert.equal(await fixture.count(), '1');
  const events = fixture.events();
  assert.equal(events.length, 1);
  const { eventId, timestamp, ...metadata } = events[0];
  assert.match(eventId, /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i);
  assert.equal(new Date(timestamp).toISOString(), timestamp);
  assert.deepEqual(metadata, {
    appId: 'local-prompt-fixture',
    ruleId: 'fixture-secret',
    detectorCategory: 'synthetic-secret',
    policyVersion: 'fixture-v1-monitor',
    decision: 'monitor',
  });
  assert.ok(fixture.logs.every((line) => !line.includes(marker) && !line.includes('Private text')));
  assert.deepEqual(fixture.requests, [['GET', fixtureUrl]]);
});

test('warn and edit holds the submission until a clean retry', async (t) => {
  const fixture = await openFixture(t);
  await fixture.mode.selectOption('warn');
  await fixture.prompt.fill(marker);
  await fixture.send.click();
  assert.equal(await fixture.count(), '0');
  await fixture.edit.click();
  assert.equal(await fixture.count(), '0');
  await fixture.prompt.fill('Clean retry');
  await fixture.send.click();
  assert.equal(await fixture.count(), '1');
  assert.deepEqual(fixture.events().map((event) => event.decision), ['warn']);
});

test('warning override is single-use and duplicate submits while waiting log once', async (t) => {
  const fixture = await openFixture(t);
  await fixture.mode.selectOption('warn');
  await fixture.prompt.fill(marker);
  await fixture.send.dblclick();
  assert.equal(await fixture.count(), '0');
  assert.deepEqual(fixture.events().map((event) => event.decision), ['warn']);
  await fixture.proceed.dblclick();
  assert.equal(await fixture.count(), '1');
  assert.deepEqual(fixture.events().map((event) => event.decision), ['warn', 'warn_override']);
  await fixture.send.click();
  assert.equal(await fixture.count(), '1');
  const events = fixture.events();
  assert.deepEqual(events.map((event) => event.decision), ['warn', 'warn_override', 'warn']);
  assert.equal(new Set(events.map((event) => event.eventId)).size, events.length);
  assert.ok(fixture.logs.every((line) => !line.includes(marker)));
});

test('changing a warned prompt or policy invalidates the pending override', async (t) => {
  const fixture = await openFixture(t);
  await fixture.mode.selectOption('warn');
  await fixture.prompt.fill(marker);
  await fixture.send.click();
  await fixture.prompt.fill(`New value ${marker}`);
  assert.equal(await fixture.proceed.isVisible(), false);
  await fixture.send.click();
  await fixture.mode.selectOption('block');
  assert.equal(await fixture.proceed.isVisible(), false);
  await fixture.send.click();
  assert.equal(await fixture.count(), '0');
  assert.deepEqual(fixture.events().map((event) => event.decision), ['warn', 'warn', 'block']);
});

test('block mode holds keyboard submissions and permits a clean retry', async (t) => {
  const fixture = await openFixture(t);
  await fixture.prompt.fill(marker);
  await fixture.prompt.press('Enter');
  assert.equal(await fixture.count(), '0');
  assert.match(await fixture.page.locator('#policy-feedback [role="status"]').textContent(), /Submission blocked/);
  assert.equal(await fixture.proceed.isVisible(), false);
  await fixture.prompt.fill('Clean retry');
  await fixture.send.click();
  assert.equal(await fixture.count(), '1');
  assert.deepEqual(fixture.events().map((event) => event.decision), ['block']);
  assert.ok(fixture.logs.every((line) => !line.includes(marker)));
});

test('the same form on another path is outside extension coverage', async (t) => {
  const page = await browser.newPage();
  t.after(() => page.close());
  await page.goto(new URL('/unprotected/', fixtureUrl).href);
  assert.equal(await page.locator('form[data-zekvar-ready]').count(), 0);
  await page.getByLabel('Prompt', { exact: true }).fill(marker);
  await page.getByRole('button', { name: 'Send prompt' }).click();
  assert.equal(await page.locator('#submission-count').textContent(), '1');
});
