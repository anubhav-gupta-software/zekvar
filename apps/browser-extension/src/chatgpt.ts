import { recordDecision } from './decisions';
import { evaluatePrompt, type MatchedDecision } from './policy';
import { chatGptApp, isChatGptPage, send, type Coverage, type Summary } from './protocol';
import { composerDiagnostics, inspectComposer, type Composer } from './chatgpt-composer';

type Warning = { input: HTMLElement; value: string; installationId: string; match: MatchedDecision };

function promptText(input: HTMLElement): string {
  return input instanceof HTMLTextAreaElement ? input.value : input.innerText;
}

function controls() {
  const host = document.createElement('div');
  host.id = 'zekvar-chatgpt';
  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = `
    :host { position: fixed; z-index: 2147483647; bottom: 1rem; right: 1rem;
      max-width: min(24rem, calc(100vw - 2rem)); color: #eaf6f2; font: 14px/1.45 system-ui, sans-serif; }
    section { padding: .7rem .9rem; border: 1px solid #447267; border-radius: .6rem;
      background: #101927; box-shadow: 0 1px 8px #0004; }
    p { margin: 0; }
    #status { color: #8aecc8; }
    #notice { margin-top: .4rem; }
    #notice:empty, [hidden] { display: none; }
    button { margin: .55rem .35rem 0 0; padding: .3rem .55rem; border: 1px solid #627b8b;
      border-radius: .35rem; color: #fff; background: #203045; cursor: pointer; font: inherit; }
    button:focus-visible { outline: 2px solid #59e6b5; outline-offset: 2px; }
    textarea { display: block; box-sizing: border-box; margin-top: .4rem; width: 100%; min-height: 4rem;
      background: #f4faf8; color: #101927; font: inherit; }
  `;
  const panel = document.createElement('section');
  panel.setAttribute('aria-label', 'Zekvar prompt policy');
  const status = document.createElement('p');
  status.id = 'status';
  status.setAttribute('role', 'status');
  const notice = document.createElement('p');
  notice.id = 'notice';
  notice.setAttribute('role', 'alert');
  const actions = document.createElement('div');
  const edit = document.createElement('button');
  edit.textContent = 'Edit prompt';
  const proceed = document.createElement('button');
  proceed.textContent = 'Continue anyway';
  actions.hidden = true;
  actions.append(edit, proceed);
  const copy = document.createElement('button');
  copy.textContent = 'Copy composer diagnostics';
  const diagnostics = document.createElement('textarea');
  diagnostics.readOnly = true;
  diagnostics.hidden = true;
  diagnostics.setAttribute('aria-label', 'Composer diagnostics');
  panel.append(status, notice, actions, copy, diagnostics);
  root.append(style, panel);
  return { host, status, notice, actions, edit, proceed, copy, diagnostics };
}

const ui = controls();
let control: Summary | undefined;
let refreshing = false;
let unsupportedSince = 0;
let lastCoverage: { installationId: string; coverage: Coverage; at: number } | undefined;
let warning: Warning | undefined;
let unsupportedInput: HTMLElement | undefined;

function clearWarning() {
  warning = undefined;
  ui.notice.textContent = '';
  ui.actions.hidden = true;
}

function observe() {
  if (!document.body) return;
  if (!ui.host.isConnected) document.body.append(ui.host);
  if (!isChatGptPage(location.href)) {
    clearWarning();
    ui.status.textContent = 'Zekvar · Unsupported ChatGPT page';
    lastCoverage = undefined;
    unsupportedSince = 0;
    unsupportedInput = undefined;
    return;
  }
  const inspection = inspectComposer();
  const current = inspection.composer;
  if (current?.button || (unsupportedInput && unsupportedInput !== current?.input)) unsupportedInput = undefined;
  if (warning && current?.input !== warning.input) clearWarning();
  const now = Date.now();
  const ready = Boolean(current && (current.button || inspection.hasEditorForm) && !unsupportedInput);
  if (ready) unsupportedSince = 0;
  else unsupportedSince ||= now;
  const coverage = ready ? 'ready' : now - unsupportedSince > 2500 ? 'unsupported' : undefined;

  const installationId = control?.installationId;
  const policy = control?.policy;
  const managedPolicy = installationId && control?.chatGptEnabled ? policy : undefined;
  const label = !managedPolicy ? 'Zekvar · ChatGPT policy unavailable' : coverage === 'unsupported' ?
    `Zekvar · Unsupported composer (${inspection.gap ?? 'Send control missing'})` : !coverage ? 'Zekvar · Checking composer…' :
      `Zekvar · ${managedPolicy.mode.toUpperCase()} v${managedPolicy.version}${control?.status === 'offline' ? ' · Offline policy' : ''}${current?.button ? '' : ' · Waiting for Send control'}`;
  if (ui.status.textContent !== label) ui.status.textContent = label;
  if (!managedPolicy || !installationId || !coverage) return;
  if (lastCoverage?.installationId === installationId && lastCoverage.coverage === coverage && now - lastCoverage.at < 60_000) return;
  const report = { installationId, coverage, at: now } as const;
  lastCoverage = report;
  void send({ type: 'coverage', installationId, coverage }).then((reply) => {
    if (reply.error && lastCoverage === report) lastCoverage = undefined;
  }, () => {
    if (lastCoverage === report) lastCoverage = undefined;
  });
}

async function refresh(type: 'sync' | 'status') {
  if (refreshing || !isChatGptPage(location.href)) return;
  refreshing = true;
  try {
    const reply = await send({ type });
    if (!reply.summary) return;
    if (control?.installationId !== reply.summary.installationId || control?.policy?.version !== reply.summary.policy?.version ||
        control?.policy?.mode !== reply.summary.policy?.mode || control?.chatGptEnabled !== reply.summary.chatGptEnabled) clearWarning();
    control = reply.summary;
  } catch {
    // Preserve any policy already received in this tab while storage is temporarily unavailable.
  } finally {
    refreshing = false;
    observe();
  }
}

function check(event: Event, current: Composer) {
  const policy = control?.policy;
  const installationId = control?.installationId;
  if (!policy || !installationId || !control?.chatGptEnabled) return;
  const value = promptText(current.input);
  const match = evaluatePrompt(value, policy);
  if (match.action === 'allow') {
    clearWarning();
    return;
  }
  if (match.action !== 'monitor') {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
  if (match.action === 'warn' && warning?.input === current.input && warning.value === value &&
      warning.match.policyVersion === match.policyVersion) return;

  clearWarning();
  recordDecision(chatGptApp, match, installationId);
  if (match.action === 'block') {
    ui.notice.textContent = 'Submission blocked. Remove the test secret and try again.';
    current.input.focus();
  } else if (match.action === 'warn') {
    warning = { input: current.input, value, installationId, match };
    ui.notice.textContent = 'This prompt contains a test secret.';
    ui.actions.hidden = false;
    ui.edit.focus();
  }
}

window.addEventListener('click', (event) => {
  if (!event.isTrusted || !isChatGptPage(location.href) || !(event.target instanceof Element) || !event.target.closest('button')) return;
  const current = inspectComposer().composer;
  if (current?.button?.contains(event.target) && !current.button.disabled) check(event, current);
}, { capture: true });

window.addEventListener('keydown', (event) => {
  if (!event.isTrusted || event.key !== 'Enter' || event.shiftKey || event.altKey || event.metaKey || event.ctrlKey ||
      event.isComposing || event.keyCode === 229 || !isChatGptPage(location.href) || !(event.target instanceof Node)) return;
  const current = inspectComposer().composer;
  if (!current?.input.contains(event.target)) return;
  if (!current.button) {
    // The native handler is unknown in this state. Report the gap rather than claiming coverage.
    unsupportedInput = current.input;
    observe();
    return;
  }
  if (!current.button.disabled) check(event, current);
}, { capture: true });

window.addEventListener('input', (event) => {
  if (warning && event.target instanceof Node && warning.input.contains(event.target)) clearWarning();
}, { capture: true });

ui.edit.addEventListener('click', () => {
  const current = inspectComposer().composer;
  clearWarning();
  current?.input.focus();
});

ui.proceed.addEventListener('click', () => {
  const pending = warning;
  const current = inspectComposer().composer;
  clearWarning();
  if (!pending || current?.input !== pending.input || !current.button || current.button.disabled ||
      promptText(current.input) !== pending.value || !isChatGptPage(location.href) || !control?.chatGptEnabled ||
      control.installationId !== pending.installationId || control.policy?.version !== pending.match.policyVersion ||
      control.policy?.mode !== 'warn') return;
  recordDecision(chatGptApp, pending.match, pending.installationId, 'warn_override');
  current.button.click();
});

ui.copy.addEventListener('click', async (event) => {
  if (!event.isTrusted) return;
  const route = location.pathname === '/' ? 'home' : isChatGptPage(location.href) ? 'conversation' : 'other';
  const text = JSON.stringify({
    version: chrome.runtime.getManifest().version,
    route,
    ...(route === 'other' ? {} : composerDiagnostics()),
  });
  try {
    await navigator.clipboard.writeText(text);
    ui.copy.textContent = 'Diagnostics copied';
  } catch {
    ui.diagnostics.value = text;
    ui.diagnostics.hidden = false;
    ui.diagnostics.select();
  }
});

let wasSupportedPage = false;
function refreshPage() {
  const supportedPage = isChatGptPage(location.href);
  if (supportedPage) void refresh(wasSupportedPage ? 'status' : 'sync');
  wasSupportedPage = supportedPage;
  observe();
}

refreshPage();
window.setInterval(refreshPage, 750);
