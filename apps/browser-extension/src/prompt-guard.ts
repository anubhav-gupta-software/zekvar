import { redactPrompt } from '../../../contracts/policy/prompt';
import { recordDecision, recordUploadDecision } from './decisions';
import { evaluatePrompt, withPolicyVersion, type MatchedDecision } from './policy';
import { isMode, send, type AiPromptApp, type Coverage, type Summary } from './protocol';
import { promptAppLabels } from '../../../contracts/policy/apps';
import { isUploadApp } from '../../../contracts/policy/uploads';
import { bindUploadGuard } from './upload-guard';
import { promptText, replacePromptText, supportsRedaction, type Composer, type ComposerInspection } from './prompt-composer';
import { leaseTime } from './prompt-exceptions';
import { evaluatePromptWithExceptions, exceptionDecision } from '../../../contracts/policy/prompt-exceptions';
import type { Policy } from './protocol';

type PromptAdapter = {
  appId: AiPromptApp;
  route: (url: string) => string;
  inspect: () => ComposerInspection;
  diagnostics: () => object;
  hideWhenDisabled?: boolean;
};

type InterruptedDraft = { input: HTMLElement; page: string; value: string; installationId: string; match: MatchedDecision };

function controls(appId: AiPromptApp) {
  const host = document.createElement('div');
  host.id = 'zekvar-' + appId;
  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = `
    :host { position: fixed; z-index: 2147483647; bottom: 1rem; right: 1rem;
      max-width: min(24rem, calc(100vw - 2rem)); color: #eaf6f2; font: 14px/1.45 system-ui, sans-serif; }
    section { padding: .7rem .9rem; border: 1px solid #447267; border-radius: .6rem;
      background: #101927; box-shadow: 0 1px 8px #0004; }
    p { margin: 0; }
    #status { color: #8aecc8; }
    #notice, #upload-notice { margin-top: .4rem; }
    #notice:empty, #upload-notice:empty, [hidden] { display: none; }
    button { margin: .55rem .35rem 0 0; padding: .3rem .55rem; border: 1px solid #627b8b;
      border-radius: .35rem; color: #fff; background: #203045; cursor: pointer; font: inherit; }
    button:focus-visible { outline: 2px solid #59e6b5; outline-offset: 2px; }
    #redact { color: #101927; background: #59e6b5; border-color: #59e6b5; font-weight: 650; }
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
  const uploadNotice = document.createElement('p');
  uploadNotice.id = 'upload-notice';
  uploadNotice.setAttribute('role', 'alert');
  const actions = document.createElement('div');
  const redact = document.createElement('button');
  redact.type = 'button';
  redact.id = 'redact';
  redact.textContent = 'Redact detected values';
  const edit = document.createElement('button');
  edit.textContent = 'Edit prompt';
  const proceed = document.createElement('button');
  proceed.textContent = 'Continue anyway';
  actions.hidden = true;
  actions.append(redact, edit, proceed);
  const copy = document.createElement('button');
  copy.textContent = 'Copy composer diagnostics';
  const diagnostics = document.createElement('textarea');
  diagnostics.readOnly = true;
  diagnostics.hidden = true;
  diagnostics.setAttribute('aria-label', 'Composer diagnostics');
  panel.append(status, uploadNotice, notice, actions, copy, diagnostics);
  root.append(style, panel);
  return { host, status, notice, uploadNotice, actions, redact, edit, proceed, copy, diagnostics };
}

export function bindPromptGuard(adapter: PromptAdapter) {
  const ui = controls(adapter.appId);
  const appName = promptAppLabels[adapter.appId];
  const uploadApp = isUploadApp(adapter.appId) ? adapter.appId : undefined;
  const enabled = (summary: Summary | undefined) => summary?.promptApps?.includes(adapter.appId) === true;
  const supported = () => adapter.route(location.href) !== 'other';
  let control: Summary | undefined;
  let refreshing = false;
  let unsupportedSince = 0;
  let lastCoverage: { installationId: string; coverage: Coverage; version: number; assignment?: number; at: number } | undefined;
  let pending: InterruptedDraft | undefined;
  let unsupportedInput: HTMLElement | undefined;

  function clearInterruption() {
    pending = undefined;
    ui.notice.textContent = '';
    ui.actions.hidden = true;
  }

  function observe() {
    if (!document.body) return;
    if (adapter.hideWhenDisabled && (!supported() || !control?.installationId || !enabled(control))) {
      ui.host.remove();
      clearInterruption();
      lastCoverage = undefined;
      unsupportedSince = 0;
      unsupportedInput = undefined;
      return;
    }
    if (!ui.host.isConnected) document.body.append(ui.host);
    if (!supported()) {
      clearInterruption();
      ui.uploadNotice.textContent = '';
      ui.status.textContent = `Zekvar · Unsupported ${appName} page`;
      lastCoverage = undefined;
      unsupportedSince = 0;
      unsupportedInput = undefined;
      return;
    }
    const inspection = adapter.inspect();
    const current = inspection.composer;
    if (current?.button || (unsupportedInput && unsupportedInput !== current?.input)) unsupportedInput = undefined;
    if (pending && (current?.input !== pending.input || pending.page !== location.href)) clearInterruption();
    const now = Date.now();
    const ready = Boolean(current && (current.button || inspection.hasEditorForm) && !unsupportedInput);
    const waiting = inspection.waitingForSend && !unsupportedInput;
    if (ready || waiting) unsupportedSince = 0;
    else unsupportedSince ||= now;
    const coverage = ready ? 'ready' : !waiting && now - unsupportedSince > 2500 ? 'unsupported' : undefined;

    const installationId = control?.installationId;
    const policy = control?.policy;
    const managedPolicy = installationId && enabled(control) ? policy : undefined;
    const github = managedPolicy?.githubPatMode;
    const card = managedPolicy?.paymentCardMode;
    const privateKey = managedPolicy?.privateKeyMode;
    const targetedUpload = uploadApp && managedPolicy?.targetedUploads?.[uploadApp];
    const upload = targetedUpload?.mode ?? (uploadApp && managedPolicy?.uploadModes?.[uploadApp]);
    if (upload !== 'block') ui.uploadNotice.textContent = '';
    const detectors = (isMode(github) ? ` · GitHub PAT ${github}` : '') + (isMode(card) ? ` · Payment card ${card}` : '') +
      (isMode(privateKey) ? ` · Private key ${privateKey}` : '') +
      (upload && upload !== 'off' ? ` · File uploads ${upload}${targetedUpload ? ' (selected types)' : ''}` : '');
    const label = !managedPolicy ? `Zekvar · ${appName} policy unavailable` : coverage === 'unsupported' ?
      `Zekvar · Unsupported composer (${inspection.gap ?? 'Send control missing'})` : !coverage && !waiting ? 'Zekvar · Checking composer…' :
        `Zekvar · ${managedPolicy.mode.toUpperCase()} v${managedPolicy.version}${detectors}${control?.status === 'offline' ? ' · Offline policy' : ''}${current?.button ? '' : ' · Waiting for Send control'}`;
    if (ui.status.textContent !== label) ui.status.textContent = label;
    if (!managedPolicy || !installationId || !coverage) return;
    if (lastCoverage?.installationId === installationId && lastCoverage.coverage === coverage &&
        lastCoverage.version === managedPolicy.version && lastCoverage.assignment === managedPolicy.assignmentVersion &&
        now - lastCoverage.at < 60_000) return;
    const report = { installationId, coverage, version: managedPolicy.version, assignment: managedPolicy.assignmentVersion, at: now } as const;
    lastCoverage = report;
    void send({ type: 'coverage', installationId, coverage, version: report.version, assignmentVersion: report.assignment }).then((reply) => {
      if (reply.error && lastCoverage === report) lastCoverage = undefined;
    }, () => {
      if (lastCoverage === report) lastCoverage = undefined;
    });
  }

  async function refresh(type: 'sync' | 'status') {
    if (refreshing || !supported()) return;
    refreshing = true;
    try {
      const reply = await send({ type });
      if (!reply.summary) return;
      if (control?.installationId !== reply.summary.installationId || control?.policy?.version !== reply.summary.policy?.version ||
          control?.policy?.assignmentVersion !== reply.summary.policy?.assignmentVersion ||
          control?.policy?.mode !== reply.summary.policy?.mode || enabled(control) !== enabled(reply.summary)) {
        clearInterruption();
        ui.uploadNotice.textContent = '';
      }
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
    if (!policy || !installationId || !enabled(control)) return;
    const value = promptText(current.input);
    const { match, exception } = evaluate(value, policy);
    if (exception) {
      clearInterruption();
      recordDecision(adapter.appId, exception.match, installationId, exceptionDecision, new Date(exception.time).toISOString());
      ui.notice.textContent = 'Temporary policy exception applied.';
      return;
    }
    if (match.action === 'allow') {
      clearInterruption();
      return;
    }
    if (match.action !== 'monitor') {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
    if (match.action === 'warn' && pending?.input === current.input && pending.page === location.href && pending.value === value &&
        pending.match.policyVersion === match.policyVersion && pending.match.assignmentVersion === match.assignmentVersion) return;

    clearInterruption();
    recordDecision(adapter.appId, match, installationId);
    if (match.action === 'monitor') return;
    pending = { input: current.input, page: location.href, value, installationId, match };
    ui.redact.hidden = !supportsRedaction(current.input);
    ui.proceed.hidden = match.action !== 'warn';
    ui.actions.hidden = false;
    if (match.action === 'block') {
      ui.notice.textContent = `Submission blocked. ${match.reason} Edit the prompt and try again.`;
      current.input.focus();
    } else {
      ui.notice.textContent = match.reason;
      ui.edit.focus();
    }
  }

  function evaluate(value: string, policy: Policy) {
    const lease = control?.promptExceptionLease;
    const now = lease && leaseTime(lease);
    if (!lease || now === undefined) return { match: evaluatePrompt(value, policy) };
    const grants = lease.grants.filter((grant) => grant.appId === adapter.appId && grant.expiresAtMs > now);
    const except = new Set(grants.map(({ ruleId }) => ruleId));
    const { match, exception } = evaluatePromptWithExceptions(value, policy, except);
    const time = leaseTime(lease);
    if (time === undefined || grants.some((grant) => grant.expiresAtMs <= time)) return { match: evaluatePrompt(value, policy) };
    return { match: match.action === 'allow' ? match : withPolicyVersion(match, policy),
      exception: exception && { match: withPolicyVersion(exception, policy), time } };
  }

  window.addEventListener('click', (event) => {
    if (!event.isTrusted || !enabled(control) || !supported() || !(event.target instanceof Element) || !event.target.closest('button')) return;
    const current = adapter.inspect().composer;
    if (current?.button?.contains(event.target) && !current.button.disabled) check(event, current);
  }, { capture: true });

  window.addEventListener('keydown', (event) => {
    if (!event.isTrusted || event.key !== 'Enter' || event.shiftKey || event.altKey || event.metaKey || event.ctrlKey ||
        event.isComposing || event.keyCode === 229 || !enabled(control) || !supported() || !(event.target instanceof Node)) return;
    const inspection = adapter.inspect();
    const current = inspection.composer;
    if (!current?.input.contains(event.target)) return;
    if (!current.button) {
      // The native handler is unknown in this state. Report the gap rather than claiming coverage.
      if (!inspection.waitingForSend) {
        unsupportedInput = current.input;
        observe();
      }
      return;
    }
    if (!current.button.disabled) check(event, current);
  }, { capture: true });

  window.addEventListener('input', (event) => {
    if (pending && event.target instanceof Node && pending.input.contains(event.target)) clearInterruption();
  }, { capture: true });

  ui.edit.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const current = adapter.inspect().composer;
    clearInterruption();
    current?.input.focus();
  });

  function reviewedDraft() {
    const draft = pending;
    const current = adapter.inspect().composer;
    clearInterruption();
    if (!draft || current?.input !== draft.input || !current.button || current.button.disabled ||
        promptText(current.input) !== draft.value || draft.page !== location.href || !supported() ||
        !enabled(control) || control?.installationId !== draft.installationId || !control.policy) return;
    const { match, exception } = evaluate(draft.value, control.policy);
    if (exception) return;
    if (match.action === 'allow' || match.action !== draft.match.action || match.ruleId !== draft.match.ruleId ||
        match.policyVersion !== draft.match.policyVersion || match.assignmentVersion !== draft.match.assignmentVersion) return;
    return { draft, button: current.button, policy: control.policy };
  }

  ui.redact.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const review = reviewedDraft();
    if (!review) return;
    const { draft, policy } = review;
    const replacement = redactPrompt(draft.value, policy);
    const edited = replacePromptText(draft.input, draft.value, replacement);
    const actual = promptText(draft.input);
    // Chrome can reshape trailing blank lines when replacing a contenteditable draft.
    const matches = actual === replacement || (!(draft.input instanceof HTMLTextAreaElement) &&
      replacement.endsWith('\n') && actual.replace(/\n+$/, '') === replacement.replace(/\n+$/, ''));
    const clean = edited && matches && evaluatePrompt(actual, policy).action === 'allow';
    ui.notice.textContent = clean ? 'Detected values redacted. Review the updated draft before sending.' :
      'Zekvar could not verify the redaction. Review and edit the draft before trying again.';
  });

  ui.proceed.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const review = reviewedDraft();
    if (review?.draft.match.action !== 'warn') return;
    recordDecision(adapter.appId, review.draft.match, review.draft.installationId, 'warn_override');
    review.button.click();
  });

  ui.copy.addEventListener('click', async (event) => {
    if (!event.isTrusted) return;
    const route = adapter.route(location.href);
    const text = JSON.stringify({
      version: chrome.runtime.getManifest().version,
      route,
      ...(route === 'other' ? {} : adapter.diagnostics()),
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
    const supportedPage = supported();
    if (supportedPage && !wasSupportedPage) void refresh('status').then(() => refresh('sync'));
    else if (supportedPage) void refresh('status');
    wasSupportedPage = supportedPage;
    observe();
  }

  if (uploadApp) bindUploadGuard(() => {
    if (!supported() || !enabled(control) || !control?.installationId || !control.policy) return;
    const targeted = control.policy.targetedUploads?.[uploadApp];
    if (targeted) return targeted;
    const mode = control.policy.uploadModes?.[uploadApp];
    if (mode === 'monitor' || mode === 'block') return { mode, types: [] };
  }, (decision, method) => {
    if (decision !== 'block') ui.uploadNotice.textContent = '';
    if (!decision || !control?.policy || !control.installationId) return;
    recordUploadDecision(uploadApp, control.policy, control.installationId, decision, method);
    if (decision === 'block') ui.uploadNotice.textContent = `File upload blocked by your organization’s ${appName} policy.`;
  });
  refreshPage();
  window.setInterval(refreshPage, 750);
}
