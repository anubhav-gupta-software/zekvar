import { evaluatePrompt, standalonePolicy, type MatchedDecision } from './policy';
import { recordDecision } from './decisions';
import { fixtureApp, fixtureUrl, isMode, send, type Summary } from './protocol';

function attachFixture() {
  const form = document.querySelector('#prompt-form');
  const prompt = document.querySelector('#prompt');
  const mode = document.querySelector('#policy-mode');
  const submit = document.querySelector('#send-prompt');
  const feedback = document.querySelector('#policy-feedback');
  const controlStatus = document.querySelector('#control-status');
  const sync = document.querySelector('#sync-policy');
  if (!(form instanceof HTMLFormElement) || !(prompt instanceof HTMLInputElement) ||
      !(mode instanceof HTMLSelectElement) || !(submit instanceof HTMLButtonElement) ||
      !(feedback instanceof HTMLElement) || !(controlStatus instanceof HTMLElement) || !(sync instanceof HTMLButtonElement)) {
    return;
  }

  const message = document.createElement('p');
  message.setAttribute('role', 'status');
  const actions = document.createElement('div');
  actions.hidden = true;
  const edit = document.createElement('button');
  edit.type = 'button';
  edit.textContent = 'Edit prompt';
  const proceed = document.createElement('button');
  proceed.type = 'button';
  proceed.textContent = 'Continue anyway';
  actions.append(edit, proceed);
  feedback.append(message, actions);

  let pending: { value: string; match: MatchedDecision } | undefined;
  let approved: MatchedDecision | undefined;
  let control: Summary | undefined;
  let refreshing = false;

  const currentPolicy = () => {
    if (control?.status === 'standalone') return isMode(mode.value) ? standalonePolicy(mode.value) : undefined;
    return control?.policy ?? standalonePolicy('block');
  };

  const refresh = async (type: 'sync' | 'status') => {
    if (refreshing) return;
    refreshing = true;
    if (type === 'sync') sync.disabled = true;
    try {
      const { summary, error } = await send({ type });
      if (!summary) throw new Error(error);
      const previous = currentPolicy();
      const previousId = control?.installationId;
      control = summary;
      const policy = currentPolicy();
      if (previous?.version !== policy?.version || previous?.assignmentVersion !== policy?.assignmentVersion ||
          previous?.mode !== policy?.mode || previousId !== control.installationId) {
        clearFeedback();
      }
      mode.disabled = control.status !== 'standalone';
      sync.hidden = control.status === 'standalone';
      if (mode.disabled && control.policy) mode.value = control.policy.mode;
      const github = control.policy?.githubPatMode;
      const label = control.policy ? `${control.policy.mode.toUpperCase()} · v${control.policy.version}${isMode(github) ? ` · GitHub PAT ${github}` : ''}` : 'waiting for a policy';
      const status = control.status === 'standalone' ? 'Standalone fixture. Open Zekvar Browser to enroll.' :
        control.status === 'connected' ? `Control policy: ${label}` :
        control.status === 'revoked' ? `Control access revoked. Last policy: ${label}.` :
        `Control offline. Last policy: ${label}.`;
      if (controlStatus.textContent !== status) controlStatus.textContent = status;
      form.dataset.zekvarReady = 'true';
    } catch {
      controlStatus.textContent = 'Control status unavailable. Reload this page to reconnect to Zekvar.';
    } finally {
      refreshing = false;
      sync.disabled = false;
    }
  };

  function clearFeedback() {
    pending = undefined;
    message.textContent = '';
    actions.hidden = true;
  }

  prompt.addEventListener('input', clearFeedback);
  mode.addEventListener('change', clearFeedback);
  sync.addEventListener('click', () => void refresh('sync'));
  edit.addEventListener('click', () => {
    clearFeedback();
    prompt.focus();
  });
  proceed.addEventListener('click', () => {
    const warning = pending;
    if (!warning) {
      return;
    }
    clearFeedback();
    const policy = currentPolicy();
    const match = policy && evaluatePrompt(prompt.value, policy);
    if (warning.value === prompt.value && match?.action === 'warn' && match.ruleId === warning.match.ruleId &&
        match.policyVersion === warning.match.policyVersion && match.assignmentVersion === warning.match.assignmentVersion) {
      approved = warning.match;
    }
    try {
      form.requestSubmit(submit);
    } finally {
      approved = undefined;
    }
  });

  form.addEventListener('submit', (event) => {
    if (approved) {
      recordDecision(fixtureApp, approved, control?.installationId, 'warn_override');
      approved = undefined;
      return;
    }

    const policy = currentPolicy();
    if (!policy) {
      event.stopImmediatePropagation();
      event.preventDefault();
      clearFeedback();
      message.textContent = 'Select a valid policy mode before sending.';
      return;
    }

    const match = evaluatePrompt(prompt.value, policy);
    if (match.action === 'allow') {
      clearFeedback();
      return;
    }

    if (match.action === 'monitor') {
      clearFeedback();
      recordDecision(fixtureApp, match, control?.installationId);
      return;
    }

    event.stopImmediatePropagation();
    event.preventDefault();
    if (match.action === 'warn' && pending?.value === prompt.value) {
      return;
    }

    clearFeedback();
    recordDecision(fixtureApp, match, control?.policy ? control.installationId : undefined);
    if (match.action === 'warn') {
      pending = { value: prompt.value, match };
      message.textContent = `${match.reason} Edit the prompt or confirm that you want to send it.`;
      actions.hidden = false;
      edit.focus();
      return;
    }
    message.textContent = `Submission blocked. ${match.reason} Edit the prompt and try again.`;
    prompt.focus();
  }, { capture: true });

  mode.disabled = true;
  void refresh('sync');
  window.setInterval(() => void refresh('status'), 1000);
}

if (location.href === fixtureUrl) {
  attachFixture();
}
