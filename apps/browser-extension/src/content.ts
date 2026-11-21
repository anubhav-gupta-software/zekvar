import { evaluatePrompt, type MatchedDecision, type PolicyMode } from './policy';

function recordDecision(match: MatchedDecision, decision: PolicyMode | 'warn_override' = match.action) {
  const event = {
    eventId: crypto.randomUUID(),
    appId: 'local-prompt-fixture',
    timestamp: new Date().toISOString(),
    ruleId: match.ruleId,
    detectorCategory: match.detectorCategory,
    policyVersion: match.policyVersion,
    decision,
  };
  console.info(`Zekvar decision ${JSON.stringify(event)}`);
}

function attachFixture() {
  const form = document.querySelector('#prompt-form');
  const prompt = document.querySelector('#prompt');
  const mode = document.querySelector('#policy-mode');
  const submit = document.querySelector('#send-prompt');
  const feedback = document.querySelector('#policy-feedback');
  if (!(form instanceof HTMLFormElement) || !(prompt instanceof HTMLInputElement) ||
      !(mode instanceof HTMLSelectElement) || !(submit instanceof HTMLButtonElement) ||
      !(feedback instanceof HTMLElement)) {
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

  function clearFeedback() {
    pending = undefined;
    message.textContent = '';
    actions.hidden = true;
  }

  prompt.addEventListener('input', clearFeedback);
  mode.addEventListener('change', clearFeedback);
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
    if (warning.value === prompt.value && mode.value === 'warn') {
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
      recordDecision(approved, 'warn_override');
      approved = undefined;
      return;
    }

    const currentMode = mode.value;
    if (currentMode !== 'monitor' && currentMode !== 'warn' && currentMode !== 'block') {
      event.stopImmediatePropagation();
      event.preventDefault();
      clearFeedback();
      message.textContent = 'Select a valid policy mode before sending.';
      return;
    }

    const match = evaluatePrompt(prompt.value, currentMode);
    if (match.action === 'allow') {
      clearFeedback();
      return;
    }

    if (match.action === 'monitor') {
      clearFeedback();
      recordDecision(match);
      return;
    }

    event.stopImmediatePropagation();
    event.preventDefault();
    if (match.action === 'warn' && pending?.value === prompt.value) {
      return;
    }

    clearFeedback();
    recordDecision(match);
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

  form.dataset.zekvarReady = 'true';
}

if (location.origin === 'http://127.0.0.1:4173' && location.pathname === '/zekvar-fixture/') {
  attachFixture();
}
