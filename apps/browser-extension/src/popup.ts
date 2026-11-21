import { send, type Summary } from './protocol';

const form = document.querySelector<HTMLFormElement>('#enroll')!;
const grant = document.querySelector<HTMLInputElement>('#grant')!;
const indicator = document.querySelector<HTMLElement>('#status')!;
const delivery = document.querySelector<HTMLElement>('#delivery')!;
const managed = document.querySelector<HTMLElement>('#managed-enrollment')!;
const errorMessage = document.querySelector<HTMLElement>('#error')!;
const sync = document.querySelector<HTMLButtonElement>('#sync')!;
const enrollButton = form.querySelector<HTMLButtonElement>('button')!;
let busy = false;

function render(summary: Summary) {
  const states = { standalone: 'Ready to enroll', connected: 'Connected to Control', offline: 'Control offline', revoked: 'Control access revoked' };
  const policy = summary.policy ? ` · ${summary.policy.mode.toUpperCase()} v${summary.policy.version}` : '';
  const status = states[summary.status] + policy;
  if (indicator.textContent !== status) indicator.textContent = status;
  delivery.textContent = summary.queued || summary.discarded
    ? `${summary.queued} queued${summary.discarded ? ` · ${summary.discarded} discarded` : ''}` : '';
  const onboarding = {
    invalid: 'Chrome policy contains an invalid enrollment grant.',
    rejected: 'Chrome policy grant expired or was already used. Ask your admin for a fresh grant.',
    retrying: 'Waiting for Control to redeem the Chrome policy grant.',
  };
  managed.textContent = summary.enrollmentSource === 'managed' ? 'Enrolled by Chrome policy.' :
    summary.managedEnrollment ? onboarding[summary.managedEnrollment] : '';
  form.hidden = Boolean(summary.installationId);
  sync.hidden = !summary.installationId;
}

async function update(type: 'status' | 'sync' | 'enroll') {
  if (busy) return;
  busy = true;
  if (type !== 'status') errorMessage.textContent = '';
  sync.disabled = enrollButton.disabled = true;
  try {
    const request = type === 'enroll' ? { type, grant: grant.value.trim() } as const : { type };
    const response = await send(request);
    if (response.summary) render(response.summary);
    if (response.error) errorMessage.textContent = response.error;
  } catch {
    errorMessage.textContent = 'Zekvar could not update its connection status.';
  } finally {
    if (type === 'enroll') grant.value = '';
    sync.disabled = enrollButton.disabled = false;
    busy = false;
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void update('enroll');
});
sync.addEventListener('click', () => void update('sync'));
void update('sync');
window.setInterval(() => void update('status'), 1500);
