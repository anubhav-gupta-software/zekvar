import { discoveryPermission, send, type Summary } from './protocol';
import { inventoryPermission } from './extension-inventory';

const form = document.querySelector<HTMLFormElement>('#enroll')!;
const grant = document.querySelector<HTMLInputElement>('#grant')!;
const indicator = document.querySelector<HTMLElement>('#status')!;
const delivery = document.querySelector<HTMLElement>('#delivery')!;
const domains = document.querySelector<HTMLElement>('#domain-rules')!;
const paths = document.querySelector<HTMLElement>('#path-rules')!;
const managed = document.querySelector<HTMLElement>('#managed-enrollment')!;
const errorMessage = document.querySelector<HTMLElement>('#error')!;
const sync = document.querySelector<HTMLButtonElement>('#sync')!;
const enrollButton = form.querySelector<HTMLButtonElement>('button')!;
const inventory = document.querySelector<HTMLElement>('#inventory')!;
const inventorySummary = document.querySelector<HTMLElement>('#inventory-status')!;
const inventoryButton = document.querySelector<HTMLButtonElement>('#inventory-permission')!;
const discovery = document.querySelector<HTMLElement>('#discovery')!;
const discoverySummary = document.querySelector<HTMLElement>('#discovery-status')!;
const discoveryButton = document.querySelector<HTMLButtonElement>('#discovery-permission')!;
let busy = false;
let inventoryEnabled = false;
let inventoryAllowed = false;
let inventoryStatus: Summary['inventoryStatus'];
let discoveryCount = 0;
let discoveryAllowed = false;

function renderInventory() {
  inventory.hidden = !inventoryEnabled && !inventoryAllowed;
  inventoryButton.textContent = inventoryAllowed ? 'Remove extension inventory permission' : 'Allow extension inventory';
  let label = 'Extension inventory is off in Control.';
  if (inventoryEnabled) {
    label = !inventoryAllowed ? 'Control requests extension names, versions, and selected permission metadata.' :
      inventoryStatus === 'reported' ? 'Extension inventory reported to Control.' :
        inventoryStatus === 'unavailable' ? 'Extension inventory is unavailable. Zekvar will retry.' : 'Waiting to report extension inventory…';
  }
  if (inventorySummary.textContent !== label) inventorySummary.textContent = label;
}

async function refreshInventoryPermission() {
  inventoryAllowed = await chrome.permissions.contains(inventoryPermission).catch(() => false);
  renderInventory();
}

function renderDiscovery() {
  discovery.hidden = !discoveryCount && !discoveryAllowed;
  discoveryButton.textContent = discoveryAllowed ? 'Remove custom app discovery permission' : 'Allow custom app discovery';
  const label = !discoveryCount ? 'Custom app discovery is off in Control.' : discoveryAllowed ?
    `Custom app discovery enabled for ${discoveryCount} cataloged ${discoveryCount === 1 ? 'site' : 'sites'}.` :
    'Control requests permission to report visits to the sites in your organization’s app catalog.';
  if (discoverySummary.textContent !== label) discoverySummary.textContent = label;
}

async function refreshDiscoveryPermission() {
  discoveryAllowed = await chrome.permissions.contains(discoveryPermission).catch(() => false);
  renderDiscovery();
}

function render(summary: Summary) {
  const states = { standalone: 'Ready to enroll', connected: 'Connected to Control', offline: 'Control offline', revoked: 'Control access revoked' };
  const policy = summary.policy ? ` · ${summary.policy.mode.toUpperCase()} v${summary.policy.version}` : '';
  const status = (summary.status === 'offline' && summary.domainRulesError ? 'Policy update pending' : states[summary.status]) + policy;
  if (indicator.textContent !== status) indicator.textContent = status;
  const domainStatus = summary.domainRulesError ? 'Chrome could not update the navigation rules. Zekvar will retry.' :
    summary.domainRuleCount ? `Active domain rules: ${summary.domainRuleCount}` : '';
  if (domains.textContent !== domainStatus) domains.textContent = domainStatus;
  const pathStatus = summary.pathRuleCount ? `Active path rules: ${summary.pathRuleCount}` : '';
  if (paths.textContent !== pathStatus) paths.textContent = pathStatus;
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
  inventoryEnabled = Boolean(summary.installationId && summary.policy?.extensionInventoryEnabled);
  inventoryStatus = summary.inventoryStatus;
  discoveryCount = summary.installationId ? summary.customDiscoveryCount ?? 0 : 0;
  renderInventory();
  renderDiscovery();
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
inventoryButton.addEventListener('click', async () => {
  inventoryButton.disabled = true;
  errorMessage.textContent = '';
  try {
    if (inventoryAllowed) await chrome.permissions.remove(inventoryPermission);
    else if (inventoryEnabled && !await chrome.permissions.request(inventoryPermission)) {
      errorMessage.textContent = 'Extension inventory permission was not granted.';
    }
    await refreshInventoryPermission();
    if (!errorMessage.textContent) await update('sync');
  } catch {
    errorMessage.textContent = 'Chrome could not change the extension inventory permission.';
  } finally {
    inventoryButton.disabled = false;
  }
});
discoveryButton.addEventListener('click', async () => {
  discoveryButton.disabled = true;
  errorMessage.textContent = '';
  try {
    if (discoveryAllowed) await chrome.permissions.remove(discoveryPermission);
    else if (discoveryCount && !await chrome.permissions.request(discoveryPermission)) {
      errorMessage.textContent = 'Custom app discovery permission was not granted.';
    }
    await refreshDiscoveryPermission();
    if (!errorMessage.textContent) await update('sync');
  } catch {
    errorMessage.textContent = 'Chrome could not change the custom app discovery permission.';
  } finally {
    discoveryButton.disabled = false;
  }
});
function refreshPermissions() {
  void refreshInventoryPermission();
  void refreshDiscoveryPermission();
}
chrome.permissions.onAdded.addListener(refreshPermissions);
chrome.permissions.onRemoved.addListener(refreshPermissions);
refreshPermissions();
void update('sync');
window.setInterval(() => void update('status'), 1500);
