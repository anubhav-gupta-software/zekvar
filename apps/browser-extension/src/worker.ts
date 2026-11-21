import {
  chatGptApp, discoveredApp, fixtureApp, fixtureDetector, fixtureRule, fixtureUrl, isChatGptPage, isDetectorMode,
  isId, isMode, isRecord, isToken, isVersion, readMetadata,
  type AppId, type AppObservation, type Coverage, type DiscoveryApp, type Policy, type PolicyEvent, type Reply, type Summary,
} from './protocol';
import { emptyDomainRules, installDomainRules, readDomainRules, sameDomainRules, type DomainRules } from './domain-rules';

declare const CONTROL_ORIGIN: string;

type Enrollment = { installationId: string; token: string; source?: Summary['enrollmentSource'] };
type State = {
  status: Summary['status'];
  enrollment?: Enrollment;
  policy?: Policy;
  domainRules?: DomainRules;
  domainRulesError?: boolean;
  chatGptEnabled?: boolean;
  coveragePending?: Coverage;
  queue: PolicyEvent[];
  observations?: Partial<Record<DiscoveryApp, AppObservation>>;
  discarded: number;
  managedEnrollment?: Summary['managedEnrollment'];
  usedManagedGrant?: string;
};

const key = 'controlState';
const alarmName = 'control-sync';
const maxQueue = 100;
let work = Promise.resolve();
let deliveryScheduled = false;

const managedGrantKey = 'EnrollmentGrant';
const setup = Promise.all([
  chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
  chrome.storage.managed.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
]);

function serial<T>(operation: () => Promise<T>): Promise<T> {
  const result = work.then(() => setup).then(operation);
  work = result.then(() => undefined, () => undefined);
  return result;
}

async function readState(): Promise<State> {
  const stored = await chrome.storage.local.get(key);
  return (stored[key] as State | undefined) ?? { status: 'standalone', queue: [], discarded: 0 };
}

function save(state: State) {
  return chrome.storage.local.set({ [key]: state });
}

function summary(state: State): Summary {
  return {
    status: state.status, installationId: state.enrollment?.installationId, enrollmentSource: state.enrollment?.source,
    policy: state.policy, chatGptEnabled: state.chatGptEnabled, queued: state.queue.length, discarded: state.discarded,
    managedEnrollment: state.managedEnrollment, domainRulesError: state.domainRulesError,
    domainRuleCount: state.domainRules ? state.domainRules.allow.length + state.domainRules.block.length : undefined,
  };
}

class HttpError extends Error {
  constructor(readonly status: number) {
    super(`HTTP ${status}`);
  }
}

async function request(path: string, token?: string, body?: object): Promise<unknown> {
  const response = await fetch(`${CONTROL_ORIGIN}/v1/${path}`, {
    method: body ? 'POST' : 'GET',
    redirect: 'error',
    cache: 'no-store',
    credentials: 'omit',
    signal: AbortSignal.timeout(3500),
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) throw new HttpError(response.status);
  return response.status === 204 ? undefined : response.json();
}

async function applyDomainRules(state: State, rules: DomainRules) {
  try {
    await installDomainRules(rules);
    state.domainRules = rules;
    state.domainRulesError = undefined;
  } catch (error) {
    state.domainRulesError = true;
    throw error;
  }
}

async function lostConnection(state: State, error: unknown) {
  if (error instanceof HttpError && error.status === 401) {
    state.status = 'revoked';
    state.enrollment = undefined;
    state.coveragePending = undefined;
    state.observations = undefined;
    state.discarded += state.queue.length;
    state.queue = [];
    state.domainRulesError = true;
    await save(state);
    await applyDomainRules(state, emptyDomainRules).catch(() => undefined);
  } else {
    state.status = 'offline';
  }
}

async function deliver(state: State) {
  if (!state.enrollment || (state.queue.length === 0 && !state.observations)) return;
  for (let delivered = 0; delivered < 20 && state.queue.length; delivered++) {
    try {
      await request('browser/events', state.enrollment.token, state.queue[0]);
    } catch (error) {
      if (!(error instanceof HttpError && error.status === 400)) {
        await lostConnection(state, error);
        break;
      }
      state.discarded++;
    }
    state.queue.shift();
  }
  await deliverObservations(state);
  await save(state);
}

async function deliverObservations(state: State) {
  if (!state.enrollment || state.status !== 'connected' || !state.observations) return;
  for (const observation of Object.values(state.observations)) {
    try {
      await request('browser/ai-app-observations', state.enrollment.token, observation);
    } catch (error) {
      if (!(error instanceof HttpError && error.status === 400)) {
        await lostConnection(state, error);
        return;
      }
    }
    delete state.observations[observation.appId];
  }
  state.observations = undefined;
}

async function sync(state: State) {
  if (!state.enrollment) return;
  const { token } = state.enrollment;
  try {
    const policy = await request('browser/policy', token);
    if (!isRecord(policy) || !isVersion(policy.version) || !isMode(policy.mode) ||
        (policy.githubPatMode !== undefined && !isDetectorMode(policy.githubPatMode)) ||
        (policy.discoveryEnabled !== undefined && typeof policy.discoveryEnabled !== 'boolean') ||
        policy.appId !== fixtureApp || policy.ruleId !== fixtureRule || policy.detectorCategory !== fixtureDetector) {
      throw new Error('Unknown policy format');
    }
    const githubPatMode = policy.githubPatMode ?? 'off';
    const discoveryEnabled = policy.discoveryEnabled ?? false;
    const domainRules = readDomainRules(policy.domainRules);
    if (!domainRules) throw new Error('Unknown domain rule format');
    if (!state.policy || policy.version > state.policy.version || (policy.version === state.policy.version &&
        policy.mode === state.policy.mode && githubPatMode === (state.policy.githubPatMode ?? 'off') &&
        discoveryEnabled === (state.policy.discoveryEnabled ?? false) &&
        sameDomainRules(domainRules, state.domainRules ?? emptyDomainRules))) {
      await applyDomainRules(state, domainRules);
      state.policy = { version: policy.version, mode: policy.mode, githubPatMode, discoveryEnabled };
      if (!discoveryEnabled) state.observations = undefined;
      state.chatGptEnabled = Array.isArray(policy.appIds) && policy.appIds.includes(chatGptApp);
      await save(state);
    }
    await heartbeat(state);
    state.status = 'connected';
    await save(state);
    await deliver(state);
  } catch (error) {
    await lostConnection(state, error);
    await save(state);
  }
}

async function heartbeat(state: State) {
  if (!state.enrollment || !state.policy) return;
  await request('browser/heartbeat', state.enrollment.token, {
    policyVersion: state.policy.version,
    chatGptCoverage: state.chatGptEnabled ? state.coveragePending : undefined,
    domainRulesApplied: state.domainRules && (state.domainRules.allow.length || state.domainRules.block.length) ? true : undefined,
  });
  state.coveragePending = undefined;
}

async function enroll(state: State, grant: unknown, managedHash?: string): Promise<Reply> {
  if (state.enrollment) return { summary: summary(state), error: 'This browser is already enrolled.' };
  if (!isToken(grant)) return { summary: summary(state), error: 'Paste the 64-character enrollment grant from Control.' };
  let enrollment;
  try {
    enrollment = await request('enroll', undefined, { grant });
  } catch (error) {
    const rejected = error instanceof HttpError && error.status === 401;
    if (managedHash) {
      state.managedEnrollment = rejected ? 'rejected' : 'retrying';
      if (rejected) state.usedManagedGrant = managedHash;
      await save(state);
    }
    return { summary: summary(state), error: rejected
      ? 'The grant is invalid, expired, or already used. Create a new grant in Control.'
      : 'Control is unavailable. Check that the local API is running and try again.' };
  }
  if (!isRecord(enrollment) || !isToken(enrollment.token) || !isId(enrollment.installationId)) {
    return { summary: summary(state), error: 'Control returned an invalid enrollment response.' };
  }
  const next: State = {
    status: 'offline', enrollment: { installationId: enrollment.installationId, token: enrollment.token,
      source: managedHash ? 'managed' : 'manual' },
    queue: [], discarded: 0,
    usedManagedGrant: managedHash ?? state.usedManagedGrant,
  };
  await save(next);
  await sync(next);
  return { summary: summary(next) };
}

async function syncOrEnroll(state: State): Promise<Reply> {
  if (state.enrollment) {
    await sync(state);
    return { summary: summary(state) };
  }
  if (state.status === 'revoked' && state.domainRulesError) {
    await applyDomainRules(state, emptyDomainRules).catch(() => undefined);
    await save(state);
  }
  const managed = await chrome.storage.managed.get(managedGrantKey).catch(() => ({} as Record<string, unknown>));
  const grant = managed[managedGrantKey];
  if (!isToken(grant)) {
    const status = grant === undefined ? undefined : 'invalid';
    if (state.managedEnrollment !== status) {
      state.managedEnrollment = status;
      await save(state);
    }
    return { summary: summary(state) };
  }
  const hashBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(grant));
  const hash = Array.from(new Uint8Array(hashBytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
  if (state.usedManagedGrant === hash) return { summary: summary(state) };
  return enroll(state, grant, hash);
}

function scheduleDelivery() {
  if (deliveryScheduled) return;
  deliveryScheduled = true;
  void serial(async () => {
    deliveryScheduled = false;
    await deliver(await readState());
  }).catch(() => undefined);
}

async function onMessage(message: Record<string, unknown>, app: AppId | undefined): Promise<Reply> {
  const state = await readState();
  if (message.type === 'enroll') return enroll(state, message.grant);
  if (message.type === 'sync') return syncOrEnroll(state);
  if (message.type === 'coverage' && state.chatGptEnabled && state.enrollment &&
      message.installationId === state.enrollment.installationId &&
      (message.coverage === 'ready' || message.coverage === 'unsupported')) {
    state.coveragePending = message.coverage;
    await save(state);
    if (state.status === 'connected') {
      try {
        await heartbeat(state);
      } catch (error) {
        await lostConnection(state, error);
      }
      await save(state);
    }
  }
  if (message.type === 'decision' && state.enrollment && message.installationId === state.enrollment.installationId) {
    const event = readMetadata(message.event);
    if (!event || event.appId !== app || (app === chatGptApp && !state.chatGptEnabled)) {
      return { summary: summary(state), error: 'Invalid event metadata.' };
    }
    if (state.queue.some(({ eventId }) => eventId === event.eventId)) return { summary: summary(state) };
    if (state.queue.length >= maxQueue) {
      state.queue.shift();
      state.discarded++;
    }
    state.queue.push(event);
    await save(state);
    if (state.status === 'connected') scheduleDelivery();
  }
  return { summary: summary(state) };
}

async function observeApp(appId: DiscoveryApp, observedAt: string) {
  const state = await readState();
  if (!state.enrollment || !state.policy?.discoveryEnabled) return {};
  state.observations ??= {};
  const previous = state.observations[appId];
  if (!previous || observedAt > previous.observedAt) {
    state.observations[appId] = { appId, observedAt, policyVersion: state.policy.version };
    await save(state);
  }
  if (state.status === 'connected') scheduleDelivery();
  return {};
}

chrome.runtime.onMessage.addListener((message: unknown, sender, reply: (response: Reply) => void) => {
  if (sender.id !== chrome.runtime.id || !isRecord(message)) return;
  if (message.type === 'observe-app') {
    const app = sender.tab && sender.frameId === 0 && sender.documentLifecycle === 'active' && discoveredApp(sender.url);
    if (!app) return;
    const observedAt = new Date().toISOString();
    serial(() => observeApp(app, observedAt)).then(reply, () => reply({}));
    return true;
  }
  const popup = sender.url === chrome.runtime.getURL('popup.html');
  const app = sender.url === fixtureUrl ? fixtureApp : isChatGptPage(sender.url) ? chatGptApp : undefined;
  const allowed = message.type === 'status' || message.type === 'sync' ||
    (popup && message.type === 'enroll') || (app && message.type === 'decision') ||
    (app === chatGptApp && message.type === 'coverage');
  if (!(popup || app) || !allowed) return;
  serial(() => onMessage(message, app)).then(reply, () => reply({ error: 'The extension could not access local storage.' }));
  return true;
});

function synchronizeInBackground() {
  void serial(async () => syncOrEnroll(await readState())).catch(() => undefined);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === alarmName) synchronizeInBackground();
});
chrome.runtime.onStartup.addListener(synchronizeInBackground);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'managed' && managedGrantKey in changes) synchronizeInBackground();
});

void serial(async () => {
  if (!await chrome.alarms.get(alarmName)) await chrome.alarms.create(alarmName, { periodInMinutes: 0.5 });
  const state = await readState();
  if (!state.enrollment) await syncOrEnroll(state);
}).catch(() => undefined);
