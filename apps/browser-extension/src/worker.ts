import {
  chatGptApp, fixtureApp, fixtureDetector, fixtureRule, fixtureUrl, isChatGptPage, isId, isMode, isRecord, isToken, isVersion, readMetadata,
  type AppId, type Coverage, type Policy, type PolicyEvent, type Reply, type Summary,
} from './protocol';

declare const CONTROL_ORIGIN: string;

type Enrollment = { installationId: string; token: string };
type State = {
  status: Summary['status'];
  enrollment?: Enrollment;
  policy?: Policy;
  chatGptEnabled?: boolean;
  coveragePending?: Coverage;
  queue: PolicyEvent[];
  discarded: number;
};

const key = 'controlState';
const alarmName = 'control-sync';
const maxQueue = 100;
let work = Promise.resolve();
let deliveryScheduled = false;

const setup = chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });

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
    status: state.status, installationId: state.enrollment?.installationId,
    policy: state.policy, chatGptEnabled: state.chatGptEnabled, queued: state.queue.length, discarded: state.discarded,
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

function lostConnection(state: State, error: unknown) {
  if (error instanceof HttpError && error.status === 401) {
    state.status = 'revoked';
    state.enrollment = undefined;
    state.coveragePending = undefined;
    state.discarded += state.queue.length;
    state.queue = [];
  } else {
    state.status = 'offline';
  }
}

async function deliver(state: State) {
  if (!state.enrollment || state.queue.length === 0) return;
  for (let delivered = 0; delivered < 20 && state.queue.length; delivered++) {
    try {
      await request('browser/events', state.enrollment.token, state.queue[0]);
    } catch (error) {
      if (!(error instanceof HttpError && error.status === 400)) {
        lostConnection(state, error);
        break;
      }
      state.discarded++;
    }
    state.queue.shift();
  }
  await save(state);
}

async function sync(state: State) {
  if (!state.enrollment) return;
  const { token } = state.enrollment;
  try {
    const policy = await request('browser/policy', token);
    if (!isRecord(policy) || !isVersion(policy.version) || !isMode(policy.mode) ||
        policy.appId !== fixtureApp || policy.ruleId !== fixtureRule || policy.detectorCategory !== fixtureDetector) {
      throw new Error('Unknown policy format');
    }
    if (!state.policy || policy.version > state.policy.version ||
        (policy.version === state.policy.version && policy.mode === state.policy.mode)) {
      state.policy = { version: policy.version, mode: policy.mode };
      state.chatGptEnabled = Array.isArray(policy.appIds) && policy.appIds.includes(chatGptApp);
      await save(state);
    }
    await heartbeat(state);
    state.status = 'connected';
    await save(state);
    await deliver(state);
  } catch (error) {
    lostConnection(state, error);
    await save(state);
  }
}

async function heartbeat(state: State) {
  if (!state.enrollment || !state.policy) return;
  await request('browser/heartbeat', state.enrollment.token, {
    policyVersion: state.policy.version,
    chatGptCoverage: state.chatGptEnabled ? state.coveragePending : undefined,
  });
  state.coveragePending = undefined;
}

async function enroll(state: State, grant: unknown): Promise<Reply> {
  if (state.enrollment) return { summary: summary(state), error: 'This browser is already enrolled.' };
  if (!isToken(grant)) return { summary: summary(state), error: 'Paste the 64-character enrollment grant from Control.' };
  let enrollment;
  try {
    enrollment = await request('enroll', undefined, { grant });
  } catch (error) {
    return { summary: summary(state), error: error instanceof HttpError && error.status === 401
      ? 'The grant is invalid, expired, or already used. Create a new grant in Control.'
      : 'Control is unavailable. Check that the local API is running and try again.' };
  }
  if (!isRecord(enrollment) || !isToken(enrollment.token) || !isId(enrollment.installationId)) {
    return { summary: summary(state), error: 'Control returned an invalid enrollment response.' };
  }
  const next: State = {
    status: 'offline', enrollment: { installationId: enrollment.installationId, token: enrollment.token },
    queue: [], discarded: 0,
  };
  await save(next);
  await sync(next);
  return { summary: summary(next) };
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
  if (message.type === 'sync') await sync(state);
  if (message.type === 'coverage' && state.chatGptEnabled && state.enrollment &&
      message.installationId === state.enrollment.installationId &&
      (message.coverage === 'ready' || message.coverage === 'unsupported')) {
    state.coveragePending = message.coverage;
    await save(state);
    if (state.status === 'connected') {
      try {
        await heartbeat(state);
      } catch (error) {
        lostConnection(state, error);
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

chrome.runtime.onMessage.addListener((message: unknown, sender, reply: (response: Reply) => void) => {
  if (sender.id !== chrome.runtime.id || !isRecord(message)) return;
  const popup = sender.url === chrome.runtime.getURL('popup.html');
  const app = sender.url === fixtureUrl ? fixtureApp : isChatGptPage(sender.url) ? chatGptApp : undefined;
  const allowed = message.type === 'status' || message.type === 'sync' ||
    (popup && message.type === 'enroll') || (app && message.type === 'decision') ||
    (app === chatGptApp && message.type === 'coverage');
  if (!(popup || app) || !allowed) return;
  serial(() => onMessage(message, app)).then(reply, () => reply({ error: 'The extension could not access local storage.' }));
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === alarmName) void serial(async () => sync(await readState())).catch(() => undefined);
});

void serial(async () => {
  if (!await chrome.alarms.get(alarmName)) await chrome.alarms.create(alarmName, { periodInMinutes: 0.5 });
}).catch(() => undefined);
