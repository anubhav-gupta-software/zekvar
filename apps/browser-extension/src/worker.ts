import {
  aiPromptApps, chatGptApp, claudeApp, discoveredApp, discoveryPermission, fixtureApp, fixtureDetector, fixtureRule, geminiApp, isDetectorMode,
  isId, isMode, isRecord, isToken, isVersion, promptApp, readMetadata,
  type AiPromptApp, type AppId, type AppObservation, type Coverage, type DiscoveryApp, type Policy, type PolicyEvent,
  type Reply, type Summary,
} from './protocol';
import { domainRuleLimit, emptyDomainRules, emptyPathRules, installDomainRules, readDomainRules, readPathRules,
  ruleCount, sameDomainRules, type DomainRules, type PathRules } from './domain-rules';
import { isFileInspection, isUploadModes, readTargetedUpload, sameUploadTypes, uploadApps, uploadsOff, type TargetedUploads } from '../../../contracts/policy/uploads';
import { collectExtensionInventory } from './extension-inventory';
import type { InventoryStatus } from '../../../contracts/policy/extension-inventory';
import { isCustomAppId, readCustomApps, type CustomApp } from '../../../contracts/policy/discovery';
import { leaseTime, readExceptionLease, sampleClock, type BrowserLease } from './prompt-exceptions';

declare const CONTROL_ORIGIN: string;

type Enrollment = { installationId: string; token: string; source?: Summary['enrollmentSource'] };
type PendingCoverage = { coverage: Coverage; observedAt: number };
type State = {
  status: Summary['status'];
  controlOrigin?: string;
  originChanged?: boolean;
  enrollment?: Enrollment;
  policy?: Policy & { customApps?: CustomApp[] };
  domainRules?: DomainRules;
  pathRules?: PathRules;
  domainRulesError?: boolean;
  chatGptEnabled?: boolean;
  coveragePending?: PendingCoverage | Coverage;
  geminiEnabled?: boolean;
  geminiCoveragePending?: PendingCoverage | Coverage;
  claudeCoveragePending?: PendingCoverage | Coverage;
  queue: PolicyEvent[];
  observations?: Partial<Record<DiscoveryApp, AppObservation>>;
  inventoryStatus?: InventoryStatus;
  inventoryReceipt?: { policyVersion: number; assignmentVersion: number; digest: string; reportedAt: number };
  discarded: number;
  managedEnrollment?: Summary['managedEnrollment'];
  usedManagedGrant?: string;
};

const key = 'controlState';
const alarmName = 'control-sync';
const maxQueue = 100;
const pendingCoverageLifetimeMs = 60_000;
const inventoryRefreshMs = 15 * 60_000;
let work = Promise.resolve();
let deliveryScheduled = false;
let promptLease: { installationId: string; version: number; assignment?: number; lease: BrowserLease } | undefined;

const managedGrantKey = 'EnrollmentGrant';
const managedOriginKey = 'ControlOrigin';
const hostedControl = CONTROL_ORIGIN.startsWith('https:');
const extensionVersion = chrome.runtime.getManifest().version;
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
  const state = stored[key] as State | undefined;
  if (!state) return { status: 'standalone', controlOrigin: CONTROL_ORIGIN, queue: [], discarded: 0 };
  if (state.controlOrigin === CONTROL_ORIGIN) return state;
  // Older development builds only addressed loopback. Never migrate their credentials to a hosted origin.
  if (state.controlOrigin === undefined && !hostedControl) {
    state.controlOrigin = CONTROL_ORIGIN;
    await save(state);
    return state;
  }
  promptLease = undefined;
  const reset: State = {
    status: 'standalone', controlOrigin: CONTROL_ORIGIN, originChanged: true, queue: [],
    discarded: state.discarded + state.queue.length, domainRulesError: true,
  };
  await applyDomainRules(reset, emptyDomainRules).catch(() => undefined);
  await save(reset);
  return reset;
}

function save(state: State) {
  return chrome.storage.local.set({ [key]: state });
}

function appEnabled(state: State, app: AiPromptApp) {
  if (app === claudeApp) return state.policy?.claudePromptEnabled === true;
  return app === chatGptApp ? state.chatGptEnabled === true : state.geminiEnabled === true;
}

function clearCoverage(state: State) {
  state.coveragePending = undefined;
  state.geminiCoveragePending = undefined;
  state.claudeCoveragePending = undefined;
}

function summary(state: State): Summary {
  const { customApps, ...policy } = state.policy ?? {};
  return {
    status: state.status, installationId: state.enrollment?.installationId, enrollmentSource: state.enrollment?.source,
    policy: state.policy && policy as Policy, promptApps: aiPromptApps.filter((app) => appEnabled(state, app)),
    queued: state.queue.length, discarded: state.discarded,
    managedEnrollment: state.managedEnrollment, domainRulesError: state.domainRulesError,
    domainRuleCount: state.domainRules && ruleCount(state.domainRules),
    pathRuleCount: state.pathRules && ruleCount(state.pathRules),
    inventoryStatus: state.inventoryStatus,
    customDiscoveryCount: state.policy?.discoveryEnabled ? customApps?.length : undefined,
    promptExceptionLease: state.status === 'connected' ? currentPromptLease(state) : undefined,
    originChanged: state.originChanged,
  };
}

function currentPromptLease(state: State) {
  if (!promptLease || promptLease.installationId !== state.enrollment?.installationId ||
      promptLease.version !== state.policy?.version || promptLease.assignment !== state.policy?.assignmentVersion) return;
  const now = leaseTime(promptLease.lease);
  if (now !== undefined && promptLease.lease.grants.some((grant) => grant.expiresAtMs > now)) return promptLease.lease;
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
      ...(path === 'browser/policy' ? { 'X-Zekvar-Assignment-Aware': '1', 'X-Zekvar-Claude-Prompt': '1',
        'X-Zekvar-Private-Key': '1', 'X-Zekvar-File-Inspection': '1', 'X-Zekvar-Extension-Version': extensionVersion } : {}),
      ...(path === 'browser/heartbeat' ? { 'X-Zekvar-Composer-Coverage': '1' } : {}),
      ...(path === 'enroll' ? { 'X-Zekvar-Scoped-Enrollment': '1' } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) throw new HttpError(response.status);
  return response.status === 204 ? undefined : response.json();
}

async function applyDomainRules(state: State, rules: DomainRules, paths = emptyPathRules) {
  try {
    await installDomainRules(rules, paths);
    state.domainRules = rules;
    state.pathRules = paths;
    state.domainRulesError = undefined;
  } catch (error) {
    state.domainRulesError = true;
    throw error;
  }
}

async function lostConnection(state: State, error: unknown) {
  promptLease = undefined;
  if (error instanceof HttpError && error.status === 401) {
    state.status = 'revoked';
    state.enrollment = undefined;
    clearCoverage(state);
    state.observations = undefined;
    state.inventoryStatus = undefined;
    state.inventoryReceipt = undefined;
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
    if (!observation) continue;
    if (isCustomAppId(observation.appId) &&
        (!state.policy?.customApps?.some(({ id }) => id === observation.appId) || !await canDiscoverCustomApps())) {
      delete state.observations[observation.appId];
      continue;
    }
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

function readTargetedUploads(value: unknown): TargetedUploads {
  if (value === undefined) return {};
  if (!isRecord(value) || Array.isArray(value)) throw new Error('Invalid scoped file upload rules');
  const filters: TargetedUploads = {};
  for (const app of uploadApps) {
    if (!Object.hasOwn(value, app)) continue;
    const filter = readTargetedUpload(value[app]);
    if (!filter) throw new Error('Invalid scoped file upload rule');
    filters[app] = filter;
  }
  if (Object.keys(value).length !== Object.keys(filters).length) throw new Error('Unknown scoped file upload destination');
  return filters;
}

function sameTargetedUploads(before: TargetedUploads, after: TargetedUploads) {
  return uploadApps.every((app) => before[app]?.mode === after[app]?.mode &&
    sameUploadTypes(before[app]?.types ?? [], after[app]?.types ?? []));
}

async function sync(state: State) {
  if (!state.enrollment) return;
  const { token } = state.enrollment;
  try {
    const requestedAt = sampleClock();
    const policy = await request('browser/policy', token);
    if (!isRecord(policy) || !isVersion(policy.version) || !isMode(policy.mode) ||
        (policy.assignmentVersion !== undefined && !isVersion(policy.assignmentVersion)) ||
        (policy.githubPatMode !== undefined && !isDetectorMode(policy.githubPatMode)) ||
        (policy.paymentCardMode !== undefined && !isDetectorMode(policy.paymentCardMode)) ||
        (policy.privateKeyMode !== undefined && !isDetectorMode(policy.privateKeyMode)) ||
        (policy.fileInspection !== undefined && !isFileInspection(policy.fileInspection)) ||
        (policy.uploadModes !== undefined && !isUploadModes(policy.uploadModes)) ||
        (policy.discoveryEnabled !== undefined && typeof policy.discoveryEnabled !== 'boolean') ||
        (policy.extensionInventoryEnabled !== undefined && typeof policy.extensionInventoryEnabled !== 'boolean') ||
        (policy.claudePromptEnabled !== undefined && typeof policy.claudePromptEnabled !== 'boolean') ||
        policy.appId !== fixtureApp || policy.ruleId !== fixtureRule || policy.detectorCategory !== fixtureDetector) {
      throw new Error('Unknown policy format');
    }
    const githubPatMode = policy.githubPatMode ?? 'off';
    const paymentCardMode = policy.paymentCardMode ?? 'off';
    const privateKeyMode = policy.privateKeyMode;
    const fileInspection = policy.fileInspection;
    const uploads = policy.uploadModes ?? uploadsOff;
    const previousUploads = state.policy?.uploadModes;
    const targetedUploads = readTargetedUploads(policy.targetedUploads);
    const previousTargets = state.policy?.targetedUploads;
    if (uploadApps.some((app) => targetedUploads[app] && uploads[app] !== 'off')) {
      throw new Error('Invalid combination of file upload rules');
    }
    const discoveryEnabled = policy.discoveryEnabled ?? false;
    const customApps = readCustomApps(policy.customApps);
    if (!customApps) throw new Error('Invalid custom app catalog');
    const previousCatalog = state.policy?.customApps;
    const lease = readExceptionLease(policy.promptExceptionLease, requestedAt);
    if (policy.promptExceptionLease !== undefined && !lease) throw new Error('Invalid prompt exception lease');
    const extensionInventoryEnabled = policy.extensionInventoryEnabled ?? false;
    const claudePromptEnabled = policy.claudePromptEnabled === true && Array.isArray(policy.appIds) && policy.appIds.includes(claudeApp);
    const domainRules = readDomainRules(policy.domainRules);
    const pathRules = readPathRules(policy.pathRules);
    if (!domainRules || !pathRules || ruleCount(domainRules) + ruleCount(pathRules) > domainRuleLimit) {
      throw new Error('Invalid navigation rules');
    }
    const assignment = policy.assignmentVersion ?? 0;
    const previousAssignment = state.policy?.assignmentVersion ?? 0;
    // Earlier Browser builds may have this version cached without settings they did not support.
    if (!state.policy || assignment > previousAssignment || (assignment === previousAssignment &&
      (policy.version > state.policy.version || (policy.version === state.policy.version &&
        policy.mode === state.policy.mode && githubPatMode === (state.policy.githubPatMode ?? 'off') &&
        (state.policy.paymentCardMode === undefined || paymentCardMode === state.policy.paymentCardMode) &&
        (state.policy.privateKeyMode === undefined || privateKeyMode === state.policy.privateKeyMode) &&
        (state.policy.fileInspection === undefined || fileInspection !== undefined &&
          uploadApps.every((app) => state.policy?.fileInspection?.[app] === fileInspection[app])) &&
        (!previousUploads || uploads.chatgpt === previousUploads.chatgpt && uploads.gemini === previousUploads.gemini) &&
        (!previousTargets || sameTargetedUploads(previousTargets, targetedUploads)) &&
        discoveryEnabled === (state.policy.discoveryEnabled ?? false) &&
        (!previousCatalog || (previousCatalog.length === customApps.length && previousCatalog.every(({ id, host, name }, index) =>
          id === customApps[index].id && host === customApps[index].host && name === customApps[index].name))) &&
        (state.policy.extensionInventoryEnabled === undefined || extensionInventoryEnabled === state.policy.extensionInventoryEnabled) &&
        (state.policy.claudePromptEnabled === undefined || claudePromptEnabled === state.policy.claudePromptEnabled) &&
        sameDomainRules(domainRules, state.domainRules ?? emptyDomainRules) &&
        (!state.pathRules || sameDomainRules(pathRules, state.pathRules)))))) {
      await applyDomainRules(state, domainRules, pathRules);
      if (policy.version !== state.policy?.version || assignment !== previousAssignment) clearCoverage(state);
      state.policy = { version: policy.version, mode: policy.mode, githubPatMode, paymentCardMode, privateKeyMode, fileInspection,
        discoveryEnabled, customApps, extensionInventoryEnabled, claudePromptEnabled,
        assignmentVersion: policy.assignmentVersion, uploadModes: { chatgpt: uploads.chatgpt, gemini: uploads.gemini }, targetedUploads };
      promptLease = lease ? { installationId: state.enrollment.installationId, version: policy.version,
        assignment: policy.assignmentVersion, lease } : undefined;
      if (!discoveryEnabled || assignment !== previousAssignment) state.observations = undefined;
      state.chatGptEnabled = Array.isArray(policy.appIds) && policy.appIds.includes(chatGptApp);
      state.geminiEnabled = Array.isArray(policy.appIds) && policy.appIds.includes(geminiApp);
      await save(state);
    } else {
      promptLease = undefined;
    }
    await heartbeat(state);
    state.status = 'connected';
    await save(state);
    await deliver(state);
    await reportExtensionInventory(state);
  } catch (error) {
    await lostConnection(state, error);
    await save(state);
  }
}

async function reportExtensionInventory(state: State) {
  const policy = state.policy;
  if (!state.enrollment || state.status !== 'connected') return;
  if (!policy?.extensionInventoryEnabled) {
    if (state.inventoryReceipt || state.inventoryStatus) {
      state.inventoryReceipt = undefined;
      state.inventoryStatus = undefined;
      await save(state);
    }
    return;
  }
  const snapshot = await collectExtensionInventory();
  const capturedAt = Date.now();
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(snapshot)));
  const digest = Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
  const assignmentVersion = policy.assignmentVersion ?? 0;
  const receipt = state.inventoryReceipt;
  if (receipt?.digest === digest && receipt.policyVersion === policy.version && receipt.assignmentVersion === assignmentVersion &&
      capturedAt - receipt.reportedAt < inventoryRefreshMs && state.inventoryStatus === snapshot.status) return;
  try {
    await request('browser/extension-inventory', state.enrollment.token, {
      ...snapshot, capturedAt: new Date(capturedAt).toISOString(), policyVersion: policy.version, assignmentVersion,
    });
    state.inventoryReceipt = { policyVersion: policy.version, assignmentVersion, digest, reportedAt: capturedAt };
    state.inventoryStatus = snapshot.status;
  } catch (error) {
    if (error instanceof HttpError && error.status === 401) await lostConnection(state, error);
    else state.inventoryStatus = snapshot.status === 'permission_required' ? snapshot.status : 'unavailable';
  }
  await save(state);
}

function recentCoverage(pending: PendingCoverage | Coverage | undefined, now: number) {
  // Older releases cached the status without an observation time.
  if (!pending || typeof pending === 'string') return undefined;
  const age = now - pending.observedAt;
  return age >= 0 && age < pendingCoverageLifetimeMs ? pending.coverage : undefined;
}

async function heartbeat(state: State) {
  if (!state.enrollment || !state.policy) return;
  const scopedUploads = uploadApps.some((app) => state.policy?.targetedUploads?.[app]);
  const now = Date.now();
  await request('browser/heartbeat', state.enrollment.token, {
    policyVersion: state.policy.version,
    assignmentVersion: state.policy.assignmentVersion,
    chatGptCoverage: state.chatGptEnabled ? recentCoverage(state.coveragePending, now) : undefined,
    geminiCoverage: state.geminiEnabled ? recentCoverage(state.geminiCoveragePending, now) : undefined,
    claudeCoverage: state.policy.claudePromptEnabled ? recentCoverage(state.claudeCoveragePending, now) : undefined,
    claudePromptApplied: state.policy.claudePromptEnabled || undefined,
    paymentCardModeApplied: isMode(state.policy.paymentCardMode) ? true : undefined,
    privateKeyModeApplied: isMode(state.policy.privateKeyMode) ? true : undefined,
    fileInspectionApplied: uploadApps.some((app) => state.policy?.fileInspection?.[app]) ? true : undefined,
    uploadControlsApplied: scopedUploads || (state.policy.uploadModes &&
      uploadApps.some((app) => state.policy?.uploadModes?.[app] !== 'off')) ? true : undefined,
    uploadTypesApplied: scopedUploads ? true : undefined,
    customDiscoveryApplied: state.policy.discoveryEnabled && state.policy.customApps?.length && await canDiscoverCustomApps() ? true : undefined,
    promptExceptionsApplied: currentPromptLease(state) ? true : undefined,
    domainRulesApplied: state.domainRules && ruleCount(state.domainRules) ? true : undefined,
    pathRulesApplied: state.pathRules && ruleCount(state.pathRules) ? true : undefined,
  });
  clearCoverage(state);
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
      : 'Control is unavailable. Check your connection to Control and try again.' };
  }
  if (!isRecord(enrollment) || !isToken(enrollment.token) || !isId(enrollment.installationId)) {
    return { summary: summary(state), error: 'Control returned an invalid enrollment response.' };
  }
  const next: State = {
    status: 'offline', controlOrigin: CONTROL_ORIGIN, enrollment: { installationId: enrollment.installationId, token: enrollment.token,
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
  if (state.domainRulesError) {
    await applyDomainRules(state, emptyDomainRules).catch(() => undefined);
    await save(state);
  }
  const managed = await chrome.storage.managed.get([managedGrantKey, managedOriginKey]).catch(() => ({} as Record<string, unknown>));
  const grant = managed[managedGrantKey];
  if (!isToken(grant)) {
    const status = grant === undefined ? undefined : 'invalid';
    if (state.managedEnrollment !== status) {
      state.managedEnrollment = status;
      await save(state);
    }
    return { summary: summary(state) };
  }
  const origin = managed[managedOriginKey];
  if ((hostedControl || origin !== undefined) && origin !== CONTROL_ORIGIN) {
    if (state.managedEnrollment !== 'origin_mismatch') {
      state.managedEnrollment = 'origin_mismatch';
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
  if (message.type === 'coverage' && app && app !== fixtureApp && appEnabled(state, app) && state.enrollment &&
      message.installationId === state.enrollment.installationId &&
      (message.coverage === 'ready' || message.coverage === 'unsupported')) {
    if (message.version !== state.policy?.version || message.assignmentVersion !== state.policy?.assignmentVersion) {
      return { summary: summary(state), error: 'Composer coverage belongs to an older policy.' };
    }
    const observation = { coverage: message.coverage, observedAt: Date.now() } satisfies PendingCoverage;
    if (app === claudeApp) state.claudeCoveragePending = observation;
    else if (app === chatGptApp) state.coveragePending = observation;
    else state.geminiCoveragePending = observation;
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
    if (!event || event.appId !== app || (app !== fixtureApp && !appEnabled(state, app))) {
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

async function observeApp(state: State, appId: DiscoveryApp, observedAt: string) {
  if (!state.enrollment || !state.policy?.discoveryEnabled) return {};
  state.observations ??= {};
  const previous = state.observations[appId];
  if (!previous || observedAt > previous.observedAt) {
    state.observations[appId] = { appId, observedAt, policyVersion: state.policy.version, assignmentVersion: state.policy.assignmentVersion };
    await save(state);
  }
  if (state.status === 'connected') scheduleDelivery();
  return {};
}

function observeCustomApp(details: chrome.webNavigation.WebNavigationTransitionCallbackDetails) {
  if (details.frameId !== 0 || details.documentLifecycle !== 'active') return;
  const url = new URL(details.url);
  if (url.protocol !== 'https:' || url.port) return;
  const host = url.hostname;
  const observedAt = new Date().toISOString();
  void serial(async () => {
    const state = await readState();
    const app = state.policy?.customApps?.find((entry) => entry.host === host);
    if (app && await canDiscoverCustomApps()) await observeApp(state, app.id, observedAt);
  }).catch(() => undefined);
}

function listenForCustomApps() {
  const event = chrome.webNavigation?.onCommitted;
  if (event && !event.hasListener(observeCustomApp)) {
    event.addListener(observeCustomApp, { url: [{ schemes: ['https'], ports: [443] }] });
  }
}

async function canDiscoverCustomApps() {
  return chrome.webNavigation?.onCommitted.hasListener(observeCustomApp) === true &&
    await chrome.permissions.contains(discoveryPermission);
}

chrome.runtime.onMessage.addListener((message: unknown, sender, reply: (response: Reply) => void) => {
  if (sender.id !== chrome.runtime.id || !isRecord(message)) return;
  if (message.type === 'observe-app') {
    const app = sender.tab && sender.frameId === 0 && sender.documentLifecycle === 'active' && discoveredApp(sender.url);
    if (!app) return;
    const observedAt = new Date().toISOString();
    serial(async () => observeApp(await readState(), app, observedAt)).then(reply, () => reply({}));
    return true;
  }
  const popup = sender.url === chrome.runtime.getURL('popup.html');
  const app = sender.tab && sender.frameId === 0 && sender.documentLifecycle === 'active' ? promptApp(sender.url) : undefined;
  const allowed = message.type === 'status' || message.type === 'sync' ||
    (popup && message.type === 'enroll') || (app && message.type === 'decision') ||
    (app && app !== fixtureApp && message.type === 'coverage');
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
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'update') synchronizeInBackground();
});
chrome.permissions.onAdded.addListener(({ permissions }) => {
  if (permissions?.includes('webNavigation')) listenForCustomApps();
  if (permissions?.some((permission) => permission === 'management' || permission === 'webNavigation')) synchronizeInBackground();
});
chrome.permissions.onRemoved.addListener(({ permissions }) => {
  if (permissions?.includes('webNavigation')) void serial(async () => {
    const state = await readState();
    if (!state.observations) return;
    for (const appId of Object.keys(state.observations)) {
      if (isCustomAppId(appId)) delete state.observations[appId];
    }
    await save(state);
  }).catch(() => undefined);
  if (permissions?.some((permission) => permission === 'management' || permission === 'webNavigation')) synchronizeInBackground();
});
listenForCustomApps();
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'managed' && (managedGrantKey in changes || managedOriginKey in changes)) synchronizeInBackground();
});

void serial(async () => {
  if (!await chrome.alarms.get(alarmName)) await chrome.alarms.create(alarmName, { periodInMinutes: 0.5 });
  const state = await readState();
  if (!state.enrollment) await syncOrEnroll(state);
}).catch(() => undefined);
