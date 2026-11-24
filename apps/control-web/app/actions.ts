'use server';

import { randomUUID } from 'node:crypto';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../lib/api';
import { classifications, decisionLabels, detectorModes, discoveryAppName, isDiscoveredAppId, isId, modes,
  type AppClassification, type DetectorMode, type Feedback, type Mode } from '../lib/control';
import { endSession, sessionToken, startSession } from '../lib/session';
import { cleanupCounts, retentionFields, type RetentionField, type RetentionPolicy } from '../lib/retention';
import { navigationRuleLimitError, readNavigationRules } from '../lib/navigation';
import { isDetectorMode, isMode, readIdentifierProtection, type IdentifierProtection } from '../../../contracts/policy/prompt';
import { identifierFormatError } from '../../../contracts/policy/organization-identifiers';
import { isUploadMode, parseUploadTypes, uploadTypesError } from '../../../contracts/policy/uploads';
import { customAppError, isCustomAppId, parseCustomApps } from '../../../contracts/policy/discovery';
import { promptExceptionError, readPromptExceptions } from '../../../contracts/policy/prompt-exceptions';
import { parseExtensionDeployment } from '../lib/extension-deployment';
import { parseBrowserHardening } from '../lib/browser-hardening';
import { isClipboardMode } from '../../../contracts/policy/clipboard';
import type { FleetSelection } from '../lib/fleet';
import { aiAppAccessCatalog, readBlockedAiAppHosts } from '../../../contracts/policy/ai-app-access';
import { domainRuleLimit, ruleCount } from '../../../contracts/policy/domains';
import { eventPath, isTriageDisposition, isTriageId, isTriageStatus } from '../lib/triage';
import { casePath, isCaseCategory, type EventReference } from '../lib/cases';
import { alertPath } from '../lib/alerts';

export async function signIn(_previous: Feedback, form: FormData): Promise<Feedback> {
  const token = form.get('token');
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token.trim())) {
    return { error: 'Enter your 64-character Control token.' };
  }
  try {
    await controlApi.session(token.trim());
  } catch (error) {
    return { error: error instanceof ApiError && error.status === 401
      ? 'This Control token was rejected.'
      : 'Control API is unavailable. Start it and try again.' };
  }
  await startSession(token.trim());
  redirect('/');
}

export async function signOut() {
  await endSession();
  redirect('/');
}

function readTriageUpdate(form: FormData) {
  const rawRevision = form.get('revision');
  const expectedRevision = Number(rawRevision);
  const status = form.get('status');
  const disposition = form.get('disposition');
  const assignee = form.get('assignee');
  if (typeof rawRevision !== 'string' || !/^\d+$/.test(rawRevision) ||
      expectedRevision > 2_147_483_647 || !isTriageStatus(status) || (assignee !== '' && !isTriageId(assignee)) ||
      (status === 'resolved' ? !isTriageDisposition(disposition) : disposition !== null)) {
    return;
  }
  return { expectedRevision, status, disposition: isTriageDisposition(disposition) ? disposition : null, assigneeId: assignee || null };
}

export async function saveEventTriage(installationId: string, eventId: string, _previous: Feedback, form: FormData): Promise<Feedback> {
  const change = readTriageUpdate(form);
  if (!isTriageId(installationId) || !isTriageId(eventId) || !change) {
    return { error: 'Choose a valid triage status, resolution, and assignee.' };
  }
  return perform(async (token) => {
    try {
      await controlApi.saveEventTriage(token, installationId, eventId, change);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'event_triage_stale') {
        return { error: 'Someone updated this event. Reload the event and review the latest triage before saving.' };
      }
      if (error instanceof ApiError && error.code === 'event_assignee_unavailable') {
        return { error: 'That administrator is unavailable. Reload the event and choose an active assignee.' };
      }
      throw error;
    }
    revalidatePath(eventPath(installationId, eventId));
    revalidatePath('/');
    revalidatePath('/audit');
    return { message: 'Event triage saved.' };
  });
}

function caseChangeError(error: unknown): Feedback {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'case_stale': return { error: 'Someone changed this case. Reload to review the current case before trying again.' };
      case 'case_resolved': return { error: 'Reopen the case before changing its linked events.' };
      case 'case_event_limit': return { error: 'This case already contains 100 retained events.' };
      case 'event_in_case': return { error: 'This event is already linked to another case. Open the event to see its current case.' };
      case 'case_request_conflict': return { error: 'This request was already used. Reload the event before creating a case.' };
      case 'event_assignee_unavailable': return { error: 'That administrator is unavailable. Reload the case and choose an active assignee.' };
    }
  }
  throw error;
}

function validCaseEvent(event: EventReference) {
  return isTriageId(event?.installationId) && isTriageId(event?.eventId);
}

export async function createIncidentCase(event: EventReference, _previous: Feedback, form: FormData): Promise<Feedback> {
  const requestId = form.get('requestId');
  const category = form.get('category');
  if (!validCaseEvent(event) || !isTriageId(requestId) || !isCaseCategory(category)) return { error: 'Choose a case category.' };
  const result = await perform(async (token) => {
    try { await controlApi.createCase(token, requestId, category, event); }
    catch (error) { return caseChangeError(error); }
    revalidatePath('/cases');
    revalidatePath('/audit');
    revalidatePath(eventPath(event.installationId, event.eventId));
    return {};
  });
  if (!result.error) redirect(casePath(requestId));
  return result;
}

export async function saveIncidentCase(id: string, _previous: Feedback, form: FormData): Promise<Feedback> {
  const change = readTriageUpdate(form);
  if (!isTriageId(id) || !change || change.expectedRevision < 1) return { error: 'Choose a valid case status, resolution, and assignee.' };
  return perform(async (token) => {
    try { await controlApi.saveCaseTriage(token, id, change); }
    catch (error) { return caseChangeError(error); }
    revalidatePath(casePath(id));
    revalidatePath('/cases');
    revalidatePath('/audit');
    return { message: 'Case triage saved.' };
  });
}

export async function linkIncidentEvent(id: string, event: EventReference, expectedRevision: number, linked: boolean): Promise<Feedback> {
  if (!isTriageId(id) || !validCaseEvent(event) || typeof linked !== 'boolean' ||
      !Number.isInteger(expectedRevision) || expectedRevision < 1 || expectedRevision > 2_147_483_647) {
    return { error: 'Choose a valid case and event.' };
  }
  const result = await perform(async (token) => {
    try { await controlApi.changeCaseMembership(token, id, event, expectedRevision, linked); }
    catch (error) { return caseChangeError(error); }
    revalidatePath(casePath(id));
    revalidatePath('/cases');
    revalidatePath('/audit');
    revalidatePath(eventPath(event.installationId, event.eventId));
    return { message: linked ? 'Event linked to case.' : 'Event unlinked from case.' };
  });
  if (linked && !result.error) redirect(casePath(id));
  return result;
}

async function perform(change: (token: string) => Promise<Feedback>): Promise<Feedback> {
  const token = await sessionToken();
  if (!token) return { error: 'Your session has expired. Reload and sign in again.' };
  try {
    return await change(token);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      await endSession();
      redirect('/?session=ended');
    }
    if (error instanceof ApiError && error.status === 403) {
      if (error.code === 'self_approval') return { error: 'A different named administrator must approve this request.' };
      if (error.code === 'named_administrator_required') return { error: 'Sign in as a named administrator to continue.' };
      return { error: 'Your Control role cannot make this change.' };
    }
    if (error instanceof ApiError && error.code === 'review_mode_changed') {
      return { error: 'The review requirement changed. Reload and review the policy before continuing.' };
    }
    if (error instanceof ApiError && error.code === 'sso_subject_exists') return { error: 'That identity already has Control access.' };
    if (error instanceof ApiError && error.code === 'enrollment_batch_exists') {
      return { error: 'This request already created a batch. Review the batch list and reload before issuing another.' };
    }
    if (error instanceof ApiError && error.status === 404) {
      return { error: 'That record is no longer available. Refresh the dashboard.' };
    }
    return { error: 'Control could not confirm the change. Refresh before trying again.' };
  }
}

export async function issueEnrollmentBatch(_previous: Feedback, form: FormData): Promise<Feedback> {
  const requestId = form.get('requestId');
  const groupId = form.get('groupId');
  const count = Number(form.get('count'));
  if (!isId(requestId) || (groupId !== '' && !isId(groupId)) || !Number.isInteger(count) || count < 1 || count > 25) {
    return { error: 'Choose a rollout group and a grant count from 1 to 25.' };
  }
  const result = await perform(async (token) => {
    const issuedEnrollmentBatch = await controlApi.issueEnrollmentBatch(token, requestId, groupId || null, count);
    revalidatePath('/enrollment');
    return { issuedEnrollmentBatch };
  });
  return { ...result, enrollmentRequestId: result.issuedEnrollmentBatch ? randomUUID() : requestId };
}

export async function cancelEnrollmentBatch(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('batchId');
  if (!isId(id)) return { error: 'Choose an enrollment batch.' };
  return perform(async (token) => {
    await controlApi.cancelEnrollmentBatch(token, id);
    revalidatePath('/enrollment');
    return { message: 'Unused grants cancelled.' };
  });
}

function readUploadSettings(form: FormData) {
  const chatgpt = form.get('upload-chatgpt');
  const gemini = form.get('upload-gemini');
  if (isUploadMode(chatgpt) && isUploadMode(gemini)) return { chatgpt, gemini };
}

function readUploadTypes(form: FormData) {
  const chatgpt = parseUploadTypes(String(form.get('upload-types-chatgpt') ?? ''));
  const gemini = parseUploadTypes(String(form.get('upload-types-gemini') ?? ''));
  if (chatgpt && gemini) return { chatgpt, gemini };
}

function readFileContentSettings(form: FormData) {
  const contentChatgpt = form.get('file-content-chatgpt');
  const contentGemini = form.get('file-content-gemini');
  if (contentChatgpt !== null || contentGemini !== null) {
    if (!isUploadMode(contentChatgpt) || !isUploadMode(contentGemini)) return null;
    return { fileContentModes: { chatgpt: contentChatgpt, gemini: contentGemini } };
  }
  const chatgpt = form.get('file-inspection-chatgpt');
  const gemini = form.get('file-inspection-gemini');
  if (chatgpt === null && gemini === null) return {};
  if ((chatgpt !== 'on' && chatgpt !== 'off') || (gemini !== 'on' && gemini !== 'off')) return null;
  return { fileInspection: { chatgpt: chatgpt === 'on', gemini: gemini === 'on' } };
}

export async function issueControlAccess(_previous: Feedback, form: FormData): Promise<Feedback> {
  const input = form.get('name');
  const name = typeof input === 'string' ? input.trim() : '';
  const role = form.get('role');
  const hours = Number(form.get('hours'));
  if (name.length < 2 || name.length > 64 || /[\x00-\x1f\x7f-\x9f]/.test(name) ||
      (role !== 'administrator' && role !== 'auditor') || !Number.isInteger(hours) || hours < 1 || hours > 720) {
    return { error: 'Enter a name, role, and token lifetime.' };
  }
  return perform(async (token) => {
    const issuedAccess = await controlApi.issueAccess(token, name, role, hours);
    revalidatePath('/access');
    return { issuedAccess };
  });
}

export async function revokeControlAccess(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('id');
  if (!isId(id)) return { error: 'Choose a valid credential.' };
  return perform(async (token) => {
    await controlApi.revokeAccess(token, id);
    revalidatePath('/access');
    return { message: 'Control access revoked.' };
  });
}

export async function issueEventFeedKey(_previous: Feedback, form: FormData): Promise<Feedback> {
  const requestId = form.get('requestId');
  const input = form.get('name');
  const name = typeof input === 'string' ? input.trim() : '';
  const days = Number(form.get('days'));
  if (!isId(requestId) || name.length < 2 || name.length > 64 || /[\x00-\x1f\x7f-\x9f]/.test(name) ||
      !Number.isInteger(days) || days < 1 || days > 90) return { error: 'Enter a name and a lifetime from 1 to 90 days.' };
  return perform(async (token) => {
    try {
      const issuedEventFeedKey = await controlApi.issueEventFeedKey(token, requestId, name, days);
      revalidatePath('/access');
      revalidatePath('/audit');
      return { issuedEventFeedKey };
    } catch (error) {
      if (error instanceof ApiError && error.code === 'event_feed_key_exists') {
        revalidatePath('/access');
        return { error: 'This request already issued a key. If you missed it, revoke it and issue a replacement.' };
      }
      if (error instanceof ApiError && error.code === 'event_feed_key_limit') {
        return { error: 'There are 20 active keys. Revoke a key before issuing another.' };
      }
      throw error;
    }
  });
}

export async function revokeEventFeedKey(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('id');
  if (!isId(id)) return { error: 'Choose a valid event feed key.' };
  return perform(async (token) => {
    await controlApi.revokeEventFeedKey(token, id);
    revalidatePath('/access');
    revalidatePath('/audit');
    return { message: 'Event feed key revoked.' };
  });
}

export async function addSsoIdentity(_previous: Feedback, form: FormData): Promise<Feedback> {
  const input = form.get('name');
  const name = typeof input === 'string' ? input.trim() : '';
  const role = form.get('role');
  const subject = form.get('subject');
  if (name.length < 2 || name.length > 64 || /[\x00-\x1f\x7f-\x9f]/.test(name) ||
      (role !== 'administrator' && role !== 'auditor') || typeof subject !== 'string' || !/^[!-~]{1,255}$/.test(subject)) {
    return { error: 'Enter a name, delegated role, and exact OIDC subject.' };
  }
  return perform(async (token) => {
    await controlApi.addSsoIdentity(token, name, role, subject);
    revalidatePath('/access');
    return { message: `Single sign-on access granted to ${name}.` };
  });
}

export async function publishPolicy(_previous: Feedback, form: FormData): Promise<Feedback> {
  const review = form.get('expectReview') === 'on';
  const expectedVersion = Number(form.get('expectedVersion'));
  const mode = form.get('mode') as Mode;
  const githubPatMode = form.get('githubPatMode') as DetectorMode;
  const paymentCardMode = form.get('paymentCardMode');
  const privateKeyMode = form.get('privateKeyMode');
  const ssnMode = form.get('ssnMode');
  const githubTokenMode = form.get('githubTokenMode');
  const clipboardMode = form.get('clipboardMode');
  const uploadModes = readUploadSettings(form);
  const uploadTypes = readUploadTypes(form);
  const fileContent = readFileContentSettings(form);
  const discovery = form.get('discoveryEnabled');
  const presetDiscovery = form.get('presetDiscoveryEnabled');
  const inventory = form.get('extensionInventoryEnabled');
  const claude = form.get('claudePromptEnabled');
  const groupId = form.get('groupId');
  if (groupId !== null && !isId(groupId)) return { error: 'Choose a valid rollout group.' };
  if (!Number.isInteger(expectedVersion) || expectedVersion < 1 || expectedVersion > 2147483647) {
    return { error: 'Reload the current policy before saving changes.' };
  }
  if (!modes.includes(mode) || !detectorModes.includes(githubPatMode) || !isDetectorMode(paymentCardMode) ||
      (privateKeyMode !== null && !isDetectorMode(privateKeyMode)) || (ssnMode !== null && !isDetectorMode(ssnMode)) ||
      (githubTokenMode !== null && !isDetectorMode(githubTokenMode)) ||
      (clipboardMode !== null && !isClipboardMode(clipboardMode)) || !uploadModes || !fileContent ||
      (discovery !== 'on' && discovery !== 'off') || (presetDiscovery !== null && presetDiscovery !== 'on' && presetDiscovery !== 'off') ||
      (inventory !== 'on' && inventory !== 'off') || (claude !== 'on' && claude !== 'off')) {
    return { error: 'Choose a setting for each policy control.' };
  }
  if (!uploadTypes) return { error: uploadTypesError };
  return perform(async (token) => {
    try {
      const policy = await controlApi.publish(token, { mode, githubPatMode, paymentCardMode, privateKeyMode: privateKeyMode ?? undefined,
        ssnMode: ssnMode ?? undefined, githubTokenMode: githubTokenMode ?? undefined, clipboardMode: clipboardMode ?? undefined,
        uploadModes, uploadTypes, ...fileContent,
        discoveryEnabled: discovery === 'on', presetDiscoveryEnabled: presetDiscovery === null ? undefined : presetDiscovery === 'on',
        extensionInventoryEnabled: inventory === 'on', claudePromptEnabled: claude === 'on', expectedVersion },
        review, groupId ?? undefined);
      if ('reviewId' in policy) return queued(policy.reviewId);
      refreshPolicyViews();
      return { message: `Version ${policy.version} published in ${decisionLabels[mode].toLowerCase()} mode.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409 && !error.code) {
        return { error: 'The policy changed. Reload and review the policy before saving changes.' };
      }
      throw error;
    }
  });
}

export async function classifyAiApp(_previous: Feedback, form: FormData): Promise<Feedback> {
  const app = form.get('appId');
  const status = form.get('status') as AppClassification;
  if (!isDiscoveredAppId(app) || !classifications.includes(status)) {
    return { error: 'Choose a cataloged app and a valid classification.' };
  }
  return perform(async (token) => {
    await controlApi.classifyApp(token, app, status);
    revalidatePath('/');
    return { message: `${isCustomAppId(app) ? 'App' : discoveryAppName(app)} classification saved.` };
  });
}

function navigationDraft(form: FormData) {
  const allow = form.get('allow');
  const block = form.get('block');
  const allowPaths = form.get('allowPaths');
  const blockPaths = form.get('blockPaths');
  if (typeof allow !== 'string' || typeof block !== 'string' || typeof allowPaths !== 'string' || typeof blockPaths !== 'string') {
    return { error: 'Enter the domain and path lists.' };
  }
  return readNavigationRules(allow, block, allowPaths, blockPaths);
}

export async function publishDomainRules(_previous: Feedback, form: FormData): Promise<Feedback> {
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  if (groupId !== null && !isId(groupId)) return { error: 'Choose a valid rollout group.' };
  if (!Number.isInteger(expectedVersion) || expectedVersion < 1 || expectedVersion > 2147483647) {
    return { error: 'Reload the policy before editing navigation rules.' };
  }
  const rules = navigationDraft(form);
  if (!rules.domainRules || !rules.pathRules) return { error: rules.error };
  return perform(async (token) => {
    try {
      const policy = await controlApi.publishNavigation(token, rules, expectedVersion, form.get('expectReview') === 'on', groupId ?? undefined);
      if ('reviewId' in policy) return queued(policy.reviewId);
      refreshPolicyViews();
      return { message: `Navigation rules published as version ${policy.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409 && !error.code) return { error: 'The policy changed. Reload and review the navigation rules again.' };
      if (error instanceof ApiError && error.code === 'navigation_rule_limit') return { error: navigationRuleLimitError };
      throw error;
    }
  });
}

export async function publishPreview(_previous: Feedback, form: FormData): Promise<Feedback> {
  const mode = form.get('mode');
  const githubPatMode = form.get('githubPatMode');
  const paymentCardMode = form.get('paymentCardMode');
  const privateKeyMode = form.get('privateKeyMode');
  const ssnMode = form.get('ssnMode');
  const githubTokenMode = form.get('githubTokenMode');
  const clipboardMode = form.get('clipboardMode');
  const uploadModes = readUploadSettings(form);
  const uploadTypes = readUploadTypes(form);
  const fileContent = readFileContentSettings(form);
  const discovery = form.get('discoveryEnabled');
  const presetDiscovery = form.get('presetDiscoveryEnabled');
  const inventory = form.get('extensionInventoryEnabled');
  const claude = form.get('claudePromptEnabled');
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  if (!isMode(mode) || !isDetectorMode(githubPatMode) || !isDetectorMode(paymentCardMode) ||
      (privateKeyMode !== null && !isDetectorMode(privateKeyMode)) || (ssnMode !== null && !isDetectorMode(ssnMode)) ||
      (githubTokenMode !== null && !isDetectorMode(githubTokenMode)) ||
      (clipboardMode !== null && !isClipboardMode(clipboardMode)) || !uploadModes || !fileContent ||
      (discovery !== 'on' && discovery !== 'off') || (presetDiscovery !== null && presetDiscovery !== 'on' && presetDiscovery !== 'off') ||
      (inventory !== 'on' && inventory !== 'off') ||
      (claude !== 'on' && claude !== 'off') ||
      (groupId !== null && !isId(groupId)) || !Number.isInteger(expectedVersion) || expectedVersion < 1 ||
      expectedVersion > 2147483647) {
    return { error: 'Run the preview again before publishing.' };
  }
  const { domainRules, pathRules, error } = navigationDraft(form);
  if (!domainRules || !pathRules) return { error };
  if (!uploadTypes) return { error: uploadTypesError };
  const customApps = parseCustomApps(String(form.get('customApps') ?? ''));
  if (!customApps) return { error: customAppError };
  const submittedHosts = form.getAll('blockedAiAppHost');
  const accessSettings = form.get('aiAppAccess') === 'present';
  const blockedAiAppHosts = accessSettings ? readBlockedAiAppHosts(submittedHosts) : undefined;
  if (accessSettings && (!blockedAiAppHosts || blockedAiAppHosts.some((host) => !aiAppAccessCatalog(customApps).some((app) => app.host === host)))) {
    return { error: 'Keep each blocked AI app in the draft catalog or clear its access block.' };
  }
  if (ruleCount(domainRules) + ruleCount(pathRules) + (blockedAiAppHosts?.length ?? 0) > domainRuleLimit) {
    return { error: navigationRuleLimitError };
  }
  let promptExceptions;
  try {
    promptExceptions = readPromptExceptions(JSON.parse(String(form.get('promptExceptions') ?? '[]')));
  } catch {
    return { error: promptExceptionError };
  }
  if (!promptExceptions) return { error: promptExceptionError };
  let identifierProtection: IdentifierProtection | undefined;
  const identifierInput = form.get('identifierProtection');
  if (identifierInput !== null) {
    try {
      if (typeof identifierInput === 'string') identifierProtection = readIdentifierProtection(JSON.parse(identifierInput));
    } catch {
      return { error: identifierFormatError };
    }
    if (!identifierProtection) return { error: identifierFormatError };
  }
  return perform(async (token) => {
    try {
      const published = await controlApi.publishPreview(token, { mode, githubPatMode, paymentCardMode, privateKeyMode: privateKeyMode ?? undefined,
        ssnMode: ssnMode ?? undefined, githubTokenMode: githubTokenMode ?? undefined, clipboardMode: clipboardMode ?? undefined,
        uploadModes, uploadTypes, ...fileContent,
        discoveryEnabled: discovery === 'on', presetDiscoveryEnabled: presetDiscovery === null ? undefined : presetDiscovery === 'on',
        extensionInventoryEnabled: inventory === 'on', claudePromptEnabled: claude === 'on',
        domainRules, pathRules, customApps, promptExceptions, blockedAiAppHosts, identifierProtection },
        expectedVersion, form.get('expectReview') === 'on', groupId ?? undefined);
      if ('reviewId' in published) return queued(published.reviewId);
      refreshPolicyViews();
      return { message: `Previewed policy published as version ${published.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.code === 'exception_expired') {
        return { error: 'An exception expired. Choose a future expiry and run the preview again.' };
      }
      if (error instanceof ApiError && error.code === 'navigation_rule_limit') return { error: navigationRuleLimitError };
      if (error instanceof ApiError && error.code === 'ai_app_access_unknown_host') {
        return { error: 'Keep each blocked AI app in the draft catalog or clear its access block.' };
      }
      if (error instanceof ApiError && error.status === 409 && !error.code) return { error: 'The policy changed after this preview. Reload and run the comparison again.' };
      throw error;
    }
  });
}

export async function publishExtensionDeployment(_previous: Feedback, form: FormData): Promise<Feedback> {
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  if ((groupId !== null && !isId(groupId)) || !Number.isInteger(expectedVersion) || expectedVersion < 1 || expectedVersion > 2147483647) {
    return { error: 'Reload the current deployment plan before saving.' };
  }
  const draft = parseExtensionDeployment(form.get('unlisted'), form.get('rules'));
  if ('error' in draft) return { error: draft.error };
  return perform(async (token) => {
    try {
      const policy = await controlApi.publishExtensionDeployment(token, draft.deployment, expectedVersion,
        form.get('expectReview') === 'on', groupId ?? undefined);
      if ('reviewId' in policy) return queued(policy.reviewId);
      refreshPolicyViews();
      return { message: `Extension deployment plan published as version ${policy.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409 && !error.code) {
        return { error: 'The policy changed. Reload and review the deployment plan again.' };
      }
      throw error;
    }
  });
}

export async function publishBrowserHardening(_previous: Feedback, form: FormData): Promise<Feedback> {
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  const draft = parseBrowserHardening(form);
  if ((groupId !== null && !isId(groupId)) || !Number.isInteger(expectedVersion) ||
      expectedVersion < 1 || expectedVersion > 2_147_483_647 || !draft) {
    return { error: 'Reload the current plan and choose supported Chrome settings.' };
  }
  return perform(async (token) => {
    try {
      const published = await controlApi.publishBrowserHardening(token, draft, expectedVersion,
        form.get('expectReview') === 'on', groupId ?? undefined);
      if ('reviewId' in published) return queued(published.reviewId);
      refreshPolicyViews();
      return { message: `Chrome hardening plan published as version ${published.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409 && !error.code) {
        return { error: 'The policy changed. Reload and review the Chrome hardening plan again.' };
      }
      throw error;
    }
  });
}

export async function saveAlertSettings(_previous: Feedback, form: FormData): Promise<Feedback> {
  const enabled = form.get('enabled');
  const threshold = Number(form.get('threshold'));
  const revision = form.get('revision');
  if ((enabled !== 'on' && enabled !== 'off') || !Number.isInteger(threshold) || threshold < 2 || threshold > 100 ||
      typeof revision !== 'string' || !/^\d{1,10}$/.test(revision) || Number(revision) >= 2_147_483_647) {
    return { error: 'Choose a mode and a threshold from 2 to 100.' };
  }
  return perform(async (token) => {
    try {
      await controlApi.saveAlertSettings(token, enabled === 'on', threshold, Number(revision));
      revalidatePath('/alerts');
      return { message: 'Alert settings saved.' };
    } catch (error) {
      if (error instanceof ApiError && error.code === 'alert_settings_changed') {
        return { error: 'Alert settings changed. Refresh the inbox and review the current settings before saving again.' };
      }
      throw error;
    }
  });
}

export async function acknowledgeAlert(id: string): Promise<Feedback> {
  if (!isId(id)) return { error: 'Choose a valid alert.' };
  return perform(async (token) => {
    try {
      await controlApi.acknowledgeAlert(token, id);
      revalidatePath('/alerts');
      revalidatePath(alertPath(id));
      return { message: 'Alert acknowledged.' };
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return { error: 'This alert is unavailable.' };
      throw error;
    }
  });
}

export async function restorePolicy(_previous: Feedback, form: FormData): Promise<Feedback> {
  const version = Number(form.get('version'));
  const groupId = form.get('groupId');
  if (groupId !== null && !isId(groupId)) return { error: 'Choose a valid rollout group.' };
  if (!Number.isInteger(version) || version < 1 || version > 2147483647) return { error: 'Choose a policy version.' };
  return perform(async (token) => {
    const policy = await controlApi.restore(token, version, form.get('expectReview') === 'on', groupId ?? undefined);
    if ('reviewId' in policy) return queued(policy.reviewId);
    refreshPolicyViews();
    return { message: `Version ${version} restored as version ${policy.version}.` };
  });
}

function refreshPolicyViews() {
  revalidatePath('/');
  revalidatePath('/groups');
  revalidatePath('/preview');
  revalidatePath('/reviews');
  revalidatePath('/extensions');
  revalidatePath('/extensions/deployment');
  revalidatePath('/hardening');
  revalidatePath('/templates');
}

function templateNumber(value: FormDataEntryValue | null) {
  return typeof value === 'string' && /^[1-9]\d{0,9}$/.test(value) && Number(value) <= 2_147_483_647 ? Number(value) : undefined;
}

function templateError(error: unknown): Feedback {
  if (error instanceof ApiError) {
    if (error.code === 'template_name_exists') return { error: 'An active template already has this name.' };
    if (error.code === 'template_limit') return { error: 'Archive an active template before creating another.' };
    if (error.code === 'template_revision_changed') return { error: 'The template revision changed. Refresh and review it again.' };
    if (error.code === 'template_target_changed') return { error: 'The destination policy changed. Run a fresh comparison.' };
    if (error.status === 404) return { error: 'This template, source policy, or destination is unavailable.' };
  }
  throw error;
}

export async function createPolicyTemplate(_previous: Feedback, form: FormData): Promise<Feedback> {
  const input = form.get('name');
  const name = typeof input === 'string' ? input.trim() : '';
  const sourceVersion = templateNumber(form.get('sourceVersion'));
  if (name.length < 2 || name.length > 64 || /[\x00-\x1f\x7f-\x9f]/.test(name) || !sourceVersion) {
    return { error: 'Enter a template name and select a source policy.' };
  }
  let createdId: string | undefined;
  const feedback = await perform(async (token) => {
    const result = await controlApi.createTemplate(token, name, sourceVersion).catch(templateError);
    if (!('id' in result)) return result;
    createdId = result.id;
    revalidatePath('/templates');
    revalidatePath('/audit');
    return {};
  });
  if (!feedback.error && createdId) redirect(`/templates?template=${createdId}`);
  return feedback;
}

export async function revisePolicyTemplate(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('templateId');
  const revision = templateNumber(form.get('expectedRevision'));
  const sourceVersion = templateNumber(form.get('sourceVersion'));
  if (!isId(id) || !revision || !sourceVersion) return { error: 'Select a source policy for this template.' };
  return perform(async (token) => {
    const result = await controlApi.reviseTemplate(token, id, revision, sourceVersion).catch(templateError);
    if (!('revision' in result)) return result;
    revalidatePath('/templates');
    revalidatePath('/audit');
    return { message: `Current template revision ${result.revision} uses policy v${result.sourceVersion}.` };
  });
}

export async function archivePolicyTemplate(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('templateId');
  const revision = templateNumber(form.get('expectedRevision'));
  if (!isId(id) || !revision) return { error: 'Reload the current template before archiving.' };
  const feedback = await perform(async (token) => {
    try { await controlApi.archiveTemplate(token, id, revision); } catch (error) { return templateError(error); }
    revalidatePath('/templates');
    revalidatePath('/audit');
    return {};
  });
  if (!feedback.error) redirect('/templates');
  return feedback;
}

export async function applyPolicyTemplate(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('templateId');
  const revision = templateNumber(form.get('revision'));
  const version = templateNumber(form.get('expectedVersion'));
  const group = form.get('targetGroup');
  if (!isId(id) || !revision || !version || (group !== null && !isId(group))) return { error: 'Compare a template and destination before applying.' };
  return perform(async (token) => {
    const result = await controlApi.applyTemplate(token, id, revision, version, group, form.get('expectReview') === 'on').catch(templateError);
    if ('reviewId' in result && result.reviewId) return queued(result.reviewId);
    if (!('version' in result)) return result;
    refreshPolicyViews();
    revalidatePath('/audit');
    return { message: `Template revision ${revision} published as policy v${result.version}.` };
  });
}

function queued(reviewId: string) {
  revalidatePath('/reviews');
  return { message: 'Review requested.', reviewId };
}

export async function setPolicyReview(_previous: Feedback, form: FormData): Promise<Feedback> {
  const value = form.get('required');
  if (value !== 'on' && value !== 'off') return { error: 'Choose a policy review setting.' };
  return perform(async (token) => {
    await controlApi.setPolicyReview(token, value === 'on');
    refreshPolicyViews();
    return { message: value === 'on' ? 'Policy reviews are required.' : 'Policy reviews are optional.' };
  });
}

export async function decidePolicyReview(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('id');
  const decision = form.get('decision');
  if (!isId(id) || (decision !== 'approve' && decision !== 'close')) return { error: 'Choose a policy review decision.' };
  return perform(async (token) => {
    try {
      const policy = await controlApi.decidePolicyReview(token, id, decision === 'approve');
      refreshPolicyViews();
      return { message: policy ? `Review approved and version ${policy.version} published.` : 'Review closed.' };
    } catch (error) {
      if (error instanceof ApiError && (error.code === 'review_stale' || error.code === 'review_closed')) {
        revalidatePath('/reviews');
        return { error: error.code === 'review_stale' ?
          'This review is stale. Refresh the review queue before submitting a new request.' : 'This review is already closed or expired.' };
      }
      throw error;
    }
  });
}

export async function createPolicyGroup(_previous: Feedback, form: FormData): Promise<Feedback> {
  const input = form.get('name');
  const name = typeof input === 'string' ? input.trim() : '';
  if (name.length < 2 || name.length > 64) return { error: 'Enter a group name from 2 to 64 characters.' };
  return perform(async (token) => {
    try {
      const group = await controlApi.createGroup(token, name);
      revalidatePath('/groups');
      return { message: `${group.name} created.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) return { error: 'A group with this name already exists.' };
      throw error;
    }
  });
}

export async function assignPolicyGroup(_previous: Feedback, form: FormData): Promise<Feedback> {
  const installationId = form.get('installationId');
  const group = form.get('groupId');
  if (!isId(installationId) || (group !== '' && !isId(group))) return { error: 'Choose a browser and a valid rollout group.' };
  return perform(async (token) => {
    try {
      await controlApi.assignGroup(token, installationId, group || null);
      refreshPolicyViews();
      return { message: 'Browser assignment saved.' };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) return { error: 'Update this browser and sync it before moving it.' };
      throw error;
    }
  });
}

export async function applyFleetChange(_previous: Feedback, form: FormData): Promise<Feedback> {
  const requestId = form.get('requestId');
  const operation = form.get('operation');
  const group = form.get('groupId');
  const rawVersion = form.get('expectedPolicyVersion');
  const policyVersion = rawVersion === null ? null : Number(rawVersion);
  const rawSelections = form.get('selections');
  if (!isId(requestId) || (operation !== 'assign' && operation !== 'revoke') || (group && !isId(group)) ||
      (operation === 'assign' && (policyVersion === null || !Number.isInteger(policyVersion) || policyVersion < 1 || policyVersion > 2_147_483_647)) ||
      (operation === 'revoke' && (group !== null || policyVersion !== null)) ||
      typeof rawSelections !== 'string' || rawSelections.length > 5000) return { error: 'Review the browser batch again before submitting.' };

  let selection: unknown;
  try { selection = JSON.parse(rawSelections); } catch { return { error: 'Choose a valid selection of browsers.' }; }
  if (!Array.isArray(selection) || selection.length < 1 || selection.length > 25 || !selection.every((row): row is FleetSelection =>
    row && isId(row.installationId) && Number.isInteger(row.assignmentVersion) && row.assignmentVersion >= 0 && row.assignmentVersion <= 2_147_483_647) ||
    new Set(selection.map(({ installationId }) => installationId.toLowerCase())).size !== selection.length) {
    return { error: 'Select 1 to 25 distinct browsers.' };
  }
  const selections = selection.map(({ installationId, assignmentVersion }) => ({ installationId, assignmentVersion }));
  return perform(async (token) => {
    try {
      const fleetChange = await controlApi.applyFleetChange(token, { requestId, operation,
        groupId: typeof group === 'string' && group ? group : null, expectedPolicyVersion: policyVersion, selections });
      revalidatePath('/fleet');
      revalidatePath('/groups');
      revalidatePath('/');
      revalidatePath('/audit');
      return { fleetChange };
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 404) return { error: 'A selected browser or destination is unavailable. Refresh the fleet and review a new batch.' };
        if (error.code === 'fleet_selection_changed' || error.code === 'fleet_policy_changed') {
          return { error: 'An assignment or destination policy changed. Refresh the fleet and review a new batch.' };
        }
        if (error.code === 'fleet_upgrade_required') return { error: 'A selected browser needs an update and a policy sync before it can move.' };
        if (error.code === 'fleet_request_conflict') return { error: 'This request ID is unavailable. Review a new batch.' };
      }
      throw error;
    }
  });
}

export async function promotePolicyGroup(_previous: Feedback, form: FormData): Promise<Feedback> {
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  const baseline = form.get('expectedBaselineVersion');
  const expectedBaselineVersion = baseline === null ? undefined : Number(baseline);
  if (!isId(groupId) || !Number.isInteger(expectedVersion) || expectedVersion < 1 || expectedVersion > 2147483647) {
    return { error: 'Choose a valid rollout group version.' };
  }
  if (expectedBaselineVersion !== undefined && (!Number.isInteger(expectedBaselineVersion) || expectedBaselineVersion < 1 || expectedBaselineVersion > 2147483647)) {
    return { error: 'Choose a valid organization baseline version.' };
  }
  return perform(async (token) => {
    try {
      const policy = await controlApi.promoteGroup(token, groupId, expectedVersion, form.get('expectReview') === 'on', expectedBaselineVersion);
      if ('reviewId' in policy) return queued(policy.reviewId);
      refreshPolicyViews();
      return { message: `Group policy promoted as organization version ${policy.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409 && !error.code) {
        return { error: 'The group or organization baseline version changed. Reload and review the current policies.' };
      }
      throw error;
    }
  });
}

export async function issueGrant(): Promise<Feedback> {
  return perform(async (token) => ({ grant: await controlApi.issueGrant(token) }));
}

export async function revokeInstallation(_previous: Feedback, form: FormData): Promise<Feedback> {
  const id = form.get('installationId');
  if (typeof id !== 'string' || !/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(id)) {
    return { error: 'Choose a browser installation.' };
  }
  return perform(async (token) => {
    await controlApi.revoke(token, id);
    revalidatePath('/');
    return { message: 'Browser access revoked.' };
  });
}

export async function saveRetention(_previous: Feedback, form: FormData): Promise<Feedback> {
  const policy: RetentionPolicy = { securityEventDays: null, aiObservationDays: null, auditDays: null };
  for (const field of Object.keys(retentionFields) as RetentionField[]) {
    const value = form.get(field);
    if (typeof value !== 'string' || (value !== '' && (!/^\d{1,4}$/.test(value) || Number(value) < 1 || Number(value) > 3650))) {
      return { error: 'Enter between 1 and 3,650 days or leave the field blank for no expiry.' };
    }
    policy[field] = value === '' ? null : Number(value);
  }
  return perform(async (token) => {
    await controlApi.saveRetention(token, policy);
    revalidatePath('/retention');
    return { message: 'Retention settings saved.' };
  });
}

export async function cleanupRetention(): Promise<Feedback> {
  return perform(async (token) => {
    const result = await controlApi.cleanupRetention(token);
    revalidatePath('/retention');
    return { message: result.securityEvents || result.aiObservations || result.auditEntries || result.incidentCases || result.alertWindows
      ? `Deleted ${cleanupCounts(result)}.` : 'No expired records found.' };
  });
}
