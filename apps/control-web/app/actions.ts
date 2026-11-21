'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../lib/api';
import { aiApps, classifications, decisionLabels, detectorModes, isId, modes,
  type AiAppId, type AppClassification, type DetectorMode, type Feedback, type Mode } from '../lib/control';
import { endSession, sessionToken, startSession } from '../lib/session';
import { cleanupCounts, retentionFields, type RetentionField, type RetentionPolicy } from '../lib/retention';

export async function signIn(_previous: Feedback, form: FormData): Promise<Feedback> {
  const token = form.get('token');
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token.trim())) {
    return { error: 'Enter the 64-character admin token configured for the Control API.' };
  }
  try {
    await controlApi.session(token.trim());
  } catch (error) {
    return { error: error instanceof ApiError && error.status === 401
      ? 'This admin token was rejected.'
      : 'Control API is unavailable. Start it and try again.' };
  }
  await startSession(token.trim());
  redirect('/');
}

export async function signOut() {
  await endSession();
  redirect('/');
}

async function perform(change: (token: string) => Promise<Feedback>): Promise<Feedback> {
  const token = await sessionToken();
  if (!token) return { error: 'Your session has expired. Reload and sign in again.' };
  try {
    return await change(token);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      await endSession();
      return { error: 'Your admin token is no longer valid. Reload and sign in again.' };
    }
    if (error instanceof ApiError && error.status === 404) {
      return { error: 'That record is no longer available. Refresh the dashboard.' };
    }
    return { error: 'Control could not confirm the change. Refresh before trying again.' };
  }
}

export async function publishPolicy(_previous: Feedback, form: FormData): Promise<Feedback> {
  const mode = form.get('mode') as Mode;
  const githubPatMode = form.get('githubPatMode') as DetectorMode;
  const discovery = form.get('discoveryEnabled');
  const groupId = form.get('groupId');
  if (groupId !== null && !isId(groupId)) return { error: 'Choose a valid rollout group.' };
  if (!modes.includes(mode) || !detectorModes.includes(githubPatMode) || (discovery !== 'on' && discovery !== 'off')) {
    return { error: 'Choose a setting for each policy control.' };
  }
  return perform(async (token) => {
    const policy = await controlApi.publish(token, mode, githubPatMode, discovery === 'on', groupId ?? undefined);
    refreshPolicyViews();
    return { message: `Version ${policy.version} published in ${decisionLabels[mode].toLowerCase()} mode.` };
  });
}

export async function classifyAiApp(_previous: Feedback, form: FormData): Promise<Feedback> {
  const app = form.get('appId') as AiAppId;
  const status = form.get('status') as AppClassification;
  if (typeof app !== 'string' || !Object.hasOwn(aiApps, app) || !classifications.includes(status)) {
    return { error: 'Choose a cataloged app and a valid classification.' };
  }
  return perform(async (token) => {
    await controlApi.classifyApp(token, app, status);
    revalidatePath('/');
    return { message: `${aiApps[app]} classification saved.` };
  });
}

export async function publishDomainRules(_previous: Feedback, form: FormData): Promise<Feedback> {
  const allow = form.get('allow');
  const block = form.get('block');
  const groupId = form.get('groupId');
  if (groupId !== null && !isId(groupId)) return { error: 'Choose a valid rollout group.' };
  if (typeof allow !== 'string' || typeof block !== 'string') return { error: 'Enter both domain lists.' };
  const lines = (value: string) => value.split('\n').map((line) => line.trim()).filter(Boolean);
  return perform(async (token) => {
    try {
      const policy = await controlApi.publishDomains(token, { allow: lines(allow), block: lines(block) }, groupId ?? undefined);
      refreshPolicyViews();
      return { message: `Domain rules published as version ${policy.version}.` };
    } catch (error) {
      if (error instanceof ApiError && (error.status === 400 || error.status === 413)) {
        return { error: 'Enter up to 50 hostnames, one per line. A hostname can appear in only one list.' };
      }
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
    const policy = await controlApi.restore(token, version, groupId ?? undefined);
    refreshPolicyViews();
    return { message: `Version ${version} restored as version ${policy.version}.` };
  });
}

function refreshPolicyViews() {
  revalidatePath('/');
  revalidatePath('/groups');
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

export async function promotePolicyGroup(_previous: Feedback, form: FormData): Promise<Feedback> {
  const groupId = form.get('groupId');
  const expectedVersion = Number(form.get('expectedVersion'));
  if (!isId(groupId) || !Number.isInteger(expectedVersion) || expectedVersion < 1 || expectedVersion > 2147483647) {
    return { error: 'Choose a valid rollout group version.' };
  }
  return perform(async (token) => {
    try {
      const policy = await controlApi.promoteGroup(token, groupId, expectedVersion);
      refreshPolicyViews();
      return { message: `Group policy promoted as organization version ${policy.version}.` };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) return { error: 'The reviewed group version changed. Reload and review the current policy.' };
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
    return { message: result.securityEvents || result.aiObservations || result.auditEntries
      ? `Deleted ${cleanupCounts(result)}.` : 'No expired records found.' };
  });
}
