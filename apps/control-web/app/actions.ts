'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../lib/api';
import { decisionLabels, modes, type Feedback, type Mode } from '../lib/control';
import { endSession, sessionToken, startSession } from '../lib/session';

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
  if (!modes.includes(mode)) return { error: 'Choose a policy mode.' };
  return perform(async (token) => {
    const policy = await controlApi.publish(token, mode);
    revalidatePath('/');
    return { message: `Version ${policy.version} published in ${decisionLabels[mode].toLowerCase()} mode.` };
  });
}

export async function restorePolicy(_previous: Feedback, form: FormData): Promise<Feedback> {
  const version = Number(form.get('version'));
  if (!Number.isInteger(version) || version < 1 || version > 2147483647) return { error: 'Choose a policy version.' };
  return perform(async (token) => {
    const policy = await controlApi.restore(token, version);
    revalidatePath('/');
    return { message: `Version ${version} restored as version ${policy.version}.` };
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
