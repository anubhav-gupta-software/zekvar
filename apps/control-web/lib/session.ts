import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';
import { ssoApi } from './api';

const hostedPilot = process.env.ZEKVAR_HOSTED_PILOT === '1';
const name = hostedPilot ? '__Host-zekvar_control_session' : 'zekvar_control_session';
const cookieScope = { httpOnly: true, secure: hostedPilot, sameSite: 'strict', path: '/' } as const;
const duration = 60 * 60;
type Session = { token: string; expires: number; sso: boolean };
const server = globalThis as typeof globalThis & { zekvarControlSessions?: Map<string, Session> };
const sessions = server.zekvarControlSessions ??= new Map();

export async function sessionToken() {
  const id = (await cookies()).get(name)?.value;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (session && session.expires > Date.now()) return session.token;
  sessions.delete(id);
  return undefined;
}

export async function startSession(token: string, ssoExpiry?: number) {
  const now = Date.now();
  const expiry = Math.min(ssoExpiry ?? Infinity, now + duration * 1000);
  const maxAge = Math.floor((expiry - now) / 1000);
  if (!Number.isFinite(maxAge) || maxAge < 1) throw new Error('Control session has already expired.');
  for (const [id, session] of sessions) {
    if (session.expires <= now) sessions.delete(id);
  }
  const jar = await cookies();
  const previous = jar.get(name)?.value;
  if (previous) await removeSession(previous);
  const id = randomBytes(32).toString('hex');
  sessions.set(id, { token, expires: expiry, sso: ssoExpiry !== undefined });
  jar.set(name, id, { ...cookieScope, maxAge });
}

export async function endSession() {
  const jar = await cookies();
  const id = jar.get(name)?.value;
  if (id) await removeSession(id);
  jar.set(name, '', { ...cookieScope, maxAge: 0 });
}

async function removeSession(id: string) {
  const session = sessions.get(id);
  sessions.delete(id);
  if (session?.sso) await ssoApi.end(session.token).catch(() => undefined);
}
