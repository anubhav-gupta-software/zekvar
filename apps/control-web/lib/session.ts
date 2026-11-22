import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';

const hostedPilot = process.env.ZEKVAR_HOSTED_PILOT === '1';
const name = hostedPilot ? '__Host-zekvar_control_session' : 'zekvar_control_session';
const cookieScope = { httpOnly: true, secure: hostedPilot, sameSite: 'strict', path: '/' } as const;
const duration = 60 * 60;
type Session = { token: string; expires: number };
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

export async function startSession(token: string) {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (session.expires <= now) sessions.delete(id);
  }
  const jar = await cookies();
  const previous = jar.get(name)?.value;
  if (previous) sessions.delete(previous);
  const id = randomBytes(32).toString('hex');
  sessions.set(id, { token, expires: now + duration * 1000 });
  jar.set(name, id, { ...cookieScope, maxAge: duration });
}

export async function endSession() {
  const jar = await cookies();
  const id = jar.get(name)?.value;
  if (id) sessions.delete(id);
  jar.set(name, '', { ...cookieScope, maxAge: 0 });
}
