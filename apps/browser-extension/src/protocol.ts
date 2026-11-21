export const fixtureUrl = 'http://127.0.0.1:4173/zekvar-fixture/';
export const fixtureApp = 'local-prompt-fixture';
export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export type PolicyMode = 'monitor' | 'warn' | 'block';
export type Policy = { version: number; mode: PolicyMode };
export type PolicyEvent = {
  eventId: string;
  appId: typeof fixtureApp;
  timestamp: string;
  ruleId: typeof fixtureRule;
  detectorCategory: typeof fixtureDetector;
  policyVersion: number;
  decision: PolicyMode | 'warn_override';
};

export type Summary = {
  status: 'standalone' | 'connected' | 'offline' | 'revoked';
  installationId?: string;
  policy?: Policy;
  queued: number;
  discarded: number;
};

type Message = { type: 'status' | 'sync' } | { type: 'enroll'; grant: string } |
  { type: 'decision'; installationId: string; event: PolicyEvent };

export type Reply = { summary?: Summary; error?: string };

export function send(message: Message): Promise<Reply> {
  return chrome.runtime.sendMessage(message);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function isToken(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function isVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 2147483647;
}

export function isMode(value: unknown): value is PolicyMode {
  return value === 'monitor' || value === 'warn' || value === 'block';
}

export function isId(value: unknown): value is string {
  return typeof value === 'string' && /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
}

export function readMetadata(value: unknown): PolicyEvent | undefined {
  if (!isRecord(value) || !isId(value.eventId) || !isVersion(value.policyVersion) ||
      value.appId !== fixtureApp || value.ruleId !== fixtureRule || value.detectorCategory !== fixtureDetector ||
      !(isMode(value.decision) || value.decision === 'warn_override') ||
      typeof value.timestamp !== 'string' || !Number.isFinite(Date.parse(value.timestamp))) return;

  return {
    eventId: value.eventId, appId: fixtureApp, timestamp: new Date(value.timestamp).toISOString(),
    ruleId: fixtureRule, detectorCategory: fixtureDetector, policyVersion: value.policyVersion, decision: value.decision,
  };
}
