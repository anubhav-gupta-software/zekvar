export const fixtureUrl = 'http://127.0.0.1:4173/zekvar-fixture/';
export const fixtureApp = 'local-prompt-fixture';
export const chatGptApp = 'chatgpt';
export type AppId = typeof fixtureApp | typeof chatGptApp;
const discoveryCatalog = {
  'https://chatgpt.com': chatGptApp,
  'https://claude.ai': 'claude',
  'https://gemini.google.com': 'gemini',
} as const;
export type DiscoveryApp = typeof discoveryCatalog[keyof typeof discoveryCatalog];
export type AppObservation = { appId: DiscoveryApp; observedAt: string; policyVersion: number; assignmentVersion?: number };

export function discoveredApp(url: string | undefined): DiscoveryApp | undefined {
  const origin = url && new URL(url).origin;
  if (origin && Object.hasOwn(discoveryCatalog, origin)) return discoveryCatalog[origin as keyof typeof discoveryCatalog];
}
export type Coverage = 'ready' | 'unsupported';
export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export const githubPatRule = 'github-classic-pat';
export const credentialDetector = 'credential';
export type PolicyMode = 'monitor' | 'warn' | 'block';
export type DetectorMode = PolicyMode | 'off';
export type Policy = { version: number; mode: PolicyMode; githubPatMode?: DetectorMode; discoveryEnabled?: boolean; assignmentVersion?: number };
export type RuleMetadata = { ruleId: typeof fixtureRule; detectorCategory: typeof fixtureDetector } |
  { ruleId: typeof githubPatRule; detectorCategory: typeof credentialDetector };
export type PolicyEvent = {
  eventId: string;
  appId: AppId;
  timestamp: string;
  policyVersion: number;
  assignmentVersion?: number;
  decision: PolicyMode | 'warn_override';
} & RuleMetadata;

export type Summary = {
  status: 'standalone' | 'connected' | 'offline' | 'revoked';
  installationId?: string;
  policy?: Policy;
  chatGptEnabled?: boolean;
  enrollmentSource?: 'managed' | 'manual';
  managedEnrollment?: 'invalid' | 'rejected' | 'retrying';
  domainRuleCount?: number;
  domainRulesError?: boolean;
  queued: number;
  discarded: number;
};

type Message = { type: 'status' | 'sync' | 'observe-app' } | { type: 'enroll'; grant: string } |
  { type: 'decision'; installationId: string; event: PolicyEvent } |
  { type: 'coverage'; installationId: string; coverage: Coverage };

export function chatGptRoute(url: string | undefined): 'home' | 'conversation' | 'guest-conversation' | 'other' {
  if (!url) return 'other';
  const page = new URL(url);
  if (page.origin !== 'https://chatgpt.com') return 'other';
  if (page.pathname === '/') return 'home';
  if (/^\/c\/[a-z\d-]+\/?$/i.test(page.pathname)) return 'conversation';
  if (/^\/uc\/[a-z\d-]+\/?$/i.test(page.pathname)) return 'guest-conversation';
  return 'other';
}

export function isChatGptPage(url: string | undefined): boolean {
  return chatGptRoute(url) !== 'other';
}

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

export function isDetectorMode(value: unknown): value is DetectorMode {
  return value === 'off' || isMode(value);
}

export function isId(value: unknown): value is string {
  return typeof value === 'string' && /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
}

export function readMetadata(value: unknown): PolicyEvent | undefined {
  if (!isRecord(value) || !isId(value.eventId) || !isVersion(value.policyVersion) ||
      (value.assignmentVersion !== undefined && !isVersion(value.assignmentVersion)) ||
      (value.appId !== fixtureApp && value.appId !== chatGptApp) ||
      !(isMode(value.decision) || value.decision === 'warn_override') ||
      typeof value.timestamp !== 'string' || !Number.isFinite(Date.parse(value.timestamp))) return;

  const event = {
    eventId: value.eventId, appId: value.appId, timestamp: new Date(value.timestamp).toISOString(),
    policyVersion: value.policyVersion, decision: value.decision, assignmentVersion: value.assignmentVersion,
  } as const;
  if (value.ruleId === fixtureRule && value.detectorCategory === fixtureDetector) {
    return { ...event, ruleId: fixtureRule, detectorCategory: fixtureDetector };
  }
  if (value.ruleId === githubPatRule && value.detectorCategory === credentialDetector) {
    return { ...event, ruleId: githubPatRule, detectorCategory: credentialDetector };
  }
}
