import { credentialDetector, fixtureDetector, fixtureRule, githubPatRule, isMode, paymentCardRule, paymentDetector, type PolicyMode,
  type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { chatGptApp, fixtureApp, geminiApp, isPromptApp, type AiPromptApp, type AppId } from '../../../contracts/policy/apps';
import { isUploadMethod, uploadCategory, uploadRule, type UploadMetadata, type UploadModes } from '../../../contracts/policy/uploads';
import type { InventoryStatus } from '../../../contracts/policy/extension-inventory';

export { fixtureRule, fixtureDetector, githubPatRule, credentialDetector, isMode, isDetectorMode } from '../../../contracts/policy/prompt';
export type { PolicyMode, DetectorMode, RuleMetadata } from '../../../contracts/policy/prompt';
export { chatGptApp, fixtureApp, geminiApp, aiPromptApps, isPromptApp } from '../../../contracts/policy/apps';
export type { AiPromptApp, AppId } from '../../../contracts/policy/apps';

export const fixtureUrl = 'http://127.0.0.1:4173/zekvar-fixture/';
const discoveryCatalog = {
  'https://chatgpt.com': chatGptApp,
  'https://claude.ai': 'claude',
  'https://gemini.google.com': geminiApp,
} as const;
export type DiscoveryApp = typeof discoveryCatalog[keyof typeof discoveryCatalog];
export type AppObservation = { appId: DiscoveryApp; observedAt: string; policyVersion: number; assignmentVersion?: number };

export function discoveredApp(url: string | undefined): DiscoveryApp | undefined {
  const origin = url && new URL(url).origin;
  if (origin && Object.hasOwn(discoveryCatalog, origin)) return discoveryCatalog[origin as keyof typeof discoveryCatalog];
}
export type Coverage = 'ready' | 'unsupported';
export type Policy = PromptPolicy & {
  version: number; discoveryEnabled?: boolean; assignmentVersion?: number; uploadModes?: UploadModes; extensionInventoryEnabled?: boolean;
};
export type PolicyEvent = {
  eventId: string;
  appId: AppId;
  timestamp: string;
  policyVersion: number;
  assignmentVersion?: number;
  decision: PolicyMode | 'warn_override';
} & (RuleMetadata | UploadMetadata);

export type Summary = {
  status: 'standalone' | 'connected' | 'offline' | 'revoked';
  installationId?: string;
  policy?: Policy;
  promptApps?: AiPromptApp[];
  enrollmentSource?: 'managed' | 'manual';
  managedEnrollment?: 'invalid' | 'rejected' | 'retrying';
  domainRuleCount?: number;
  pathRuleCount?: number;
  domainRulesError?: boolean;
  inventoryStatus?: InventoryStatus;
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

export function geminiRoute(url: string | undefined): 'home' | 'conversation' | 'other' {
  if (!url) return 'other';
  const page = new URL(url);
  if (page.origin !== 'https://gemini.google.com') return 'other';
  if (/^\/app\/?$/.test(page.pathname)) return 'home';
  if (/^\/app\/[a-z\d-]+\/?$/i.test(page.pathname)) return 'conversation';
  return 'other';
}

export function promptApp(url: string | undefined): AppId | undefined {
  if (url === fixtureUrl) return fixtureApp;
  if (chatGptRoute(url) !== 'other') return chatGptApp;
  if (geminiRoute(url) !== 'other') return geminiApp;
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

export function isId(value: unknown): value is string {
  return typeof value === 'string' && /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
}

export function readMetadata(value: unknown): PolicyEvent | undefined {
  if (!isRecord(value) || !isId(value.eventId) || !isVersion(value.policyVersion) ||
      (value.assignmentVersion !== undefined && !isVersion(value.assignmentVersion)) ||
      !isPromptApp(value.appId) ||
      !(isMode(value.decision) || value.decision === 'warn_override') ||
      typeof value.timestamp !== 'string' || !Number.isFinite(Date.parse(value.timestamp))) return;

  const event = {
    eventId: value.eventId, appId: value.appId, timestamp: new Date(value.timestamp).toISOString(),
    policyVersion: value.policyVersion, decision: value.decision, assignmentVersion: value.assignmentVersion,
  } as const;
  if (value.ruleId === uploadRule && value.detectorCategory === uploadCategory && value.appId !== fixtureApp &&
      (value.decision === 'monitor' || value.decision === 'block') && isUploadMethod(value.uploadMethod)) {
    return { ...event, ruleId: uploadRule, detectorCategory: uploadCategory, uploadMethod: value.uploadMethod };
  }
  if (value.uploadMethod !== undefined) return;
  if (value.ruleId === fixtureRule && value.detectorCategory === fixtureDetector) {
    return { ...event, ruleId: fixtureRule, detectorCategory: fixtureDetector };
  }
  if (value.ruleId === githubPatRule && value.detectorCategory === credentialDetector) {
    return { ...event, ruleId: githubPatRule, detectorCategory: credentialDetector };
  }
  if (value.ruleId === paymentCardRule && value.detectorCategory === paymentDetector) {
    return { ...event, ruleId: paymentCardRule, detectorCategory: paymentDetector };
  }
}
