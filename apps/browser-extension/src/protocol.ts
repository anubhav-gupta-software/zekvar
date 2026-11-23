import { credentialDetector, fixtureDetector, fixtureRule, githubPatRule, identifierDetector, identifierRule, isMode,
  paymentCardRule, paymentDetector, privateKeyRule, type PolicyMode,
  type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { chatGptApp, claudeApp, fixtureApp, geminiApp, isPromptApp, type AiPromptApp, type AppId } from '../../../contracts/policy/apps';
import { fileInspectionUnavailableRule, isUploadApp, isUploadMethod, uploadCategory, uploadRule, type FileInspection, type TargetedUploads,
  type UploadMetadata, type UploadMethod, type UploadModes } from '../../../contracts/policy/uploads';
import type { InventoryStatus } from '../../../contracts/policy/extension-inventory';
import { builtInDiscoveryApps, type BuiltInDiscoveryApp, type CustomAppId, type DiscoveryPreset } from '../../../contracts/policy/discovery';
import { exceptionDecision } from '../../../contracts/policy/prompt-exceptions';
import type { BrowserLease } from './prompt-exceptions';

export { fixtureRule, fixtureDetector, githubPatRule, credentialDetector, isMode, isDetectorMode } from '../../../contracts/policy/prompt';
export type { PolicyMode, DetectorMode, RuleMetadata } from '../../../contracts/policy/prompt';
export { chatGptApp, claudeApp, fixtureApp, geminiApp, aiPromptApps, isPromptApp } from '../../../contracts/policy/apps';
export type { AiPromptApp, AppId } from '../../../contracts/policy/apps';

export const fixtureUrl = 'http://127.0.0.1:4173/zekvar-fixture/';
export const discoveryPermission: chrome.permissions.Permissions = { permissions: ['webNavigation'] };
export type DiscoveryApp = BuiltInDiscoveryApp | CustomAppId | DiscoveryPreset;
export type AppObservation = { appId: DiscoveryApp; observedAt: string; policyVersion: number; assignmentVersion?: number };

export function discoveredApp(url: string | undefined): BuiltInDiscoveryApp | undefined {
  const origin = url && new URL(url).origin;
  if (origin && Object.hasOwn(builtInDiscoveryApps, origin)) return builtInDiscoveryApps[origin as keyof typeof builtInDiscoveryApps];
}
export type Coverage = 'ready' | 'unsupported';
export type Policy = PromptPolicy & {
  version: number; discoveryEnabled?: boolean; assignmentVersion?: number; uploadModes?: UploadModes;
  targetedUploads?: TargetedUploads; extensionInventoryEnabled?: boolean; claudePromptEnabled?: boolean;
  fileInspection?: FileInspection;
  fileContentModes?: UploadModes;
  presetDiscovery?: boolean;
};
export type PolicyEvent = {
  eventId: string;
  appId: AppId;
  timestamp: string;
  policyVersion: number;
  assignmentVersion?: number;
  decision: PolicyMode | 'warn_override' | typeof exceptionDecision;
} & ((RuleMetadata & { uploadMethod?: UploadMethod }) | UploadMetadata);

export type Summary = {
  status: 'standalone' | 'connected' | 'offline' | 'revoked';
  installationId?: string;
  policy?: Policy;
  promptApps?: AiPromptApp[];
  enrollmentSource?: 'managed' | 'manual';
  managedEnrollment?: 'invalid' | 'rejected' | 'retrying' | 'origin_mismatch';
  originChanged?: boolean;
  domainRuleCount?: number;
  pathRuleCount?: number;
  aiAppAccessRuleCount?: number;
  domainRulesError?: boolean;
  inventoryStatus?: InventoryStatus;
  customDiscoveryCount?: number;
  promptExceptionLease?: BrowserLease;
  queued: number;
  discarded: number;
};

type Message = { type: 'status' | 'sync' | 'observe-app' } | { type: 'enroll'; grant: string } |
  { type: 'decision'; installationId: string; event: PolicyEvent } |
  { type: 'coverage'; installationId: string; coverage: Coverage; version: number; assignmentVersion?: number };

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

export function claudeRoute(url: string | undefined): 'new' | 'conversation' | 'other' {
  if (!url) return 'other';
  const page = new URL(url);
  if (page.origin !== 'https://claude.ai') return 'other';
  if (/^\/new\/?$/.test(page.pathname)) return 'new';
  if (/^\/chat\/[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\/?$/i.test(page.pathname)) return 'conversation';
  return 'other';
}

export function promptApp(url: string | undefined): AppId | undefined {
  if (url === fixtureUrl) return fixtureApp;
  if (chatGptRoute(url) !== 'other') return chatGptApp;
  if (geminiRoute(url) !== 'other') return geminiApp;
  if (claudeRoute(url) !== 'other') return claudeApp;
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
      !(isMode(value.decision) || value.decision === 'warn_override' || (value.decision === exceptionDecision && value.appId !== fixtureApp)) ||
      typeof value.timestamp !== 'string' || !Number.isFinite(Date.parse(value.timestamp))) return;

  const event = {
    eventId: value.eventId, appId: value.appId, timestamp: new Date(value.timestamp).toISOString(),
    policyVersion: value.policyVersion, decision: value.decision, assignmentVersion: value.assignmentVersion,
  } as const;
  if ((value.ruleId === uploadRule || value.ruleId === fileInspectionUnavailableRule) &&
      value.detectorCategory === uploadCategory && isUploadApp(value.appId) &&
      (value.decision === 'block' || value.ruleId === uploadRule && value.decision === 'monitor') && isUploadMethod(value.uploadMethod)) {
    return { ...event, ruleId: value.ruleId, detectorCategory: uploadCategory, uploadMethod: value.uploadMethod };
  }
  if (value.uploadMethod !== undefined && !(isUploadApp(value.appId) && (value.decision === 'monitor' || value.decision === 'block') &&
      isUploadMethod(value.uploadMethod))) return;
  const source = isUploadMethod(value.uploadMethod) ? { uploadMethod: value.uploadMethod } : {};
  if (value.ruleId === fixtureRule && value.detectorCategory === fixtureDetector) {
    return { ...event, ...source, ruleId: fixtureRule, detectorCategory: fixtureDetector };
  }
  if (value.ruleId === githubPatRule && value.detectorCategory === credentialDetector) {
    return { ...event, ...source, ruleId: githubPatRule, detectorCategory: credentialDetector };
  }
  if (value.ruleId === paymentCardRule && value.detectorCategory === paymentDetector) {
    return { ...event, ...source, ruleId: paymentCardRule, detectorCategory: paymentDetector };
  }
  if (value.ruleId === privateKeyRule && value.detectorCategory === credentialDetector) {
    return { ...event, ...source, ruleId: privateKeyRule, detectorCategory: credentialDetector };
  }
  if (value.ruleId === identifierRule && value.detectorCategory === identifierDetector) {
    return { ...event, ...source, ruleId: identifierRule, detectorCategory: identifierDetector };
  }
}
