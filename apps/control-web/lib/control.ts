import { modes, type DetectorMode, type PolicyMode } from '../../../contracts/policy/prompt';
export { modes, detectorModes } from '../../../contracts/policy/prompt';
import { detectionRuleLabels as promptRuleLabels } from '../../../contracts/policy/prompt';
import { clipboardUnavailableRule, type ClipboardMode } from '../../../contracts/policy/clipboard';
export const ruleLabels = { ...promptRuleLabels, [clipboardUnavailableRule]: 'Clipboard check unavailable' };
export type { DetectorMode } from '../../../contracts/policy/prompt';
export type { DomainRules, PathRules } from '../../../contracts/policy/domains';
import type { DomainRules, PathRules } from '../../../contracts/policy/domains';
import type { FileInspection, UploadMethod, UploadModes, UploadTypes } from '../../../contracts/policy/uploads';
import { discoveryPresets, isCustomAppId, isDiscoveryPreset, type CustomApp, type CustomAppId, type DiscoveryPreset } from '../../../contracts/policy/discovery';
import { exceptionDecision, type PromptException } from '../../../contracts/policy/prompt-exceptions';

export const decisions = [...modes, 'warn_override', exceptionDecision] as const;
export type Mode = PolicyMode;
export type Decision = typeof decisions[number];

export const decisionLabels: Record<Decision, string> = {
  monitor: 'Monitor', warn: 'Warn', block: 'Block', warn_override: 'Warning overridden',
  exception_applied: 'Exception applied',
};

export const detectorModeLabels: Record<DetectorMode, string> = {
  off: 'Off', monitor: 'Monitor', warn: 'Warn', block: 'Block',
};

export { aiPromptApps, promptAppLabels, isPromptApp } from '../../../contracts/policy/apps';

export const aiApps = { chatgpt: 'ChatGPT', claude: 'Claude', gemini: 'Gemini' } as const;
export type AiAppId = keyof typeof aiApps;
export type DiscoveredAppId = AiAppId | DiscoveryPreset | CustomAppId;
export function isDiscoveredAppId(value: unknown): value is DiscoveredAppId {
  return typeof value === 'string' && (isCustomAppId(value) || isDiscoveryPreset(value) || Object.hasOwn(aiApps, value));
}
export function discoveryAppName(appId: DiscoveredAppId) {
  if (isDiscoveryPreset(appId)) return discoveryPresets[appId].name;
  return Object.hasOwn(aiApps, appId) ? aiApps[appId as AiAppId] : 'Custom app';
}
export const classifications = ['unreviewed', 'approved', 'unapproved'] as const;
export type AppClassification = typeof classifications[number];
export const classificationLabels: Record<AppClassification, string> = {
  unreviewed: 'Unreviewed', approved: 'Approved', unapproved: 'Unapproved',
};
export type DiscoveredApp = {
  appId: DiscoveredAppId; status: AppClassification; browsersSeen: number; lastObservedAt: string | null; name?: string; host?: string;
};
export type PolicyGroup = { id: string; name: string; effectiveVersion: number; publishedVersion: number | null; browsers: number; baselineVersion?: number };
export type PolicyGroupChange = { groupId: string | null; groupName: string | null; installationId: string | null; sourceVersion: number | null };

export type Policy = {
  version: number;
  mode: Mode;
  githubPatMode?: DetectorMode;
  paymentCardMode?: DetectorMode;
  privateKeyMode?: DetectorMode;
  ssnMode?: DetectorMode;
  githubTokenMode?: DetectorMode;
  cloudCredentialMode?: DetectorMode;
  classificationProtection?: import('../../../contracts/policy/prompt').ClassificationProtection;
  promptAppModes?: import('../../../contracts/policy/prompt-app-modes').PromptAppModes;
  adapterControls?: import('../../../contracts/policy/adapter-controls').AdapterControls;
  identifierProtection?: import('../../../contracts/policy/prompt').IdentifierProtection;
  uploadModes?: UploadModes;
  uploadTypes?: UploadTypes;
  fileInspection?: FileInspection;
  fileContentModes?: UploadModes;
  clipboardMode?: ClipboardMode;
  discoveryEnabled?: boolean;
  presetDiscoveryEnabled?: boolean;
  saasDiscoveryEnabled?: boolean;
  customApps?: CustomApp[];
  promptExceptions?: PromptException[];
  extensionInventoryEnabled?: boolean;
  extensionDeployment?: import('./extension-deployment').ExtensionDeployment;
  browserHardening?: import('./browser-hardening').BrowserHardening;
  blockedAiAppHosts?: string[];
  claudePromptEnabled?: boolean;
  domainRules?: DomainRules;
  pathRules?: PathRules;
  publishedAt: string;
  restoredFrom: number | null;
};

export type Coverage = 'ready' | 'unsupported' | 'disabled';
export type Installation = {
  installationId: string;
  enrolledAt: string;
  lastSeenAt: string;
  appliedPolicyVersion: number | null;
  revokedAt: string | null;
  chatGptCoverage?: Coverage | null;
  chatGptCheckedAt?: string | null;
  geminiCoverage?: Coverage | null;
  geminiCheckedAt?: string | null;
  claudePromptEnabled?: boolean;
  claudeCoverage?: Coverage | null;
  claudeCheckedAt?: string | null;
  policyGroupId?: string | null;
  policyGroupName?: string | null;
  expectedPolicyVersion?: number;
  assignmentAware?: boolean;
  extensionVersion?: string | null;
  extensionVersionReportedAt?: string | null;
  composerReadiness?: Record<AiAppId, ComposerCheck>;
};

export type BrowserReleaseCount = {
  kind: 'release' | 'other' | 'unreported';
  extensionVersion: string | null;
  installations: number;
  recentReports: number;
};

export type BrowserHealthView = {
  activeInstallations: number;
  releases: BrowserReleaseCount[];
  installations: Installation[];
  composerReadiness?: BrowserComposerReadiness;
  composerReadinessExportAvailable?: boolean;
};

export const composerStateLabels = {
  detected: 'Detected', unsupported: 'Unsupported', stale: 'Stale', unobserved: 'Unobserved',
  policy_pending: 'Policy pending', off: 'Off', disabled_by_admin: 'Disabled by administrator',
} as const;
export type ComposerState = keyof typeof composerStateLabels;
export const composerStates = Object.keys(composerStateLabels) as ComposerState[];
export type ComposerCheck = { state: ComposerState; checkedAt: string | null };
export type BrowserComposerReadiness = {
  activeInstallations: number;
  apps: { appId: AiAppId; counts: Record<ComposerState, number>; attachmentsDisabled?: number }[];
};
export type ComposerReadinessReport = BrowserComposerReadiness & {
  schemaVersion: 1;
  asOf: string;
  scope: {
    rolloutGroup: string;
    rolloutGroupName: string | null;
    browserVersion: string | null;
    targetPolicyVersion: number | null;
  };
  freshness: { heartbeatSeconds: number; observationSeconds: number };
};

export type SecurityEvent = {
  eventId: string;
  installationId: string;
  appId: string;
  timestamp: string;
  receivedAt: string;
  detectorCategory: string;
  ruleId: string;
  policyVersion: number;
  decision: Decision;
  uploadMethod?: UploadMethod;
  clipboardPaste?: true;
  rollout?: { kind: 'baseline' | 'unattributed' } | { kind: 'group'; groupId: string; groupName: string };
  triage?: import('./triage').EventTriage;
};

export const fileCheckUnavailableLabel = 'File check unavailable';

export type Grant = { grant: string; expiresAt: string };
export type Feedback = {
  error?: string; message?: string; grant?: Grant; issuedAccess?: import('./access').IssuedControlAccess; reviewId?: string;
  issuedEventFeedKey?: import('./access').IssuedEventFeedKey;
  fleetChange?: import('./fleet').FleetChange;
  issuedEnrollmentBatch?: import('./enrollment').IssuedEnrollmentBatch; enrollmentRequestId?: string;
};

export const utc = new Intl.DateTimeFormat('en-US', {
  dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC',
});

export function isId(value: unknown): value is string {
  return typeof value === 'string' && /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
}

export function rolloutFilter(value: unknown) {
  if (value === undefined || value === '') return '';
  if (value === 'baseline' || value === 'unattributed') return value;
  if (isId(value) && value !== '00000000-0000-0000-0000-000000000000') return value.toLowerCase();
  return undefined;
}
