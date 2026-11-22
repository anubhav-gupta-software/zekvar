import { modes, type DetectorMode, type PolicyMode } from '../../../contracts/policy/prompt';
export { modes, detectorModes } from '../../../contracts/policy/prompt';
export { ruleLabels } from '../../../contracts/policy/prompt';
export type { DetectorMode } from '../../../contracts/policy/prompt';
export type { DomainRules, PathRules } from '../../../contracts/policy/domains';
import type { DomainRules, PathRules } from '../../../contracts/policy/domains';
import type { UploadMethod, UploadModes, UploadTypes } from '../../../contracts/policy/uploads';
import type { CustomApp, CustomAppId } from '../../../contracts/policy/discovery';
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
export type DiscoveredAppId = AiAppId | CustomAppId;
export const classifications = ['unreviewed', 'approved', 'unapproved'] as const;
export type AppClassification = typeof classifications[number];
export const classificationLabels: Record<AppClassification, string> = {
  unreviewed: 'Unreviewed', approved: 'Approved', unapproved: 'Unapproved',
};
export type DiscoveredApp = {
  appId: DiscoveredAppId; status: AppClassification; browsersSeen: number; lastObservedAt: string | null; name?: string; host?: string;
};
export type PolicyGroup = { id: string; name: string; effectiveVersion: number; publishedVersion: number | null; browsers: number };
export type PolicyGroupChange = { groupId: string | null; groupName: string | null; installationId: string | null; sourceVersion: number | null };

export type Policy = {
  version: number;
  mode: Mode;
  githubPatMode?: DetectorMode;
  paymentCardMode?: DetectorMode;
  privateKeyMode?: DetectorMode;
  uploadModes?: UploadModes;
  uploadTypes?: UploadTypes;
  discoveryEnabled?: boolean;
  customApps?: CustomApp[];
  promptExceptions?: PromptException[];
  extensionInventoryEnabled?: boolean;
  claudePromptEnabled?: boolean;
  domainRules?: DomainRules;
  pathRules?: PathRules;
  publishedAt: string;
  restoredFrom: number | null;
};

export type Installation = {
  installationId: string;
  enrolledAt: string;
  lastSeenAt: string;
  appliedPolicyVersion: number | null;
  revokedAt: string | null;
  chatGptCoverage?: 'ready' | 'unsupported' | null;
  chatGptCheckedAt?: string | null;
  geminiCoverage?: 'ready' | 'unsupported' | null;
  geminiCheckedAt?: string | null;
  claudePromptEnabled?: boolean;
  claudeCoverage?: 'ready' | 'unsupported' | null;
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
};

export const composerStateLabels = {
  detected: 'Detected', unsupported: 'Unsupported', stale: 'Stale', unobserved: 'Unobserved',
  policy_pending: 'Policy pending', off: 'Off',
} as const;
export type ComposerState = keyof typeof composerStateLabels;
export type ComposerCheck = { state: ComposerState; checkedAt: string | null };
export type BrowserComposerReadiness = {
  activeInstallations: number;
  apps: { appId: AiAppId; counts: Record<ComposerState, number> }[];
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
};

export type Grant = { grant: string; expiresAt: string };
export type Feedback = {
  error?: string; message?: string; grant?: Grant; issuedAccess?: import('./access').IssuedControlAccess; reviewId?: string;
  issuedEnrollmentBatch?: import('./enrollment').IssuedEnrollmentBatch; enrollmentRequestId?: string;
};

export const utc = new Intl.DateTimeFormat('en-US', {
  dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC',
});

export function isId(value: unknown): value is string {
  return typeof value === 'string' && /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
}
