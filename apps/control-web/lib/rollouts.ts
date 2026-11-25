import type { AccessIdentity } from './access';
import type { AiPromptApp } from '../../../contracts/policy/apps';

export const rolloutStatuses = {
  pending_review: 'Awaiting approval', running: 'Running', paused: 'Paused', completed: 'Completed', rolled_back: 'Rolled back',
  cancelled: 'Cancelled', rejected: 'Rejected', withdrawn: 'Withdrawn', expired: 'Expired',
} as const;

export const rolloutPauseReasons = {
  paused_by_administrator: 'An administrator paused the plan.',
  acknowledgment_below_threshold: 'Too few active browsers acknowledged the stage policy after the soak time.',
  composer_readiness_incomplete: 'A required app is missing a fresh detected composer on some stage browsers.',
  no_active_browsers: 'The stage has no active browsers to measure.',
  block_events_exceeded: 'Block events under the stage policy exceeded the limit.',
  warn_override_rate_exceeded: 'Employees continued past too many warnings under the stage policy.',
  target_changed: 'The stage scope was changed outside this plan.',
  approver_inactive: 'The approving administrator no longer has active Control access.',
  review_mode_changed: 'Policy reviews became required after this plan started without approval.',
} as const;

export const rolloutStageStates = {
  waiting: 'Waiting', active: 'Current stage', passed: 'Passed', restored: 'Restored', changed: 'Changed outside plan · kept',
} as const;

export type RolloutStatus = keyof typeof rolloutStatuses;
export type RolloutPauseReason = keyof typeof rolloutPauseReasons;

export type RolloutStage = {
  position: number; groupId: string | null; groupName: string | null; minSoakSeconds: number; minAcknowledgedPercent: number;
  requireComposerReady: AiPromptApp[]; maxBlockEvents: number | null; maxWarnOverridePercent: number | null;
  priorVersion: number | null; publishedVersion: number | null; publishedAt: string | null; rollbackVersion: number | null;
  rollbackOutcome: 'restored' | 'changed' | null; state: keyof typeof rolloutStageStates;
};

export type RolloutGate = {
  evaluatedAt: string; stage: number; policyVersion: number; currentVersion: number; soakEndsAt: string; soaked: boolean;
  acknowledgment: { active: number; acknowledged: number; threshold: number; passed: boolean };
  composers: { appId: AiPromptApp; active: number; detected: number; unsupported: number; passed: boolean }[];
  blocks: { blocks: number; threshold: number | null; passed: boolean };
  overrides: { warnings: number; overrides: number; threshold: number | null; passed: boolean };
  passed: boolean; failure: RolloutPauseReason | null;
};

export type RolloutPlan = {
  id: string; name: string; sourceVersion: number; status: RolloutStatus; currentStage: number; revision: number; requiresReview: boolean;
  creator: AccessIdentity | null; approver: AccessIdentity | null; createdAt: string; expiresAt: string; decidedAt: string | null;
  evaluatedAt: string | null; nextEvaluationAt: string | null; pauseReason: RolloutPauseReason | null; gate: RolloutGate | null;
  finishedAt: string | null; stages: RolloutStage[];
};

export type RolloutStageRequest = {
  groupId: string | null; minSoakSeconds: number; minAcknowledgedPercent: number; requireComposerReady?: AiPromptApp[];
  maxBlockEvents?: number | null; maxWarnOverridePercent?: number | null;
};

export type RolloutAudit = {
  planId: string; planName: string; event: string; stage?: number; groupId?: string; groupName?: string; reason?: RolloutPauseReason;
  automatic?: boolean; approver?: AccessIdentity;
};

export const rolloutEvents: Record<string, string> = {
  requested: 'Approval requested', approved: 'Approved and started', started: 'Started', stage_published: 'Stage published',
  stage_restored: 'Stage restored', paused: 'Paused', resumed: 'Resumed', completed: 'Completed', rolled_back: 'Rolled back',
  cancelled: 'Cancelled', rejected: 'Rejected', withdrawn: 'Withdrawn',
};

export const maxRolloutStages = 5;

export function percent(part: number, whole: number) {
  return whole === 0 ? 0 : Math.floor((part * 100) / whole);
}

export function soakLabel(seconds: number) {
  if (seconds === 0) return 'No soak';
  if (seconds % 3600 === 0) return `${seconds / 3600} h soak`;
  return `${Math.round(seconds / 60)} min soak`;
}
