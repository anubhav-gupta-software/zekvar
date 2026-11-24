import type { AiPromptApp } from '../../../contracts/policy/apps';
import type { PromptRuleId } from '../../../contracts/policy/prompt';

export const promptRequestDecisions = ['declined', 'exception_available'] as const;
export type PromptRequestDecision = typeof promptRequestDecisions[number];
export type PromptRequestStatus = PromptRequestDecision | 'pending';
export type PromptExceptionRequest = {
  id: string; installationId: string; eventId: string; appId: AiPromptApp; ruleId: PromptRuleId;
  policyVersion: number; decision: 'warn' | 'block';
  groupId: string | null; groupName: string | null;
  requestedAt: string; status: PromptRequestStatus; decidedAt: string | null; decidedBy: string | null; publishedVersion: number | null;
};

export const promptRequestLabels: Record<PromptRequestStatus, string> = {
  pending: 'Pending', declined: 'Declined', exception_available: 'Exception published',
};
