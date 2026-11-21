import type { MatchedDecision } from './policy';
import { send, type AiPromptApp, type AppId, type Policy, type PolicyEvent } from './protocol';
import { uploadCategory, uploadRule, type UploadDecision, type UploadMethod } from '../../../contracts/policy/uploads';

export function recordDecision(appId: AppId, match: MatchedDecision, installationId: string | undefined,
  decision: PolicyEvent['decision'] = match.action) {
  const { action: _action, reason: _reason, policyVersion, ...rule } = match;
  report({
    eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(),
    ...rule, policyVersion, decision,
  }, installationId);
}

export function recordUploadDecision(appId: AiPromptApp, policy: Policy, installationId: string, decision: UploadDecision, uploadMethod: UploadMethod) {
  report({
    eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(),
    policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, decision,
    ruleId: uploadRule, detectorCategory: uploadCategory, uploadMethod,
  }, installationId);
}

function report(event: PolicyEvent, installationId: string | undefined) {
  console.info(`Zekvar decision ${JSON.stringify(event)}`);
  if (installationId) {
    void send({ type: 'decision', installationId, event }).then(({ error }) => {
      if (error) console.warn('Zekvar could not queue this event.');
    }, () => console.warn('Zekvar could not queue this event.'));
  }
}
