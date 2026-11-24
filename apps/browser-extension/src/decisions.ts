import type { MatchedDecision } from './policy';
import { send, type AppId, type Policy, type PolicyEvent, type RuleMetadata } from './protocol';
import { uploadCategory, uploadRule, type UploadApp, type UploadDecision, type UploadMetadata, type UploadMethod } from '../../../contracts/policy/uploads';
import type { inspectClipboard } from '../../../contracts/policy/clipboard';

export function recordDecision(appId: AppId, match: MatchedDecision, installationId: string | undefined,
  decision: PolicyEvent['decision'] = match.action, timestamp = new Date().toISOString()) {
  const { action: _action, reason: _reason, policyVersion, ...rule } = match;
  const eventId = crypto.randomUUID();
  report({
    eventId, appId, timestamp,
    ...rule, policyVersion, decision,
  }, installationId);
  return eventId;
}

export function recordUploadDecision(appId: UploadApp, policy: Policy, installationId: string, decision: UploadDecision, uploadMethod: UploadMethod) {
  report({
    eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(),
    policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, decision,
    ruleId: uploadRule, detectorCategory: uploadCategory, uploadMethod,
  }, installationId);
}

export function recordFileInspection(appId: UploadApp, policy: Policy, installationId: string,
  rule: RuleMetadata | Pick<UploadMetadata, 'ruleId' | 'detectorCategory'>, uploadMethod: UploadMethod,
  timestamp: string, decision: UploadDecision = 'monitor') {
  report({ eventId: crypto.randomUUID(), appId, timestamp, ...rule,
    policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, decision, uploadMethod }, installationId);
}

export function recordClipboardDecision(appId: AppId, policy: Policy, installationId: string, result: NonNullable<ReturnType<typeof inspectClipboard>>) {
  report({ eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(), ...result,
    policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, clipboardPaste: true }, installationId);
}

function report(event: PolicyEvent, installationId: string | undefined) {
  console.info(`Zekvar decision ${JSON.stringify(event)}`);
  if (installationId) {
    void send({ type: 'decision', installationId, event }).then(({ error }) => {
      if (error) console.warn('Zekvar could not queue this event.');
    }, () => console.warn('Zekvar could not queue this event.'));
  }
}
