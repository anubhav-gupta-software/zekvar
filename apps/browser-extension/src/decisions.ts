import type { MatchedDecision } from './policy';
import { send, type AppId, type PolicyEvent } from './protocol';

export function recordDecision(appId: AppId, match: MatchedDecision, installationId: string | undefined,
  decision: PolicyEvent['decision'] = match.action) {
  const event: PolicyEvent = {
    eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(),
    ruleId: match.ruleId, detectorCategory: match.detectorCategory, policyVersion: match.policyVersion, decision,
  };
  console.info(`Zekvar decision ${JSON.stringify(event)}`);
  if (installationId) {
    void send({ type: 'decision', installationId, event }).then(({ error }) => {
      if (error) console.warn('Zekvar could not queue this event.');
    }, () => console.warn('Zekvar could not queue this event.'));
  }
}
