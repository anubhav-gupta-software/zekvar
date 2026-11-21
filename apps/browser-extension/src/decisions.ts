import type { MatchedDecision } from './policy';
import { send, type AppId, type PolicyEvent } from './protocol';

export function recordDecision(appId: AppId, match: MatchedDecision, installationId: string | undefined,
  decision: PolicyEvent['decision'] = match.action) {
  const { action: _action, reason: _reason, policyVersion, ...rule } = match;
  const event = {
    eventId: crypto.randomUUID(), appId, timestamp: new Date().toISOString(),
    ...rule, policyVersion, decision,
  } satisfies PolicyEvent;
  console.info(`Zekvar decision ${JSON.stringify(event)}`);
  if (installationId) {
    void send({ type: 'decision', installationId, event }).then(({ error }) => {
      if (error) console.warn('Zekvar could not queue this event.');
    }, () => console.warn('Zekvar could not queue this event.'));
  }
}
