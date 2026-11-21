import { isRecord } from './protocol';

export type DomainRules = { allow: string[]; block: string[] };
export const emptyDomainRules: DomainRules = { allow: [], block: [] };

const ruleLimit = 50;
const firstDomainRuleId = 1;
const hostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function readDomainRules(value: unknown): DomainRules | undefined {
  if (value === undefined) return emptyDomainRules;
  if (!isRecord(value) || !Array.isArray(value.allow) || !Array.isArray(value.block) ||
      value.allow.length + value.block.length > ruleLimit) return;
  const entries: unknown[] = [...value.allow, ...value.block];
  if (new Set(entries).size !== entries.length || entries.some((entry) =>
    typeof entry !== 'string' || entry.length > 253 || entry.trim() !== entry || !hostname.test(entry))) return;
  return { allow: [...value.allow].sort(), block: [...value.block].sort() };
}

export function sameDomainRules(a: DomainRules, b: DomainRules): boolean {
  return a.allow.join(',') === b.allow.join(',') && a.block.join(',') === b.block.join(',');
}

export async function installDomainRules(rules: DomainRules) {
  const dnr = chrome.declarativeNetRequest;
  const addRules: chrome.declarativeNetRequest.Rule[] = [];
  for (const action of [dnr.RuleActionType.ALLOW, dnr.RuleActionType.BLOCK] as const) {
    for (const domain of rules[action]) {
      addRules.push({
        id: firstDomainRuleId + addRules.length,
        priority: domain.split('.').length,
        action: { type: action },
        condition: { requestDomains: [domain], resourceTypes: [dnr.ResourceType.MAIN_FRAME] },
      });
    }
  }
  const ruleIds = Array.from({ length: ruleLimit }, (_, index) => firstDomainRuleId + index);
  const current = await dnr.getDynamicRules({ ruleIds });
  const byId = new Map(current.map((rule) => [rule.id, rule]));
  if (current.length === addRules.length && addRules.every((rule) => {
    const installed = byId.get(rule.id);
    return installed !== undefined && installed.priority === rule.priority && installed.action.type === rule.action.type &&
      installed.condition.requestDomains?.length === 1 && installed.condition.requestDomains[0] === rule.condition.requestDomains?.[0] &&
      installed.condition.resourceTypes?.length === 1 && installed.condition.resourceTypes[0] === dnr.ResourceType.MAIN_FRAME;
  })) return;

  await dnr.updateDynamicRules({ removeRuleIds: current.map(({ id }) => id), addRules });
}
