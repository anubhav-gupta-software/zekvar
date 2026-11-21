import { isRecord } from './protocol';
import { domainActions, domainRuleLimit, domainRulePriority, emptyDomainRules, isCanonicalDomain,
  type DomainRules } from '../../../contracts/policy/domains';

export { emptyDomainRules, sameDomainRules } from '../../../contracts/policy/domains';
export type { DomainRules } from '../../../contracts/policy/domains';

const firstDomainRuleId = 1;

export function readDomainRules(value: unknown): DomainRules | undefined {
  if (value === undefined) return emptyDomainRules;
  if (!isRecord(value) || !Array.isArray(value.allow) || !Array.isArray(value.block) ||
      value.allow.length + value.block.length > domainRuleLimit) return;
  const entries: unknown[] = [...value.allow, ...value.block];
  if (new Set(entries).size !== entries.length || !entries.every(isCanonicalDomain)) return;
  return { allow: [...value.allow].sort(), block: [...value.block].sort() };
}

export async function installDomainRules(rules: DomainRules) {
  const dnr = chrome.declarativeNetRequest;
  const addRules: chrome.declarativeNetRequest.Rule[] = [];
  for (const action of domainActions) {
    for (const domain of rules[action]) {
      addRules.push({
        id: firstDomainRuleId + addRules.length,
        priority: domainRulePriority(domain),
        action: { type: action === 'allow' ? dnr.RuleActionType.ALLOW : dnr.RuleActionType.BLOCK },
        condition: { requestDomains: [domain], resourceTypes: [dnr.ResourceType.MAIN_FRAME] },
      });
    }
  }
  const ruleIds = Array.from({ length: domainRuleLimit }, (_, index) => firstDomainRuleId + index);
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
