import { isRecord } from './protocol';
import { canonicalizePathRules, domainActions, domainRuleLimit, domainRulePriority, emptyDomainRules, emptyPathRules,
  isCanonicalDomain, pathRuleRegex, sameDomainRules, splitPathRule, type DomainRules, type PathRules } from '../../../contracts/policy/domains';

export { domainRuleLimit, emptyDomainRules, emptyPathRules, ruleCount, sameDomainRules } from '../../../contracts/policy/domains';
export type { DomainRules, PathRules } from '../../../contracts/policy/domains';

const firstDomainRuleId = 1;

export function readDomainRules(value: unknown): DomainRules | undefined {
  if (value === undefined) return emptyDomainRules;
  if (!isRecord(value) || !Array.isArray(value.allow) || !Array.isArray(value.block) ||
      value.allow.length + value.block.length > domainRuleLimit) return;
  const entries: unknown[] = [...value.allow, ...value.block];
  if (new Set(entries).size !== entries.length || !entries.every(isCanonicalDomain)) return;
  return { allow: [...value.allow].sort(), block: [...value.block].sort() };
}

export function readPathRules(value: unknown): PathRules | undefined {
  if (value === undefined) return emptyPathRules;
  if (!isRecord(value) || !Array.isArray(value.allow) || !Array.isArray(value.block) ||
      ![...value.allow, ...value.block].every((entry) => typeof entry === 'string')) return;
  const submitted = { allow: [...value.allow].sort(), block: [...value.block].sort() };
  const normalized = canonicalizePathRules(submitted);
  if (normalized && sameDomainRules(normalized, submitted)) return normalized;
}

export async function installDomainRules(rules: DomainRules, paths: PathRules) {
  const dnr = chrome.declarativeNetRequest;
  const addRules: chrome.declarativeNetRequest.Rule[] = [];
  for (const action of domainActions) {
    const type = action === 'allow' ? dnr.RuleActionType.ALLOW : dnr.RuleActionType.BLOCK;
    for (const domain of rules[action]) {
      addRules.push({
        id: firstDomainRuleId + addRules.length,
        priority: domainRulePriority(domain),
        action: { type },
        condition: { requestDomains: [domain], resourceTypes: [dnr.ResourceType.MAIN_FRAME] },
      });
    }
    for (const entry of paths[action]) {
      const { domain, path } = splitPathRule(entry);
      addRules.push({
        id: firstDomainRuleId + addRules.length,
        priority: domainRulePriority(domain, path),
        action: { type },
        condition: { requestDomains: [domain], resourceTypes: [dnr.ResourceType.MAIN_FRAME],
          regexFilter: pathRuleRegex(action, path), isUrlFilterCaseSensitive: true },
      });
    }
  }
  const ruleIds = Array.from({ length: domainRuleLimit }, (_, index) => firstDomainRuleId + index);
  const current = await dnr.getDynamicRules({ ruleIds });
  const byId = new Map(current.map((rule) => [rule.id, rule]));
  if (current.length === addRules.length && addRules.every((rule) => {
    const installed = byId.get(rule.id);
    return installed !== undefined && installed.priority === rule.priority && installed.action.type === rule.action.type &&
      installed.condition.regexFilter === rule.condition.regexFilter &&
      (installed.condition.isUrlFilterCaseSensitive ?? false) === (rule.condition.isUrlFilterCaseSensitive ?? false) &&
      installed.condition.requestDomains?.length === 1 && installed.condition.requestDomains[0] === rule.condition.requestDomains?.[0] &&
      installed.condition.resourceTypes?.length === 1 && installed.condition.resourceTypes[0] === dnr.ResourceType.MAIN_FRAME;
  })) return;

  await Promise.all(addRules.map(async ({ condition: { regexFilter } }) => {
    if (regexFilter && !(await dnr.isRegexSupported({ regex: regexFilter, isCaseSensitive: true })).isSupported) {
      throw new Error('Chrome rejected a URL path rule');
    }
  }));
  await dnr.updateDynamicRules({ removeRuleIds: current.map(({ id }) => id), addRules });
}
