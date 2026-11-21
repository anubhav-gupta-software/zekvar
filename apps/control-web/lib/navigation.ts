import { canonicalizeDomainRules, canonicalizePathRules, domainLines, domainRuleLimit,
  ruleCount } from '../../../contracts/policy/domains';

export function readNavigationRules(allow: string, block: string, allowPaths: string, blockPaths: string) {
  const domains = { allow: domainLines(allow), block: domainLines(block) };
  const paths = { allow: domainLines(allowPaths), block: domainLines(blockPaths) };
  const domainRules = canonicalizeDomainRules(domains);
  if (!domainRules) return { error: 'Enter up to 50 hostnames, one per line. A hostname can appear in only one list.' };
  const pathRules = canonicalizePathRules(paths);
  if (!pathRules) return { error: 'Enter distinct hostname/path prefixes such as example.com/work. Each path can contain up to 64 characters.' };
  if (ruleCount(domains) + ruleCount(paths) > domainRuleLimit) return { error: 'Enter up to 50 domain and path rules combined.' };
  return { domainRules, pathRules };
}
