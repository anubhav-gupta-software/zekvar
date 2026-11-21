export type DomainRules = { allow: string[]; block: string[] };
export type PathRules = { allow: string[]; block: string[] };
export const emptyDomainRules: DomainRules = { allow: [], block: [] };
export const emptyPathRules: PathRules = { allow: [], block: [] };
export const domainRuleLimit = 50;
export const pathLengthLimit = 64;
export const domainActions = ['allow', 'block'] as const;
const hostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isCanonicalDomain(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 253 && value.trim() === value && hostname.test(value);
}

export function domainRulePriority(domain: string, path = '') {
  return domain.split('.').length * (pathLengthLimit + 1) + path.length;
}

export function sameDomainRules(a: DomainRules, b: DomainRules): boolean {
  return a.allow.join(',') === b.allow.join(',') && a.block.join(',') === b.block.join(',');
}

function withoutTrailingDot(value: string) {
  return value.endsWith('.') ? value.slice(0, -1) : value;
}

export function canonicalizeDomainRules(input: DomainRules): DomainRules | undefined {
  if (input.allow.length + input.block.length > domainRuleLimit) return;
  const normalized = (domains: string[]) => [...new Set(domains.map((domain) => {
    const value = withoutTrailingDot(domain.trim());
    // Match Control's ASCII validation before normalizing case.
    return /^[\x00-\x7f]+$/.test(value) ? value.toLowerCase() : value;
  }))].sort();
  const allow = normalized(input.allow);
  const block = normalized(input.block);
  if (![...allow, ...block].every(isCanonicalDomain) || allow.some((domain) => block.includes(domain))) return;
  return { allow, block };
}

export function splitPathRule(value: string) {
  const slash = value.indexOf('/');
  return { domain: value.slice(0, slash), path: value.slice(slash) };
}

export function canonicalizePathRules(input: PathRules): PathRules | undefined {
  if (input.allow.length + input.block.length > domainRuleLimit) return;
  const paths = { allow: new Set<string>(), block: new Set<string>() };
  for (const action of domainActions) {
    for (const entry of input[action]) {
      const value = entry.trim();
      if (!value.includes('/')) return;
      const { domain, path } = splitPathRule(value);
      if (!/^[\x00-\x7f]+$/.test(domain)) return;
      const host = withoutTrailingDot(domain.toLowerCase());
      const prefix = path.endsWith('/') ? path.slice(0, -1) : path;
      if (!isCanonicalDomain(host) || prefix.length > pathLengthLimit || prefix.trim() !== prefix ||
          !/^(?:\/[A-Za-z0-9._~-]+)+$/.test(prefix) || prefix.split('/').some((segment) => segment === '.' || segment === '..')) return;
      paths[action].add(host + prefix);
    }
  }
  if ([...paths.allow].some((entry) => paths.block.has(entry))) return;
  return { allow: [...paths.allow].sort(), block: [...paths.block].sort() };
}

export function pathRuleRegex(action: 'allow' | 'block', path: string): string {
  const prefix = '^https?://[^/?#]+' + path.replaceAll('.', '\\.');
  if (action === 'allow') {
    return prefix + '(?:/[A-Za-z0-9._~/-]*)?(?:[?#]|$)';
  }
  return prefix + '(?:[/;?#]|%2[fF]|$)';
}

export function ruleCount(rules: DomainRules) {
  return rules.allow.length + rules.block.length;
}

export function domainLines(value: string) {
  return value.split('\n').map((line) => line.trim()).filter(Boolean);
}

export function parseWebAddress(input: string): URL | undefined {
  try {
    const url = new URL(input);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url;
  } catch {
    return undefined;
  }
}

export function evaluateNavigation(url: URL, rules: DomainRules, paths = emptyPathRules):
  { action: 'allow' | 'block'; domain?: string; pathRule?: string } {
  const host = withoutTrailingDot(url.hostname);
  const matchesHost = (domain: string) => host === domain || host.endsWith(`.${domain}`);
  let best: { action: 'allow' | 'block'; domain?: string; pathRule?: string } = { action: 'allow' };
  let priority = 0;
  for (const action of domainActions) {
    for (const domain of rules[action]) {
      if (matchesHost(domain) && domainRulePriority(domain) > priority) {
        best = { action, domain };
        priority = domainRulePriority(domain);
      }
    }
    for (const entry of paths[action]) {
      const { domain, path } = splitPathRule(entry);
      const score = domainRulePriority(domain, path);
      if (score > priority && matchesHost(domain) && new RegExp(pathRuleRegex(action, path)).test(url.href)) {
        best = { action, domain, pathRule: entry };
        priority = score;
      }
    }
  }
  return best;
}
