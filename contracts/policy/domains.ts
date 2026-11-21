export type DomainRules = { allow: string[]; block: string[] };
export const emptyDomainRules: DomainRules = { allow: [], block: [] };
export const domainRuleLimit = 50;
export const domainActions = ['allow', 'block'] as const;
const hostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isCanonicalDomain(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 253 && value.trim() === value && hostname.test(value);
}

export function domainRulePriority(domain: string) {
  return domain.split('.').length;
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

export function evaluateNavigation(url: URL, rules: DomainRules): { action: 'allow' | 'block'; domain?: string } {
  const host = withoutTrailingDot(url.hostname);
  let best: { action: 'allow' | 'block'; domain?: string } = { action: 'allow' };
  for (const action of domainActions) {
    for (const domain of rules[action]) {
      if ((host === domain || host.endsWith(`.${domain}`)) &&
          (!best.domain || domainRulePriority(domain) > domainRulePriority(best.domain))) {
        best = { action, domain };
      }
    }
  }
  return best;
}
