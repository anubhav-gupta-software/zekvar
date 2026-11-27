import catalog from './saas-catalog.json';

// The bundled SaaS catalog ships with Browser and Control. Browser matches only the exact hostnames in `hosts`
// and the domains in `domains` (the domain itself or any subdomain). It reports the catalog ID, never the URL.
export const saasCategories = {
  collaboration: 'Collaboration', productivity: 'Productivity', 'file-sharing': 'File sharing', developer: 'Developer tools',
  crm: 'CRM and support', hr: 'HR and recruiting', finance: 'Finance', design: 'Design', marketing: 'Marketing',
  personal: 'Personal accounts', ai: 'AI tools',
} as const;
export const saasRisks = {
  business: 'Business tool', 'personal-file-sharing': 'Personal file sharing', 'personal-webmail': 'Personal webmail',
  'personal-messaging': 'Personal messaging', 'public-paste': 'Public paste or code sharing', 'unsanctioned-ai': 'Unsanctioned AI',
} as const;
export type SaasCategory = keyof typeof saasCategories;
export type SaasRisk = keyof typeof saasRisks;
export type SaasApp = { id: string; name: string; category: SaasCategory; risk: SaasRisk; hosts: string[]; domains: string[] };

export const saasCatalogVersion: number = catalog.version;
export const saasCatalog = catalog.apps as SaasApp[];
export const saasClassifications = ['unclassified', 'under_review', 'sanctioned', 'unsanctioned'] as const;
export type SaasClassification = typeof saasClassifications[number];
export const saasClassificationLabels: Record<SaasClassification, string> = {
  unclassified: 'Unclassified', under_review: 'Under review', sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned',
};

const byId = new Map(saasCatalog.map((app) => [app.id, app]));
const byHost = new Map<string, string>();
const byDomain = new Map<string, string>();
for (const app of saasCatalog) {
  for (const host of app.hosts) byHost.set(host, app.id);
  for (const domain of app.domains) byDomain.set(domain, app.id);
}

export function isSaasAppId(value: unknown): value is string {
  return typeof value === 'string' && byId.has(value);
}

export function saasApp(id: string) {
  return byId.get(id);
}

export function isSaasCategory(value: unknown): value is SaasCategory {
  return typeof value === 'string' && Object.hasOwn(saasCategories, value);
}

export function isSaasRisk(value: unknown): value is SaasRisk {
  return typeof value === 'string' && Object.hasOwn(saasRisks, value);
}

export function isSaasClassification(value: unknown): value is SaasClassification {
  return typeof value === 'string' && (saasClassifications as readonly string[]).includes(value);
}

// An exact hostname wins over a domain, so gist.github.com is not counted as GitHub.
export function saasAppAt(hostname: string): string | undefined {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const exact = byHost.get(host);
  if (exact) return exact;
  for (let suffix = host; suffix;) {
    const match = byDomain.get(suffix);
    if (match) return match;
    const dot = suffix.indexOf('.');
    suffix = dot < 0 ? '' : suffix.slice(dot + 1);
  }
}

// Domain rules block a domain and its subdomains, so blocking an app uses its hostnames and domains.
export function saasBlockDomains(id: string) {
  const app = byId.get(id);
  return app ? [...new Set([...app.domains, ...app.hosts])].sort() : [];
}

// The coarse UTC day is the only time Browser reports for a SaaS app.
export function saasDay(time: number) {
  return new Date(time).toISOString().slice(0, 10);
}
