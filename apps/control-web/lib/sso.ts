import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';
import * as oidc from 'openid-client';
import { ssoApi } from './api';
import { startSession } from './session';

function httpsUrl(input: unknown) {
  if (typeof input !== 'string' || !input || input !== input.trim() || input.length > 2048 || /[?#]/.test(input) || !URL.canParse(input)) return;
  const value = new URL(input);
  if (value.protocol === 'https:' && !value.username && !value.password) return value;
}

function provider(dashboard: URL | undefined, { issuer, clientId, clientSecret, exchangeToken, authMethod = 'basic' }: Record<string, unknown>,
  organizationSlug?: string) {
  const issuerUrl = httpsUrl(issuer);
  if (typeof issuer !== 'string' || !issuerUrl || dashboard?.pathname !== '/' ||
      typeof clientId !== 'string' || !clientId || typeof clientSecret !== 'string' || !clientSecret ||
      typeof exchangeToken !== 'string' || !/^[a-f0-9]{64}$/.test(exchangeToken) ||
      (authMethod !== 'basic' && authMethod !== 'post')) return;
  return { issuer, issuerUrl, dashboard, clientId, clientSecret, exchangeToken, authMethod, organizationSlug };
}

type Options = NonNullable<ReturnType<typeof provider>>;

function providers() {
  if (process.env.ZEKVAR_HOSTED_PILOT !== '1') return;
  const dashboard = httpsUrl(process.env.ZEKVAR_OIDC_DASHBOARD_ORIGIN);
  const issuer = process.env.ZEKVAR_OIDC_ISSUER;
  const exchangeToken = process.env.ZEKVAR_OIDC_EXCHANGE_TOKEN;
  const configured = process.env.ZEKVAR_OIDC_ORGANIZATIONS;
  if (!configured) {
    const legacy = provider(dashboard, { issuer, exchangeToken, clientId: process.env.ZEKVAR_OIDC_CLIENT_ID,
      clientSecret: process.env.ZEKVAR_OIDC_CLIENT_SECRET, authMethod: process.env.ZEKVAR_OIDC_CLIENT_AUTH || 'basic' });
    return legacy ? { legacy } : undefined;
  }
  if (issuer || exchangeToken || process.env.ZEKVAR_OIDC_CLIENT_ID || process.env.ZEKVAR_OIDC_CLIENT_SECRET)
    throw new Error('Choose either legacy OIDC settings or organization OIDC settings.');
  let entries: unknown;
  try { entries = JSON.parse(configured); }
  catch { throw new Error('Configure organization OIDC settings as a JSON array.'); }
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('Configure a nonempty array of organization OIDC settings.');
  const organizations = new Map<string, Options>();
  const tokens = new Set<string>();
  for (const entry of entries) {
    const slug: unknown = entry?.organizationSlug;
    if (typeof slug !== 'string' || !/^[a-z0-9-]{1,63}$/.test(slug) || organizations.has(slug))
      throw new Error('Configure distinct organization slugs for OIDC.');
    const settings = provider(dashboard, entry, slug);
    if (!settings || tokens.has(settings.exchangeToken))
      throw new Error('Configure HTTPS OIDC settings and a distinct exchange token for each organization.');
    organizations.set(slug, settings);
    tokens.add(settings.exchangeToken);
  }
  return { organizations };
}

export function ssoMode() {
  const registry = providers();
  return registry?.organizations ? 'organization' : registry?.legacy ? 'legacy' : undefined;
}

export function ssoOptions(organizationSlug?: string) {
  const registry = providers();
  return organizationSlug === undefined ? registry?.legacy : registry?.organizations?.get(organizationSlug);
}

type Transaction = { state: string; nonce: string; verifier: string; expires: number; organizationSlug?: string };
const cookie = '__Host-zekvar_control_sso';
const cookieScope = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' } as const;
const lifetime = 300;
const server = globalThis as typeof globalThis & {
  zekvarSsoTransactions?: Map<string, Transaction>;
  zekvarSsoDiscovery?: Map<string, Promise<oidc.Configuration>>;
};
const transactions = server.zekvarSsoTransactions ??= new Map();
const discoveries = server.zekvarSsoDiscovery ??= new Map();

function configuration(options: Options) {
  const key = options.organizationSlug ?? '';
  const cached = discoveries.get(key);
  if (cached) return cached;
  const pending = discover(options).catch((error: unknown) => {
    discoveries.delete(key);
    throw error;
  });
  discoveries.set(key, pending);
  return pending;
}

async function discover(options: Options) {
  const clientAuth = options.authMethod === 'post' ? oidc.ClientSecretPost(options.clientSecret) : oidc.ClientSecretBasic(options.clientSecret);
  const config = await oidc.discovery(options.issuerUrl, options.clientId,
    { id_token_signed_response_alg: 'RS256' }, clientAuth, { timeout: 5, execute: [oidc.enableNonRepudiationChecks] });
  const metadata = config.serverMetadata();
  if (metadata.issuer !== options.issuer || !metadata.jwks_uri) throw new Error('Unexpected OpenID Connect issuer or signing keys.');
  return config;
}

function callbackUrl(options: Options) {
  const path = '/auth/sso/callback';
  return new URL(options.organizationSlug === undefined ? path : `${path}/${options.organizationSlug}`, options.dashboard);
}

export async function beginSso(options: Options) {
  const config = await configuration(options);
  const transaction = { state: oidc.randomState(), nonce: oidc.randomNonce(), verifier: oidc.randomPKCECodeVerifier(),
    expires: Date.now() + lifetime * 1000, organizationSlug: options.organizationSlug };
  const redirect = oidc.buildAuthorizationUrl(config, {
    redirect_uri: callbackUrl(options).href,
    scope: 'openid', response_type: 'code', response_mode: 'query',
    state: transaction.state, nonce: transaction.nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(transaction.verifier), code_challenge_method: 'S256',
  });
  const jar = await cookies();
  const previous = jar.get(cookie)?.value;
  if (previous) transactions.delete(previous);
  const now = Date.now();
  for (const [id, value] of transactions) if (value.expires <= now) transactions.delete(id);
  if (transactions.size >= 500) throw new Error('Too many pending sign-ins.');
  const id = randomBytes(32).toString('hex');
  transactions.set(id, transaction);
  jar.set(cookie, id, { ...cookieScope, maxAge: lifetime });
  return redirect;
}

async function finishSso(options: Options, request: URL) {
  const callback = callbackUrl(options);
  const query = request.searchParams;
  const jar = await cookies();
  const id = jar.get(cookie)?.value;
  const transaction = id && transactions.get(id);
  if (!id || !transaction || transaction.expires <= Date.now() || query.getAll('state').length !== 1 ||
      query.get('state') !== transaction.state || transaction.organizationSlug !== options.organizationSlug ||
      request.pathname !== callback.pathname) throw new Error('Invalid sign-in transaction.');
  transactions.delete(id);
  jar.set(cookie, '', { ...cookieScope, maxAge: 0 });

  callback.search = query.toString();
  const result = await oidc.authorizationCodeGrant(await configuration(options), callback, {
    expectedState: transaction.state, expectedNonce: transaction.nonce, pkceCodeVerifier: transaction.verifier,
  });
  const identity = result.claims();
  if (!identity || identity.iss !== options.issuer || !/^[!-~]{1,255}$/.test(identity.sub)) throw new Error('Invalid OpenID Connect identity.');
  const expiresAt = new Date(identity.exp * 1000).toISOString();
  const session = await ssoApi.exchange(options.exchangeToken, options.issuer, identity.sub, expiresAt, options.organizationSlug);
  if (!/^[a-f0-9]{64}$/.test(session.token)) throw new Error('Invalid Control session.');
  await startSession(session.token, Date.parse(session.expiresAt));
}

export async function completeSsoRequest(request: Request, organizationSlug?: string) {
  const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };
  const settings = ssoOptions(organizationSlug);
  if (!settings) return new Response(null, { status: 404, headers });
  try {
    await finishSso(settings, new URL(request.url));
  } catch {
    return new Response(null, { status: 303, headers: { ...headers, Location: '/?signIn=sso-error' } });
  }

  // Complete the cross-site navigation before using the Strict session cookie on the dashboard.
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=/"><title>Signed in to Control</title><main><h1>Signed in to Control</h1><a href="/">Continue to Control</a></main></html>`, {
    headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" },
  });
}
