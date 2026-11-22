import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';
import * as oidc from 'openid-client';
import { ssoApi } from './api';
import { startSession } from './session';

function httpsUrl(input: string | undefined) {
  if (!input || input !== input.trim() || input.length > 2048 || /[?#]/.test(input) || !URL.canParse(input)) return;
  const value = new URL(input);
  if (value.protocol === 'https:' && !value.username && !value.password) return value;
}

export function ssoOptions() {
  if (process.env.ZEKVAR_HOSTED_PILOT !== '1') return;
  const issuer = process.env.ZEKVAR_OIDC_ISSUER;
  const issuerUrl = httpsUrl(issuer);
  const dashboard = httpsUrl(process.env.ZEKVAR_OIDC_DASHBOARD_ORIGIN);
  const clientId = process.env.ZEKVAR_OIDC_CLIENT_ID;
  const secret = process.env.ZEKVAR_OIDC_CLIENT_SECRET;
  const exchangeToken = process.env.ZEKVAR_OIDC_EXCHANGE_TOKEN;
  const authMethod = process.env.ZEKVAR_OIDC_CLIENT_AUTH || 'basic';
  if (!issuer || !issuerUrl || dashboard?.pathname !== '/' || !clientId || !secret ||
      !exchangeToken || !/^[a-f0-9]{64}$/.test(exchangeToken) || !['basic', 'post'].includes(authMethod)) return;
  return { issuer, issuerUrl, dashboard, clientId, secret, exchangeToken, authMethod };
}

type Options = NonNullable<ReturnType<typeof ssoOptions>>;
type Transaction = { state: string; nonce: string; verifier: string; expires: number };
const cookie = '__Host-zekvar_control_sso';
const cookieScope = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' } as const;
const lifetime = 300;
const server = globalThis as typeof globalThis & {
  zekvarSsoTransactions?: Map<string, Transaction>;
  zekvarSsoDiscovery?: Promise<oidc.Configuration>;
};
const transactions = server.zekvarSsoTransactions ??= new Map();

function configuration(options: Options) {
  return server.zekvarSsoDiscovery ??= discover(options).catch((error: unknown) => {
    server.zekvarSsoDiscovery = undefined;
    throw error;
  });
}

async function discover(options: Options) {
  const clientAuth = options.authMethod === 'post' ? oidc.ClientSecretPost(options.secret) : oidc.ClientSecretBasic(options.secret);
  const config = await oidc.discovery(options.issuerUrl, options.clientId,
    { id_token_signed_response_alg: 'RS256' }, clientAuth, { timeout: 5, execute: [oidc.enableNonRepudiationChecks] });
  const metadata = config.serverMetadata();
  if (metadata.issuer !== options.issuer || !metadata.jwks_uri) throw new Error('Unexpected OpenID Connect issuer or signing keys.');
  return config;
}

export async function beginSso(options: Options) {
  const config = await configuration(options);
  const transaction = { state: oidc.randomState(), nonce: oidc.randomNonce(), verifier: oidc.randomPKCECodeVerifier(),
    expires: Date.now() + lifetime * 1000 };
  const redirect = oidc.buildAuthorizationUrl(config, {
    redirect_uri: new URL('/auth/sso/callback', options.dashboard).href,
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

export async function finishSso(options: Options, query: URLSearchParams) {
  const jar = await cookies();
  const id = jar.get(cookie)?.value;
  const transaction = id && transactions.get(id);
  if (!id || !transaction || transaction.expires <= Date.now() || query.getAll('state').length !== 1 ||
      query.get('state') !== transaction.state) throw new Error('Invalid sign-in transaction.');
  transactions.delete(id);
  jar.set(cookie, '', { ...cookieScope, maxAge: 0 });

  const callback = new URL('/auth/sso/callback', options.dashboard);
  callback.search = query.toString();
  const result = await oidc.authorizationCodeGrant(await configuration(options), callback, {
    expectedState: transaction.state, expectedNonce: transaction.nonce, pkceCodeVerifier: transaction.verifier,
  });
  const identity = result.claims();
  if (!identity || identity.iss !== options.issuer || !/^[!-~]{1,255}$/.test(identity.sub)) throw new Error('Invalid OpenID Connect identity.');
  const expiresAt = new Date(identity.exp * 1000).toISOString();
  const session = await ssoApi.exchange(options.exchangeToken, options.issuer, identity.sub, expiresAt);
  if (!/^[a-f0-9]{64}$/.test(session.token)) throw new Error('Invalid Control session.');
  await startSession(session.token, Date.parse(session.expiresAt));
}
