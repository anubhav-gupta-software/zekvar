import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:https';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

export async function startIdentityProvider(tls, clientId, secret, callback) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const otherKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const key = { ...publicKey.export({ format: 'jwk' }), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const attempts = [];
  const fixture = { scenario: { subject: 'pilot-administrator' }, discoveryUnavailable: false, attempts };
  let issuer;
  const server = createServer(tls, async (request, response) => {
    const json = (status, value) => response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      .end(JSON.stringify(value));
    try {
      const url = new URL(request.url, issuer);
      if (url.pathname === '/.well-known/openid-configuration') {
        if (fixture.discoveryUnavailable) return json(503, { error: 'temporarily_unavailable' });
        return json(200, {
          issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks',
          scopes_supported: ['openid'], response_types_supported: ['code'], response_modes_supported: ['query'],
          grant_types_supported: ['authorization_code'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'],
        });
      }
      if (url.pathname === '/jwks') return json(200, { keys: [key] });
      if (url.pathname === '/authorize') {
        assert.equal(url.searchParams.get('redirect_uri'), callback);
        assert.equal(url.searchParams.get('client_id'), clientId);
        assert.equal(url.searchParams.get('scope'), 'openid');
        assert.equal(url.searchParams.get('response_type'), 'code');
        assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
        const state = url.searchParams.get('state');
        const nonce = url.searchParams.get('nonce');
        const challenge = url.searchParams.get('code_challenge');
        for (const value of [state, nonce, challenge]) assert.match(value, /^[A-Za-z0-9_-]{43,128}$/);
        const code = randomUUID();
        const scenario = { ...fixture.scenario };
        codes.set(code, { nonce, challenge, scenario });
        const redirect = new URL(callback);
        redirect.searchParams.set('state', scenario.kind === 'wrong-state' ? randomUUID() : state);
        if (scenario.kind === 'duplicate-state') redirect.searchParams.append('state', state);
        if (scenario.kind === 'denied') redirect.searchParams.set('error', 'access_denied');
        else redirect.searchParams.set('code', code);
        attempts.push({ state, nonce, challenge, redirect: redirect.href });
        return response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }).end(
          `<!doctype html><title>Identity provider fixture</title><h1>Identity provider fixture</h1><a href="${redirect.href.replaceAll('&', '&amp;')}">Continue as test account</a>`);
      }
      if (url.pathname !== '/token' || request.method !== 'POST') return json(404, { error: 'not_found' });
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const fields = new URLSearchParams(Buffer.concat(chunks).toString());
      const authorization = request.headers.authorization;
      const received = authorization?.startsWith('Basic ') && Buffer.from(authorization.slice(6), 'base64').toString().split(':')
        .map((part) => decodeURIComponent(part.replaceAll('+', ' ')));
      const basic = received?.length === 2 && received[0] === clientId && received[1] === secret;
      assert.ok(basic || (fields.get('client_id') === clientId && fields.get('client_secret') === secret));
      assert.equal(fields.get('grant_type'), 'authorization_code');
      assert.equal(fields.get('redirect_uri'), callback);
      const code = fields.get('code');
      const grant = codes.get(code);
      codes.delete(code);
      if (!grant || createHash('sha256').update(fields.get('code_verifier') ?? '').digest('base64url') !== grant.challenge) {
        return json(400, { error: 'invalid_grant' });
      }
      fixture.lastAuth = basic ? 'basic' : 'post';
      const { scenario } = grant;
      const now = Math.floor(Date.now() / 1000);
      const header = encode({ alg: 'RS256', kid: key.kid, typ: 'JWT' });
      const payload = encode({ iss: scenario.kind === 'wrong-issuer' ? issuer + '/other' : issuer,
        aud: scenario.kind === 'wrong-audience' ? 'another-client' : clientId,
        sub: scenario.subject, iat: now - 60, exp: now + (scenario.seconds ?? 300),
        nonce: scenario.kind === 'wrong-nonce' ? randomUUID() : grant.nonce,
        email: 'synthetic-idp-claim@example.test', groups: ['organization-owner'], role: 'owner',
      });
      const signingInput = `${header}.${payload}`;
      const signature = sign('RSA-SHA256', Buffer.from(signingInput), scenario.kind === 'wrong-signature' ? otherKey : privateKey).toString('base64url');
      return json(200, { id_token: `${signingInput}.${signature}`, access_token: 'opaque-fixture-provider-token', token_type: 'Bearer', expires_in: 300 });
    } catch (error) {
      fixture.error = error.message;
      return json(400, { error: 'invalid_request' });
    }
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  issuer = `https://127.0.0.1:${server.address().port}`;
  return Object.assign(fixture, { issuer, close: () => new Promise((resolve) => server.close(resolve)) });
}
