import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';

export const domainFixtureArgs = ['--host-resolver-rules=MAP *.test 127.0.0.1, MAP *.test. 127.0.0.1', '--no-proxy-server'];

export async function startDomainFixture() {
  const requests = [];
  const server = createServer((request, reply) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    requests.push(url.href);
    if (url.hostname === 'redirect.test') {
      const target = new URL(url);
      target.hostname = 'apps.test';
      reply.writeHead(302, { Location: target.href }).end();
      return;
    }
    reply.writeHead(200, { 'Content-Type': 'text/plain' }).end('Zekvar domain fixture');
  });
  const close = () => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  let sequence = 0;

  async function visit(context, host, blocked, path = '/') {
    const address = new URL(`http://${host}:${server.address().port}${path}`);
    address.searchParams.set('private-navigation', String(++sequence));
    const candidate = new URL(address);
    candidate.hash = '';
    if (host === 'redirect.test') candidate.hostname = 'apps.test';
    const page = await context.newPage();
    try {
      if (blocked) {
        await assert.rejects(page.goto(address.href), /ERR_BLOCKED_BY_CLIENT/);
        assert.ok(!requests.includes(candidate.href), 'The blocked navigation reached the HTTP server.');
      } else {
        assert.equal((await page.goto(address.href)).status(), 200);
        assert.equal(await page.locator('body').textContent(), 'Zekvar domain fixture');
        assert.ok(requests.includes(candidate.href));
      }
      if (host === 'redirect.test') {
        address.hash = '';
        assert.ok(requests.includes(address.href), 'The original request must reach the redirector.');
      }
    } finally {
      await page.close();
    }
  }
  return { visit, close };
}
