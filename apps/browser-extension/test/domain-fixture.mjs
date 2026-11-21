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

  async function visit(context, host, blocked) {
    const url = `http://${host}:${server.address().port}/private-navigation-${++sequence}`;
    const page = await context.newPage();
    try {
      if (blocked) {
        await assert.rejects(page.goto(url), /ERR_BLOCKED_BY_CLIENT/);
        const candidate = new URL(url);
        if (host === 'redirect.test') candidate.hostname = 'apps.test';
        assert.ok(!requests.includes(candidate.href), 'The blocked navigation reached the HTTP server.');
        if (host === 'redirect.test') assert.ok(requests.includes(url), 'The original request must reach the redirector.');
      } else {
        assert.equal((await page.goto(url)).status(), 200);
        assert.equal(await page.locator('body').textContent(), 'Zekvar domain fixture');
        assert.ok(requests.includes(url));
      }
    } finally {
      await page.close();
    }
  }
  return { visit, close };
}
