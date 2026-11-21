import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export const fixtureUrl = 'http://127.0.0.1:4173/zekvar-fixture/';
const root = '/zekvar-fixture/';

export async function startFixture() {
  const html = await readFile(new URL('index.html', import.meta.url));
  const server = createServer((request, response) => {
    if (request.method === 'GET' && (request.url === root || request.url === '/unprotected/')) {
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(html);
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(4173, '127.0.0.1', resolve);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await startFixture();
  console.log(`Zekvar prompt fixture at ${fixtureUrl}`);
}
