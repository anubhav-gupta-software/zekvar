import { build } from 'esbuild';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const hostedOrigin = process.env.ZEKVAR_CONTROL_ORIGIN;
const outdir = process.env.ZEKVAR_EXTENSION_OUTDIR ?? 'dist';
function controlOrigin() {
  if (hostedOrigin !== undefined) {
    if (process.env.ZEKVAR_CONTROL_PORT !== undefined) throw new Error('Set either the hosted origin or the loopback port.');
    if (!/^https:\/\/[a-zA-Z\d.-]+(?::[1-9]\d{0,4})?\/?$/.test(hostedOrigin)) {
      throw new Error('ZEKVAR_CONTROL_ORIGIN must be an HTTPS origin without a path, query, or credentials.');
    }
    const url = new URL(hostedOrigin);
    if (url.hostname.endsWith('.')) throw new Error('Use the canonical HTTPS hostname without a trailing dot.');
    return url.origin;
  }
  const port = Number(process.env.ZEKVAR_CONTROL_PORT ?? 5187);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('ZEKVAR_CONTROL_PORT must be a loopback port between 1024 and 65535.');
  }
  return `http://127.0.0.1:${port}`;
}
const origin = controlOrigin();
const manifest = JSON.parse(await readFile('manifest.json', 'utf8'));
if (hostedOrigin !== undefined) manifest.content_scripts = manifest.content_scripts.filter((script) => !script.js.includes('content.js'));
// A new worker path also refreshes unpacked extensions that keep their prior Chrome profile.
const worker = `worker-${manifest.version}-${createHash('sha256').update(origin).digest('hex').slice(0, 12)}`;
await build({
  entryPoints: {
    ...(hostedOrigin === undefined ? { content: 'src/content.ts' } : {}),
    chatgpt: 'src/chatgpt.ts', claude: 'src/claude.ts', gemini: 'src/gemini.ts',
    discovery: 'src/discovery.ts', popup: 'src/popup.ts', [worker]: 'src/worker.ts',
  },
  bundle: true,
  format: 'iife',
  outdir,
  define: { CONTROL_ORIGIN: JSON.stringify(origin) },
});
manifest.background.service_worker = `${worker}.js`;
manifest.host_permissions = [`${origin}/*`];
await Promise.all([
  writeFile(join(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'),
  copyFile('src/popup.html', join(outdir, 'popup.html')),
  copyFile('managed-schema.json', join(outdir, 'managed-schema.json')),
]);
