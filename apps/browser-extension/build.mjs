import { build } from 'esbuild';
import { cp, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { versionParts } from './chrome-version.mjs';

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
const { values: { version } } = parseArgs({ options: { version: { type: 'string' } } });
if (version !== undefined) {
  versionParts(version);
  manifest.version = version;
}
if (hostedOrigin !== undefined) manifest.content_scripts = manifest.content_scripts.filter((script) => !script.js.includes('content.js'));
// A new worker path also refreshes unpacked extensions that keep their prior Chrome profile.
const worker = `worker-${manifest.version}-${createHash('sha256').update(origin).digest('hex').slice(0, 12)}`;
await build({
  entryPoints: {
    ...(hostedOrigin === undefined ? { content: 'src/content.ts' } : {}),
    chatgpt: 'src/chatgpt.ts', claude: 'src/claude.ts', gemini: 'src/gemini.ts',
    discovery: 'src/discovery.ts', popup: 'src/popup.ts', [worker]: 'src/worker.ts', 'pdf-offscreen': 'src/pdf-offscreen.ts',
  },
  bundle: true,
  format: 'iife',
  outdir,
  define: { CONTROL_ORIGIN: JSON.stringify(origin), SERVICE_WORKER_PATH: JSON.stringify(`${worker}.js`) },
});
manifest.background.service_worker = `${worker}.js`;
manifest.host_permissions = [`${origin}/*`];
const pdf = 'node_modules/pdfjs-dist';
const pdfAssets = join(outdir, 'pdf-assets');
await mkdir(pdfAssets, { recursive: true });
await Promise.all([
  writeFile(join(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'),
  copyFile('src/popup.html', join(outdir, 'popup.html')),
  copyFile('managed-schema.json', join(outdir, 'managed-schema.json')),
  copyFile('src/pdf-offscreen.html', join(outdir, 'pdf-offscreen.html')),
  copyFile(join(pdf, 'legacy/build/pdf.min.mjs'), join(pdfAssets, 'pdf.min.mjs')),
  copyFile(join(pdf, 'legacy/build/pdf.worker.min.mjs'), join(pdfAssets, 'pdf.worker.min.mjs')),
  copyFile(join(pdf, 'LICENSE'), join(pdfAssets, 'LICENSE')),
  cp(join(pdf, 'cmaps'), join(pdfAssets, 'cmaps'), { recursive: true }),
  cp(join(pdf, 'standard_fonts'), join(pdfAssets, 'standard_fonts'), { recursive: true }),
]);
