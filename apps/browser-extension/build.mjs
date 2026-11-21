import { build } from 'esbuild';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const port = Number(process.env.ZEKVAR_CONTROL_PORT ?? 5187);
const outdir = process.env.ZEKVAR_EXTENSION_OUTDIR ?? 'dist';
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error('ZEKVAR_CONTROL_PORT must be a loopback port between 1024 and 65535.');
}
const origin = `http://127.0.0.1:${port}`;
await build({
  entryPoints: ['src/content.ts', 'src/chatgpt.ts', 'src/discovery.ts', 'src/popup.ts', 'src/worker.ts'],
  bundle: true,
  format: 'iife',
  outdir,
  define: { CONTROL_ORIGIN: JSON.stringify(origin) },
});
const manifest = JSON.parse(await readFile('manifest.json', 'utf8'));
manifest.host_permissions = [`${origin}/*`];
await Promise.all([
  writeFile(join(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'),
  copyFile('src/popup.html', join(outdir, 'popup.html')),
  copyFile('managed-schema.json', join(outdir, 'managed-schema.json')),
]);
