// Release supply-chain checks. Run from the repository root:
//   node scripts/release-checks.mjs [--sbom-dir DIRECTORY] [--offline] [--require-audit] [--audit-level high]
// 1. Pinned versions: every package.json dependency must be an exact version and every .csproj PackageReference an exact version.
// 2. SBOM: one CycloneDX 1.5 JSON document per component, generated from lockfiles only (no network, no installed packages).
// 3. Vulnerabilities: `npm audit --omit=dev` and `dotnet list package --vulnerable` when the registries are reachable.
//    Offline runs report the audit as "skipped" and exit 0 unless --require-audit is set.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const exact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const severities = ['info', 'low', 'moderate', 'high', 'critical'];

export const components = [
  { name: 'zekvar-browser-extension', kind: 'npm', directory: 'apps/browser-extension' },
  { name: 'zekvar-control-web', kind: 'npm', directory: 'apps/control-web' },
  { name: 'zekvar-control-api', kind: 'nuget', directory: 'apps/control-api', project: 'Control.Api.csproj' },
];

export async function pinnedVersionProblems(root, list = components) {
  const problems = [];
  for (const component of list) {
    if (component.kind === 'npm') {
      const manifest = JSON.parse(await readFile(join(root, component.directory, 'package.json'), 'utf8'));
      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        for (const [name, version] of Object.entries(manifest[field] ?? {})) {
          if (!exact.test(version)) problems.push(`${component.directory}/package.json ${field}.${name} uses "${version}"; pin an exact version.`);
        }
      }
    } else {
      const project = await readFile(join(root, component.directory, component.project), 'utf8');
      for (const match of project.matchAll(/<PackageReference\b[^>]*>/g)) {
        const name = match[0].match(/Include="([^"]+)"/)?.[1] ?? '(unnamed)';
        const version = match[0].match(/Version="([^"]*)"/)?.[1];
        if (!version || !exact.test(version)) problems.push(`${component.directory}/${component.project} ${name} uses "${version ?? ''}"; pin an exact version.`);
      }
    }
  }
  return problems;
}

function npmPurl(name, version) {
  const [scope, bare] = name.startsWith('@') ? name.split('/') : [undefined, name];
  return `pkg:npm/${scope ? `${encodeURIComponent(scope)}/` : ''}${encodeURIComponent(bare)}@${encodeURIComponent(version)}`;
}

function integrityHashes(integrity) {
  const hashes = [];
  for (const entry of String(integrity ?? '').split(/\s+/)) {
    const [algorithm, value] = entry.split('-', 2);
    const alg = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' }[algorithm];
    if (alg && value) hashes.push({ alg, content: Buffer.from(value, 'base64').toString('hex') });
  }
  return hashes;
}

async function npmComponents(directory) {
  const lock = JSON.parse(await readFile(join(directory, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion < 2 || !lock.packages) throw new Error(`${directory}/package-lock.json must use lockfileVersion 2 or later.`);
  const root = lock.packages[''] ?? {};
  const entries = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || entry.link) continue;
    const name = entry.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const component = { type: 'library', 'bom-ref': `${npmPurl(name, entry.version)}#${path}`, name, version: entry.version,
      purl: npmPurl(name, entry.version), scope: entry.dev ? 'excluded' : entry.optional ? 'optional' : 'required' };
    const hashes = integrityHashes(entry.integrity);
    if (hashes.length) component.hashes = hashes;
    if (entry.license) component.licenses = [{ expression: String(entry.license) }];
    if (entry.resolved) component.externalReferences = [{ type: 'distribution', url: entry.resolved }];
    const properties = [{ name: 'cdx:npm:package:path', value: path }];
    if (entry.dev) properties.push({ name: 'cdx:npm:package:development', value: 'true' });
    if (entry.inBundle) properties.push({ name: 'cdx:npm:package:bundled', value: 'true' });
    component.properties = properties;
    entries.push(component);
  }
  return { root: { name: root.name ?? 'unknown', version: root.version ?? '0.0.0' }, entries };
}

async function nugetComponents(directory, project) {
  const lock = JSON.parse(await readFile(join(directory, 'packages.lock.json'), 'utf8'));
  const source = await readFile(join(directory, project), 'utf8');
  const entries = new Map();
  for (const [framework, packages] of Object.entries(lock.dependencies ?? {})) {
    for (const [name, entry] of Object.entries(packages)) {
      if (entry.type === 'Project') continue;
      const purl = `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(entry.resolved)}`;
      if (entries.has(purl)) continue;
      const component = { type: 'library', 'bom-ref': purl, name, version: entry.resolved, purl, scope: 'required',
        properties: [{ name: 'cdx:nuget:dependency:type', value: entry.type }, { name: 'cdx:nuget:target-framework', value: framework }] };
      if (entry.contentHash) component.hashes = [{ alg: 'SHA-512', content: Buffer.from(entry.contentHash, 'base64').toString('hex') }];
      entries.set(purl, component);
    }
  }
  const version = source.match(/<Version>([^<]+)<\/Version>/)?.[1] ?? '0.0.0';
  return { root: { name: project.replace(/\.csproj$/, ''), version }, entries: [...entries.values()] };
}

// Deterministic: the serial number and timestamp derive from the lockfile content or SOURCE_DATE_EPOCH.
export async function sbom(root, component, timestamp = new Date()) {
  const directory = join(root, component.directory);
  const { root: subject, entries } = component.kind === 'npm'
    ? await npmComponents(directory) : await nugetComponents(directory, component.project);
  entries.sort((left, right) => left['bom-ref'].localeCompare(right['bom-ref']));
  const digest = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
  const serial = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-${(8 | (parseInt(digest[16], 16) & 3)).toString(16)}${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${serial}`, version: 1,
    metadata: {
      timestamp: timestamp.toISOString(),
      tools: { components: [{ type: 'application', name: 'zekvar-release-checks', version: '1' }] },
      component: { type: 'application', 'bom-ref': component.name, name: component.name, version: subject.version,
        properties: [{ name: 'zekvar:source', value: component.directory }] },
    },
    components: entries,
    dependencies: [{ ref: component.name, dependsOn: entries.filter(({ scope }) => scope !== 'excluded').map((entry) => entry['bom-ref']) }],
  };
}

export async function registriesReachable(timeout = 4000) {
  const probe = (url) => fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(timeout) }).then((response) => response.status < 500, () => false);
  const [npm, nuget] = await Promise.all([probe('https://registry.npmjs.org/'), probe('https://api.nuget.org/v3/index.json')]);
  return { npm, nuget };
}

async function npmAudit(directory, level) {
  const result = await run('npm', ['audit', '--omit=dev', '--json'], { cwd: directory, maxBuffer: 64 * 1024 * 1024 })
    .catch((error) => ({ stdout: error.stdout ?? '', failed: error }));
  let report;
  try { report = JSON.parse(result.stdout); } catch { return { status: 'error', detail: 'npm audit did not return JSON.' }; }
  if (report.error) return { status: 'error', detail: report.error.summary ?? 'npm audit failed.' };
  const counts = report.metadata?.vulnerabilities ?? {};
  const blocking = severities.slice(severities.indexOf(level)).reduce((total, severity) => total + (counts[severity] ?? 0), 0);
  return { status: blocking ? 'fail' : 'pass', counts, advisories: Object.keys(report.vulnerabilities ?? {}).sort() };
}

async function dotnetAudit(directory, project, level) {
  const result = await run('dotnet', ['list', project, 'package', '--vulnerable', '--include-transitive', '--format', 'json'],
    { cwd: directory, maxBuffer: 16 * 1024 * 1024 }).catch((error) => ({ stdout: error.stdout ?? '', failed: error }));
  let report;
  try { report = JSON.parse(result.stdout); } catch { return { status: 'error', detail: 'dotnet list package did not return JSON.' }; }
  if (report.problems?.length) return { status: 'error', detail: report.problems.map(({ text }) => text).join(' ') };
  const found = [];
  for (const projectEntry of report.projects ?? []) {
    for (const framework of projectEntry.frameworks ?? []) {
      for (const entry of [...(framework.topLevelPackages ?? []), ...(framework.transitivePackages ?? [])]) {
        for (const vulnerability of entry.vulnerabilities ?? []) {
          found.push({ package: entry.id, version: entry.resolvedVersion, severity: String(vulnerability.severity).toLowerCase(),
            advisory: vulnerability.advisoryurl });
        }
      }
    }
  }
  const blocking = found.filter(({ severity }) => severities.indexOf(severity === 'medium' ? 'moderate' : severity) >= severities.indexOf(level));
  return { status: blocking.length ? 'fail' : 'pass', vulnerabilities: found };
}

async function main(args) {
  const options = { sbomDir: 'artifacts/sbom', offline: false, requireAudit: false, auditLevel: 'high' };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--offline') options.offline = true;
    else if (arg === '--require-audit') options.requireAudit = true;
    else if (arg === '--sbom-dir' && args[index + 1]) options.sbomDir = args[++index];
    else if (arg === '--audit-level' && severities.includes(args[index + 1])) options.auditLevel = args[++index];
    else throw new Error('Usage: node scripts/release-checks.mjs [--sbom-dir DIRECTORY] [--offline] [--require-audit] [--audit-level low|moderate|high|critical]');
  }
  const root = fileURLToPath(new URL('../', import.meta.url));
  const summary = { checkedAt: new Date().toISOString(), pinnedVersions: {}, sbom: [], vulnerabilityAudit: {} };
  let failed = false;

  const problems = await pinnedVersionProblems(root);
  summary.pinnedVersions = { status: problems.length ? 'fail' : 'pass', problems };
  failed ||= problems.length > 0;

  const epoch = process.env.SOURCE_DATE_EPOCH;
  const timestamp = epoch && /^\d+$/.test(epoch) ? new Date(Number(epoch) * 1000) : new Date();
  const outDir = resolve(root, options.sbomDir);
  await mkdir(outDir, { recursive: true });
  for (const component of components) {
    const document = await sbom(root, component, timestamp);
    const file = join(outDir, `${component.name}.cdx.json`);
    const text = `${JSON.stringify(document, null, 2)}\n`;
    await writeFile(file, text);
    summary.sbom.push({ component: component.name, file, components: document.components.length,
      sha256: createHash('sha256').update(text).digest('hex') });
  }

  const reachable = options.offline ? { npm: false, nuget: false } : await registriesReachable();
  for (const component of components) {
    const online = component.kind === 'npm' ? reachable.npm : reachable.nuget;
    const directory = join(root, component.directory);
    const result = !online
      ? { status: 'skipped', detail: options.offline ? 'Offline mode requested.' : 'Package registry unreachable; vulnerability data unavailable.' }
      : component.kind === 'npm' ? await npmAudit(directory, options.auditLevel) : await dotnetAudit(directory, component.project, options.auditLevel);
    summary.vulnerabilityAudit[component.name] = result;
    failed ||= result.status === 'fail' || (options.requireAudit && result.status !== 'pass');
  }

  console.log(JSON.stringify(summary, null, 2));
  for (const [name, result] of Object.entries(summary.vulnerabilityAudit)) {
    if (result.status === 'skipped') console.error(`WARNING: ${name} vulnerability audit skipped: ${result.detail} Rerun with network access before release.`);
    if (result.status === 'error') console.error(`WARNING: ${name} vulnerability audit could not complete: ${result.detail}`);
  }
  console.error(failed ? 'Release checks failed.' : 'Release checks passed.');
  process.exitCode = failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main(process.argv.slice(2));
