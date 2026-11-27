import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { components, pinnedVersionProblems, sbom } from '../release-checks.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));

test('the repository pins every direct dependency to an exact version', async () => {
  assert.deepEqual(await pinnedVersionProblems(root), []);
});

test('ranges, tags, and floating NuGet versions are rejected', async (t) => {
  const fixture = await mkdtemp(join(tmpdir(), 'zekvar-release-'));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  await mkdir(join(fixture, 'web'));
  await mkdir(join(fixture, 'api'));
  await writeFile(join(fixture, 'web/package.json'), JSON.stringify({ dependencies: { a: '^1.2.3', b: '1.2.3', c: 'latest' },
    devDependencies: { d: '~2.0.0', e: '1.0.0-beta.1' } }));
  await writeFile(join(fixture, 'api/Api.csproj'), '<Project><ItemGroup><PackageReference Include="Fixed" Version="1.0.0" />' +
    '<PackageReference Include="Floating" Version="1.*" /><PackageReference Include="Range" Version="[1.0,2.0)" /></ItemGroup></Project>');
  const problems = await pinnedVersionProblems(fixture, [
    { kind: 'npm', directory: 'web' }, { kind: 'nuget', directory: 'api', project: 'Api.csproj' }]);
  assert.equal(problems.length, 5);
  for (const name of ['.a ', '.c ', '.d ', 'Floating', 'Range']) assert.ok(problems.some((problem) => problem.includes(name)), name);
});

test('SBOMs are CycloneDX documents derived from lockfiles with hashes, purls, and dev scope', async () => {
  const at = new Date('2026-11-25T00:00:00Z');
  for (const component of components) {
    const document = await sbom(root, component, at);
    assert.deepEqual([document.bomFormat, document.specVersion, document.metadata.timestamp], ['CycloneDX', '1.5', at.toISOString()]);
    assert.match(document.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.ok(document.components.length > 0);
    assert.ok(document.components.every(({ purl, version, hashes, properties }) => purl.includes(`@${encodeURIComponent(version)}`) &&
      (hashes?.length || properties.some(({ name }) => name === 'cdx:npm:package:bundled'))));
    assert.deepEqual(await sbom(root, component, at), document);
  }
  const web = await sbom(root, components[1], at);
  const next = web.components.find(({ name }) => name === 'next');
  assert.deepEqual([next.purl, next.scope], ['pkg:npm/next@16.4.6', 'required']);
  assert.equal(web.components.find(({ name }) => name === 'typescript').scope, 'excluded');
  const scoped = web.components.find(({ name }) => name.startsWith('@types/'));
  assert.match(scoped.purl, /^pkg:npm\/%40types\//);
  const api = await sbom(root, components[2], at);
  assert.equal(api.components.find(({ name }) => name === 'Npgsql').purl, 'pkg:nuget/Npgsql@10.0.3');
});

test('offline mode writes SBOMs and reports skipped audits without failing', async (t) => {
  const out = await mkdtemp(join(tmpdir(), 'zekvar-sbom-'));
  t.after(() => rm(out, { recursive: true, force: true }));
  const { stdout, stderr } = await promisify(execFile)(process.execPath, ['scripts/release-checks.mjs', '--offline', '--sbom-dir', out],
    { cwd: root, env: { ...process.env, SOURCE_DATE_EPOCH: '1795000000' } });
  const summary = JSON.parse(stdout);
  assert.equal(summary.pinnedVersions.status, 'pass');
  assert.ok(Object.values(summary.vulnerabilityAudit).every(({ status }) => status === 'skipped'));
  assert.match(stderr, /vulnerability audit skipped/);
  const written = JSON.parse(await readFile(join(out, 'zekvar-control-api.cdx.json'), 'utf8'));
  assert.equal(written.metadata.timestamp, new Date(1795000000 * 1000).toISOString());
  await assert.rejects(promisify(execFile)(process.execPath, ['scripts/release-checks.mjs', '--offline', '--require-audit', '--sbom-dir', out],
    { cwd: root }), (error) => error.code === 1 && /Release checks failed/.test(error.stderr));
});
