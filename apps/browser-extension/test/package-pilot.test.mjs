import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

const run = promisify(execFile);
const root = fileURLToPath(new URL('..', import.meta.url));
const hello = 'https://browser.zekvar.test:9443';
const update = 'https://updates.zekvar.test:9443';
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const load = async (file) => JSON.parse(await readFile(file, 'utf8'));

// Chrome's local signer emits length-delimited CRX3 protobuf fields.
function fields(bytes) {
  let cursor = 0;
  function varint() {
    let size = 0;
    for (let shift = 0; shift < 28 && cursor < bytes.length; shift += 7) {
      const value = bytes[cursor++];
      size += (value & 127) * 2 ** shift;
      if (value < 128) return size;
    }
    assert.fail('Invalid CRX3 field');
  }
  const result = new Map();
  while (cursor < bytes.length) {
    const tag = varint();
    assert.equal(tag % 8, 2);
    const length = varint();
    assert.ok(cursor + length <= bytes.length);
    result.set(Math.floor(tag / 8), bytes.subarray(cursor, cursor + length));
    cursor += length;
  }
  return result;
}

async function inspect(work, path, signingKey) {
  const release = await load(join(path, 'release.json'));
  const archive = await readFile(join(path, 'public', release.channel, `zekvar-browser-${release.version}.crx`));
  assert.equal(hash(archive).toString('hex'), release.sha256);
  assert.equal(archive.toString('ascii', 0, 4), 'Cr24');
  assert.equal(archive.readUInt32LE(4), 3);
  const zipOffset = 12 + archive.readUInt32LE(8);
  const header = fields(archive.subarray(12, zipOffset));
  const proof = fields(header.get(2));
  const signed = header.get(10000);
  const publicKey = createPublicKey(signingKey);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  assert.deepEqual(proof.get(1), der);
  const idBytes = hash(der).subarray(0, 16);
  assert.deepEqual(fields(signed).get(1), idBytes);
  assert.equal(release.extensionId, idBytes.toString('hex').replace(/[0-9a-f]/g, (value) => String.fromCharCode(97 + Number.parseInt(value, 16))));
  const length = Buffer.alloc(4);
  length.writeUInt32LE(signed.length);
  const zip = archive.subarray(zipOffset);
  const data = Buffer.concat([Buffer.from('CRX3 SignedData\0'), length, signed, zip]);
  assert.ok(verify('sha256', data, publicKey, proof.get(2)));
  data[data.length - 1] ^= 1;
  assert.equal(verify('sha256', data, publicKey, proof.get(2)), false);
  const zipPath = join(work, `${release.extensionId}-${release.version}.zip`);
  await writeFile(zipPath, zip);
  const entries = (await run('unzip', ['-Z1', zipPath])).stdout.trim().split('\n');
  const pdfAsset = /^pdf-assets\/(?:|LICENSE|pdf(?:\.worker)?\.min\.mjs|cmaps\/(?:[\w-]+\.bcmap|LICENSE)?|standard_fonts\/(?:[\w-]+\.(?:pfb|ttf)|LICENSE_\w+)?)$/;
  assert.ok(entries.every((file) => /^(?:[a-z0-9.-]+\.js|manifest\.json|managed-schema\.json|(?:popup|pdf-offscreen)\.html)$/.test(file) || pdfAsset.test(file)));
  for (const asset of ['pdf-offscreen.html', 'pdf-offscreen.js', 'pdf-assets/pdf.min.mjs', 'pdf-assets/pdf.worker.min.mjs', 'pdf-assets/LICENSE']) {
    assert.ok(entries.includes(asset), `The signed build is missing ${asset}`);
  }
  assert.ok(!entries.includes('content.js'));
  const manifest = JSON.parse((await run('unzip', ['-p', zipPath, 'manifest.json'])).stdout);
  assert.deepEqual(manifest.host_permissions, [`${hello}/*`]);
  assert.ok(manifest.permissions.includes('offscreen'));
  assert.equal(manifest.web_accessible_resources, undefined);
  assert.equal(manifest.version, release.version);
  assert.equal(manifest.update_url, release.updateUrl);
  assert.match(manifest.background.service_worker, new RegExp(`^worker-${release.version.replaceAll('.', '\\.')}-[a-f0-9]{12}\\.js$`));
  assert.ok(entries.includes(manifest.background.service_worker));
  return release;
}

test('the Chrome packer produces immutable signed pilot releases with a pinned identity', { timeout: 120_000 }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'zekvar-pack-test-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const scratchExtension = join(work, 'source/apps/browser-extension');
  await mkdir(scratchExtension, { recursive: true });
  for (const file of ['package-pilot.mjs', 'build.mjs', 'chrome-version.mjs', 'manifest.json', 'managed-schema.json', 'src']) {
    await cp(join(root, file), join(scratchExtension, file), { recursive: true });
  }
  await symlink(resolve(root, '../../contracts'), join(work, 'source/contracts'));
  await symlink(join(root, 'node_modules'), join(scratchExtension, 'node_modules'));
  const script = (args) => run(process.execPath, [join(scratchExtension, 'package-pilot.mjs'), ...args], { env: { ...process.env, ZEKVAR_CONTROL_PORT: '21212' } });
  async function key(name) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    const file = join(work, `${name}.pem`);
    await writeFile(file, privateKey, { mode: 0o600 });
    const id = (await script(['--print-id', '--key', file])).stdout.trim();
    assert.match(id, /^[a-p]{32}$/);
    return { file, privateKey, id };
  }
  const firstKey = await key('first');
  const otherKey = await key('other');
  const browser = process.env.ZEKVAR_PACK_TEST_CHROME ?? chromium.executablePath();
  const base = ({ identity = firstKey, id = identity.id, chrome = browser, updateOrigin = update } = {}) =>
    ['--key', identity.file, '--id', id, '--chrome', chrome, '--control-origin', hello, '--update-origin', updateOrigin, '--channel', 'pilot'];
  const first = join(work, 'first');
  const next = join(work, 'next');
  const rollback = join(work, 'rollback');
  const wrongSigner = join(work, 'wrong-signer');
  const previous = join(first, 'release.json');
  await chmod(firstKey.file, 0o644);
  await assert.rejects(script(['--print-id', '--key', firstKey.file]), /permissions 0600/);
  await chmod(firstKey.file, 0o600);
  const misplacedKey = join(scratchExtension, 'misplaced.pem');
  await cp(firstKey.file, misplacedKey);
  await assert.rejects(script(['--print-id', '--key', misplacedKey]), /outside the checkout/);
  await assert.rejects(script([...base({ id: otherKey.id }), '--first', '--output', first]), /pinned extension ID/);
  await assert.rejects(script([...base({ updateOrigin: 'https://updates.zekvar.test/path' }), '--first', '--output', first]), /HTTPS origin/);
  await assert.rejects(script([...base(), '--first', '--version', '9.1', '--output', first]), /Use --version with --previous/);
  await assert.rejects(script([...base({ chrome: join(work, 'missing-chrome') }), '--first', '--output', first]), /ENOENT/);
  await assert.rejects(stat(first), { code: 'ENOENT' });
  const packFirst = () => script([...base(), '--first', '--output', first]);
  const attempts = await Promise.allSettled([packFirst(), packFirst()]);
  assert.equal(attempts.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.match(attempts.find(({ status }) => status === 'rejected').reason.stderr, /new output directory/);
  const original = await inspect(work, first, firstKey.privateKey);
  assert.equal(original.extensionId, firstKey.id);
  const policy = await load(join(first, 'chrome-policy.json'));
  assert.deepEqual(policy.ExtensionSettings[firstKey.id], { installation_mode: 'force_installed', update_url: original.updateUrl, override_update_url: true });
  assert.deepEqual(policy['3rdparty'].extensions[firstKey.id], { ControlOrigin: hello });
  assert.deepEqual((await readdir(first)).sort(), ['chrome-policy.json', 'public', 'release.json']);
  assert.deepEqual((await readdir(join(first, 'public/pilot'))).sort(), ['updates.xml', `zekvar-browser-${original.version}.crx`].sort());
  const manifestFile = join(scratchExtension, 'manifest.json');
  const originalManifest = await readFile(manifestFile, 'utf8');
  const manifest = await load(manifestFile);
  await assert.rejects(script([...base(), '--previous', previous, '--output', next]), /Increase the manifest version/);
  const version = manifest.version.split('.').map(Number);
  version[2] += 1;
  const composerFile = join(scratchExtension, 'src/chatgpt.ts');
  const knownGoodComposer = await readFile(composerFile, 'utf8');
  await writeFile(composerFile, knownGoodComposer + '\ndocument.addEventListener("DOMContentLoaded", () => { document.documentElement.dataset.zekvarTestRelease = "candidate"; }, { once: true });\n');
  await writeFile(manifestFile, JSON.stringify({ ...manifest, version: version.join('.') }));
  await assert.rejects(script([...base({ identity: otherKey }), '--previous', previous, '--output', next]), /different extension ID/);
  await script([...base(), '--previous', previous, '--output', next]);
  await script([...base({ identity: otherKey }), '--first', '--output', wrongSigner]);
  const upgraded = await inspect(work, next, firstKey.privateKey);
  assert.equal(upgraded.extensionId, original.extensionId);
  assert.equal(upgraded.updateUrl, original.updateUrl);
  assert.equal(upgraded.version, version.join('.'));
  const xml = await readFile(join(next, 'public/pilot/updates.xml'), 'utf8');
  assert.ok(xml.includes(`appid="${original.extensionId}"`));
  assert.ok(xml.includes(`codebase="${upgraded.packageUrl}" version="${upgraded.version}" prodversionmin="${manifest.minimum_chrome_version}"`));
  await writeFile(manifestFile, originalManifest);
  await writeFile(composerFile, knownGoodComposer);
  await assert.rejects(script([...base(), '--previous', join(next, 'release.json'), '--output', join(work, 'older')]), /Increase the manifest version/);
  const rollbackArgs = [...base(), '--previous', join(next, 'release.json'), '--output', rollback];
  const rollbackVersion = [...version, 1].join('.');
  await assert.rejects(script([...rollbackArgs, '--version', upgraded.version]), /Increase the manifest version/);
  await assert.rejects(script([...rollbackArgs, '--version', `${upgraded.version}.0`]), /Increase the manifest version/);
  await assert.rejects(script([...base({ updateOrigin: 'https://another-update.zekvar.test' }), '--previous',
    join(next, 'release.json'), '--version', rollbackVersion, '--output', rollback]), /different extension ID, Control origin, or update URL/);
  await assert.rejects(script([...rollbackArgs, '--version', original.version]), /higher than the source manifest/);
  await assert.rejects(script([...rollbackArgs, '--version', '1.3.65536']), /valid Chrome version/);
  await assert.rejects(script([...rollbackArgs, '--version', '../update']), /valid Chrome version/);
  await assert.rejects(stat(rollback), { code: 'ENOENT' });
  await script([...rollbackArgs, '--version', rollbackVersion]);
  const restored = await inspect(work, rollback, firstKey.privateKey);
  assert.equal(restored.version, rollbackVersion);
  assert.equal(restored.sourceVersion, original.version);
  assert.equal(restored.extensionId, original.extensionId);
  assert.equal(restored.updateUrl, original.updateUrl);
  assert.equal(await readFile(manifestFile, 'utf8'), originalManifest);
  assert.equal(await readFile(composerFile, 'utf8'), knownGoodComposer);

  const artifacts = process.env.ZEKVAR_SIGNED_PILOT_ARTIFACTS;
  if (artifacts) {
    const output = resolve(artifacts);
    await mkdir(output, { mode: 0o700 });
    await Promise.all([['first', first], ['next', next], ['wrong-signer', wrongSigner], ['rollback', rollback]]
      .map(([name, dir]) => cp(dir, join(output, name), { recursive: true })));
  }
});
