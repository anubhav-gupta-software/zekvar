import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';

const root = fileURLToPath(new URL('.', import.meta.url));
const exec = promisify(execFile);
const json = (value) => JSON.stringify(value, null, 2) + '\n';
const load = async (file) => JSON.parse(await readFile(file, 'utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

function required(options, name) {
  if (!options[name]) throw new Error(`Specify --${name}.`);
  return options[name];
}

function httpsOrigin(input, name) {
  if (!/^https:\/\/[a-zA-Z\d.-]+(?::[1-9]\d{0,4})?\/?$/.test(input)) {
    throw new Error(`--${name} must be an HTTPS origin without a path, query, or credentials.`);
  }
  const url = new URL(input);
  if (url.hostname.endsWith('.')) throw new Error(`Use the canonical --${name} hostname without a trailing dot.`);
  return url.origin;
}

function versionParts(version) {
  if (typeof version !== 'string' || !/^(?:0|[1-9]\d{0,4})(?:\.(?:0|[1-9]\d{0,4})){0,3}$/.test(version)) {
    throw new Error('The manifest and previous release must use valid Chrome versions.');
  }
  const parts = version.split('.').map(Number);
  if (parts.some((part) => part > 65535) || parts.every((part) => part === 0)) {
    throw new Error('The manifest and previous release must use valid Chrome versions.');
  }
  return parts;
}

function newer(next, previous) {
  const current = versionParts(next);
  const old = versionParts(previous);
  for (let index = 0; index < 4; index++) {
    const difference = (current[index] ?? 0) - (old[index] ?? 0);
    if (difference) return difference > 0;
  }
  return false;
}

async function signingIdentity(path) {
  const file = await realpath(path);
  const repository = await realpath(join(root, '../..'));
  const local = relative(repository, file);
  if (local !== '..' && !local.startsWith(`..${sep}`) && !isAbsolute(local)) {
    throw new Error('Keep the signing key outside the checkout.');
  }
  const info = await stat(file);
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error('Use a private signing key file with permissions 0600 or stricter.');
  }
  const key = createPrivateKey(await readFile(file));
  if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048) {
    throw new Error('Use an RSA signing key of at least 2048 bits.');
  }
  const publicKey = createPublicKey(key).export({ type: 'spki', format: 'der' });
  const id = sha256(publicKey).subarray(0, 16).toString('hex').replace(/[0-9a-f]/g, (digit) => 'abcdefghijklmnop'[parseInt(digit, 16)]);
  return { file, id };
}

async function packageRelease() {
  const { values: options } = parseArgs({ options: {
    key: { type: 'string' }, 'print-id': { type: 'boolean' }, id: { type: 'string' },
    chrome: { type: 'string' }, output: { type: 'string' }, 'control-origin': { type: 'string' },
    'update-origin': { type: 'string' }, channel: { type: 'string' },
    first: { type: 'boolean' }, previous: { type: 'string' },
  } });
  const { file: key, id: extensionId } = await signingIdentity(required(options, 'key'));
  if (options['print-id']) {
    console.log(extensionId);
    return;
  }
  if (required(options, 'id') !== extensionId) throw new Error('The key does not match the pinned extension ID.');
  const chrome = resolve(required(options, 'chrome'));
  const output = resolve(required(options, 'output'));
  const controlOrigin = httpsOrigin(required(options, 'control-origin'), 'control-origin');
  const updateOrigin = httpsOrigin(required(options, 'update-origin'), 'update-origin');
  const channel = required(options, 'channel');
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(channel)) throw new Error('Use a lowercase output channel name with letters, numbers, or hyphens.');
  const updateUrl = `${updateOrigin}/${channel}/updates.xml`;
  const { version, minimum_chrome_version: minimumChrome } = await load(join(root, 'manifest.json'));
  versionParts(version);
  versionParts(minimumChrome);
  if (Boolean(options.first) === Boolean(options.previous)) throw new Error('Specify --first for a new channel or --previous with the last release.json.');
  if (options.previous) {
    const prior = await load(resolve(options.previous));
    if (prior.extensionId !== extensionId || prior.controlOrigin !== controlOrigin || prior.updateUrl !== updateUrl) {
      throw new Error('The previous release has a different extension ID, Control origin, or update URL.');
    }
    if (!newer(version, prior.version)) throw new Error('Increase the manifest version before publishing another release to this channel.');
  }

  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-package-'));
  let ownedOutput = false;
  try {
    await mkdir(output, { mode: 0o700 });
    ownedOutput = true;
    const extension = join(scratch, 'extension');
    const env = { ...process.env, ZEKVAR_CONTROL_ORIGIN: controlOrigin, ZEKVAR_EXTENSION_OUTDIR: extension };
    delete env.ZEKVAR_CONTROL_PORT;
    await exec(process.execPath, [join(root, 'build.mjs')], { cwd: root, env, timeout: 60_000 });
    const manifestFile = join(extension, 'manifest.json');
    const manifest = await load(manifestFile);
    if (manifest.version !== version || manifest.key || manifest.update_url) throw new Error('The source manifest changed or contains a distribution identity.');
    await writeFile(manifestFile, json({ ...manifest, update_url: updateUrl }));
    await exec(chrome, [`--user-data-dir=${join(scratch, 'pack-profile')}`, '--no-first-run',
      `--pack-extension=${extension}`, `--pack-extension-key=${key}`], { timeout: 60_000 });
    const crx = await readFile(`${extension}.crx`);
    if (crx.length < 12 || crx.toString('ascii', 0, 4) !== 'Cr24' || crx.readUInt32LE(4) !== 3) {
      throw new Error('Chrome did not produce a CRX3 package.');
    }

    const packageName = `zekvar-browser-${version}.crx`;
    const packageUrl = `${updateOrigin}/${channel}/${packageName}`;
    const staging = join(output, '.staging');
    const directory = join(staging, channel);
    await mkdir(directory, { recursive: true });
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">\n  <app appid="${extensionId}">\n    <updatecheck codebase="${packageUrl}" version="${version}" prodversionmin="${minimumChrome}" />\n  </app>\n</gupdate>\n`;
    const policy = {
      ExtensionSettings: { [extensionId]: { installation_mode: 'force_installed', update_url: updateUrl, override_update_url: true } },
      '3rdparty': { extensions: { [extensionId]: { ControlOrigin: controlOrigin } } },
    };
    await Promise.all([
      writeFile(join(directory, packageName), crx), writeFile(join(directory, 'updates.xml'), xml),
      writeFile(join(output, 'chrome-policy.json'), json(policy)),
      writeFile(join(output, 'release.json'), json({
        extensionId, version, channel, controlOrigin, updateUrl, packageUrl, sha256: sha256(crx).toString('hex'),
      })),
    ]);
    await rename(staging, join(output, 'public'));
    console.log(`Packaged Zekvar Browser ${version} for ${channel} at ${output}`);
  } catch (error) {
    if (ownedOutput) await rm(output, { recursive: true, force: true });
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

try {
  await packageRelease();
} catch (error) {
  console.error(error.code === 'EEXIST' ? 'Choose a new output directory.' : error.stderr?.trim() || error.message);
  process.exitCode = 1;
}
