import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';

const bucket = 'zekvar-backup-fixture';
const owner = '123456789012';
const sha256 = (body) => createHash('sha256').update(body).digest('base64');
const xml = (res, status, body) => res.writeHead(status, { 'Content-Type': 'application/xml' }).end(body);
const reject = (res, status, code) => xml(res, status, `<Error><Code>${code}</Code><Message>${code}</Message></Error>`);

// A loopback S3 protocol fixture. The test runs the real AWS CLI against it.
export async function startBackupBucket(prefix) {
  const objects = new Map();
  const uploads = [];
  let failNext = false;
  let putDenied = false;
  let corrupt = false;
  let reads = 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const header = (name) => req.headers[name];
    const role = header('authorization')?.match(/Credential=ZEKVARFIXTURE(WRITER|READER|MONITOR)\//)?.[1];
    if (header('x-amz-expected-bucket-owner') !== owner || !url.pathname.startsWith(`/${bucket}`)) {
      return reject(res, 403, 'AccessDenied');
    }
    const key = decodeURIComponent(url.pathname.slice(bucket.length + 2));
    if (req.method === 'PUT' && role === 'WRITER' && key.startsWith(`${prefix}/`) && !putDenied) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      uploads.push(key);
      if (failNext) {
        failNext = false;
        return reject(res, 503, 'SlowDown');
      }
      if (header('if-none-match') !== '*') return reject(res, 400, 'InvalidRequest');
      if (objects.has(key)) return reject(res, 412, 'PreconditionFailed');
      const checksum = sha256(body);
      if (checksum !== header('x-amz-checksum-sha256')) return reject(res, 400, 'BadDigest');
      objects.set(key, { body, checksum, modified: new Date(), metadata: {
        release: header('x-amz-meta-release'), keyId: header('x-amz-meta-recovery-key-id'), started: header('x-amz-meta-snapshot-started-utc'),
      } });
      return res.writeHead(200, { 'x-amz-checksum-sha256': checksum }).end();
    }
    if (req.method === 'GET' && role === 'MONITOR' && !key && url.searchParams.get('list-type') === '2') {
      const requestedPrefix = url.searchParams.get('prefix');
      if (requestedPrefix !== `${prefix}/`) return reject(res, 403, 'AccessDenied');
      const entries = [...objects].filter(([name]) => name.startsWith(requestedPrefix)
        && name > (url.searchParams.get('start-after') ?? '')).sort(([a], [b]) => a.localeCompare(b));
      const index = Number(url.searchParams.get('continuation-token') ?? '0');
      const next = index + 1;
      const isTruncated = next < entries.length;
      const [name, object] = entries[index] ?? [];
      return xml(res, 200, `<ListBucketResult><IsTruncated>${isTruncated}</IsTruncated>${isTruncated ? `<NextContinuationToken>${next}</NextContinuationToken>` : ''}${name
        ? `<Contents><Key>${name}</Key><LastModified>${object.modified.toISOString()}</LastModified><Size>${object.body.length}</Size></Contents>`
        : ''}</ListBucketResult>`);
    }
    if (req.method === 'GET' && role === 'READER' && key.startsWith(`${prefix}/`)) {
      reads += 1;
      const object = objects.get(key);
      if (!object) return reject(res, 404, 'NoSuchKey');
      if (header('x-amz-checksum-mode') !== 'ENABLED') return reject(res, 400, 'InvalidRequest');
      const body = corrupt ? Buffer.concat([object.body.subarray(0, -1), Buffer.from([object.body.at(-1) ^ 1])]) : object.body;
      return res.writeHead(200, { 'Content-Length': body.length, 'x-amz-checksum-sha256': object.checksum }).end(body);
    }
    return reject(res, 403, 'AccessDenied');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  return {
    objects, uploads, reads: () => reads,
    failNextUpload() { failNext = true; },
    denyUploads() { putDenied = true; },
    allowUploads() { putDenied = false; },
    corruptDownloads(value) { corrupt = value; },
    env(role) {
      return {
        AWS_ENDPOINT_URL_S3: `http://127.0.0.1:${server.address().port}`, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: 'false',
        AWS_ACCESS_KEY_ID: `ZEKVARFIXTURE${role}`, AWS_SECRET_ACCESS_KEY: 'local-fixture-signing-key', AWS_SESSION_TOKEN: '', AWS_REGION: 'us-east-1',
        ZEKVAR_BACKUP_BUCKET: bucket, ZEKVAR_BACKUP_BUCKET_OWNER: owner, ZEKVAR_BACKUP_PREFIX: prefix,
        ZEKVAR_BACKUP_RELEASE: 'test-release', ZEKVAR_BACKUP_KEY_ID: 'test-recovery-key',
      };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
