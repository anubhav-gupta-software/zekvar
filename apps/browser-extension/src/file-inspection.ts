import { evaluateFileInspection, fileInspectionDetectors } from '../../../contracts/policy/file-inspection';
import { fixtureRule, githubPatRule, identifierRule, paymentCardRule, privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { readOfficeText } from './office-text';
import { hasZipHeader, type OfficeReadBudget } from './office-zip';

const maxPlainFileBytes = 256 * 1024;
const maxBatchBytes = 1024 * 1024;
const maxExpandedOfficeBytes = 1024 * 1024;
const maxFiles = 16;
const binaryControls = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/;
const priority = [fixtureRule, identifierRule, githubPatRule, paymentCardRule, privateKeyRule];

type FileScan = { match?: RuleMetadata; complete: boolean; snapshots: File[] };
type ScanOptions = { signal?: AbortSignal; snapshot?: boolean };

async function* fileText(bytes: Uint8Array<ArrayBuffer>, officeBudget: OfficeReadBudget): AsyncGenerator<string, boolean> {
  if (hasZipHeader(bytes)) return yield* readOfficeText(bytes, officeBudget);
  if (bytes.length > maxPlainFileBytes) return false;
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (binaryControls.test(text) || text.startsWith('%PDF-')) return false;
  yield text;
  return true;
}

export async function scanFileContents(files: readonly File[], policy: PromptPolicy, { signal, snapshot }: ScanOptions = {}): Promise<FileScan> {
  const detectors = fileInspectionDetectors(policy);
  const officeBudget: OfficeReadBudget = { remainingBytes: maxExpandedOfficeBytes, remainingParts: 64 };
  let remaining = maxBatchBytes;
  let best: RuleMetadata | undefined;
  let complete = files.length <= maxFiles;
  const snapshots: File[] = [];
  for (const file of files.slice(0, maxFiles)) {
    signal?.throwIfAborted();
    if (file.size === 0) {
      if (snapshot) snapshots.push(snapshotFile(file, new Uint8Array(0)));
      continue;
    }
    if (file.size > remaining) {
      complete = false;
      continue;
    }
    try {
      if (file.size > maxPlainFileBytes && !hasZipHeader(new Uint8Array(await file.slice(0, 4).arrayBuffer()))) {
        complete = false;
        continue;
      }
      remaining -= file.size;
      const bytes = new Uint8Array(await file.arrayBuffer());
      const text = fileText(bytes, officeBudget);
      try {
        let part = await text.next();
        while (!part.done) {
          signal?.throwIfAborted();
          const match = evaluateFileInspection(part.value, detectors);
          if (match && (!best || priority.indexOf(match.ruleId) > priority.indexOf(best.ruleId))) best = match;
          if (best?.ruleId === privateKeyRule) return { match: best, complete: false, snapshots: [] };
          part = await text.next();
        }
        complete &&= part.value;
        if (snapshot && complete && !best && !file.webkitRelativePath) snapshots.push(snapshotFile(file, bytes));
      } finally {
        await text.return(false);
      }
    } catch {
      signal?.throwIfAborted();
      complete = false;
    }
  }
  return { match: best, complete, snapshots };
}

function snapshotFile(file: File, bytes: Uint8Array<ArrayBuffer>) {
  return new File([bytes], file.name, { type: file.type, lastModified: file.lastModified });
}

export async function inspectFiles(files: readonly File[], policy: PromptPolicy) {
  return (await scanFileContents(files, policy)).match;
}
