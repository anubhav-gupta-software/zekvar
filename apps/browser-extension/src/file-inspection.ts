import { evaluateFileInspection, fileInspectionDetectors, preferredFileMatch } from '../../../contracts/policy/file-inspection';
import { privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { readOfficeText } from './office-text';
import { hasZipHeader, type OfficeReadBudget } from './office-zip';
import { hasPdfHeader, pdfUnavailable, type PdfInspection } from './pdf-inspection';

const maxPlainFileBytes = 256 * 1024;
const maxBatchBytes = 1024 * 1024;
const maxExpandedOfficeBytes = 1024 * 1024;
const maxFiles = 16;
const binaryControls = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/;
type FileScan = { match?: RuleMetadata; complete: boolean; snapshots: File[] };
type ScanOptions = { signal?: AbortSignal; snapshot?: boolean; pdf?: (bytes: Uint8Array) => Promise<PdfInspection> };

async function* fileText(bytes: Uint8Array<ArrayBuffer>, officeBudget: OfficeReadBudget): AsyncGenerator<string, boolean> {
  if (hasZipHeader(bytes)) return yield* readOfficeText(bytes, officeBudget);
  if (bytes.length > maxPlainFileBytes) return false;
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (binaryControls.test(text) || text.startsWith('%PDF-')) return false;
  yield text;
  return true;
}

export async function scanFileContents(files: readonly File[], policy: PromptPolicy, { signal, snapshot, pdf }: ScanOptions = {}): Promise<FileScan> {
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
      if (file.size > maxPlainFileBytes) {
        const header = new Uint8Array(await file.slice(0, 5).arrayBuffer());
        if (!hasZipHeader(header) && !hasPdfHeader(header)) {
          complete = false;
          continue;
        }
      }
      remaining -= file.size;
      const bytes = new Uint8Array(await file.arrayBuffer());
      signal?.throwIfAborted();
      if (hasPdfHeader(bytes)) {
        const result = pdf ? await pdf(bytes) : pdfUnavailable;
        signal?.throwIfAborted();
        best = preferredFileMatch(best, result.match);
        complete &&= result.complete;
      } else {
        const text = fileText(bytes, officeBudget);
        try {
          let part = await text.next();
          while (!part.done) {
            signal?.throwIfAborted();
            best = preferredFileMatch(best, evaluateFileInspection(part.value, detectors));
            if (best?.ruleId === privateKeyRule) return { match: best, complete: false, snapshots: [] };
            part = await text.next();
          }
          complete &&= part.value;
        } finally {
          await text.return(false);
        }
      }
      if (best?.ruleId === privateKeyRule) return { match: best, complete: false, snapshots: [] };
      if (snapshot && complete && !best && !file.webkitRelativePath) snapshots.push(snapshotFile(file, bytes));
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

export async function inspectFiles(files: readonly File[], policy: PromptPolicy, options?: ScanOptions) {
  return (await scanFileContents(files, policy, options)).match;
}
