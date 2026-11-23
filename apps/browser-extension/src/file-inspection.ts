import { evaluateFileInspection, fileInspectionDetectors } from '../../../contracts/policy/file-inspection';
import { fixtureRule, githubPatRule, paymentCardRule, privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { readOfficeText } from './office-text';
import { hasZipHeader, type OfficeReadBudget } from './office-zip';

const maxPlainFileBytes = 256 * 1024;
const maxBatchBytes = 1024 * 1024;
const maxExpandedOfficeBytes = 1024 * 1024;
const maxFiles = 16;
const binaryControls = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/;
const priority = [fixtureRule, githubPatRule, paymentCardRule, privateKeyRule];

async function* fileText(bytes: Uint8Array<ArrayBuffer>, officeBudget: OfficeReadBudget) {
  if (hasZipHeader(bytes)) {
    yield* readOfficeText(bytes, officeBudget);
    return;
  }
  if (bytes.length > maxPlainFileBytes) return;
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (!binaryControls.test(text) && !text.startsWith('%PDF-')) yield text;
}

export async function inspectFiles(files: readonly File[], policy: PromptPolicy): Promise<RuleMetadata | undefined> {
  const detectors = fileInspectionDetectors(policy);
  const officeBudget: OfficeReadBudget = { remainingBytes: maxExpandedOfficeBytes, remainingParts: 64 };
  let remaining = maxBatchBytes;
  let best: RuleMetadata | undefined;
  for (const file of files.slice(0, maxFiles)) {
    if (file.size === 0 || file.size > remaining) continue;
    try {
      if (file.size > maxPlainFileBytes && !hasZipHeader(new Uint8Array(await file.slice(0, 4).arrayBuffer()))) continue;
      remaining -= file.size;
      const bytes = new Uint8Array(await file.arrayBuffer());
      for await (const text of fileText(bytes, officeBudget)) {
        const match = evaluateFileInspection(text, detectors);
        if (match && (!best || priority.indexOf(match.ruleId) > priority.indexOf(best.ruleId))) best = match;
        if (best?.ruleId === privateKeyRule) return best;
      }
    } catch {
      // Continue with the rest of the intake if a file cannot be inspected.
    }
  }
  return best;
}
