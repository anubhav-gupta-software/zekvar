import { evaluateFileInspection, fileInspectionDetectors } from '../../../contracts/policy/file-inspection';
import { fixtureRule, githubPatRule, paymentCardRule, privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';

const maxFileBytes = 256 * 1024;
const maxBatchBytes = 1024 * 1024;
const maxFiles = 16;
const binaryControls = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/;
const priority = [fixtureRule, githubPatRule, paymentCardRule, privateKeyRule];

export async function inspectFiles(files: readonly File[], policy: PromptPolicy): Promise<RuleMetadata | undefined> {
  const detectors = fileInspectionDetectors(policy);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let remaining = maxBatchBytes;
  let best: RuleMetadata | undefined;
  for (const file of files.slice(0, maxFiles)) {
    if (file.size === 0 || file.size > maxFileBytes || file.size > remaining) continue;
    remaining -= file.size;
    let text: string;
    try {
      text = decoder.decode(await file.arrayBuffer());
    } catch {
      continue;
    }
    if (binaryControls.test(text) || text.startsWith('%PDF-')) continue;
    const match = evaluateFileInspection(text, detectors);
    if (match && (!best || priority.indexOf(match.ruleId) > priority.indexOf(best.ruleId))) best = match;
    if (best?.ruleId === privateKeyRule) return best;
  }
  return best;
}
