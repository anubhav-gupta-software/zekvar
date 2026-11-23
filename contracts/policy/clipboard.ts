import { evaluateFileInspection, fileInspectionDetectors } from './file-inspection';
import type { PromptPolicy } from './prompt';

export const clipboardModes = ['off', 'monitor', 'block'] as const;
export type ClipboardMode = typeof clipboardModes[number];
export const clipboardUnavailableRule = 'clipboard-inspection-unavailable';
export const clipboardCategory = 'clipboard';
export const clipboardTextLimit = 64_000;

export function isClipboardMode(value: unknown): value is ClipboardMode {
  return value === 'off' || value === 'monitor' || value === 'block';
}

export function inspectClipboard(text: string | undefined, policy: PromptPolicy, mode: ClipboardMode) {
  if (mode === 'off') return;
  if (text === undefined || text.length > clipboardTextLimit) {
    return mode === 'block' ? { decision: mode, ruleId: clipboardUnavailableRule, detectorCategory: clipboardCategory } as const : undefined;
  }
  const match = evaluateFileInspection(text, fileInspectionDetectors(policy));
  return match ? { decision: mode, ...match } : undefined;
}
