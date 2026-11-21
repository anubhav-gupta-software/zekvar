import type { AiPromptApp } from './apps';

export const uploadModes = ['off', 'monitor', 'block'] as const;
export type UploadMode = typeof uploadModes[number];
export type UploadDecision = Exclude<UploadMode, 'off'>;
export type UploadModes = Record<AiPromptApp, UploadMode>;
export const uploadsOff: UploadModes = { chatgpt: 'off', gemini: 'off' };

export const uploadRule = 'ai-file-upload';
export const uploadCategory = 'file-upload';
export const uploadMethods = { picker: 'File picker', drop: 'Drag and drop', paste: 'Clipboard file' } as const;
export type UploadMethod = keyof typeof uploadMethods;
export type UploadMetadata = { ruleId: typeof uploadRule; detectorCategory: typeof uploadCategory; uploadMethod: UploadMethod };

export function isUploadMode(value: unknown): value is UploadMode {
  return value === 'off' || value === 'monitor' || value === 'block';
}

export function isUploadModes(value: unknown): value is UploadModes {
  return typeof value === 'object' && value !== null && 'chatgpt' in value && 'gemini' in value &&
    isUploadMode(value.chatgpt) && isUploadMode(value.gemini);
}

export function isUploadMethod(value: unknown): value is UploadMethod {
  return typeof value === 'string' && Object.hasOwn(uploadMethods, value);
}
