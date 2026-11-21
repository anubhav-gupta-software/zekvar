import type { AiPromptApp } from './apps';

export const uploadModes = ['off', 'monitor', 'block'] as const;
export type UploadMode = typeof uploadModes[number];
export type UploadDecision = Exclude<UploadMode, 'off'>;
export type UploadModes = Record<AiPromptApp, UploadMode>;
export const uploadsOff: UploadModes = { chatgpt: 'off', gemini: 'off' };
export type UploadTypes = Record<AiPromptApp, string[]>;
export const allUploadTypes: UploadTypes = { chatgpt: [], gemini: [] };
export type UploadFile = { name: string; type: string };
export type UploadFilter = { mode: UploadDecision; types: string[] };
export type TargetedUploads = Partial<Record<AiPromptApp, UploadFilter>>;
export const uploadTypesHint = 'Leave blank for all files, or enter up to 25 types such as .pdf or image/*. Separate types with spaces, commas, or line breaks.';
export const uploadTypesError = 'Enter up to 25 valid file extensions or media types per app, with at most 64 characters per type.';

const uploadTypePattern = /^(?:\.[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*|[a-z0-9][a-z0-9.+_-]*\/(?:\*|[a-z0-9][a-z0-9.+_-]*))$/;

function isUploadType(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && uploadTypePattern.test(value);
}

export function parseUploadTypes(text: string) {
  const types = text.split(/[\s,]+/).filter(Boolean).map((type) => type.toLowerCase());
  if (types.length <= 25 && types.every(isUploadType)) return [...new Set(types)].sort();
}

export function sameUploadTypes(a: readonly string[], b: readonly string[]) {
  return a.length === b.length && a.every((type, index) => type === b[index]);
}

export function readTargetedUpload(value: unknown): UploadFilter | undefined {
  if (typeof value !== 'object' || value === null || !('mode' in value) || !('types' in value) ||
      (value.mode !== 'monitor' && value.mode !== 'block') || !Array.isArray(value.types) ||
      !value.types.length || value.types.length > 25 || !value.types.every(isUploadType) ||
      !sameUploadTypes(value.types, [...new Set(value.types)].sort())) return;
  return { mode: value.mode, types: value.types };
}

export function matchesUploadType(file: UploadFile, types: readonly string[]) {
  const name = file.name.toLowerCase();
  const mime = file.type.toLowerCase().split(';', 1)[0].trim();
  return types.some((type) => {
    if (type.startsWith('.')) return name.endsWith(type);
    if (type.endsWith('/*')) return mime.startsWith(type.slice(0, -1));
    return mime === type;
  });
}

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
