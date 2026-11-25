import type { RuleMetadata } from '../../../contracts/policy/prompt';
import type { Policy } from './protocol';
import { rasterType } from './raster-image';

export type AttachmentKind = 'pdf' | 'image';
export type AttachmentInspection = { complete: boolean; match?: RuleMetadata };
export const maxAttachmentBytes = 1024 * 1024;
export const inspectionUnavailable: AttachmentInspection = { complete: false };

export function attachmentKind(bytes: Uint8Array): AttachmentKind | undefined {
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2d) return 'pdf';
  if (rasterType(bytes)) return 'image';
}

export function isInspectionPayload(kind: AttachmentKind, encoded: unknown): encoded is string {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(maxAttachmentBytes / 3) * 4) return false;
  return kind === 'pdf' ? encoded.startsWith('JVBERi') : encoded.startsWith('iVBORw0KGgo') || encoded.startsWith('/9j/');
}

export function decodeAttachment(encoded: string): Uint8Array<ArrayBuffer> {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export async function inspectAttachment(kind: AttachmentKind, bytes: Uint8Array, policy: Policy, installationId: string): Promise<AttachmentInspection> {
  if (bytes.length > maxAttachmentBytes) return inspectionUnavailable;
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  try {
    const result = await chrome.runtime.sendMessage({ type: `inspect-${kind}`, encoded: btoa(binary),
      installationId, version: policy.version, assignmentVersion: policy.assignmentVersion });
    return typeof result?.complete === 'boolean' ? result : inspectionUnavailable;
  } catch {
    return inspectionUnavailable;
  }
}
