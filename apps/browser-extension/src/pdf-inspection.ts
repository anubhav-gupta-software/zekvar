import type { RuleMetadata } from '../../../contracts/policy/prompt';
import type { Policy } from './protocol';

export type PdfInspection = { complete: boolean; match?: RuleMetadata };
export const maxPdfBytes = 1024 * 1024;
export const pdfUnavailable: PdfInspection = { complete: false };

export function hasPdfHeader(bytes: Uint8Array) {
  return bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2d;
}

export function isPdfPayload(encoded: unknown): encoded is string {
  // Chrome extension messages use JSON serialization.
  return typeof encoded === 'string' && encoded.startsWith('JVBERi') && encoded.length <= Math.ceil(maxPdfBytes / 3) * 4;
}

export async function inspectPdf(bytes: Uint8Array, policy: Policy, installationId: string): Promise<PdfInspection> {
  if (bytes.length > maxPdfBytes) return pdfUnavailable;
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  try {
    const result = await chrome.runtime.sendMessage({ type: 'inspect-pdf', encoded: btoa(binary),
      installationId, version: policy.version, assignmentVersion: policy.assignmentVersion });
    return typeof result?.complete === 'boolean' ? result : pdfUnavailable;
  } catch {
    return pdfUnavailable;
  }
}
