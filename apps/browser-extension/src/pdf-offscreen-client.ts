import type { PromptPolicy } from '../../../contracts/policy/prompt';
import { inspectionUnavailable, type AttachmentInspection, type AttachmentKind } from './attachment-inspection';

const documentPath = 'pdf-offscreen.html';
let creating: Promise<void> | undefined;
let active = 0;

async function openDocument() {
  if (!creating) {
    creating = (async () => {
      const documents = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
        documentUrls: [chrome.runtime.getURL(documentPath)],
      });
      if (documents.length) return;
      await chrome.offscreen.createDocument({
        url: documentPath,
        reasons: ['WORKERS'],
        justification: 'Inspect protected attachments locally in disposable workers.',
      });
    })().finally(() => { creating = undefined; });
  }
  return creating;
}

export async function inspectOffscreen(kind: AttachmentKind, encoded: string, detectors: PromptPolicy): Promise<AttachmentInspection> {
  if (active >= 2) return inspectionUnavailable;
  active++;
  try {
    await openDocument();
    const port = chrome.runtime.connect({ name: `inspect-offscreen-${kind}` });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await new Promise<AttachmentInspection>((resolve) => {
        timer = setTimeout(() => resolve(inspectionUnavailable), 2400);
        port.onDisconnect.addListener(() => resolve(inspectionUnavailable));
        port.onMessage.addListener((result) => resolve(typeof result?.complete === 'boolean' ? result : inspectionUnavailable));
        port.postMessage({ encoded, detectors });
      });
    } finally {
      clearTimeout(timer);
      port.disconnect();
    }
  } catch {
    return inspectionUnavailable;
  } finally {
    active--;
  }
}
