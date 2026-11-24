import type { PromptPolicy } from '../../../contracts/policy/prompt';
import { pdfUnavailable, type PdfInspection } from './pdf-inspection';

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
        justification: 'Run local PDF text inspection in a disposable worker before protected file uploads.',
      });
    })().finally(() => { creating = undefined; });
  }
  return creating;
}

export async function inspectPdfOffscreen(encoded: string, detectors: PromptPolicy): Promise<PdfInspection> {
  if (active >= 2) return pdfUnavailable;
  active++;
  try {
    await openDocument();
    const port = chrome.runtime.connect({ name: 'inspect-offscreen-pdf' });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await new Promise<PdfInspection>((resolve) => {
        timer = setTimeout(() => resolve(pdfUnavailable), 2400);
        port.onDisconnect.addListener(() => resolve(pdfUnavailable));
        port.onMessage.addListener((result) => resolve(typeof result?.complete === 'boolean' ? result : pdfUnavailable));
        port.postMessage({ encoded, detectors });
      });
    } finally {
      clearTimeout(timer);
      port.disconnect();
    }
  } catch {
    return pdfUnavailable;
  } finally {
    active--;
  }
}
