import { evaluateFileInspection, preferredFileMatch } from '../../../contracts/policy/file-inspection';
import { privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { hasPdfHeader, isPdfPayload, maxPdfBytes, pdfUnavailable, type PdfInspection } from './pdf-inspection';

type PdfLibrary = typeof import('pdfjs-dist');
declare const SERVICE_WORKER_PATH: string;
const resources = 'pdf-assets/';
const maxPages = 24;
const maxText = 256 * 1024;
const inspectionMs = 2200;

async function scanDocument(data: Uint8Array<ArrayBuffer>, detectors: PromptPolicy, pdf: PdfLibrary, port: Worker): Promise<PdfInspection> {
  const worker = pdf.PDFWorker.create({ port, verbosity: pdf.VerbosityLevel.ERRORS });
  const task = pdf.getDocument({
    data, worker, stopAtErrors: true, disableFontFace: true, useSystemFonts: false, useWasm: false, useWorkerFetch: false,
    disableWorkerRendering: true, disableAutoFetch: true, disableRange: true, disableStream: true,
    cMapUrl: chrome.runtime.getURL(resources + 'cmaps/'),
    standardFontDataUrl: chrome.runtime.getURL(resources + 'standard_fonts/'),
    verbosity: pdf.VerbosityLevel.ERRORS,
  });
  try {
    const doc = await task.promise;
    if (doc.numPages < 1 || doc.numPages > maxPages) return pdfUnavailable;
    const types = pdf.AnnotationType;
    const unsupportedAnnotations = new Set([
      types.TEXT, types.FREETEXT, types.FILEATTACHMENT, types.WIDGET, types.SOUND, types.MOVIE, types.SCREEN, types.THREED, types.RICHMEDIA,
    ]);
    const [attachments, fields, scripts, annotations] = await Promise.all([
      doc.getAttachments(), doc.getFieldObjects(), doc.getJSActions(), doc.getAnnotationsByType(unsupportedAnnotations, new Set()),
    ]);
    let complete = !doc.isPureXfa && !attachments?.size && !fields?.size && !scripts?.size && annotations.length === 0;
    let remaining = maxText;
    let match: RuleMetadata | undefined;
    for (let number = 1; number <= doc.numPages; number++) {
      const page = await doc.getPage(number);
      const reader = page.streamTextContent().getReader();
      const text: string[] = [];
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const item of value.items) {
            if (!('str' in item)) continue;
            const line = item.str + (item.hasEOL ? '\n' : '');
            if (!line) continue;
            if (line.length > remaining) {
              await reader.cancel();
              match = preferredFileMatch(match, evaluateFileInspection(text.join(''), detectors));
              return { complete: false, match };
            }
            text.push(line);
            remaining -= line.length;
          }
        }
      } finally {
        reader.releaseLock();
      }
      const content = text.join('');
      if (!content.trim() || content.includes('\ufffd')) complete = false;
      match = preferredFileMatch(match, evaluateFileInspection(content, detectors));
      if (match?.ruleId === privateKeyRule) return { complete: false, match };
    }
    return { complete, match };
  } finally {
    await task.destroy().catch(() => undefined);
    worker.destroy();
  }
}

async function inspect(encoded: string, detectors: PromptPolicy): Promise<PdfInspection> {
  let port: Worker | undefined;
  let expired = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const scan = async () => {
    const binary = atob(encoded);
    if (binary.length > maxPdfBytes) return pdfUnavailable;
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
    if (!hasPdfHeader(bytes)) return pdfUnavailable;
    const pdf: PdfLibrary = await import(chrome.runtime.getURL(resources + 'pdf.min.mjs'));
    if (expired) return pdfUnavailable;
    // An explicitly created worker also disables PDF.js's main-thread fallback.
    const parsingWorker = port = new Worker(chrome.runtime.getURL(resources + 'pdf.worker.min.mjs'), { type: 'module' });
    const crashed = new Promise<PdfInspection>((resolve) => parsingWorker.addEventListener('error', (event) => {
      event.preventDefault();
      resolve(pdfUnavailable);
    }, { once: true }));
    return Promise.race([scanDocument(bytes, detectors, pdf, parsingWorker), crashed]);
  };
  const deadline = new Promise<PdfInspection>((resolve) => { timer = setTimeout(() => resolve(pdfUnavailable), inspectionMs); });
  try {
    return await Promise.race([scan(), deadline]);
  } catch {
    return pdfUnavailable;
  } finally {
    expired = true;
    clearTimeout(timer);
    port?.terminate();
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'inspect-offscreen-pdf') return;
  const sender = port.sender;
  if (sender?.id !== chrome.runtime.id || sender.tab || sender.url !== new URL(SERVICE_WORKER_PATH, location.href).href) {
    port.disconnect();
    return;
  }
  let started = false;
  let connected = true;
  port.onDisconnect.addListener(() => { connected = false; });
  port.onMessage.addListener((message) => {
    if (started || !isPdfPayload(message?.encoded)) return;
    started = true;
    void inspect(message.encoded, message.detectors).then((result) => {
      if (connected) port.postMessage(result);
    }).catch(() => undefined);
  });
});
