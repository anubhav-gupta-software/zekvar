import type { PDFPageProxy } from 'pdfjs-dist';
import { evaluateFileInspection, preferredFileMatch } from '../../../contracts/policy/file-inspection';
import { privateKeyRule, type PromptPolicy, type RuleMetadata } from '../../../contracts/policy/prompt';
import { attachmentKind, inspectionUnavailable, maxAttachmentBytes, type AttachmentInspection } from './attachment-inspection';
import { openOcr, recognizePixels } from './ocr-engine';

type PdfLibrary = typeof import('pdfjs-dist');
const maxPages = 24;
const maxText = 256 * 1024;
const maxOcrPages = 3;
const maxRenderPixels = 1_500_000;
const maxRenderEdge = 4096;
const maxSourceImagePixels = 10_000_000;
const maxOperators = 50_000;

function resizeCanvas(canvas: OffscreenCanvas, width: number, height: number) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 ||
      width > 8192 || height > 8192 || width * height > maxSourceImagePixels) throw new Error('PDF canvas exceeds the scan limits.');
  canvas.width = width;
  canvas.height = height;
}

class WorkerCanvasFactory {
  create(width: number, height: number) {
    const canvas = new OffscreenCanvas(1, 1);
    resizeCanvas(canvas, width, height);
    return { canvas, context: canvas.getContext('2d', { willReadFrequently: true }) };
  }
  reset({ canvas }: { canvas: OffscreenCanvas }, width: number, height: number) {
    resizeCanvas(canvas, width, height);
  }
  destroy(target: { canvas: OffscreenCanvas | null; context: OffscreenCanvasRenderingContext2D | null }) {
    if (target.canvas) target.canvas.width = target.canvas.height = 0;
    target.canvas = target.context = null;
  }
  getNoAlphaContext(canvas: OffscreenCanvas) {
    return canvas.getContext('2d', { alpha: false, willReadFrequently: true });
  }
}

async function renderPage(page: PDFPageProxy, annotationMode: number) {
  const size = page.getViewport({ scale: 1 });
  if (!Number.isFinite(size.width) || !Number.isFinite(size.height) || size.width <= 0 || size.height <= 0 ||
      size.width > maxRenderEdge || size.height > maxRenderEdge) return;
  const scale = Math.min(2, maxRenderEdge / size.width, maxRenderEdge / size.height,
    Math.sqrt(maxRenderPixels / (size.width * size.height)));
  const viewport = page.getViewport({ scale });
  const width = Math.floor(viewport.width);
  const height = Math.floor(viewport.height);
  if (!width || !height || width * height > maxRenderPixels) return;
  const canvas = new OffscreenCanvas(width, height);
  try {
    const context = canvas.getContext('2d');
    if (!context) return;
    // PDF.js declares a DOM 2D context here, but the canvas renderer accepts OffscreenCanvas contexts too.
    await page.render({ canvas: null, canvasContext: context as unknown as CanvasRenderingContext2D, viewport, annotationMode,
      background: '#fff', transform: [width / viewport.width, 0, 0, height / viewport.height, 0, 0] }).promise;
    return await canvas.convertToBlob({ type: 'image/png' });
  } finally {
    canvas.width = canvas.height = 0;
  }
}

async function scanDocument(data: Uint8Array<ArrayBuffer>, detectors: PromptPolicy, pdf: PdfLibrary, port: Worker): Promise<AttachmentInspection> {
  const worker = pdf.PDFWorker.create({ port, verbosity: pdf.VerbosityLevel.ERRORS });
  const asset = (name: string) => new URL(`pdf-assets/${name}`, self.location.href).href;
  const task = pdf.getDocument({
    data, worker, stopAtErrors: true, disableFontFace: true, useSystemFonts: false, useWasm: false, useWorkerFetch: false,
    disableWorkerRendering: true, disableAutoFetch: true, disableRange: true, disableStream: true,
    CanvasFactory: WorkerCanvasFactory, maxImageSize: maxSourceImagePixels, canvasMaxAreaInBytes: maxSourceImagePixels * 4,
    cMapUrl: asset('cmaps/'), standardFontDataUrl: asset('standard_fonts/'), verbosity: pdf.VerbosityLevel.ERRORS,
  });
  let ocr: Awaited<ReturnType<typeof openOcr>> | undefined;
  let match: RuleMetadata | undefined;
  function record(candidate: RuleMetadata | undefined) {
    const best = preferredFileMatch(match, candidate);
    if (best !== match) {
      match = best;
      self.postMessage({ match });
    }
    return best;
  }
  try {
    const doc = await task.promise;
    if (doc.numPages < 1 || doc.numPages > maxPages) return inspectionUnavailable;
    const types = pdf.AnnotationType;
    const unsupportedAnnotations = new Set([
      types.TEXT, types.FREETEXT, types.FILEATTACHMENT, types.WIDGET, types.SOUND, types.MOVIE, types.SCREEN, types.THREED, types.RICHMEDIA,
      types.STAMP,
    ]);
    const [attachments, fields, scripts, annotations] = await Promise.all([
      doc.getAttachments(), doc.getFieldObjects(), doc.getJSActions(), doc.getAnnotationsByType(unsupportedAnnotations, new Set()),
    ]);
    let complete = !doc.isPureXfa && !attachments?.size && !fields?.size && !scripts?.size && annotations.length === 0;
    const ops = pdf.OPS;
    const rasterOperations = new Set([ops.paintImageXObject, ops.paintImageXObjectRepeat, ops.paintInlineImageXObject,
      ops.paintInlineImageXObjectGroup, ops.paintImageMaskXObject, ops.paintImageMaskXObjectGroup, ops.paintImageMaskXObjectRepeat]);
    const annotationMode = pdf.AnnotationMode.DISABLE;
    let remaining = maxText;
    let ocrPages = 0;
    for (let number = 1; number <= doc.numPages; number++) {
      const page = await doc.getPage(number);
      try {
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
                record(evaluateFileInspection(text.join(''), detectors));
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
        if (content.includes('\ufffd')) complete = false;
        if (record(evaluateFileInspection(content, detectors))?.ruleId === privateKeyRule) return { complete: false, match };
        const { fnArray } = await page.getOperatorList({ annotationMode });
        if (fnArray.length > maxOperators) {
          complete = false;
          continue;
        }
        if (content.trim() && !fnArray.some((op: number) => rasterOperations.has(op))) continue;
        if (++ocrPages > maxOcrPages) {
          complete = false;
          continue;
        }
        const pixels = await renderPage(page, annotationMode);
        if (!pixels) {
          complete = false;
          continue;
        }
        ocr ??= await openOcr();
        const recognized = await recognizePixels(ocr, pixels, detectors);
        complete &&= recognized.complete;
        if (record(recognized.match)?.ruleId === privateKeyRule) return { complete: false, match };
      } finally {
        page.cleanup();
      }
    }
    return { complete, match };
  } catch {
    return { complete: false, match };
  } finally {
    await ocr?.terminate();
    await task.destroy().catch(() => undefined);
    worker.destroy();
  }
}

async function inspect(data: Uint8Array<ArrayBuffer>, detectors: PromptPolicy): Promise<AttachmentInspection> {
  if (data.length > maxAttachmentBytes || attachmentKind(data) !== 'pdf') return inspectionUnavailable;
  const pdf: PdfLibrary = await import(new URL('pdf-assets/pdf.min.mjs', self.location.href).href);
  const parser = new Worker(new URL('pdf-assets/pdf.worker.min.mjs', self.location.href), { type: 'module' });
  try {
    return await scanDocument(data, detectors, pdf, parser);
  } finally {
    parser.terminate();
  }
}

self.addEventListener('message', ({ data }) => {
  void inspect(data.bytes, data.detectors).catch(() => inspectionUnavailable).then((result) => self.postMessage(result));
}, { once: true });
