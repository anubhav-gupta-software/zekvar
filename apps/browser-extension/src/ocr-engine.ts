import { createWorker, OEM, PSM, type Worker } from 'tesseract.js';
import { evaluateFileInspection } from '../../../contracts/policy/file-inspection';
import type { PromptPolicy } from '../../../contracts/policy/prompt';
import type { AttachmentInspection } from './attachment-inspection';

export async function openOcr() {
  const assets = new URL('ocr-assets/', self.location.href);
  const worker = await createWorker('eng', OEM.LSTM_ONLY, {
    workerPath: new URL('worker.min.js', assets).href,
    corePath: new URL('tesseract-core-simd-lstm.js', assets).href,
    langPath: assets.href,
    workerBlobURL: false,
    cacheMethod: 'none',
    errorHandler: () => undefined,
  });
  try {
    await worker.setParameters({ tessedit_pageseg_mode: PSM.SPARSE_TEXT });
    return worker;
  } catch (error) {
    await worker.terminate();
    throw error;
  }
}

export async function recognizePixels(worker: Worker, pixels: Blob, detectors: PromptPolicy): Promise<AttachmentInspection> {
  const { data } = await worker.recognize(pixels, {}, { text: true, blocks: true });
  const text = data.text.slice(0, 64 * 1024);
  const match = evaluateFileInspection(text, detectors);
  const words = data.blocks?.flatMap((block) => block.paragraphs.flatMap((paragraph) => paragraph.lines.flatMap((line) => line.words))) ?? [];
  const complete = text.length === data.text.length && /[\p{L}\p{N}]/u.test(text) &&
    !text.includes('\ufffd') && data.confidence >= 75 && words.length > 0 && words.every((word) => word.confidence >= 65);
  return { complete, match };
}
