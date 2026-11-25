import { createWorker, OEM, PSM } from 'tesseract.js';
import { evaluateFileInspection } from '../../../contracts/policy/file-inspection';
import type { PromptPolicy } from '../../../contracts/policy/prompt';
import { inspectionUnavailable, maxAttachmentBytes, type AttachmentInspection } from './attachment-inspection';
import { readRaster } from './raster-image';

async function rasterPixels(bytes: Uint8Array<ArrayBuffer>) {
  if (bytes.length > maxAttachmentBytes) return;
  const size = readRaster(bytes);
  if (!size) return;
  const decoder = new ImageDecoder({ data: bytes, type: size.type, preferAnimation: false });
  try {
    await decoder.tracks.ready;
    if (decoder.tracks.selectedTrack?.frameCount !== 1) return;
    const { image, complete } = await decoder.decode({ completeFramesOnly: true });
    try {
      if (!complete || image.codedWidth !== size.width || image.codedHeight !== size.height) return;
      const upright = image.displayWidth === size.width && image.displayHeight === size.height;
      const rotated = image.displayWidth === size.height && image.displayHeight === size.width;
      if (!upright && !rotated) return;
      const canvas = new OffscreenCanvas(image.displayWidth, image.displayHeight);
      const context = canvas.getContext('2d');
      if (!context) return;
      context.fillStyle = '#fff';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.drawImage(image, 0, 0);
      return await canvas.convertToBlob({ type: 'image/png' });
    } finally {
      image.close();
    }
  } finally {
    decoder.close();
  }
}

async function inspect(bytes: Uint8Array<ArrayBuffer>, detectors: PromptPolicy): Promise<AttachmentInspection> {
  const pixels = await rasterPixels(bytes);
  if (!pixels) return inspectionUnavailable;
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
    const { data } = await worker.recognize(pixels, {}, { text: true, blocks: true });
    const text = data.text.slice(0, 64 * 1024);
    const match = evaluateFileInspection(text, detectors);
    const words = data.blocks?.flatMap((block) => block.paragraphs.flatMap((paragraph) => paragraph.lines.flatMap((line) => line.words))) ?? [];
    const complete = text.length === data.text.length && /[\p{L}\p{N}]/u.test(text) &&
      !text.includes('\ufffd') && data.confidence >= 75 && words.length > 0 && words.every((word) => word.confidence >= 65);
    return { complete, match };
  } finally {
    await worker.terminate();
  }
}

self.addEventListener('message', ({ data }) => {
  void inspect(data.bytes, data.detectors).catch(() => inspectionUnavailable).then((result) => self.postMessage(result));
}, { once: true });
