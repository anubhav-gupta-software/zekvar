import type { PromptPolicy } from '../../../contracts/policy/prompt';
import { inspectionUnavailable, maxAttachmentBytes, type AttachmentInspection } from './attachment-inspection';
import { openOcr, recognizePixels } from './ocr-engine';
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
  const worker = await openOcr();
  try {
    return await recognizePixels(worker, pixels, detectors);
  } finally {
    await worker.terminate();
  }
}

self.addEventListener('message', ({ data }) => {
  void inspect(data.bytes, data.detectors).catch(() => inspectionUnavailable).then((result) => self.postMessage(result));
}, { once: true });
