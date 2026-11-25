const pngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
const maxEdge = 4096;
const maxPixels = 1_500_000;

export function rasterType(bytes: Uint8Array) {
  if (pngSignature.every((part, index) => bytes[index] === part)) return 'image/png';
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return 'image/jpeg';
}

function pngSize(bytes: Uint8Array, view: DataView): [number, number] | undefined {
  if (bytes.length < 45 || view.getUint32(8) !== 13 || view.getUint32(12) !== 0x49484452) return;
  for (let index = 8; index + 12 <= bytes.length;) {
    const length = view.getUint32(index);
    const type = view.getUint32(index + 4);
    index += length + 12;
    if (index > bytes.length || type === 0x6163544c || type === 0x6663544c || type === 0x66644154) return; // APNG
    if (type === 0x49484452 && index !== 33) return;
    if (type === 0x49454e44) {
      if (length === 0 && index === bytes.length) return [view.getUint32(16), view.getUint32(20)];
      return;
    }
  }
}

function jpegSize(bytes: Uint8Array, view: DataView): [number, number] | undefined {
  let size: [number, number] | undefined;
  let scanning = false;
  let sawScan = false;
  for (let index = 2; index < bytes.length;) {
    if (scanning) {
      index = bytes.indexOf(255, index);
      if (index === -1) return;
    }
    if (bytes[index++] !== 255) return;
    while (bytes[index] === 255) index++;
    const marker = bytes[index++];
    if (scanning && (marker === 0 || (marker >= 0xd0 && marker <= 0xd7))) continue;
    if (marker === 0xd9) return sawScan && index === bytes.length ? size : undefined;
    if (marker === 0 || marker === 0xd8 || index + 2 > bytes.length) return;
    const length = view.getUint16(index);
    const end = index + length;
    if (length < 2 || end > bytes.length) return;
    const frame = marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker);
    if (frame) {
      if (size || length < 8 || (marker !== 0xc0 && marker !== 0xc2)) return;
      size = [view.getUint16(index + 5), view.getUint16(index + 3)];
    }
    if (marker === 0xe2 && length >= 6 && view.getUint32(index + 2) === 0x4d504600) return; // Multi-picture JPEG
    scanning = marker === 0xda;
    if (scanning && !size) return;
    sawScan ||= scanning;
    index = end;
  }
}

export function readRaster(bytes: Uint8Array) {
  const type = rasterType(bytes);
  if (!type) return;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const size = type === 'image/png' ? pngSize(bytes, view) : jpegSize(bytes, view);
  if (!size) return;
  const [width, height] = size;
  if (width < 1 || height < 1 || width > maxEdge || height > maxEdge || width * height > maxPixels) return;
  return { type, width, height };
}
