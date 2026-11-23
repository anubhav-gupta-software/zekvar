const localSignature = 0x04034b50;
const centralSignature = 0x02014b50;
const endSignature = 0x06054b50;
const filenameDecoder = new TextDecoder('utf-8', { fatal: true });

type ZipEntry = { flags: number; method: number; crc: number; compressedSize: number; size: number; offset: number };
export type OfficeReadBudget = { remainingBytes: number; remainingParts: number };

const crcTable = Uint32Array.from({ length: 256 }, (_, index) => {
  let crc = index;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  return crc;
});

function checksum(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

export function hasZipHeader(bytes: Uint8Array) {
  return bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4;
}

export function openOfficeZip(bytes: Uint8Array<ArrayBuffer>) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (at: number) => view.getUint16(at, true);
  const u32 = (at: number) => view.getUint32(at, true);
  let end = bytes.length - 22;
  const searchStart = Math.max(0, end - 65535);
  while (end >= searchStart && (u32(end) !== endSignature || end + 22 + u16(end + 20) !== bytes.length)) end--;
  if (end < searchStart || u16(end + 4) !== 0 || u16(end + 6) !== 0) return;
  const count = u16(end + 10);
  const central = u32(end + 16);
  if (!count || count > 1024 || u16(end + 8) !== count || central + u32(end + 12) !== end) return;

  const entries = new Map<string, ZipEntry>();
  let at = central;
  for (let index = 0; index < count; index++) {
    if (at + 46 > end || u32(at) !== centralSignature || u16(at + 34) !== 0) return;
    const nameStart = at + 46;
    const nameEnd = nameStart + u16(at + 28);
    const next = nameEnd + u16(at + 30) + u16(at + 32);
    if (nameEnd === nameStart || next > end) return;
    const name = filenameDecoder.decode(bytes.subarray(nameStart, nameEnd));
    if (entries.has(name)) return;
    entries.set(name, { flags: u16(at + 8), method: u16(at + 10), crc: u32(at + 16),
      compressedSize: u32(at + 20), size: u32(at + 24), offset: u32(at + 42) });
    at = next;
  }
  if (at !== end) return;

  async function read(name: string, budget: OfficeReadBudget) {
    const entry = entries.get(name);
    if (!entry || !entry.size || budget.remainingParts === 0 || entry.size > Math.min(256 * 1024, budget.remainingBytes)) return;
    const { offset, flags, method } = entry;
    // Accept stored and deflated parts, including archives that write sizes after the data.
    if ((flags & ~0x080e) !== 0 || (method !== 0 && method !== 8) || offset + 30 > central ||
        u32(offset) !== localSignature || u16(offset + 6) !== flags || u16(offset + 8) !== method) return;
    const nameEnd = offset + 30 + u16(offset + 26);
    const dataStart = nameEnd + u16(offset + 28);
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > central || filenameDecoder.decode(bytes.subarray(offset + 30, nameEnd)) !== name) return;
    if (!(flags & 8) && (u32(offset + 14) !== entry.crc ||
        u32(offset + 18) !== entry.compressedSize || u32(offset + 22) !== entry.size)) return;

    budget.remainingBytes -= entry.size;
    budget.remainingParts--;
    const input = bytes.subarray(dataStart, dataEnd);
    const output = method === 0 ? input : await inflate(input, entry.size);
    if (output?.length === entry.size && checksum(output) === entry.crc) return output;
  }
  return { names: [...entries.keys()], read };
}

async function inflate(input: Uint8Array<ArrayBuffer>, size: number) {
  let compressedOffset = 0;
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    pull(controller) {
      if (compressedOffset === input.length) {
        controller.close();
        return;
      }
      const chunk = input.subarray(compressedOffset, compressedOffset + 1024);
      compressedOffset += chunk.length;
      controller.enqueue(chunk);
    },
  }).pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  const output = new Uint8Array(size);
  let at = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return at === size ? output : undefined;
      if (at + value.length > size) {
        await reader.cancel();
        return;
      }
      output.set(value, at);
      at += value.length;
    }
  } finally {
    reader.releaseLock();
  }
}
