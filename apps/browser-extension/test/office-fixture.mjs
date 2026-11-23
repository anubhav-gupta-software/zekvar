import { crc32, deflateRawSync } from 'node:zlib';

const namespace = 'http://schemas.openxmlformats.org/';
const mime = 'application/vnd.openxmlformats-officedocument.';
const packages = {
  docx: ['word/document.xml', mime + 'wordprocessingml.document.main+xml'],
  xlsx: ['xl/workbook.xml', mime + 'spreadsheetml.sheet.main+xml'],
  pptx: ['ppt/presentation.xml', mime + 'presentationml.presentation.main+xml'],
};

export function zipParts(parts, { comment = '', descriptor = false } = {}) {
  const files = [];
  const directory = [];
  let position = 0;
  for (const [path, input] of parts) {
    const { text, store = false, declaredSize, badCrc = false, encrypted = false } =
      typeof input === 'string' || Buffer.isBuffer(input) ? { text: input } : input;
    const payload = Buffer.from(text);
    const compressed = store ? payload : deflateRawSync(payload);
    const name = Buffer.from(path);
    const local = Buffer.alloc(30);
    const central = Buffer.alloc(46);
    const flags = 0x800 | (descriptor ? 8 : 0) | (encrypted ? 1 : 0);
    const method = store ? 0 : 8;
    function metadata(header, at) {
      header.writeUInt32LE((crc32(payload) ^ (badCrc ? 1 : 0)) >>> 0, at);
      header.writeUInt32LE(compressed.length, at + 4);
      header.writeUInt32LE(declaredSize ?? payload.length, at + 8);
    }
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    if (!descriptor) metadata(local, 14);
    local.writeUInt16LE(name.length, 26);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    metadata(central, 16);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(position, 42);
    const trailer = Buffer.alloc(descriptor ? 16 : 0);
    if (descriptor) {
      trailer.writeUInt32LE(0x08074b50);
      metadata(trailer, 4);
    }
    files.push(local, name, compressed, trailer);
    directory.push(central, name);
    position += local.length + name.length + compressed.length + trailer.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(parts.length, 8);
  end.writeUInt16LE(parts.length, 10);
  end.writeUInt32LE(Buffer.concat(directory).length, 12);
  end.writeUInt32LE(position, 16);
  const commentBytes = Buffer.from(comment);
  end.writeUInt16LE(commentBytes.length, 20);
  return Buffer.concat([...files, ...directory, end, commentBytes]);
}

export function officeFile(format, parts, zipOptions) {
  const [path, contentType] = packages[format];
  const types = `<Types xmlns="${namespace}package/2006/content-types"><Override PartName="/${path}" ContentType="${contentType}"/></Types>`;
  return zipParts([['[Content_Types].xml', types], ...parts], zipOptions);
}

export const textXml = {
  word: (fragment) => `<w:document xmlns:w="${namespace}wordprocessingml/2006/main"><w:body>${fragment}</w:body></w:document>`,
  header: (fragment) => `<w:hdr xmlns:w="${namespace}wordprocessingml/2006/main">${fragment}</w:hdr>`,
  workbook: `<workbook xmlns="${namespace}spreadsheetml/2006/main"/>`,
  sheet: (fragment) => `<worksheet xmlns="${namespace}spreadsheetml/2006/main"><sheetData><row>${fragment}</row></sheetData></worksheet>`,
  strings: (fragment) => `<sst xmlns="${namespace}spreadsheetml/2006/main">${fragment}</sst>`,
  presentation: `<p:presentation xmlns:p="${namespace}presentationml/2006/main"/>`,
  slide: (fragment) => `<p:sld xmlns:p="${namespace}presentationml/2006/main" xmlns:a="${namespace}drawingml/2006/main"><p:cSld>${fragment}</p:cSld></p:sld>`,
  notes: (fragment) => `<p:notes xmlns:p="${namespace}presentationml/2006/main" xmlns:a="${namespace}drawingml/2006/main"><p:cSld>${fragment}</p:cSld></p:notes>`,
};

export function officeSamples(marker, pat, key) {
  return {
    docx: officeFile('docx', [['word/document.xml', textXml.word(
      `<w:p><w:r><w:t>${marker.slice(0, 6)}</w:t></w:r><w:r><w:t>${marker.slice(6)}</w:t></w:r></w:p>`)]], { descriptor: true }),
    xlsx: officeFile('xlsx', [['xl/workbook.xml', textXml.workbook],
      ['xl/sharedStrings.xml', textXml.strings(`<si><r><t>${pat.slice(0, 4)}</t></r><r><t>${pat.slice(4)}</t></r></si>`)],
      ['xl/worksheets/sheet1.xml', textXml.sheet('<c t="s"><v>0</v></c>')]]),
    pptx: officeFile('pptx', [['ppt/presentation.xml', textXml.presentation],
      ['ppt/slides/slide1.xml', { text: textXml.slide(`<a:p>${key.split('\n').map((line) =>
        `<a:r><a:t>${line}</a:t></a:r>`).join('<a:br/>')}</a:p>`), store: true }]]),
  };
}
