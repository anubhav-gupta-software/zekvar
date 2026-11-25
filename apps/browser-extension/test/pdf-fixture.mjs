import { deflateSync } from 'node:zlib';

const literal = (text) => '(' + text.replace(/[\\()]/g, '\\$&') + ')';

// Write ordinary PDF page streams and a cross-reference table for controlled tests.
export function pdfFixture(pages, { embedded = false } = {}) {
  const objects = [
    `<< /Type /Catalog /Pages 2 0 R${embedded ? ' /Names << /EmbeddedFiles << /Names [(example.txt) 4 0 R] >> >>' : ''} >>`,
    'pages',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  if (embedded) {
    objects.push('<< /Type /Filespec /F (example.txt) /EF << /F 5 0 R >> >>',
      '<< /Type /EmbeddedFile /Length 14 >>\nstream\nSynthetic note\nendstream');
  }
  const kids = [];
  for (const spec of pages) {
    const { lines = [], image } = Array.isArray(spec) ? { lines: spec } : spec;
    const page = objects.length + 1;
    kids.push(`${page} 0 R`);
    const resource = image ? ` /XObject << /Scan ${page + 2} 0 R >>` : '';
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
      /Resources << /Font << /F1 3 0 R >>${resource} >> /Contents ${page + 1} 0 R >>`);
    const drawImage = image ? [`q 468 0 0 ${Math.min(570, 468 * image.height / image.width)} 72 360 cm /Scan Do Q`] : [];
    const text = [...drawImage, 'BT /F1 12 Tf 14 TL 72 720 Td', ...lines.map((line) =>
      Array.isArray(line) ? `[${line.map(literal).join(' 0 ')}] TJ T*` : `${literal(line)} Tj T*`), 'ET'].join('\n');
    const compressed = deflateSync(Buffer.from(text, 'latin1'));
    objects.push(Buffer.concat([Buffer.from(`<< /Length ${compressed.length} /Filter /FlateDecode >>\nstream\n`),
      compressed, Buffer.from('\nendstream')]));
    if (image) objects.push(Buffer.concat([
      Buffer.from(`<< /Type /XObject /Subtype /Image /Width ${image.width} /Height ${image.height}
        /BitsPerComponent 8 /ColorSpace /DeviceRGB /Filter /DCTDecode /Length ${image.bytes.length} >>\nstream\n`),
      image.bytes, Buffer.from('\nendstream'),
    ]));
  }
  objects[1] = `<< /Type /Pages /Kids [${kids.join(' ')}] /Count ${kids.length} >>`;
  const parts = [Buffer.from('%PDF-1.7\n%\x80\x81\x82\x83\n', 'latin1')];
  const offsets = [];
  let length = parts[0].length;
  for (const [index, object] of objects.entries()) {
    offsets.push(length);
    const bytes = Buffer.concat([Buffer.from(`${index + 1} 0 obj\n`), Buffer.from(object), Buffer.from('\nendobj\n')]);
    parts.push(bytes);
    length += bytes.length;
  }
  parts.push(Buffer.from(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` +
    offsets.map((offset) => `${String(offset).padStart(10, '0')} 00000 n \n`).join('') +
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${length}\n%%EOF\n`));
  return Buffer.concat(parts);
}
