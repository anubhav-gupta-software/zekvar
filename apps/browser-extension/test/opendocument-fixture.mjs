import { zipParts } from './office-fixture.mjs';

const odf = 'urn:oasis:names:tc:opendocument:xmlns:';
const namespaces = ['office', 'text', 'table', 'drawing', 'presentation', 'style']
  .map((name) => `xmlns:${name}="${odf}${name}:1.0"`).join(' ');
const manifestNs = odf + 'manifest:1.0';
const formats = { odt: 'text', ods: 'spreadsheet', odp: 'presentation' };
export const odfXml = {
  body: (format, body, before = '') => `<office:document-content ${namespaces}
    xmlns:xlink="http://www.w3.org/1999/xlink">${before}<office:body><office:${formats[format]}>${body}</office:${formats[format]}></office:body></office:document-content>`,
  styles: (body) => `<office:document-styles ${namespaces}><office:master-styles>${body}</office:master-styles></office:document-styles>`,
};

export function openDocumentFile(format, content, { extra = [], mediaEntries = {}, encrypted = [], manifestExtra = '' } = {}) {
  const media = 'application/vnd.oasis.opendocument.' + formats[format];
  const entries = { '/': media, 'content.xml': 'text/xml',
    ...Object.fromEntries(extra.map(([name]) => [name, name.endsWith('.xml') ? 'text/xml' : ''])), ...mediaEntries };
  const manifest = Object.entries(entries).map(([path, type]) => `<manifest:file-entry manifest:full-path="${path}"
    manifest:media-type="${type}">${encrypted.includes(path) ? '<manifest:encryption-data/>' : ''}</manifest:file-entry>`).join('');
  return zipParts([['mimetype', { text: media, store: true }],
    ['META-INF/manifest.xml', `<manifest:manifest xmlns:manifest="${manifestNs}">${manifest}${manifestExtra}</manifest:manifest>`],
    ['content.xml', content], ...extra]);
}

export function openDocumentSamples(marker, pat, key) {
  return {
    odt: openDocumentFile('odt', odfXml.body('odt', `<text:p><text:span>${marker.slice(0, 7)}</text:span>${marker.slice(7)}</text:p>`)),
    ods: openDocumentFile('ods', odfXml.body('ods', `<table:table><table:table-row><table:table-cell office:value-type="string"
      office:string-value="${pat}"><text:p>Synthetic credential field</text:p></table:table-cell></table:table-row></table:table>`)),
    odp: openDocumentFile('odp', odfXml.body('odp', `<drawing:page><presentation:notes><drawing:frame><drawing:text-box>
      <text:p>${key.split('\n').join('<text:line-break/>')}</text:p>
      </drawing:text-box></drawing:frame></presentation:notes></drawing:page>`)),
  };
}
