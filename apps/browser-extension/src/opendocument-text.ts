import { isElement, readOfficeXml } from './office-xml';
import type { OfficeArchive, OfficeReadBudget } from './office-zip';

const odf = 'urn:oasis:names:tc:opendocument:xmlns:';
const office = odf + 'office:1.0';
const textNs = odf + 'text:1.0';
const table = odf + 'table:1.0';
const drawing = odf + 'drawing:1.0';
const manifest = odf + 'manifest:1.0';
const xlink = 'http://www.w3.org/1999/xlink';
const configurationPath = 'Configurations2/';
const configurationMedia = 'application/vnd.sun.xml.ui.configuration';
const mediaPrefix = 'application/vnd.oasis.opendocument.';
const formats = ['text', 'spreadsheet', 'presentation'];
const manifestPath = 'META-INF/manifest.xml';
const contentPath = 'content.xml';
const stylesPath = 'styles.xml';
const ignoredParts = new Set(['meta.xml', 'settings.xml', 'manifest.rdf', 'Thumbnails/thumbnail.png',
  'META-INF/documentsignatures.xml', 'META-INF/macrosignatures.xml']);
const imageTypes = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/tiff', 'image/bmp', 'image/webp']);
const unsafeDrawing = ['object', 'object-ole', 'applet', 'plugin', 'floating-frame'];
const maxText = 256 * 1024;

type Entry = { media: string; encrypted: boolean };

function manifestEntries(root: Element) {
  const entries = new Map<string, Entry>();
  for (const node of root.children) {
    if (!isElement(node, ['file-entry'], [manifest])) return;
    const path = node.getAttributeNS(manifest, 'full-path');
    if (!path || entries.has(path)) return;
    entries.set(path, { media: node.getAttributeNS(manifest, 'media-type') ?? '',
      encrypted: node.getElementsByTagNameNS(manifest, 'encryption-data').length !== 0 });
  }
  return entries;
}

function regularImage(path: string, entry: Entry | undefined) {
  return path.startsWith('Pictures/') && entry && imageTypes.has(entry.media) && !entry.encrypted;
}

function paragraph(node: Node) {
  return node instanceof Element && isElement(node, ['p', 'h'], [textNs]);
}

function extract(root: Element, imagePaths: ReadonlySet<string>) {
  const paragraphs: string[] = [];
  const cells: string[] = [];
  let remaining = maxText;
  let complete = true;
  let depth = 0;
  function append(target: string[], value: string) {
    if (!value) return;
    if (value.length > remaining) {
      complete = false;
      remaining = 0;
      return;
    }
    target.push(value);
    remaining -= value.length;
  }

  // Visit descendants without recursion. Paragraph boundaries keep independent runs and cells separate.
  let node: Node | null = root.firstChild;
  while (node && remaining > 0) {
    if (paragraph(node)) {
      if (depth > 0) append(paragraphs, '\n');
      depth++;
    } else if (node instanceof Element) {
      if (isElement(node, unsafeDrawing, [drawing]) ||
          isElement(node, ['binary-data'], [office]) ||
          isElement(node, ['section-source'], [textNs]) ||
          isElement(node, ['table-source', 'cell-range-source', 'dde-link'], [table])) complete = false;
      if (isElement(node, ['image'], [drawing])) {
        const href = node.getAttributeNS(xlink, 'href')?.replace(/^\.\//, '');
        if (!href || !imagePaths.has(href)) complete = false;
      }
      if (isElement(node, ['table-cell'], [table])) {
        const value = node.getAttributeNS(office, 'string-value') ?? node.getAttributeNS(office, 'value');
        if (value) append(cells, value + '\n');
      }
      if (depth > 0 && isElement(node, ['s', 'tab', 'line-break'], [textNs])) {
        const spacing = node.getAttributeNS(textNs, 'c') ?? '1';
        if (node.localName === 's') {
          const count = Number(spacing);
          if (/^[1-9]\d*$/.test(spacing) && count <= remaining) append(paragraphs, ' '.repeat(count));
          else {
            complete = false;
            append(paragraphs, '\n');
          }
        } else append(paragraphs, node.localName === 'tab' ? '\t' : '\n');
      }
    } else if (depth > 0 && (node.nodeType === Node.TEXT_NODE || node.nodeType === Node.CDATA_SECTION_NODE)) {
      append(paragraphs, node.nodeValue ?? '');
    }

    if (node.firstChild) {
      node = node.firstChild;
      continue;
    }
    while (node && node !== root) {
      if (paragraph(node)) {
        append(paragraphs, '\n');
        depth--;
      }
      if (node.nextSibling) {
        node = node.nextSibling;
        break;
      }
      node = node.parentNode;
    }
    if (node === root) node = null;
  }
  return { paragraphs: paragraphs.join(''), cells: cells.join(''), complete: complete && !node };
}

export async function* readOpenDocumentText(archive: OfficeArchive, budget: OfficeReadBudget): AsyncGenerator<string, boolean> {
  const mime = await archive.read('mimetype', budget, { firstStored: true });
  const media = mime && new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(mime);
  const format = formats.find((value) => media === mediaPrefix + value);
  if (!format) return false;
  const root = await readOfficeXml(archive, budget, manifestPath);
  if (!isElement(root, ['manifest'], [manifest])) return false;
  const entries = manifestEntries(root);
  if (!entries || entries.get('/')?.media !== media || entries.get(contentPath)?.media !== 'text/xml') return false;

  const names = new Set(archive.names);
  const imagePaths = new Set<string>();
  let complete = true;
  for (const [path, entry] of entries) {
    const standardDirectory = path === '/' || !entry.media ||
      path === configurationPath && entry.media === configurationMedia;
    if (entry.encrypted || (path.endsWith('/') ? !standardDirectory : !names.has(path))) complete = false;
  }
  for (const name of names) {
    if (regularImage(name, entries.get(name))) imagePaths.add(name);
    else if (!name.endsWith('/') && !['mimetype', manifestPath, contentPath, stylesPath].includes(name) &&
        !ignoredParts.has(name) && !/^Configurations2\/[\w./-]+$/.test(name)) complete = false;
  }

  const content = !entries.get(contentPath)?.encrypted && await readOfficeXml(archive, budget, contentPath);
  const body = content && isElement(content, ['document-content'], [office]) &&
    Array.from(content.children).filter((child) => isElement(child, ['body'], [office]));
  if (!body || body.length !== 1 || body[0].childElementCount !== 1 ||
      !isElement(body[0].firstElementChild, [format], [office])) return false;
  if (content && Array.from(content.getElementsByTagNameNS(office, 'scripts')).some((node) => node.childElementCount)) complete = false;
  const main = extract(body[0], imagePaths);
  yield main.paragraphs;
  if (main.cells) yield main.cells;
  complete &&= main.complete;

  if (names.has(stylesPath)) {
    const style = entries.get(stylesPath);
    const styles = style?.media === 'text/xml' && !style.encrypted && await readOfficeXml(archive, budget, stylesPath);
    if (!styles || !isElement(styles, ['document-styles'], [office])) return false;
    const supplemental = extract(styles, imagePaths);
    yield supplemental.paragraphs;
    if (supplemental.cells) yield supplemental.cells;
    complete &&= supplemental.complete;
  }
  return complete;
}
