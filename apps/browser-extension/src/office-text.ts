import { openOfficeZip, type OfficeReadBudget } from './office-zip';
import { isElement, readOfficeXml } from './office-xml';
import { readOpenDocumentText } from './opendocument-text';

const transitional = 'http://schemas.openxmlformats.org/';
const strict = 'http://purl.oclc.org/ooxml/';
const word = [transitional + 'wordprocessingml/2006/main', strict + 'wordprocessingml/main'];
const sheet = [transitional + 'spreadsheetml/2006/main', strict + 'spreadsheetml/main'];
const presentation = [transitional + 'presentationml/2006/main', strict + 'presentationml/main'];
const drawing = [transitional + 'drawingml/2006/main', strict + 'drawingml/main'];
const packageTypes = transitional + 'package/2006/content-types';

const documentPart = 'word/document.xml';
const sharedStringsPart = 'xl/sharedStrings.xml';
const workbookPart = 'xl/workbook.xml';
const presentationPart = 'ppt/presentation.xml';
const mainParts: Readonly<Record<string, string>> = {
  [documentPart]: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
  [workbookPart]: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml',
  [presentationPart]: 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml',
};

function pickMainPart(types: Element, names: readonly string[]) {
  if (!isElement(types, ['Types'], [packageTypes])) return;
  const parts = Array.from(types.children).filter((part) => isElement(part, ['Override'], [packageTypes])).flatMap((part) => {
    const name = part.getAttribute('PartName')?.slice(1);
    return name && Object.hasOwn(mainParts, name) && names.includes(name) &&
      part.getAttribute('PartName') === '/' + name && part.getAttribute('ContentType') === mainParts[name] ? [name] : [];
  });
  if (parts.length === 1) return parts[0];
}

function ownText(element: Element) {
  return Array.from(element.childNodes, (child) =>
    child.nodeType === Node.TEXT_NODE || child.nodeType === Node.CDATA_SECTION_NODE ? child.nodeValue ?? '' : '').join('');
}

function paragraphText(root: Element, namespaces: readonly string[]) {
  const walker = root.ownerDocument.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
  const text: string[] = [];
  while (walker.nextNode()) {
    const element = walker.currentNode as Element;
    if (!namespaces.includes(element.namespaceURI ?? '')) continue;
    if (element.localName === 't') text.push(ownText(element));
    if (['p', 'br', 'cr'].includes(element.localName)) text.push('\n');
    if (element.localName === 'tab') text.push('\t');
  }
  return text.join('');
}

function excelText(value: string) {
  return value.replace(/_x([a-f0-9]{4})_/gi, (_, code: string) => String.fromCharCode(Number.parseInt(code, 16)));
}

function richCellText(node: Element) {
  const namespace = node.namespaceURI;
  const segments = Array.from(node.children).flatMap((child) =>
    child.namespaceURI === namespace && child.localName === 'r' ? Array.from(child.children) : [child]);
  return excelText(segments.filter((child) => child.namespaceURI === namespace && child.localName === 't').map(ownText).join(''));
}

function worksheetText(root: Element, shared: readonly string[]) {
  const text: string[] = [];
  let remaining = 256 * 1024;
  let complete = true;
  const cells = root.getElementsByTagNameNS(root.namespaceURI, 'c');
  for (let index = 0; index < cells.length; index++) {
    const cell = cells[index];
    const format = cell.getAttribute('t') ?? 'n';
    const value = Array.from(cell.children).find((child) =>
      child.namespaceURI === root.namespaceURI && child.localName === (format === 'inlineStr' ? 'is' : 'v'));
    if (!value) continue;
    const raw = ownText(value);
    const content = format === 's' && /^\d+$/.test(raw) ? shared[Number(raw)]
      : format === 'inlineStr' ? richCellText(value)
        : format === 'n' || format === 'str' ? excelText(raw) : undefined;
    if (format === 's' && content === undefined) complete = false;
    if (!content) continue;
    if (content.length >= remaining) return { text: text.join('\n'), complete: false };
    remaining -= content.length + 1;
    text.push(content);
  }
  return { text: text.join('\n'), complete };
}

export async function* readOfficeText(bytes: Uint8Array<ArrayBuffer>, budget: OfficeReadBudget): AsyncGenerator<string, boolean> {
  const archive = openOfficeZip(bytes);
  if (!archive) return false;
  const { names } = archive;
  if (names.includes('mimetype')) {
    if (names.includes('[Content_Types].xml')) return false;
    return yield* readOpenDocumentText(archive, budget);
  }
  const readPart = (name: string) => readOfficeXml(archive, budget, name);
  const types = await readPart('[Content_Types].xml');
  const main = types && pickMainPart(types, names);
  if (!main) return false;

  let complete = !names.some((name) => /^(?:word|xl|ppt)\/embeddings\/.+/.test(name));
  const root = await readPart(main);
  if (main === documentPart && isElement(root, ['document'], word)) {
    yield paragraphText(root, [...word, ...drawing]);
    const parts = names.filter((name) => /^word\/(?:header\d+|footer\d+|footnotes|endnotes)\.xml$/.test(name)).sort();
    for (const part of parts) {
      const xml = await readPart(part);
      if (isElement(xml, ['hdr', 'ftr', 'footnotes', 'endnotes'], word)) yield paragraphText(xml, [...word, ...drawing]);
      else complete = false;
    }
  } else if (main === workbookPart && isElement(root, ['workbook'], sheet)) {
    const strings = await readPart(sharedStringsPart);
    const shared = isElement(strings, ['sst'], sheet)
      ? Array.from(strings.children).filter((node) => isElement(node, ['si'], sheet)).map(richCellText) : [];
    if (names.includes(sharedStringsPart) && !isElement(strings, ['sst'], sheet)) complete = false;
    const parts = names.filter((name) => /^xl\/worksheets\/sheet\d+\.xml$/.test(name)).sort();
    for (const part of parts) {
      const xml = await readPart(part);
      if (!isElement(xml, ['worksheet'], sheet)) {
        complete = false;
        continue;
      }
      const worksheet = worksheetText(xml, shared);
      complete &&= worksheet.complete;
      yield worksheet.text;
    }
  } else if (main === presentationPart && isElement(root, ['presentation'], presentation)) {
    const parts = names.filter((name) => /^ppt\/(?:slides\/slide|notesSlides\/notesSlide)\d+\.xml$/.test(name)).sort();
    for (const part of parts) {
      const xml = await readPart(part);
      if (isElement(xml, ['sld', 'notes'], presentation)) yield paragraphText(xml, drawing);
      else complete = false;
    }
  } else return false;
  return complete;
}
