import type { OfficeArchive, OfficeReadBudget } from './office-zip';

export function isElement(element: Element | null | undefined, names: readonly string[], namespaces: readonly string[]): element is Element {
  return !!element && names.includes(element.localName) && namespaces.includes(element.namespaceURI ?? '');
}

export async function readOfficeXml(archive: OfficeArchive, budget: OfficeReadBudget, name: string) {
  try {
    const bytes = await archive.read(name, budget);
    if (!bytes) return;
    const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le'
      : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : 'utf-8';
    const text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    // Keep all XML detached and reject document type declarations before parsing.
    if (/<!DOCTYPE/i.test(text)) return;
    const xml = new DOMParser().parseFromString(text, 'application/xml');
    if (xml.getElementsByTagName('parsererror').length === 0) return xml.documentElement;
  } catch {
    // Other supported parts may still supply text when this part is unreadable.
  }
}
