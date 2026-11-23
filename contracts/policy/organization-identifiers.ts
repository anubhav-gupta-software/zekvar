export type IdentifierFormat = { prefix: string; digits: number };

const prefixPattern = /^[A-Za-z][A-Za-z0-9]{1,14}[-_]$/;
export const identifierFormatHint = 'Enter up to 16 formats, one per line. For example, CUST- 8 matches CUST- followed by eight digits.';
export const identifierFormatError = 'Use distinct prefixes of 3 to 16 ASCII characters ending in - or _, followed by a length from 4 to 12 digits.';

export function readIdentifierFormats(input: unknown): IdentifierFormat[] | undefined {
  if (!Array.isArray(input) || input.length > 16) return;
  const formats = new Map<string, IdentifierFormat>();
  for (const format of input) {
    if (!format || typeof format !== 'object' || Object.keys(format).length !== 2 ||
        typeof format.prefix !== 'string' || !prefixPattern.test(format.prefix.trim()) ||
        !Number.isInteger(format.digits) || format.digits < 4 || format.digits > 12) return;
    const prefix = format.prefix.trim().toUpperCase();
    if (formats.has(prefix)) return;
    formats.set(prefix, { prefix, digits: format.digits });
  }
  return [...formats.values()].sort((left, right) => left.prefix < right.prefix ? -1 : 1);
}

export function parseIdentifierFormats(input: string) {
  const values = [];
  for (const line of input.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = /^([A-Za-z0-9_-]+)[ \t]+(\d{1,2})$/.exec(line.trim());
    if (!parts) return;
    values.push({ prefix: parts[1], digits: Number(parts[2]) });
  }
  return readIdentifierFormats(values);
}

export function sameIdentifierFormats(left: readonly IdentifierFormat[], right: readonly IdentifierFormat[]) {
  return left.length === right.length && left.every(({ prefix, digits }, index) =>
    right[index].prefix === prefix && right[index].digits === digits);
}

const tokenCharacter = '[\\p{L}\\p{M}\\p{N}\\p{Pc}\\p{Pd}]';
const compiled = new WeakMap<readonly IdentifierFormat[], { single: RegExp; all: RegExp }>();

function identifierPatterns(formats: readonly IdentifierFormat[]) {
  if (!formats.length) return;
  const previous = compiled.get(formats);
  if (previous) return previous;
  const alternatives = formats.map(({ prefix, digits }) =>
    prefix.replace(/[A-Z]/g, (letter) => `[${letter}${letter.toLowerCase()}]`) + `[0-9]{${digits}}`);
  const expression = `(?<!${tokenCharacter})(?:${alternatives.join('|')})(?!${tokenCharacter})`;
  const patterns = { single: new RegExp(expression, 'u'), all: new RegExp(expression, 'gu') };
  compiled.set(formats, patterns);
  return patterns;
}

export function containsIdentifier(text: string, formats: readonly IdentifierFormat[]) {
  return identifierPatterns(formats)?.single.test(text) ?? false;
}

export function redactIdentifiers(text: string, formats: readonly IdentifierFormat[], placeholder: string) {
  const patterns = identifierPatterns(formats);
  return patterns ? text.replaceAll(patterns.all, placeholder) : text;
}
