import { containsIdentifier, readIdentifierFormats, redactIdentifiers, sameIdentifierFormats, type IdentifierFormat } from './organization-identifiers';

// Structural checks only. Zekvar never looks up a provider, registrant, or beneficiary.
export const npiRule = 'us-national-provider-identifier';
export const deaRule = 'dea-registration-number';
export const mbiRule = 'medicare-beneficiary-identifier';
export const medicalRecordRule = 'medical-record-number';
export const healthDetector = 'health';
export const healthRules = [npiRule, deaRule, mbiRule, medicalRecordRule] as const;
export type HealthRule = typeof healthRules[number];
export const healthLabels: Record<HealthRule, string> = {
  [npiRule]: 'U.S. National Provider Identifier',
  [deaRule]: 'DEA registration number',
  [mbiRule]: 'Medicare Beneficiary Identifier',
  [medicalRecordRule]: 'Medical record number',
};

const word = '[\\p{L}\\p{N}\\p{M}\\p{Pc}]';
const valueEnd = `(?!${word}|-[\\p{L}\\p{N}])`;
// A label, an optional "number" suffix, then up to 24 non-digit characters on the same line, such as ": ", " is ", or " for Dr. Roe: ".
const window = '[^\\p{N}\\r\\n]{0,24}?';
const suffix = '(?:[ \\t]{1,4}(?:number|no\\.?|#))?';

// NPI: ten digits that start with 1 or 2 and pass Luhn over the 80840 health industry prefix (CMS NPI check digit).
// Roughly one random 10-digit number in ten passes the check, so phone numbers and order numbers would collide.
// The rule requires an NPI label before the value.
const npiLabel = `(?<!${word})((?:NPI|National[ \\t]{1,4}Provider[ \\t]{1,4}(?:Identifier|ID))${suffix}${window})`;
const npiPattern = new RegExp(`${npiLabel}(?<!\\p{N})([12][0-9]{9})${valueEnd}`, 'giu');

// DEA: two letters and seven digits. The first letter is a registrant type, and the seventh digit is the checksum
// (d1 + d3 + d5 + 2 × (d2 + d4 + d6)) mod 10. Purchase orders and SKUs share this shape and pass the checksum one time in ten,
// so the rule requires a DEA label before the value.
const deaLabel = `(?<!${word})(DEA${'(?:[ \\t]{1,4}registration)?'}${suffix}${window})`;
const deaPattern = new RegExp(`${deaLabel}(?<!${word})([ABCDEFGHJKLMPRSTUX][A-Z][0-9]{7})${valueEnd}`, 'giu');

// MBI: CMS fixes the character class of each of the 11 positions and excludes S, L, O, I, B, and Z.
// The shape is distinctive, so no label is required. Dashes may separate positions 4|5 and 7|8 as printed on cards.
const letter = '[ACDEFGHJKMNPQRTUVWXY]';
const alnum = '[0-9ACDEFGHJKMNPQRTUVWXY]';
const mbiSource = `[1-9]${letter}${alnum}[0-9](-?)${letter}${alnum}[0-9]\\1${letter}${letter}[0-9]{2}`;
const mbiPattern = new RegExp(`(?<!${word}|[\\p{L}\\p{N}]-)${mbiSource}${valueEnd}`, 'gu');
// CMS publishes this sample MBI in its format guidance. It is documentation, not a beneficiary.
const mbiDocumentationSample = '1EG4' + 'TE5' + 'MK73';

function deaChecksum(value: string) {
  const d = value.slice(2).split('').map(Number);
  return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 === d[6];
}

function npiChecksum(value: string) {
  const digits = '80840' + value;
  let sum = 0;
  for (let index = 0; index < digits.length; index++) {
    let digit = digits.charCodeAt(digits.length - 1 - index) - 48;
    if (index % 2 === 1) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
  }
  return sum % 10 === 0;
}

function possibleMbi(value: string) {
  return value.replaceAll('-', '') !== mbiDocumentationSample;
}

// Medical record numbers have no national format. Organizations configure prefix-and-digit formats with the same
// validation as organization identifiers. A configured format matches as a prefixed token, such as MRN-00123456, and a value
// with exactly the configured digit count matches after an MRN or medical record label, such as "MRN: 00123456".
export type HealthProtection = { mode: 'off' | 'monitor' | 'warn' | 'block'; recordFormats: IdentifierFormat[] };
const recordLabel = `(?<!${word})((?:MRN|MR[ \\t]?#|Medical[ \\t]{1,4}record${suffix})${'(?:["\']?[ \\t]{0,12}[:=#][ \\t]{0,12}|[ \\t]{1,12})["\']?'})`;
const recordPatterns = new WeakMap<readonly IdentifierFormat[], RegExp>();

function labeledRecordPattern(formats: readonly IdentifierFormat[]) {
  let pattern = recordPatterns.get(formats);
  if (!pattern) {
    const lengths = [...new Set(formats.map(({ digits }) => digits))].sort((left, right) => right - left);
    pattern = new RegExp(`${recordLabel}((?:${lengths.map((length) => `[0-9]{${length}}`).join('|')}))${valueEnd}`, 'giu');
    recordPatterns.set(formats, pattern);
  }
  return pattern;
}

export function readHealthRecordFormats(input: unknown) {
  return readIdentifierFormats(input);
}

export function sameHealthProtection(left?: HealthProtection, right?: HealthProtection) {
  return left?.mode === right?.mode && sameIdentifierFormats(left?.recordFormats ?? [], right?.recordFormats ?? []);
}

function firstMatch(pattern: RegExp, text: string, accept: (match: RegExpMatchArray) => boolean) {
  for (const match of text.matchAll(pattern)) if (accept(match)) return match.index!;
}

// Returns the earliest health identifier in the text so a prompt reports a single rule.
export function findHealthIdentifier(text: string, recordFormats: readonly IdentifierFormat[]): HealthRule | undefined {
  const candidates: [HealthRule, number | undefined][] = [
    [npiRule, firstMatch(npiPattern, text, (match) => npiChecksum(match[2]))],
    [deaRule, firstMatch(deaPattern, text, (match) => deaChecksum(match[2].toUpperCase()))],
    [mbiRule, firstMatch(mbiPattern, text, (match) => possibleMbi(match[0]))],
  ];
  if (recordFormats.length) {
    const labeled = firstMatch(labeledRecordPattern(recordFormats), text, () => true);
    candidates.push([medicalRecordRule, labeled ?? (containsIdentifier(text, recordFormats) ? text.length : undefined)]);
  }
  let found: [HealthRule, number] | undefined;
  for (const [rule, index] of candidates) if (index !== undefined && (!found || index < found[1])) found = [rule, index];
  return found?.[0];
}

export function redactHealthIdentifiers(text: string, recordFormats: readonly IdentifierFormat[], replacement: string) {
  let value = text.replace(npiPattern, (match, label: string, npi: string) => npiChecksum(npi) ? label + replacement : match)
    .replace(deaPattern, (match, label: string, dea: string) => deaChecksum(dea.toUpperCase()) ? label + replacement : match)
    .replace(mbiPattern, (match) => possibleMbi(match) ? replacement : match);
  if (recordFormats.length) {
    value = redactIdentifiers(value.replace(labeledRecordPattern(recordFormats), (_match, label: string) => label + replacement),
      recordFormats, replacement);
  }
  return value;
}
