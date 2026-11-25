export const classificationTermLimit = 16;
export const classificationTermHint = 'Enter up to 16 labels or phrases, one per line, each 3 to 64 characters. ' +
  'For example, CONFIDENTIAL – INTERNAL or Project Bluebird. Matching ignores case and requires whole words.';
export const classificationTermError = 'Use up to 16 distinct labels or phrases of 3 to 64 characters with at least 3 letters or digits. ' +
  'Use letters, digits, spaces, and - – — _ . & / : \' only.';

const allowed = /^[A-Za-z0-9 \-–—_.&/:']+$/;
const dashes = /[-–—]/;
const word = /[A-Za-z0-9]/;

// Admins see and edit the same canonical text that Control stores and Browser compiles.
export function normalizeClassificationTerm(value: string) {
  return value.trim().replace(/[ \t]+/g, ' ');
}

function validTerm(term: string) {
  return term.length >= 3 && term.length <= 64 && allowed.test(term) && (term.match(/[A-Za-z0-9]/g)?.length ?? 0) >= 3;
}

export function readClassificationTerms(input: unknown): string[] | undefined {
  if (!Array.isArray(input) || input.length > classificationTermLimit) return;
  const terms = new Map<string, string>();
  for (const value of input) {
    if (typeof value !== 'string') return;
    const term = normalizeClassificationTerm(value);
    const key = term.toUpperCase();
    if (!validTerm(term) || terms.has(key)) return;
    terms.set(key, term);
  }
  return [...terms.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([, term]) => term);
}

export function parseClassificationTerms(input: string) {
  return readClassificationTerms(input.split(/\r?\n/).filter((line) => line.trim()));
}

export function sameClassificationTerms(left: readonly string[], right: readonly string[]) {
  return left.length === right.length && left.every((term, index) => right[index] === term);
}

const boundary = '[\\p{L}\\p{N}\\p{M}\\p{Pc}]';
const compiled = new WeakMap<readonly string[], RegExp>();

function termSource(term: string) {
  let source = '';
  for (let index = 0; index < term.length; index++) {
    const character = term[index];
    if (dashes.test(character)) {
      source = source.replace(/\\s\+$/, '') + '\\s*\\p{Pd}\\s*';
      while (term[index + 1] === ' ') index++;
    } else if (character === ' ') {
      if (!source.endsWith('\\s*')) source += '\\s+';
    } else {
      source += character.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    }
  }
  const start = word.test(term[0]) ? `(?<!${boundary})` : '';
  const end = word.test(term[term.length - 1]) ? `(?!${boundary})` : '';
  return start + source + end;
}

function classificationPattern(terms: readonly string[]) {
  if (!terms.length) return;
  let pattern = compiled.get(terms);
  if (!pattern) {
    pattern = new RegExp(terms.map(termSource).join('|'), 'giu');
    compiled.set(terms, pattern);
  }
  return pattern;
}

export function containsClassificationTerm(text: string, terms: readonly string[]) {
  const pattern = classificationPattern(terms);
  if (!pattern) return false;
  pattern.lastIndex = 0;
  return pattern.test(text);
}

export function redactClassificationTerms(text: string, terms: readonly string[], replacement: string) {
  const pattern = classificationPattern(terms);
  return pattern ? text.replace(pattern, replacement) : text;
}
