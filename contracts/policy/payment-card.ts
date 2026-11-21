// Accept whole numeric tokens. A longer sequence joined by card separators is ambiguous.
const word = '[\\p{L}\\p{M}\\p{N}_]';
const separator = '[ \\u00a0\\u202f-]';
const plain = '(?<![0-9]-)[0-9]{13,19}(?!-[0-9])';
const grouped = `(?<![0-9]${separator})[0-9]{4}(?<separator>${separator})` +
  '(?:[0-9]{6}\\k<separator>[0-9]{4,5}|[0-9]{4}\\k<separator>[0-9]{4}\\k<separator>' +
  '(?:[0-9]{4}\\k<separator>[0-9]{1,3}|[0-9]{1,4}))' +
  `(?!${separator}[0-9])`;
const candidates = new RegExp(`(?<!${word})(?:${plain}|${grouped})(?!${word})`, 'gu');

const cardShapes: { lengths: number[]; ranges: [number, number][] }[] = [
  { lengths: [13, 16, 19], ranges: [[400000, 499999]] }, // Visa
  { lengths: [16], ranges: [[510000, 559999], [222100, 272099]] }, // Mastercard
  { lengths: [15], ranges: [[340000, 349999], [370000, 379999]] }, // American Express
  { lengths: [16], ranges: [[601100, 601199], [644000, 659999]] }, // Discover
  { lengths: [16, 17, 18, 19], ranges: [[352800, 358999]] }, // JCB
  { lengths: [14], ranges: [[300000, 305999], [309500, 309599], [360000, 369999], [380000, 399999]] }, // Diners Club
];

function isPossibleCard(candidate: string): boolean {
  const digits = candidate.replace(/[^0-9]/g, '');
  const prefix = Number(digits.slice(0, 6));
  if (!cardShapes.some(({ lengths, ranges }) => lengths.includes(digits.length) &&
      ranges.some(([first, last]) => prefix >= first && prefix <= last))) return false;

  let sum = 0;
  for (let index = digits.length - 1; index >= 0; index--) {
    const digit = digits.charCodeAt(index) - 48;
    const value = (digits.length - 1 - index) % 2 === 1 ? digit * 2 : digit;
    sum += value > 9 ? value - 9 : value;
  }
  return sum % 10 === 0;
}

export function containsPaymentCard(prompt: string): boolean {
  for (const [candidate] of prompt.matchAll(candidates)) {
    if (isPossibleCard(candidate)) return true;
  }
  return false;
}

export function redactPaymentCards(prompt: string, placeholder: string): string {
  return prompt.replaceAll(candidates, (candidate) => isPossibleCard(candidate) ? placeholder : candidate);
}
