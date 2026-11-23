// SSA omits these area, group, and serial ranges from assignment.
function possibleSsn(value: string) {
  const digits = value.replace(/[- ]/g, '');
  const area = Number(digits.slice(0, 3));
  return area !== 0 && area !== 666 && area < 900 && digits.slice(3, 5) !== '00' && digits.slice(5) !== '0000';
}

// Standalone hyphenated values have a distinctive shape. Compact and spaced values require a label.
const hyphenated = /(?<![\p{L}\p{N}\p{M}\p{Pc}]|[\p{L}\p{N}]-)[0-9]{3}-[0-9]{2}-[0-9]{4}(?![\p{L}\p{N}\p{M}\p{Pc}]|-[\p{L}\p{N}])/gu;
const labeled = /(?<![\p{L}\p{N}\p{M}\p{Pc}])((?:SSN|Social[ \t]{1,8}Security[ \t]{1,8}(?:number|no\.?|#))(?:["']?[ \t]{0,12}[:=][ \t]{0,12}|[ \t]{1,12})["']?)([0-9]{3} [0-9]{2} [0-9]{4}|[0-9]{9})(?![\p{L}\p{N}\p{M}\p{Pc}]|-[\p{L}\p{N}])/giu;

export function containsSsn(text: string) {
  for (const [value] of text.matchAll(hyphenated)) {
    if (possibleSsn(value)) return true;
  }
  for (const [, , value] of text.matchAll(labeled)) {
    if (possibleSsn(value)) return true;
  }
  return false;
}

export function redactSsns(text: string, replacement: string) {
  return text.replace(hyphenated, (value) => possibleSsn(value) ? replacement : value)
    .replace(labeled, (match, label: string, value: string) => possibleSsn(value) ? label + replacement : match);
}
