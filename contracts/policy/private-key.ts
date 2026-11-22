const privateKeyStart = /-----BEGIN ((?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----/g;
const lineBreaks = /\r\n|\r|\\r\\n|\\n/g;
const legacyEncryption = /^Proc-Type:[\t ]*4,ENCRYPTED[\t ]*\n[\t ]*DEK-Info:[\t ]*[A-Z0-9-]+,[A-Fa-f0-9]+[\t ]*\n/;

function* privateKeyRanges(text: string) {
  for (const start of text.matchAll(privateKeyStart)) {
    const bodyAt = start.index + start[0].length;
    const footer = `-----END ${start[1]}-----`;
    const footerAt = text.indexOf('-----', bodyAt);
    if (footerAt < 0 || !text.startsWith(footer, footerAt)) continue;
    const body = text.slice(bodyAt, footerAt).replace(lineBreaks, '\n');
    if (!/^[\t ]*\n/.test(body) || !/\n[\t ]*$/.test(body)) continue;
    const payload = body.trim().replace(legacyEncryption, '').replace(/[\t \n]/g, '');
    if (payload.length >= 32 && payload.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(payload)) {
      yield { start: start.index, end: footerAt + footer.length };
    }
  }
}

export function containsPrivateKey(text: string) {
  return !privateKeyRanges(text).next().done;
}

export function redactPrivateKeys(text: string, replacement: string) {
  let end = 0;
  const redacted: string[] = [];
  for (const range of privateKeyRanges(text)) {
    redacted.push(text.slice(end, range.start), replacement);
    end = range.end;
  }
  return end ? redacted.join('') + text.slice(end) : text;
}
