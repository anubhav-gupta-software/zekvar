import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { officeFile, officeSamples, textXml, zipParts } from './office-fixture.mjs';

const marker = 'ZEKVAR_TEST_SECRET';
const pat = `ghp_${'0'.repeat(36)}`;
const key = ['-----BEGIN PRIVATE KEY-----', 'A'.repeat(64), '-----END PRIVATE KEY-----'].join('\n');
const policy = { mode: 'block', githubPatMode: 'warn', paymentCardMode: 'monitor', privateKeyMode: 'block' };
const documentPath = 'word/document.xml';
const paragraph = (value) => `<w:p><w:r><w:t>${value}</w:t></w:r></w:p>`;
const samples = officeSamples(marker, pat, key);
const wordText = textXml.word(paragraph(marker));

test('extracts bounded Office text in Chrome', { timeout: 30_000 }, async (t) => {
  const bundle = await build({ entryPoints: [fileURLToPath(new URL('../src/file-inspection.ts', import.meta.url))],
    bundle: true, format: 'iife', globalName: 'officeInspection', platform: 'browser', write: false });
  const browser = await chromium.launch({ channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const requests = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  async function scan(files, detectorPolicy = policy) {
    return page.evaluate(({ byteStrings, detectorPolicy }) => officeInspection.inspectFiles(byteStrings.map((bytes) =>
      new File([Uint8Array.from(atob(bytes), (character) => character.charCodeAt(0))], 'misleading.png', { type: 'image/png' })),
    detectorPolicy), { byteStrings: files.map((bytes) => Buffer.from(bytes).toString('base64')), detectorPolicy });
  }

  await t.test('recognizes Word, Excel, and PowerPoint by bytes and combines formatted text runs', async () => {
    assert.equal((await scan([samples.docx])).ruleId, 'fixture-secret');
    assert.equal((await scan([samples.xlsx])).ruleId, 'github-classic-pat');
    assert.equal((await scan([samples.pptx])).ruleId, 'pem-private-key');
    assert.equal((await scan(Object.values(samples))).ruleId, 'pem-private-key');
    assert.equal(await scan([samples.xlsx, samples.pptx], { ...policy, githubPatMode: 'off', privateKeyMode: 'off' }), undefined);
  });

  await t.test('reads supplemental Word and PowerPoint text and Excel inline and numeric cells', async () => {
    const strict = wordText.replace('schemas.openxmlformats.org/wordprocessingml/2006/main', 'purl.oclc.org/ooxml/wordprocessingml/main');
    const xmlUtf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(strict, 'utf16le')]);
    assert.equal((await scan([officeFile('docx', [[documentPath, xmlUtf16]], { comment: 'Synthetic package comment' })])).ruleId, 'fixture-secret');
    const header = officeFile('docx', [[documentPath, textXml.word('')], ['word/header1.xml', textXml.header(paragraph(marker))]]);
    assert.equal((await scan([header])).ruleId, 'fixture-secret');
    const notes = officeFile('pptx', [['ppt/presentation.xml', textXml.presentation],
      ['ppt/notesSlides/notesSlide1.xml', textXml.notes(`<a:p><a:r><a:t>${marker}</a:t></a:r></a:p>`)]]);
    assert.equal((await scan([notes])).ruleId, 'fixture-secret');
    const workbook = (cells, extra = []) => officeFile('xlsx', [['xl/workbook.xml', textXml.workbook],
      ['xl/worksheets/sheet2.xml', textXml.sheet(cells)], ...extra]);
    const inline = workbook('<c t="inlineStr"><is><r><t>_x005A_EKVAR_</t></r><r><t>TEST_SECRET</t></r></is></c>');
    assert.equal((await scan([inline])).ruleId, 'fixture-secret');
    assert.equal((await scan([workbook('<c><v>4242424242424242</v></c>')])).ruleId, 'payment-card-number');
    const unused = workbook(`<c><f>${marker}</f><v>7</v></c><c t="s"><v>1</v></c>`,
      [['xl/sharedStrings.xml', textXml.strings(`<si><t>${marker}</t></si><si><t>clean</t></si>`)]]);
    assert.equal(await scan([unused]), undefined);
  });

  await t.test('skips corrupt, encrypted, spoofed, unsupported, and unrelated ZIP or XML parts', async () => {
    const spoofed = zipParts([[documentPath, wordText]]);
    const dtd = officeFile('docx', [[documentPath, `<!DOCTYPE w:document [<!ENTITY xx SYSTEM "https://synthetic.invalid/external">]>${wordText}`]]);
    const malformed = officeFile('docx', [[documentPath, wordText.slice(0, -2)]]);
    const duplicate = officeFile('docx', [[documentPath, wordText], [documentPath, textXml.word('')]]);
    const badCrc = officeFile('docx', [[documentPath, { text: wordText, badCrc: true }]]);
    const encrypted = officeFile('docx', [[documentPath, { text: wordText, encrypted: true }]]);
    const mismatched = Buffer.from(samples.pptx);
    const offset = mismatched.indexOf(Buffer.from('ppt/slides/slide1.xml'));
    mismatched[offset] = 'a'.charCodeAt(0);
    const unrelated = officeFile('docx', [[documentPath, textXml.word('')], ['word/embeddings/nested.docx', samples.docx],
      ['docProps/core.xml', marker], ['word/comments.xml', wordText], ['word/_rels/document.xml.rels', 'https://synthetic.invalid/external']]);
    for (const file of [spoofed, dtd, malformed, duplicate, badCrc, encrypted, mismatched, unrelated, samples.docx.subarray(0, -4)]) {
      assert.equal(await scan([file]), undefined);
    }
    assert.equal((await scan([malformed, samples.xlsx])).ruleId, 'github-classic-pat');
    assert.deepEqual(requests, []);
  });

  await t.test('bounds expanded XML and continues after oversized or inconsistent parts', async () => {
    const oversized = textXml.word(paragraph(marker + ' '.repeat(400 * 1024)));
    const beyondLimit = officeFile('docx', [[documentPath, oversized]]);
    const wrongSize = officeFile('docx', [[documentPath, { text: oversized, declaredSize: 512 }]]);
    assert.equal(await scan([beyondLimit, wrongSize]), undefined);
    assert.equal((await scan([wrongSize, samples.xlsx])).ruleId, 'github-classic-pat');
    const bigPart = officeFile('docx', [[documentPath, textXml.word(paragraph('X'.repeat(235 * 1024)))]]);
    const heavy = officeFile('docx', [[documentPath, textXml.word(paragraph('X'.repeat(235 * 1024)))],
      ['word/header1.xml', textXml.header(paragraph('X'.repeat(235 * 1024)))],
      ['word/header2.xml', textXml.header(paragraph('X'.repeat(235 * 1024)))],
      ['word/header3.xml', textXml.header(paragraph('X'.repeat(235 * 1024)))],
      ['word/header4.xml', textXml.header(paragraph('X'.repeat(120 * 1024) + marker))]]);
    assert.equal(await scan([heavy]), undefined);
    assert.equal(await scan([bigPart, bigPart, bigPart, bigPart, heavy]), undefined);
    const header = ['word/header999.xml', textXml.header(paragraph(marker))];
    const manyParts = Array.from({ length: 62 }, (_, index) =>
      [`word/header${String(index + 1).padStart(3, '0')}.xml`, textXml.header(paragraph('clean'))]);
    assert.equal(await scan([officeFile('docx', [[documentPath, textXml.word('')], ...manyParts, header])]), undefined);
    assert.equal((await scan([officeFile('docx', [[documentPath, textXml.word('')], ...manyParts.slice(1), header])])).ruleId, 'fixture-secret');
    const mediumDoc = officeFile('docx', [[documentPath, wordText], ['word/media/unscanned.bin', { text: randomBytes(320 * 1024), store: true }]]);
    assert.ok(mediumDoc.length > 256 * 1024);
    assert.equal((await scan([mediumDoc])).ruleId, 'fixture-secret');
    const tooBig = officeFile('docx', [[documentPath, wordText], ['word/media/unscanned.bin', { text: randomBytes(1024 * 1024), store: true }]]);
    assert.equal(await scan([tooBig]), undefined);
  });
});
