// Labeled synthetic corpus for detector precision and recall. Every key-shaped value is assembled at runtime from
// split prefixes and a seeded generator, so the repository holds no literal credential-shaped strings.
const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const lower = upper.toLowerCase();
const digits = '0123456789';
const alnum = upper + lower + digits;
const urlSafe = alnum + '_-';
const base32 = upper + '234567';
const hex = '0123456789abcdef';
const base64 = alnum + '+/';

export function generator(seed = 0x5eed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
  const pick = (charset, length) => Array.from({ length }, () => charset[Math.floor(next() * charset.length)]).join('');
  return { next, pick };
}

export const prefixes = {
  aws: 'AK' + 'IA', awsTemporary: 'AS' + 'IA', slackBot: 'xo' + 'xb-', slackUser: 'xo' + 'xp-', slackApp: 'xo' + 'xa-',
  slackRefresh: 'xo' + 'xr-', stripeSecret: 'sk' + '_live_', stripeRestricted: 'rk' + '_live_', stripeTest: 'sk' + '_test_',
  stripePublishable: 'pk' + '_live_', google: 'AI' + 'za', openAi: 's' + 'k-', openAiProject: 's' + 'k-proj-',
  openAiMarker: 'T3Blbk' + 'FJ', anthropic: 's' + 'k-ant-api03-', anthropicAdmin: 's' + 'k-ant-admin01-',
  githubClassic: 'gh' + 'p_', githubFineGrained: 'github' + '_pat_', githubOAuth: 'gh' + 'o_',
};

function luhnComplete(partial) {
  let sum = 0;
  for (let index = 0; index < partial.length; index++) {
    let digit = Number(partial[partial.length - 1 - index]);
    if (index % 2 === 0) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
  }
  return partial + ((10 - (sum % 10)) % 10);
}

// Health identifier helpers. NPI check digits use Luhn over the 80840 prefix; DEA uses its weighted checksum. All values are synthetic.
export function npiComplete(nine) {
  return luhnComplete('80840' + nine).slice(5);
}

export function deaComplete(letters, six) {
  const d = six.split('').map(Number);
  return letters + six + ((d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10);
}

const mbiLetters = 'ACDEFGHJKMNPQRTUVWXY';
export function mbi(pick, dashed = false) {
  const value = pick('123456789', 1) + pick(mbiLetters, 1) + pick(mbiLetters + digits, 1) + pick(digits, 1) +
    pick(mbiLetters, 1) + pick(mbiLetters + digits, 1) + pick(digits, 1) + pick(mbiLetters, 2) + pick(digits, 2);
  return dashed ? `${value.slice(0, 4)}-${value.slice(4, 7)}-${value.slice(7)}` : value;
}

function invalidCard(card) {
  return card.slice(0, -1) + ((Number(card.slice(-1)) + 1) % 10);
}

export const classificationTerms = ['CONFIDENTIAL – INTERNAL', 'Project Bluebird', 'Restricted Distribution'];
export const identifierFormats = [{ prefix: 'CUST-', digits: 8 }];
export const recordFormats = [{ prefix: 'MRN-', digits: 8 }];
const health = { healthProtection: { mode: 'block', recordFormats } };

// Rule IDs mirror contracts/policy. Each detector row in the benchmark enables exactly one setting.
export const detectors = [
  { name: 'GitHub classic PAT', policy: { githubPatMode: 'block' }, rules: ['github-classic-pat'] },
  { name: 'GitHub tokens', policy: { githubTokenMode: 'block' }, rules: ['github-app-or-fine-grained-token'] },
  { name: 'AWS access key ID', policy: { cloudCredentialMode: 'block' }, rules: ['aws-access-key-id'], grouped: true },
  { name: 'Slack token', policy: { cloudCredentialMode: 'block' }, rules: ['slack-token'], grouped: true },
  { name: 'Stripe live secret key', policy: { cloudCredentialMode: 'block' }, rules: ['stripe-live-secret-key'], grouped: true },
  { name: 'Google API key', policy: { cloudCredentialMode: 'block' }, rules: ['google-api-key'], grouped: true },
  { name: 'OpenAI API key', policy: { cloudCredentialMode: 'block' }, rules: ['openai-api-key'], grouped: true },
  { name: 'Anthropic API key', policy: { cloudCredentialMode: 'block' }, rules: ['anthropic-api-key'], grouped: true },
  { name: 'Payment card', policy: { paymentCardMode: 'block' }, rules: ['payment-card-number'] },
  { name: 'Private key', policy: { privateKeyMode: 'block' }, rules: ['pem-private-key'] },
  { name: 'U.S. SSN', policy: { ssnMode: 'block' }, rules: ['us-social-security-number'] },
  { name: 'Organization identifier', policy: { identifierProtection: { mode: 'block', formats: identifierFormats } },
    rules: ['organization-identifier'] },
  { name: 'U.S. NPI', policy: health, rules: ['us-national-provider-identifier'], grouped: true },
  { name: 'DEA registration number', policy: health, rules: ['dea-registration-number'], grouped: true },
  { name: 'Medicare Beneficiary Identifier', policy: health, rules: ['medicare-beneficiary-identifier'], grouped: true },
  { name: 'Medical record number', policy: health, rules: ['medical-record-number'], grouped: true },
  { name: 'Classification rule', policy: { classificationProtection: { mode: 'block', terms: classificationTerms } },
    rules: ['organization-classification-rule'] },
];

const contexts = [
  (value) => value,
  (value) => `export API_KEY=${value}`,
  (value) => `{"credentials": {"key": "${value}"}}`,
  (value) => `const client = new Client('${value}');`,
  (value) => `Can you tell me why this fails? I am using ${value} in my config.`,
  (value) => `token: ${value}\nregion: us-east-1`,
  (value) => `https://api.example.test/v1/items?key=${value}&page=2`,
];

// Clinical and administrative contexts where health identifiers appear in prompts and files.
const healthContexts = [
  (value) => value,
  (value) => `Patient summary:\n${value}\nFollow-up in two weeks.`,
  (value) => `{"note": "${value}", "status": "pending"}`,
  (value) => `Can you draft a referral letter for this case? ${value}.`,
  (value) => `| Roe, Jane | ${value} | Cardiology |`,
  (value) => `Re: prior authorization (${value}), thanks`,
  (value) => `name,detail\n"Doe, Alex","${value}"`,
];

export function buildCorpus(seed = 0x5eed) {
  const { next, pick } = generator(seed);
  const samples = [];
  const positive = (rule, values) => {
    for (const value of values) for (const context of contexts) samples.push({ rule, text: context(value) });
  };
  const negative = (kind, values) => {
    for (const value of values) samples.push({ rule: null, kind, text: value });
  };
  const clinical = (rule, values) => {
    for (const value of values) for (const context of healthContexts) samples.push({ rule, text: context(value) });
  };
  const npi = () => npiComplete(pick('12', 1) + pick(digits, 8));
  const dea = () => deaComplete(pick('ABFGMPRX', 1) + pick(upper, 1), pick(digits, 6));
  const wrongCheck = (value) => value.slice(0, -1) + ((Number(value.slice(-1)) + 1 + Math.floor(next() * 8)) % 10);

  clinical('us-national-provider-identifier', [`NPI: ${npi()}`, `Referring NPI ${npi()}`, `National Provider Identifier ${npi()}`,
    `npi=${npi()}`, `Billing NPI number: ${npi()}`]);
  clinical('dea-registration-number', [`DEA: ${dea()}`, `DEA # ${dea()}`, `DEA registration number ${dea()}`, `Prescriber DEA ${dea()}`]);
  clinical('medicare-beneficiary-identifier', [mbi(pick), mbi(pick, true), `Medicare ID ${mbi(pick)}`, `MBI: ${mbi(pick, true)}`]);
  clinical('medical-record-number', [`MRN-${pick(digits, 8)}`, `MRN: ${pick(digits, 8)}`, `Medical record number ${pick(digits, 8)}`,
    `MR# ${pick(digits, 8)}`, `mrn-${pick(digits, 8)}`]);

  positive('aws-access-key-id', [prefixes.aws + pick(base32, 16), prefixes.awsTemporary + pick(base32, 16), prefixes.aws + pick(base32, 16)]);
  positive('slack-token', [
    `${prefixes.slackBot}${pick(digits, 11)}-${pick(digits, 12)}-${pick(alnum, 24)}`,
    `${prefixes.slackUser}${pick(digits, 12)}-${pick(digits, 12)}-${pick(digits, 12)}-${pick(hex, 32)}`,
    `${prefixes.slackApp}2-${pick(digits, 12)}-${pick(alnum, 40)}`,
    `${prefixes.slackRefresh}${pick(digits, 13)}-${pick(alnum, 48)}`,
  ]);
  positive('stripe-live-secret-key', [prefixes.stripeSecret + pick(alnum, 24), prefixes.stripeSecret + pick(alnum, 99),
    prefixes.stripeRestricted + pick(alnum, 99)]);
  positive('google-api-key', [prefixes.google + pick(urlSafe, 35), prefixes.google + pick(urlSafe, 35)]);
  positive('openai-api-key', [
    prefixes.openAi + pick(alnum, 20) + prefixes.openAiMarker + pick(alnum, 20),
    prefixes.openAiProject + pick(urlSafe, 74) + prefixes.openAiMarker + pick(urlSafe, 74),
    's' + 'k-svcacct-' + pick(urlSafe, 74) + prefixes.openAiMarker + pick(urlSafe, 74),
  ]);
  positive('anthropic-api-key', [prefixes.anthropic + pick(urlSafe, 93) + 'AA', prefixes.anthropicAdmin + pick(urlSafe, 93) + 'AA']);
  positive('github-classic-pat', [prefixes.githubClassic + pick(alnum, 36)]);
  positive('github-app-or-fine-grained-token', [prefixes.githubFineGrained + pick(alnum, 22) + '_' + pick(alnum, 59),
    prefixes.githubOAuth + pick(alnum, 36)]);
  positive('payment-card-number', [luhnComplete('4' + pick(digits, 14)), luhnComplete('51' + pick(digits, 13))]
    .map((card) => card.replace(/(\d{4})(?=\d)/g, '$1 ')));
  positive('us-social-security-number', [`${200 + Math.floor(next() * 400)}-${pick('123456789', 2)}-${pick('123456789', 4)}`]);
  positive('organization-identifier', ['CUST-' + pick(digits, 8), 'cust-' + pick(digits, 8)]);
  positive('organization-classification-rule', ['CONFIDENTIAL – INTERNAL', 'Confidential-Internal', 'confidential — internal',
    'Project Bluebird', 'project  bluebird', 'RESTRICTED DISTRIBUTION']);
  for (const body of [pick(base64, 64), pick(base64, 64), pick(base64, 128), pick(base64, 48)]) {
    samples.push({ rule: 'pem-private-key', text: ['-----BEGIN ' + 'PRIVATE KEY-----', body, '-----END ' + 'PRIVATE KEY-----'].join('\n') });
    samples.push({ rule: 'pem-private-key', text: ['Here is the key:', '-----BEGIN RSA ' + 'PRIVATE KEY-----', body, body,
      '-----END RSA ' + 'PRIVATE KEY-----'].join('\n') });
  }

  // Intentionally invalid or documentation keys: wrong prefix, length, charset, environment, or placeholder bodies.
  negative('invalid example key', [
    prefixes.aws + 'X'.repeat(16), prefixes.aws + 'IOSFODNN7' + 'EXAMPLE', prefixes.aws + pick(base32, 15),
    prefixes.aws + pick(base32, 17), (prefixes.aws + pick(base32, 16)).toLowerCase(), prefixes.aws + pick(base32, 15) + '1',
    `aws_access_key_id = ${prefixes.aws}${'0'.repeat(16)}`, 'AKIA is the prefix used by long-term AWS access key IDs.',
    `${prefixes.slackBot}your-token-here`, `${prefixes.slackBot}${'0'.repeat(10)}-${'0'.repeat(10)}-${'x'.repeat(24)}`,
    'xo' + 'xc-' + pick(digits, 11) + '-' + pick(alnum, 24), `${prefixes.slackBot}${pick(digits, 11)}-${pick(alnum, 12)}`,
    prefixes.stripeTest + pick(alnum, 24), prefixes.stripePublishable + pick(alnum, 24), prefixes.stripeSecret + 'placeholder',
    prefixes.stripeSecret + pick(alnum, 20), `STRIPE_KEY=${prefixes.stripeSecret}${'x'.repeat(24)}`,
    prefixes.google + pick(urlSafe, 34), prefixes.google + pick(alnum, 36), prefixes.google + 'X'.repeat(35),
    prefixes.openAi + pick(alnum, 48), prefixes.openAi + pick(hex, 32), prefixes.openAiProject + pick(urlSafe, 120),
    prefixes.openAi + 'your-api-key-here', prefixes.openAi + '...' + prefixes.openAiMarker,
    prefixes.anthropic + pick(urlSafe, 93) + 'AB', prefixes.anthropic + pick(urlSafe, 40), prefixes.anthropic + 'x'.repeat(95),
    's' + 'k-ant-...', prefixes.githubClassic + pick(alnum, 35), 'github' + '_pat_' + pick(alnum, 21),
  ]);
  const uuid = () => `${pick(hex, 8)}-${pick(hex, 4)}-4${pick(hex, 3)}-a${pick(hex, 3)}-${pick(hex, 12)}`;
  negative('identifier', [uuid(), uuid(), uuid().toUpperCase(), `request-id: ${uuid()}`, `arn:aws:iam::${pick(digits, 12)}:user/deploy-bot`,
    `Order ${pick(digits, 10)} shipped`, `Tracking 1Z${pick(upper + digits, 16)}`, 'ISBN 978-0-306-40615-7', 'Call 555-201-4477 tomorrow',
    'Release date 2026-11-25', 'ZIP 94105-1234', `invoice INV-${pick(digits, 8)}`, `CUST-${pick(digits, 7)}`, `CUST-${pick(digits, 9)}`,
    `XCUST-${pick(digits, 8)}`, `SSN 000-12-3456`, `666-${pick('123456789', 2)}-${pick('123456789', 4)}`,
    `Card ${invalidCard(luhnComplete('4' + pick(digits, 14)))}`, `Order ${invalidCard(luhnComplete('5' + pick(digits, 15)))}`,
    `cus_${pick(alnum, 14)}`, `pi_${pick(alnum, 24)}`, `ch_${pick(alnum, 24)}`, `10.${pick(digits, 2)}.0.1`]);
  // Health near misses: numbers that share a shape with NPI, DEA, MBI, or MRN values but lack the label, length, character rules,
  // or check digit. Several carry a valid NPI or DEA checksum to show that the label requirement is what rejects them.
  const phone = () => `${pick('23456789', 1)}${pick(digits, 2)}`;
  negative('health near miss', [
    `Call (${phone()}) 555-${pick(digits, 4)} to schedule`, `Phone: ${phone()}${pick(digits, 7)}`, `tel:+1${phone()}${pick(digits, 7)}`,
    `NPI pending; office phone ${phone()}-555-${pick(digits, 4)}`, `Fax 1-${phone()}-${pick(digits, 3)}-${pick(digits, 4)}`,
    `Invoice ${pick(digits, 10)} is past due`, `INV-${pick(digits, 10)}`, `Invoice number: ${dea()}`, `PO ${dea()} approved`,
    `SKU ${dea()}`, `Ship to ZIP 94105-${pick(digits, 4)}`, `ZIP+4 ${pick(digits, 5)}-${pick(digits, 4)}`,
    `Order ${pick(digits, 10)} shipped`, `Account 1${pick(digits, 9)}`, `Ticket ${npi()} closed`, `Reference ${npi()}`,
    `NPI: ${wrongCheck(npi())}`, `NPI ${wrongCheck(npi())}`, `NPI: 3${pick(digits, 9)}`, `NPI: ${npi()}${pick(digits, 1)}`,
    `NPI: ${npi().slice(0, 9)}`, `DEA: ${wrongCheck(dea())}`, `DEA # ${wrongCheck(dea())}`, `DEA: ${deaComplete('Z' + pick(upper, 1), pick(digits, 6))}`,
    `DEA: ${dea()}${pick(digits, 1)}`, `IDEA ${dea()}`,
    `Medicare ID 1S${pick(digits, 1)}${pick(digits, 1)}-${pick('ACD', 1)}${pick(digits, 1)}${pick(digits, 1)}-${pick('AC', 2)}${pick(digits, 2)}`,
    `${pick('123456789', 1)}${pick('ACD', 1)}${pick(digits, 2)}${pick('BILOSZ', 1)}${pick(digits, 2)}${pick('ACD', 2)}${pick(digits, 2)}`,
    `0${mbi(pick).slice(1)}`, mbi(pick).toLowerCase(), mbi(pick).slice(0, 10), mbi(pick) + pick(digits, 1),
    `${mbi(pick, true).slice(0, 8)}${mbi(pick).slice(7)}`, 'MBI example: 1EG4' + '-TE5-' + 'MK73',
    `MRN: ${pick(digits, 7)}`, `MRN: ${pick(digits, 9)}`, `MRN-${pick(digits, 9)}`, `XMRN-${pick(digits, 8)}`, `Case ${pick(digits, 8)}`,
    `Room ${pick(digits, 3)}, bed ${pick(digits, 1)}`, 'Diagnosis E11.9 type 2 diabetes; follow up on Z79.4',
    'Medicare Part B covers outpatient care.', 'Our NPI registry lookup tool is down today.',
    'The DEA guidance on telehealth prescribing changed.', 'Ask for the MRN before you open the chart.',
    `Version 1.${pick(digits, 2)}.${pick(digits, 1)} build ${pick(digits, 10)}`,
  ]);
  negative('hash', [pick(hex, 40), pick(hex, 64), `sha256:${pick(hex, 64)}`, `sha512-${pick(base64, 86)}==`,
    `commit ${pick(hex, 40)}`, `etag: "${pick(hex, 32)}"`]);
  negative('base64 blob', [pick(base64, 120), pick(base64, 400) + '==', `data:image/png;base64,${pick(base64, 300)}`,
    `eyJ${pick(urlSafe, 30)}.eyJ${pick(urlSafe, 60)}.${pick(urlSafe, 43)}`]);
  negative('code', [
    'const apiKey = process.env.OPENAI_API_KEY;\nif (!apiKey) throw new Error("missing key");',
    'aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID',
    'stripe.api_key = os.environ["STRIPE_SECRET_KEY"]  # sk_live keys stay in the vault',
    'slack_client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])',
    'const key = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkq...\\n-----END PUBLIC KEY-----";',
    'git checkout -b feature/confidential-review-flow',
    'function isInternal(label) { return label.startsWith("internal"); }',
    'SELECT id, ssn_hash FROM customers WHERE created_at > now() - interval \'7 days\';',
  ]);
  negative('prose', [
    'Please summarize the quarterly planning notes and highlight risks.',
    'This document is confidential and internal to the team.',
    'The bluebird project kickoff moved to Thursday.',
    'Projects Bluebirds and Robin are on the restricted list draft.',
    'Our Stripe dashboard shows live mode is enabled for payments.',
    'Rotate any AWS keys that start with AKIA or ASIA every 90 days.',
    'Slack tokens begin with xoxb or xoxp and must never be pasted into chats.',
    'Google API keys usually begin with AIza and are 39 characters long.',
    'Anthropic keys start with sk-ant and OpenAI keys start with sk-.',
    'Internal confidential notes: none.',
  ]);
  return samples;
}
