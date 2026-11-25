import { aiPromptApps, chatGptApp, geminiApp, type AiPromptApp } from '../../../contracts/policy/apps';
import { clipboardTextLimit } from '../../../contracts/policy/clipboard';
import { parseWebAddress } from '../../../contracts/policy/domains';
import { modes, testMarker } from '../../../contracts/policy/prompt';
import { exceptionDecision } from '../../../contracts/policy/prompt-exceptions';
import { isUploadApp, type UploadApp, type UploadFile } from '../../../contracts/policy/uploads';
import { clipboardOutcome, fileInspectionOutcome, navigationOutcome, promptOutcome,
  type PreviewDecision, type PreviewPolicy, type PreviewSnapshot } from './preview';

export const maxTestPackBytes = 256 * 1024;
const maxCases = 100;
const actions = ['allow', ...modes, exceptionDecision] as const;

type Expectation = { id: string; expect: PreviewDecision['action'] };
type TestCase = Expectation & (
  | { kind: 'prompt'; app: AiPromptApp; text: string }
  | { kind: 'clipboard'; app: AiPromptApp; text?: string }
  | { kind: 'navigation'; url: string }
  | { kind: 'upload'; app: UploadApp; file: UploadFile; text?: string }
);
type TestPack = { version: 1; cases: TestCase[] };
type ParsedPack = { pack: TestPack; error?: never } | { pack?: never; error: string };

export const starterTestPack: TestPack = {
  version: 1,
  cases: [
    { id: 'clean-planning-prompt', kind: 'prompt', app: chatGptApp, text: 'Summarize the planning notes.', expect: 'allow' },
    { id: 'test-marker-prompt', kind: 'prompt', app: chatGptApp, text: testMarker, expect: 'block' },
    { id: 'test-marker-paste', kind: 'clipboard', app: geminiApp, text: testMarker, expect: 'block' },
    { id: 'allowed-planning-site', kind: 'navigation', url: 'https://planning.example.test/', expect: 'allow' },
    { id: 'test-marker-upload', kind: 'upload', app: geminiApp, file: { name: 'synthetic.txt', type: 'text/plain' },
      text: testMarker, expect: 'block' },
  ],
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnly(value: Record<string, unknown>, fields: readonly string[]) {
  return Object.keys(value).every((key) => fields.includes(key));
}

function isText(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length <= limit;
}

function isAction(value: unknown): value is PreviewDecision['action'] {
  return actions.some((action) => action === value);
}

function isAiApp(value: unknown): value is AiPromptApp {
  return aiPromptApps.some((app) => app === value);
}

function readTestCase(value: unknown): TestCase | undefined {
  if (!record(value)) return;
  const { id, expect, kind, app, text, url, file } = value;
  if (!isText(id, 64) || !/^[a-z0-9][a-z0-9_-]*$/i.test(id) || !isAction(expect)) return;
  const fields = ['id', 'kind', 'expect'];
  if (kind === 'navigation' && hasOnly(value, [...fields, 'url']) && isText(url, 4096) &&
      /^https?:\/\//i.test(url) && parseWebAddress(url) && (expect === 'allow' || expect === 'block')) {
    return { id, expect, kind, url };
  }
  if (!isAiApp(app) || (text !== undefined && !isText(text, clipboardTextLimit + 1))) return;
  if (kind === 'prompt' && hasOnly(value, [...fields, 'app', 'text']) && typeof text === 'string') {
    return { id, expect, kind, app, text };
  }
  if (expect !== exceptionDecision && expect !== 'warn' && hasOnly(value, [...fields, 'app', 'text', ...(kind === 'upload' ? ['file'] : [])])) {
    if (kind === 'clipboard') return { id, expect, kind, app, text };
    if (kind === 'upload' && isUploadApp(app) && record(file) && hasOnly(file, ['name', 'type']) &&
        isText(file.name, 255) && file.name.trim() && isText(file.type, 128)) {
      return { id, expect, kind, app, file: { name: file.name, type: file.type }, text };
    }
  }
}

export function parseTestPack(raw: string): ParsedPack {
  if (new TextEncoder().encode(raw).byteLength > maxTestPackBytes) return { error: 'Choose a test pack of 256 KiB or less.' };
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return { error: 'Choose a valid JSON test pack.' };
  }
  if (!record(value) || !hasOnly(value, ['version', 'cases']) || value.version !== 1 || !Array.isArray(value.cases) ||
      value.cases.length < 1 || value.cases.length > maxCases) {
    return { error: 'Use test pack version 1 with 1–100 cases.' };
  }
  const cases: TestCase[] = [];
  const ids = new Set<string>();
  for (const item of value.cases) {
    const sample = readTestCase(item);
    if (!sample) return { error: `Check the fields and expected outcome in case ${cases.length + 1}.` };
    const key = sample.id.toLowerCase();
    if (ids.has(key)) return { error: `Use a unique case ID in case ${cases.length + 1}.` };
    ids.add(key);
    cases.push(sample);
  }
  return { pack: { version: 1, cases } };
}

function outcome(sample: TestCase, policy: PreviewPolicy, now: number) {
  switch (sample.kind) {
    case 'prompt': return promptOutcome(sample.text, policy, sample.app, now);
    case 'clipboard': return clipboardOutcome(sample.text, policy, sample.app);
    case 'navigation': return navigationOutcome(new URL(sample.url), policy);
    case 'upload': return fileInspectionOutcome(policy, sample.app, sample.file, sample.text);
  }
}

export function compareTestPack(pack: TestPack, reference: PreviewSnapshot, candidate: PreviewPolicy,
  scope: string, draftSourceVersion: number, now: number) {
  const cases = pack.cases.map((sample) => {
    const current = outcome(sample, reference, now).action;
    const draft = outcome(sample, candidate, now).action;
    const { id, kind, expect } = sample;
    const result: 'pass' | 'fixed' | 'regression' | 'mismatch' = draft === expect ? (current === expect ? 'pass' : 'fixed')
      : (current === expect ? 'regression' : 'mismatch');
    return { id, kind, app: 'app' in sample ? sample.app : undefined, expect, current, draft, result };
  });
  return {
    version: 1,
    evaluatedAt: new Date(now).toISOString(),
    scope,
    currentVersion: reference.version,
    draftSourceVersion,
    summary: {
      currentPassed: cases.filter(({ current, expect }) => current === expect).length,
      draftPassed: cases.filter(({ draft, expect }) => draft === expect).length,
      fixes: cases.filter(({ result }) => result === 'fixed').length,
      regressions: cases.filter(({ result }) => result === 'regression').length,
    },
    cases,
  };
}

export type { TestPack };
export type TestPackReport = ReturnType<typeof compareTestPack>;
