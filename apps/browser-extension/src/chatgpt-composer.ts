const editorSelector = '#prompt-textarea, [data-testid="prompt-textarea"]';
const buttonSelector = 'button[data-testid="send-button"], button#composer-submit-button[aria-label="Send prompt"]';
const labeledEditorSelector = 'textarea[placeholder="Ask ChatGPT"], textarea[aria-label="Ask ChatGPT"]';
const labeledSendSelector = 'button[aria-label="Send prompt"], button[aria-label="Send message"], button[aria-label="Send"]';

type Composer = { input: HTMLElement; button?: HTMLButtonElement };
type Gap = 'editable field missing' | 'multiple editable fields' | 'Send control missing';

function visible(element: HTMLElement): boolean {
  return element.getClientRects().length > 0 && getComputedStyle(element).visibility === 'visible';
}

export function promptText(input: HTMLElement): string {
  return input instanceof HTMLTextAreaElement ? input.value : input.innerText;
}

export function supportsRedaction(input: HTMLElement): boolean {
  if (input instanceof HTMLTextAreaElement) return !input.readOnly && !input.disabled;
  return input.isContentEditable && !input.querySelector(':not(p, div, br), [contenteditable]');
}

export function replacePromptText(input: HTMLElement, original: string, replacement: string): boolean {
  if (!input.isConnected || !supportsRedaction(input)) return false;
  input.focus();
  if (document.activeElement !== input || promptText(input) !== original) return false;
  if (input instanceof HTMLTextAreaElement) {
    input.setSelectionRange(0, input.value.length);
  } else {
    const selection = window.getSelection();
    if (!selection) return false;
    const range = document.createRange();
    range.selectNodeContents(input);
    selection.removeAllRanges();
    selection.addRange(range);
  }
  // Use Chrome's native edit so the site receives an input event and the edit is undoable.
  return document.execCommand('insertText', false, replacement);
}

function detectButton(input: HTMLElement, form: HTMLFormElement | null, selector: string): HTMLButtonElement | undefined {
  if (form) {
    const buttons = [...form.querySelectorAll<HTMLButtonElement>(selector)].filter(visible);
    if (buttons.length) return buttons.length === 1 ? buttons[0] : undefined;
  }

  // Associate the controls only within a nearby composer container. Page-wide matches can be unrelated.
  let container = input.parentElement;
  for (let depth = 0; container && depth < 6 && !container.matches('main, body, html'); depth++) {
    const buttons = [...container.querySelectorAll<HTMLButtonElement>(selector)].filter(visible);
    if (buttons.length) return buttons.length === 1 ? buttons[0] : undefined;
    container = container.parentElement;
  }
}

function inspectLabeledEditor() {
  const editors = [...document.querySelectorAll<HTMLTextAreaElement>(labeledEditorSelector)]
    .filter((editor) => visible(editor) && !editor.readOnly && !editor.disabled);
  if (editors.length !== 1) return { visibleLabeledEditors: editors.length };
  const [input] = editors;
  const form = input.closest('form');
  const button = detectButton(input, form, `${buttonSelector}, ${labeledSendSelector}`);
  return { visibleLabeledEditors: 1, composer: { input, button }, hasEditorForm: Boolean(form) };
}

type Inspection = {
  composer?: Composer;
  gap?: Gap;
  markedEditors: number;
  visibleMarkedEditors: number;
  visibleLabeledEditors?: number;
  hasEditorForm?: boolean;
};

export function inspectComposer(): Inspection {
  const markers = [...document.querySelectorAll<HTMLElement>(editorSelector)];
  const editors = markers.filter((input) => (input instanceof HTMLTextAreaElement || input.isContentEditable) && visible(input));
  const counts = { markedEditors: markers.length, visibleMarkedEditors: editors.length };
  if (editors.length > 1) return { ...counts, gap: 'multiple editable fields' };
  if (editors.length === 0) {
    const fallback = inspectLabeledEditor();
    const gap = fallback.composer?.button ? undefined : fallback.composer ? 'Send control missing' :
      fallback.visibleLabeledEditors > 1 ? 'multiple editable fields' : 'editable field missing';
    return { ...counts, ...fallback, gap };
  }
  const [input] = editors;
  const form = input.closest('form');
  const button = detectButton(input, form, buttonSelector);
  return { ...counts, composer: { input, button }, hasEditorForm: Boolean(form), gap: button ? undefined : 'Send control missing' };
}

export function composerDiagnostics() {
  const { composer, ...inspection } = inspectComposer();
  return {
    ...inspection,
    visibleTextareas: [...document.querySelectorAll<HTMLElement>('textarea')].filter(visible).length,
    visibleEditableRoots: [...document.querySelectorAll<HTMLElement>('[contenteditable]')]
      .filter((editor) => editor.isContentEditable && visible(editor)).length,
    hasComposerSubmitId: Boolean(document.getElementById('composer-submit-button')),
    hasSendTestId: Boolean(document.querySelector('button[data-testid="send-button"]')),
    hasLabeledSend: Boolean(document.querySelector(labeledSendSelector)),
    hasPairedSend: Boolean(composer?.button),
  };
}

export type { Composer };
