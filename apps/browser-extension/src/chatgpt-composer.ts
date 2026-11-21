const editorSelector = '#prompt-textarea, [data-testid="prompt-textarea"]';
const buttonSelector = 'button[data-testid="send-button"], button#composer-submit-button[aria-label="Send prompt"]';

type Composer = { input: HTMLElement; button?: HTMLButtonElement };
type Gap = 'editable field missing' | 'multiple editable fields' | 'Send control missing';

function visible(element: HTMLElement): boolean {
  return element.getClientRects().length > 0 && getComputedStyle(element).visibility === 'visible';
}

function detectButton(input: HTMLElement, form: HTMLFormElement | null): HTMLButtonElement | undefined {
  if (form) {
    const buttons = [...form.querySelectorAll<HTMLButtonElement>(buttonSelector)].filter(visible);
    if (buttons.length) return buttons.length === 1 ? buttons[0] : undefined;
  }

  // Associate the controls only within a nearby composer container. Page-wide matches can be unrelated.
  let container = input.parentElement;
  for (let depth = 0; container && depth < 6 && !container.matches('main, body, html'); depth++) {
    const buttons = [...container.querySelectorAll<HTMLButtonElement>(buttonSelector)].filter(visible);
    if (buttons.length) return buttons.length === 1 ? buttons[0] : undefined;
    container = container.parentElement;
  }
}

export function inspectComposer(): { composer?: Composer; gap?: Gap; markedEditors: number; visibleMarkedEditors: number; hasEditorForm?: boolean } {
  const markers = [...document.querySelectorAll<HTMLElement>(editorSelector)];
  const editors = markers.filter((input) => (input instanceof HTMLTextAreaElement || input.isContentEditable) && visible(input));
  const counts = { markedEditors: markers.length, visibleMarkedEditors: editors.length };
  if (editors.length !== 1) return { ...counts, gap: editors.length ? 'multiple editable fields' : 'editable field missing' };
  const [input] = editors;
  const form = input.closest('form');
  const button = detectButton(input, form);
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
    hasPairedSend: Boolean(composer?.button),
  };
}

export type { Composer };
