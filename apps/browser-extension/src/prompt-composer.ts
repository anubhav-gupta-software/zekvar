export type Composer = { input: HTMLElement; button?: HTMLButtonElement };
export type ComposerInspection = {
  composer?: Composer;
  gap?: string;
  hasEditorForm?: boolean;
  waitingForSend?: boolean;
};

export function visible(element: HTMLElement): boolean {
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
