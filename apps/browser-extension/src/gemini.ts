import { geminiApp, geminiRoute } from './protocol';
import { promptText, visible, type ComposerInspection } from './prompt-composer';
import { bindPromptGuard } from './prompt-guard';

const editorSelector = 'input-area-v2 rich-textarea .ql-editor[role="textbox"][aria-label="Enter a prompt for Gemini"]';
const sendSelector = 'button[aria-label="Send message"]';

function inspectGeminiComposer() {
  const marker = [...document.querySelectorAll<HTMLElement>(editorSelector)];
  const editors = marker.filter((editor) => editor.isContentEditable && visible(editor));
  const counts = { markedEditors: marker.length, visibleMarkedEditors: editors.length };
  if (editors.length !== 1) {
    return { ...counts, gap: editors.length ? 'multiple editable fields' : 'editable field missing' };
  }
  const [input] = editors;
  const scope = input.closest('input-area-v2')!;
  const buttons = [...scope.querySelectorAll<HTMLButtonElement>(sendSelector)].filter(visible);
  const button = buttons.length === 1 ? buttons[0] : undefined;
  const result: ComposerInspection = {
    composer: { input, button },
    waitingForSend: buttons.length === 0 && !promptText(input).trim(),
    gap: buttons.length > 1 ? 'multiple Send controls' : button ? undefined : 'Send control missing',
  };
  return { ...counts, ...result };
}

function diagnostics() {
  const { composer, ...inspection } = inspectGeminiComposer();
  return { ...inspection, hasPairedSend: Boolean(composer?.button) };
}

bindPromptGuard({ appId: geminiApp, route: geminiRoute, inspect: inspectGeminiComposer, diagnostics });
