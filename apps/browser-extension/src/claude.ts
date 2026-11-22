import { claudeApp, claudeRoute } from './protocol';
import { promptText, visible, type ComposerInspection } from './prompt-composer';
import { bindPromptGuard } from './prompt-guard';

const composerScope = '[data-testid="chat-input"], fieldset, form';
const editorSelector = 'div.ProseMirror[contenteditable="true"]';
const sendSelector = 'button[aria-label="Send message" i], button[data-testid="send-button"]';

function inspectClaudeComposer(): ComposerInspection & { markedEditors: number; visibleMarkedEditors: number } {
  const marked = [...document.querySelectorAll<HTMLElement>(editorSelector)].filter((editor) => editor.closest(composerScope));
  const visibleEditors = marked.filter((editor) => editor.isContentEditable && visible(editor));
  const counts = { markedEditors: marked.length, visibleMarkedEditors: visibleEditors.length };
  if (visibleEditors.length !== 1) {
    return { ...counts, gap: visibleEditors.length ? 'multiple editable fields' : 'editable field missing' };
  }
  const [input] = visibleEditors;
  for (let scope = input.closest(composerScope); scope; scope = scope.parentElement?.closest(composerScope) ?? null) {
    const buttons = [...scope.querySelectorAll<HTMLButtonElement>(sendSelector)].filter(visible);
    if (buttons.length > 1) return { ...counts, composer: { input }, gap: 'multiple Send controls' };
    if (buttons.length === 1) return { ...counts, composer: { input, button: buttons[0] } };
  }
  return { ...counts, composer: { input }, waitingForSend: !promptText(input).trim(), gap: 'Send control missing' };
}

function diagnostics() {
  const { composer, ...details } = inspectClaudeComposer();
  return { ...details, hasPairedSend: Boolean(composer?.button) };
}

bindPromptGuard({ appId: claudeApp, route: claudeRoute, inspect: inspectClaudeComposer, diagnostics, hideWhenDisabled: true });
