import type { UploadDecision, UploadMethod } from '../../../contracts/policy/uploads';

function hold(event: Event) {
  event.preventDefault();
  event.stopImmediatePropagation();
}

function hasFileTransfer(data: DataTransfer | null): boolean {
  return Boolean(data && (data.files.length > 0 || Array.from(data.items).some(({ kind }) => kind === 'file')));
}

export function bindUploadGuard(mode: () => UploadDecision | undefined, report: (decision: UploadDecision, method: UploadMethod) => void) {
  // Chrome dispatches input and change for one file picker selection.
  const pendingChange = new WeakMap<HTMLInputElement, UploadDecision>();
  const nativeDrops = new WeakSet<HTMLInputElement>();
  function picker(event: Event) {
    if (!event.isTrusted) return;
    const input = event.composedPath()[0];
    if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
    const pending = pendingChange.get(input);
    pendingChange.delete(input);
    if (event.type === 'cancel' || nativeDrops.has(input)) return;
    if (event.type === 'change' && pending) {
      if (pending === 'block') hold(event);
      return;
    }
    const decision = mode();
    if (!decision || !input.files?.length) return;
    if (event.type === 'input') pendingChange.set(input, decision);
    if (decision === 'block') {
      hold(event);
      input.value = '';
    }
    report(decision, 'picker');
  }

  window.addEventListener('input', picker, true);
  window.addEventListener('change', picker, true);
  window.addEventListener('cancel', picker, true);
  window.addEventListener('dragover', (event) => {
    if (event.isTrusted && mode() === 'block' && event.dataTransfer?.types.includes('Files')) event.preventDefault();
  }, true);
  window.addEventListener('drop', (event) => {
    const decision = mode();
    if (!event.isTrusted || !decision || !hasFileTransfer(event.dataTransfer)) return;
    if (decision === 'block') hold(event);
    else {
      const target = event.composedPath()[0];
      if (target instanceof HTMLInputElement && target.type === 'file') {
        // A native drop onto a file input can also produce input and change in the same task.
        nativeDrops.add(target);
        window.setTimeout(() => nativeDrops.delete(target), 0);
      }
    }
    report(decision, 'drop');
  }, true);
  window.addEventListener('paste', (event) => {
    const decision = mode();
    if (!event.isTrusted || !decision || !hasFileTransfer(event.clipboardData)) return;
    if (decision === 'block') hold(event);
    report(decision, 'paste');
  }, true);
}
