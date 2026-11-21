import { matchesUploadType, type UploadDecision, type UploadFilter, type UploadMethod } from '../../../contracts/policy/uploads';

function hold(event: Event) {
  event.preventDefault();
  event.stopImmediatePropagation();
}

function pickerDecision(filter: UploadFilter, files: FileList) {
  if (!filter.types.length || Array.from(files).some((file) => matchesUploadType(file, filter.types))) return filter.mode;
}

export function bindUploadGuard(policy: () => UploadFilter | undefined,
  report: (decision: UploadDecision | undefined, method: UploadMethod) => void) {
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
    const filter = policy();
    if (!filter || !input.files?.length) return;
    const decision = pickerDecision(filter, input.files);
    if (event.type === 'input' && decision) pendingChange.set(input, decision);
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
    if (event.isTrusted && policy()?.mode === 'block' && event.dataTransfer?.types.includes('Files')) event.preventDefault();
  }, true);
  function transfer(event: Event, data: DataTransfer | null, method: 'drop' | 'paste') {
    if (!event.isTrusted || !data) return;
    const filter = policy();
    if (!filter) return;
    const files = data.files.length ? Array.from(data.files) :
      Array.from(data.items).filter(({ kind }) => kind === 'file')
        .map((item) => item.getAsFile() ?? { name: '', type: item.type });
    if (!files.length) return;
    const decision = !filter.types.length || files.some((file) => matchesUploadType(file, filter.types)) ? filter.mode : undefined;
    if (decision === 'block') hold(event);
    else if (decision && method === 'drop') {
      const target = event.composedPath()[0];
      if (target instanceof HTMLInputElement && target.type === 'file') {
        // A native drop onto a file input can also produce input and change in the same task.
        nativeDrops.add(target);
        window.setTimeout(() => nativeDrops.delete(target), 0);
      }
    }
    report(decision, method);
  }
  window.addEventListener('drop', (event) => transfer(event, event.dataTransfer, 'drop'), true);
  window.addEventListener('paste', (event) => {
    transfer(event, event.clipboardData, 'paste');
  }, true);
}
