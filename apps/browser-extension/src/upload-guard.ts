import { matchesUploadType, type UploadDecision, type UploadFile, type UploadFilter, type UploadMethod } from '../../../contracts/policy/uploads';

type UploadGuardPolicy = { filter?: UploadFilter; inspect?: (files: readonly File[], method: UploadMethod) => void };

function hold(event: Event) {
  event.preventDefault();
  event.stopImmediatePropagation();
}

function uploadDecision(filter: UploadFilter | undefined, files: readonly UploadFile[]) {
  if (filter && (!filter.types.length || files.some((file) => matchesUploadType(file, filter.types)))) return filter.mode;
}

export function bindUploadGuard(policy: () => UploadGuardPolicy | undefined,
  report: (decision: UploadDecision | undefined, method: UploadMethod) => void) {
  // Chrome dispatches input and change for one file picker selection.
  const pendingChange = new WeakMap<HTMLInputElement, boolean>();
  const nativeDrops = new WeakSet<HTMLInputElement>();
  function picker(event: Event) {
    if (!event.isTrusted) return;
    const input = event.composedPath()[0];
    if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
    const pending = pendingChange.get(input);
    pendingChange.delete(input);
    if (event.type === 'cancel' || nativeDrops.has(input)) return;
    if (event.type === 'change' && pending !== undefined) {
      if (pending) hold(event);
      return;
    }
    const active = policy();
    if (!active || !input.files?.length) return;
    const files = Array.from(input.files);
    const decision = uploadDecision(active.filter, files);
    if (event.type === 'input' && (decision || active.inspect)) pendingChange.set(input, decision === 'block');
    if (decision === 'block') {
      hold(event);
      input.value = '';
    }
    report(decision, 'picker');
    if (decision !== 'block') active.inspect?.(files, 'picker');
  }

  window.addEventListener('input', picker, true);
  window.addEventListener('change', picker, true);
  window.addEventListener('cancel', picker, true);
  window.addEventListener('dragover', (event) => {
    if (event.isTrusted && policy()?.filter?.mode === 'block' && event.dataTransfer?.types.includes('Files')) event.preventDefault();
  }, true);
  function transfer(event: Event, data: DataTransfer | null, method: 'drop' | 'paste') {
    if (!event.isTrusted || !data) return;
    const active = policy();
    if (!active) return;
    const files = data.files.length ? Array.from(data.files) :
      Array.from(data.items).filter(({ kind }) => kind === 'file')
        .map((item) => item.getAsFile() ?? { name: '', type: item.type });
    if (!files.length) return;
    const decision = uploadDecision(active.filter, files);
    if (decision === 'block') hold(event);
    else if ((decision || active.inspect) && method === 'drop') {
      const target = event.composedPath()[0];
      if (target instanceof HTMLInputElement && target.type === 'file') {
        // A native drop onto a file input can also produce input and change in the same task.
        nativeDrops.add(target);
        window.setTimeout(() => nativeDrops.delete(target), 0);
      }
    }
    report(decision, method);
    if (decision !== 'block') active.inspect?.(files.filter((file) => file instanceof File), method);
  }
  window.addEventListener('drop', (event) => transfer(event, event.dataTransfer, 'drop'), true);
  window.addEventListener('paste', (event) => {
    transfer(event, event.clipboardData, 'paste');
  }, true);
}
