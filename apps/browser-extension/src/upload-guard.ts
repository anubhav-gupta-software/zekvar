import { matchesUploadType, type UploadDecision, type UploadFile, type UploadFilter, type UploadMethod } from '../../../contracts/policy/uploads';
import type { RuleMetadata } from '../../../contracts/policy/prompt';

export type UploadCheck = { kind: 'allow'; files: File[] } | { kind: 'blocked'; rule: RuleMetadata } | { kind: 'unavailable' };
type GateStatus = Exclude<UploadCheck['kind'], 'allow'> | 'checking' | 'retry' | 'released';
type UploadGuardPolicy = {
  scope: string;
  filter?: UploadFilter;
  inspect?: (files: readonly File[], method: UploadMethod) => void;
  check?: (files: readonly UploadFile[]) => Promise<UploadCheck>;
};

function hold(event: Event) {
  event.preventDefault();
  event.stopImmediatePropagation();
}

function uploadDecision(filter: UploadFilter | undefined, files: readonly UploadFile[]) {
  if (filter && (!filter.types.length || files.some((file) => matchesUploadType(file, filter.types)))) return filter.mode;
}

export function bindUploadGuard(policy: () => UploadGuardPolicy | undefined,
  report: (decision: UploadDecision | undefined, method: UploadMethod) => void,
  gate: (state: GateStatus, method: UploadMethod, rule?: RuleMetadata) => void) {
  // Chrome dispatches input and change for one file picker selection.
  const pendingChange = new WeakMap<HTMLInputElement, boolean>();
  const nativeDrops = new WeakSet<HTMLInputElement>();
  const pendingSelections = new WeakMap<HTMLInputElement, object>();
  let latest = 0;
  let visit = 0;
  window.addEventListener('pagehide', () => { visit++; });

  function check(active: UploadGuardPolicy, target: EventTarget, files: readonly UploadFile[], method: UploadMethod,
    release: (data: DataTransfer) => void, input?: HTMLInputElement) {
    const inspect = active.check;
    if (!inspect) return;
    const page = location.href;
    const openedAt = visit;
    const activity = ++latest;
    const ticket = {};
    if (input) pendingSelections.set(input, ticket);
    const notify = (status: GateStatus, rule?: RuleMetadata) => {
      if (status === 'blocked' || status === 'unavailable' || activity === latest) gate(status, method, rule);
    };
    notify('checking');
    void inspect(files).catch((): UploadCheck => ({ kind: 'unavailable' })).then((outcome) => {
      if (input && pendingSelections.get(input) !== ticket) return;
      if (input) pendingSelections.delete(input);
      if (visit !== openedAt || location.href !== page || policy()?.scope !== active.scope || (target instanceof Node && !target.isConnected)) {
        notify('retry');
        return;
      }
      if (outcome.kind === 'blocked') notify('blocked', outcome.rule);
      else if (outcome.kind === 'unavailable') notify('unavailable');
      else {
        try {
          const data = new DataTransfer();
          for (const file of outcome.files) {
            if (!data.items.add(file)) throw new Error('Chrome could not reopen the inspected file.');
          }
          release(data);
          notify('released');
        } catch {
          notify('retry');
        }
      }
    });
  }

  function replaceFiles(input: HTMLInputElement, files: FileList) {
    if (input.type !== 'file' || input.disabled) throw new Error('The original file input is unavailable.');
    input.files = files;
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function picker(event: Event) {
    if (!event.isTrusted) return;
    const input = event.composedPath()[0];
    if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
    const pending = pendingChange.get(input);
    pendingChange.delete(input);
    if (event.type === 'cancel') return;
    if (nativeDrops.has(input)) return;
    if (event.type === 'change' && pending !== undefined) {
      if (pending) hold(event);
      return;
    }
    const active = policy();
    if (!active || !input.files?.length) return;
    const files = Array.from(input.files);
    pendingSelections.delete(input);
    const decision = uploadDecision(active.filter, files);
    const held = decision === 'block' || !!active.check;
    if (event.type === 'input' && (held || decision || active.inspect)) pendingChange.set(input, held);
    if (held) {
      hold(event);
      input.value = '';
    }
    report(decision, 'picker');
    if (decision === 'block') return;
    if (active.check) check(active, input, files, 'picker', (data) => {
      if (input.files?.length) throw new Error('The file input selection changed.');
      replaceFiles(input, data.files);
    }, input);
    else active.inspect?.(files, 'picker');
  }

  window.addEventListener('input', picker, true);
  window.addEventListener('change', picker, true);
  window.addEventListener('cancel', picker, true);
  window.addEventListener('dragover', (event) => {
    if (!event.isTrusted || !event.dataTransfer?.types.includes('Files')) return;
    const active = policy();
    if (active?.filter?.mode === 'block' || active?.check) event.preventDefault();
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
    const target = event.composedPath()[0];
    const input = method === 'drop' && target instanceof HTMLInputElement && target.type === 'file' ? target : undefined;
    if (input) pendingSelections.delete(input);
    if (decision === 'block' || active.check) hold(event);
    else if ((decision || active.inspect) && input) {
      // A native drop onto a file input can also produce input and change in the same task.
      nativeDrops.add(input);
      window.setTimeout(() => nativeDrops.delete(input), 0);
    }
    report(decision, method);
    if (decision === 'block') return;
    if (active.check && target) {
      const directory = method === 'drop' && Array.from(data.items).some((item) => item.webkitGetAsEntry()?.isDirectory);
      const inspectionFiles = directory ? [{ name: '', type: '' }] : files;
      check(active, target, inspectionFiles, method, (transfer) => {
        const init = { bubbles: true, cancelable: true, composed: true };
        if (method === 'paste') target.dispatchEvent(new ClipboardEvent('paste', { ...init, clipboardData: transfer }));
        else {
          const { clientX, clientY, screenX, screenY, ctrlKey, metaKey, shiftKey, altKey } = event as DragEvent;
          const handled = !target.dispatchEvent(new DragEvent('drop', {
            ...init, clientX, clientY, screenX, screenY, ctrlKey, metaKey, shiftKey, altKey, dataTransfer: transfer,
          }));
          if (input && !handled && input.isConnected) {
            const selected = new DataTransfer();
            for (const file of Array.from(transfer.files).slice(0, input.multiple ? undefined : 1)) selected.items.add(file);
            replaceFiles(input, selected.files);
          }
        }
      }, input);
    } else active.inspect?.(files.filter((file): file is File => file instanceof File), method);
  }
  window.addEventListener('drop', (event) => transfer(event, event.dataTransfer, 'drop'), true);
  window.addEventListener('paste', (event) => {
    transfer(event, event.clipboardData, 'paste');
  }, true);
}
