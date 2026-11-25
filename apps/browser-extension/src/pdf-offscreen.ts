import { preferredFileMatch } from '../../../contracts/policy/file-inspection';
import type { PromptPolicy, RuleMetadata } from '../../../contracts/policy/prompt';
import { decodeAttachment, inspectionUnavailable, isInspectionPayload, maxAttachmentBytes,
  type AttachmentInspection, type AttachmentKind } from './attachment-inspection';

declare const SERVICE_WORKER_PATH: string;
const inspectionMs = 2200;
let active = 0;
let imageActive = false;

async function inspect(kind: AttachmentKind, encoded: string, detectors: PromptPolicy, signal: AbortSignal): Promise<AttachmentInspection> {
  if (signal.aborted || active >= 2 || (kind === 'image' && imageActive)) return inspectionUnavailable;
  active++;
  if (kind === 'image') imageActive = true;
  let job: Worker | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let match: RuleMetadata | undefined;
  try {
    const bytes = decodeAttachment(encoded);
    if (bytes.length > maxAttachmentBytes) return inspectionUnavailable;
    const worker = job = new Worker(chrome.runtime.getURL(kind === 'image' ? 'ocr-job.js' : 'pdf-job.js'));
    return await new Promise<AttachmentInspection>((resolve) => {
      const unavailable = () => resolve({ complete: false, match });
      timer = setTimeout(unavailable, inspectionMs);
      signal.addEventListener('abort', unavailable, { once: true });
      worker.onmessage = ({ data }) => {
        if (!data) return;
        match = preferredFileMatch(match, data.match);
        if (typeof data.complete === 'boolean') resolve({ complete: data.complete, match });
      };
      worker.onerror = (event) => {
        event.preventDefault();
        unavailable();
      };
      worker.postMessage({ bytes, detectors }, [bytes.buffer]);
    });
  } catch {
    return { complete: false, match };
  } finally {
    clearTimeout(timer);
    job?.terminate();
    if (kind === 'image') imageActive = false;
    active--;
  }
}

chrome.runtime.onConnect.addListener((port) => {
  const kind = port.name === 'inspect-offscreen-image' ? 'image' : port.name === 'inspect-offscreen-pdf' ? 'pdf' : undefined;
  if (!kind) return;
  const sender = port.sender;
  if (sender?.id !== chrome.runtime.id || sender.tab || sender.url !== new URL(SERVICE_WORKER_PATH, location.href).href) {
    port.disconnect();
    return;
  }
  let started = false;
  const connection = new AbortController();
  port.onDisconnect.addListener(() => connection.abort());
  port.onMessage.addListener((message) => {
    if (started || !isInspectionPayload(kind, message?.encoded)) return;
    started = true;
    void inspect(kind, message.encoded, message.detectors, connection.signal).then((result) => {
      if (!connection.signal.aborted) port.postMessage(result);
    }).catch(() => undefined);
  });
});
