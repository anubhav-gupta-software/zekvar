import { exceptionKey, exceptionWindowMs, isExceptionTarget, promptExceptionLimit, type PromptExceptionLease } from '../../../contracts/policy/prompt-exceptions';
import { isRecord } from './protocol';

const freshnessMs = 45_000;

type ClockSample = { wallMs: number; monotonicMs: number };
export type BrowserLease = PromptExceptionLease & { clock: ClockSample };

// The service worker and its content scripts share the browser's monotonic clock.
export function sampleClock(): ClockSample {
  return { wallMs: Date.now(), monotonicMs: performance.timeOrigin + performance.now() };
}

export function leaseTime(lease: BrowserLease, now = sampleClock()) {
  const wall = now.wallMs - lease.clock.wallMs;
  const monotonic = now.monotonicMs - lease.clock.monotonicMs;
  if (wall < 0 || monotonic < 0 || Math.abs(wall - monotonic) > 2000) return;
  const elapsed = Math.ceil(Math.max(wall, monotonic));
  if (elapsed < freshnessMs) return lease.serverTimeMs + elapsed;
}

export function readExceptionLease(value: unknown, clock: ClockSample): BrowserLease | undefined {
  if (!isRecord(value) || typeof value.serverTimeMs !== 'number' || !Number.isSafeInteger(value.serverTimeMs) ||
      value.serverTimeMs <= 0 || value.serverTimeMs >= 8.64e15 - exceptionWindowMs ||
      !Array.isArray(value.grants) || value.grants.length < 1 || value.grants.length > promptExceptionLimit) return;
  const serverTimeMs = value.serverTimeMs;
  const grants: BrowserLease['grants'] = [];
  for (const item of value.grants) {
    if (!isRecord(item) || !isExceptionTarget(item.appId, item.ruleId) ||
        typeof item.expiresAtMs !== 'number' || !Number.isSafeInteger(item.expiresAtMs) ||
        item.expiresAtMs <= serverTimeMs || item.expiresAtMs > serverTimeMs + exceptionWindowMs) return;
    const grant = { appId: item.appId, ruleId: item.ruleId, expiresAtMs: item.expiresAtMs } as BrowserLease['grants'][number];
    if (grants.some((previous) => exceptionKey(previous) === exceptionKey(grant))) return;
    grants.push(grant);
  }
  return { clock, serverTimeMs, grants };
}
