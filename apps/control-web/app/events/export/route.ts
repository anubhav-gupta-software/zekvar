import { ApiError, controlApi } from '../../../lib/api';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };
const filterKeys = new Set(['appId', 'decision', 'since', 'until', 'installationId']);

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export security events.', { status: 401, headers });
  const filters = new URL(request.url).searchParams;
  if ([...filters.keys()].some((key) => !filterKeys.has(key) || filters.getAll(key).length > 1)) {
    return new Response('Invalid security event filters.', { status: 400, headers });
  }
  try {
    const signal = AbortSignal.any([request.signal, AbortSignal.timeout(60_000)]);
    const upstream = await controlApi.exportEvents(token, filters, signal);
    return new Response(upstream.body, {
      headers: {
        ...headers,
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="zekvar-security-events.json"',
      },
    });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not export security events.', { status: error.status, headers });
  }
}
