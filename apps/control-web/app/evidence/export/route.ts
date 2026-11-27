import { ApiError, controlApi } from '../../../lib/api';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };
const periods = new Set(['30', '90', '180', '365']);

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to download compliance evidence.', { status: 401, headers });
  const query = new URL(request.url).searchParams;
  const days = query.get('days') ?? '90';
  if ([...query.keys()].some((key) => key !== 'days') || query.getAll('days').length > 1 || !periods.has(days))
    return new Response('Choose a 30, 90, 180, or 365 day evidence period.', { status: 400, headers });
  try {
    const upstream = await controlApi.evidencePack(token, Number(days));
    return new Response(upstream.body, { headers: { ...headers, 'Content-Type': 'application/json',
      'Content-Disposition': upstream.headers.get('Content-Disposition') ?? 'attachment; filename="zekvar-evidence.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    const message = error.status === 403 ? 'Only the organization owner and auditors can download compliance evidence.'
      : 'Control could not prepare the evidence pack.';
    return new Response(message, { status: error.status, headers });
  }
}
