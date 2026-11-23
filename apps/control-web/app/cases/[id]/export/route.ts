import { ApiError, controlApi } from '../../../../lib/api';
import { sessionToken } from '../../../../lib/session';
import { isTriageId } from '../../../../lib/triage';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export an incident case.', { status: 401, headers });
  const { id } = await context.params;
  if (!isTriageId(id)) return new Response('Case unavailable.', { status: 404, headers });
  try {
    const upstream = await controlApi.exportCase(token, id);
    return new Response(upstream.body, { headers: { ...headers, 'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="zekvar-case-${id}.json"` } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not export this case.', { status: error.status, headers });
  }
}
