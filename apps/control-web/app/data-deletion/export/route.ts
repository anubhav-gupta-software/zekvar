import { ApiError, controlApi } from '../../../lib/api';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

// Streams the owner-only organization export from Control without buffering it in the dashboard.
export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export organization data.', { status: 401, headers });
  try {
    const response = await controlApi.organizationExport(token, AbortSignal.any([request.signal, AbortSignal.timeout(15 * 60_000)]));
    return new Response(response.body, { headers: { ...headers, 'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="zekvar-organization-export.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not export the organization data.', { status: error.status, headers });
  }
}
