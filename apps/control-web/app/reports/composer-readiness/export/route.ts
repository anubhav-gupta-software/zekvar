import { ApiError, controlApi } from '../../../../lib/api';
import { sessionToken } from '../../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export composer readiness.', { status: 401, headers });
  try {
    const report = await controlApi.composerReadiness(token, new URL(request.url).searchParams);
    return Response.json(report, { headers: { ...headers, 'Content-Disposition': 'attachment; filename="zekvar-composer-readiness.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    const message = error.status === 400 ? 'Apply valid Browser health filters before exporting.' : 'Control could not export composer readiness.';
    return new Response(message, { status: error.status, headers });
  }
}
