import { ApiError, controlApi } from '../../../lib/api';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export the AI enforcement report.', { status: 401, headers });
  try {
    const report = await controlApi.aiEnforcement(token, new URL(request.url).searchParams, true);
    return Response.json(report, { headers: { ...headers, 'Content-Disposition': 'attachment; filename="zekvar-ai-enforcement.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    const message = error.status === 400 ? 'Reload the report and try exporting again.' : 'Control could not export the AI enforcement report.';
    return new Response(message, { status: error.status, headers });
  }
}
