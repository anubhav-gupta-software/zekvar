import { ApiError, controlApi } from '../../../../lib/api';
import { sessionToken } from '../../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export rollout impact.', { status: 401, headers });
  try {
    const report = await controlApi.policyImpact(token, new URL(request.url).searchParams);
    return Response.json(report, { headers: { ...headers, 'Content-Disposition': 'attachment; filename="zekvar-policy-rollout-impact.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response(error.status === 409 ? 'The reviewed policy version changed.' : 'Control could not export rollout impact.',
      { status: error.status, headers });
  }
}
