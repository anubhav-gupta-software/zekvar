import { ApiError, controlApi } from '../../../lib/api';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

export async function GET() {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to download the deletion receipt.', { status: 401, headers });
  try {
    const response = await controlApi.deletionReceipt(token);
    return new Response(await response.text(), { headers: { ...headers, 'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="zekvar-deletion-receipt.json"' } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not provide a deletion receipt.', { status: error.status, headers });
  }
}
