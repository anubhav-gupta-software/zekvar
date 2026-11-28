import { ApiError, controlApi } from '../../../../../lib/api';
import { isId } from '../../../../../lib/control';
import { sessionToken } from '../../../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin' };

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to download an invoice.', { status: 401, headers });
  const { id } = await context.params;
  if (!isId(id)) return new Response('Invoice unavailable.', { status: 404, headers });
  try {
    const upstream = await controlApi.exportBillingInvoice(token, id);
    const disposition = upstream.headers.get('Content-Disposition') ?? `attachment; filename="zekvar-invoice-${id}.json"`;
    return new Response(upstream.body, { headers: { ...headers, 'Content-Type': 'application/json', 'Content-Disposition': disposition } });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not export this invoice.', { status: error.status, headers });
  }
}
