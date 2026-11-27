import { ApiError, controlApi } from '../../../lib/api';
import { auditFilters, auditSearchValues } from '../../../lib/audit';
import { sessionToken } from '../../../lib/session';

const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return new Response('Sign in to export the audit log.', { status: 401, headers });
  const filters = auditFilters(auditSearchValues(new URL(request.url).searchParams));
  if (!filters) return new Response('Invalid audit filters.', { status: 400, headers });
  filters.query.delete('beforeAt');
  filters.query.delete('beforeId');
  try {
    // Control records the export, with its filters and entry count, in the access log.
    const audit = await controlApi.exportAudit(token, filters.query);
    return Response.json(audit, {
      headers: { ...headers, 'Content-Disposition': 'attachment; filename="zekvar-control-audit.json"' },
    });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return new Response('Control could not export the audit log.', { status: error.status, headers });
  }
}
