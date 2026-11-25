import { completeSsoRequest } from '../../../../../lib/sso';

export async function GET(request: Request, { params }: { params: Promise<{ organization: string }> }) {
  return completeSsoRequest(request, (await params).organization);
}
