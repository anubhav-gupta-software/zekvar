import { completeSsoRequest } from '../../../../lib/sso';

export function GET(request: Request) {
  return completeSsoRequest(request);
}
