import { beginSso, ssoMode, ssoOptions } from '../../../../lib/sso';

const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

export async function GET(request: Request) {
  const mode = ssoMode();
  if (!mode) return new Response(null, { status: 404, headers });
  try {
    const organizations = new URL(request.url).searchParams.getAll('organization');
    if (organizations.length !== (mode === 'organization' ? 1 : 0)) throw new Error('Invalid organization selection.');
    const settings = ssoOptions(organizations[0]);
    if (!settings) throw new Error('Invalid organization selection.');
    const destination = await beginSso(settings);
    return new Response(null, { status: 303, headers: { ...headers, Location: destination.href } });
  } catch {
    return new Response(null, { status: 303, headers: { ...headers, Location: '/?signIn=sso-error' } });
  }
}
