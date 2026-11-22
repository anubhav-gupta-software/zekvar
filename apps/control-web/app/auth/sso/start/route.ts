import { beginSso, ssoOptions } from '../../../../lib/sso';

const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

export async function GET() {
  const settings = ssoOptions();
  if (!settings) return new Response(null, { status: 404, headers });

  try {
    const destination = await beginSso(settings);
    return new Response(null, { status: 303, headers: { ...headers, Location: destination.href } });
  } catch {
    return new Response(null, { status: 303, headers: { ...headers, Location: '/?signIn=sso-error' } });
  }
}
