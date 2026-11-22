import { finishSso, ssoOptions } from '../../../../lib/sso';

const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };

export async function GET(request: Request) {
  const settings = ssoOptions();
  if (!settings) return new Response(null, { status: 404, headers });

  try {
    await finishSso(settings, new URL(request.url).searchParams);
  } catch {
    return new Response(null, { status: 303, headers: { ...headers, Location: '/?signIn=sso-error' } });
  }

  // Complete the cross-site navigation before using the Strict session cookie on the dashboard.
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=/"><title>Signed in to Control</title><main><h1>Signed in to Control</h1><a href="/">Continue to Control</a></main></html>`, {
    headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" },
  });
}
