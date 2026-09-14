// Cloudflare Pages Function — GET /api/whoami
//
// Cloudflare Access injects headers into every request it lets through:
//   Cf-Access-Authenticated-User-Email  -> the logged-in user's email
//   Cf-Access-Jwt-Assertion             -> the signed JWT proving the login
//
// This function just echoes those back so the admin page can prove Access
// identity is actually flowing through, not just that the page loaded.

export async function onRequestGet(context) {
  const { request } = context;

  const email = request.headers.get('Cf-Access-Authenticated-User-Email');
  const jwt = request.headers.get('Cf-Access-Jwt-Assertion');

  return new Response(
    JSON.stringify({
      email: email || null,
      hasJwt: Boolean(jwt),
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );
}