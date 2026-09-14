// This is the actual code that runs for every request to wall.marketing.
// For one specific path (/api/whoami) it runs its own logic. For every
// other path, it just hands the request off to serve your static files
// exactly as before (admin/index.html, index.html, sites.html, etc).

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/whoami') {
      // Cloudflare Access injects these headers into requests it lets
      // through. If Access isn't set up on this path yet, they'll just
      // be empty, and the admin page will say so.
      const email = request.headers.get('Cf-Access-Authenticated-User-Email');
      const jwt = request.headers.get('Cf-Access-Jwt-Assertion');

      return new Response(
        JSON.stringify({
          email: email || null,
          hasJwt: Boolean(jwt),
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Everything else: serve the static site exactly as before.
    return env.ASSETS.fetch(request);
  },
};
