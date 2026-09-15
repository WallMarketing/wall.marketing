// This is the code that runs for every request to wall.marketing.
// Three paths get their own handling; everything else falls through to
// serving your static site exactly as before.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- Cloudflare Access identity check (unchanged from before) ---
    if (url.pathname === '/api/whoami') {
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

    // --- ESP32 check-in: telemetry + (eventually) image/OTA response ---
    if (url.pathname === '/api/checkin') {
      const params = url.searchParams;
      const deviceId = params.get('device_id');

      // Without a device_id we have nowhere to file this — reject early
      // rather than writing a row we can't attribute to anything.
      if (!deviceId) {
        return new Response(
          JSON.stringify({ error: 'device_id is required' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // Every value below is untrusted input from the network. Parsing
      // with parseInt and falling back to null (rather than trusting
      // whatever string showed up) keeps a malformed value from causing
      // a confusing failure deeper in the query.
      const toIntOrNull = (v) => {
        const n = parseInt(v ?? '', 10);
        return Number.isFinite(n) ? n : null;
      };

      const uptime = toIntOrNull(params.get('uptime'));
      const rssi = toIntOrNull(params.get('rssi'));
      const heap = toIntOrNull(params.get('heap'));
      const errors = toIntOrNull(params.get('errors'));
      const imageHash = params.get('image_hash') || null;
      const firmwareVersion = params.get('fw') || null;

      // Two writes, sent together as a batch so they commit as one round
      // trip instead of two separate awaits:
      //   1. Append this check-in to history (never overwritten).
      //   2. Upsert the device's "last seen" row — creates it on first
      //      contact, just bumps the timestamp on every check-in after.
      //      friendly_name and target_firmware_version are admin-managed,
      //      so this deliberately never overwrites them.
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO checkins
             (device_id, uptime_seconds, rssi, free_heap, image_hash, error_count, firmware_version)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(deviceId, uptime, rssi, heap, imageHash, errors, firmwareVersion),

        env.DB.prepare(
          `INSERT INTO devices (device_id, last_seen_at)
           VALUES (?, datetime('now'))
           ON CONFLICT(device_id) DO UPDATE SET last_seen_at = datetime('now')`
        ).bind(deviceId),
      ]);

      // Placeholder response for now. Once the image pipeline and OTA
      // gating exist, this is where they'll plug in — telling the device
      // whether there's a new image or firmware to fetch. For now it just
      // confirms the check-in landed.
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Everything else: serve the static site exactly as before.
    return env.ASSETS.fetch(request);
  },
};