// This is the code that runs for every request to wall.marketing.
// Static site + whoami + checkin (unchanged) + new image generate/history
// endpoints, all in one place.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- Cloudflare Access identity check ---
    if (url.pathname === '/api/whoami') {
      const email = request.headers.get('Cf-Access-Authenticated-User-Email');
      const jwt = request.headers.get('Cf-Access-Jwt-Assertion');
      return new Response(
        JSON.stringify({ email: email || null, hasJwt: Boolean(jwt) }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // --- ESP32 check-in: telemetry history ---
    if (url.pathname === '/api/checkin') {
      const params = url.searchParams;
      const deviceId = params.get('device_id');

      if (!deviceId) {
        return new Response(
          JSON.stringify({ error: 'device_id is required' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }

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

      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Images: list history ---
    if (url.pathname === '/api/images' && request.method === 'GET') {
      const limitParam = url.searchParams.get('limit');
      const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 200) : 50;

      const { results } = await env.DB.prepare(
        `SELECT id, number, r2_key, created_at, byte_size
           FROM images ORDER BY id DESC LIMIT ?`
      ).bind(limit).all();

      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Images: generate a new one (admin page sends the already-packed
    //     raw bytes; this just stores them) ---
    if (url.pathname === '/api/images' && request.method === 'POST') {
      const number = parseInt(url.searchParams.get('number') ?? '', 10);
      if (!Number.isFinite(number)) {
        return new Response(
          JSON.stringify({ error: 'number query param is required' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }

      const bytes = await request.arrayBuffer();
      if (bytes.byteLength === 0) {
        return new Response(
          JSON.stringify({ error: 'empty body' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }

      const r2Key = `images/${Date.now()}-${number}.bin`;
      await env.IMAGES.put(r2Key, bytes);

      const insertResult = await env.DB.prepare(
        `INSERT INTO images (number, r2_key, byte_size) VALUES (?, ?, ?)`
      ).bind(number, r2Key, bytes.byteLength).run();

      return new Response(
        JSON.stringify({
          id: insertResult.meta.last_row_id,
          number,
          r2_key: r2Key,
          byte_size: bytes.byteLength,
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // --- Images: raw bytes for the most recent one (this is what the
    //     ESP32 will eventually poll once the device side is built) ---
    if (url.pathname === '/api/images/latest/raw' && request.method === 'GET') {
      const row = await env.DB.prepare(
        `SELECT r2_key FROM images ORDER BY id DESC LIMIT 1`
      ).first();

      if (!row) return new Response('No images yet', { status: 404 });

      const object = await env.IMAGES.get(row.r2_key);
      if (!object) return new Response('Image data missing from storage', { status: 404 });

      return new Response(object.body, {
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }

    // --- Images: raw bytes for one specific historical entry (used by
    //     the admin page's "Preview" button) ---
    const rawMatch = url.pathname.match(/^\/api\/images\/(\d+)\/raw$/);
    if (rawMatch && request.method === 'GET') {
      const id = parseInt(rawMatch[1], 10);
      const row = await env.DB.prepare(
        `SELECT r2_key FROM images WHERE id = ?`
      ).bind(id).first();

      if (!row) return new Response('Not found', { status: 404 });

      const object = await env.IMAGES.get(row.r2_key);
      if (!object) return new Response('Image data missing from storage', { status: 404 });

      return new Response(object.body, {
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }

    // Everything else: serve the static site exactly as before.
    return env.ASSETS.fetch(request);
  },
};