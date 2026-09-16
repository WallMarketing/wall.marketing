// This is the code that runs for every request to wall.marketing.
// Static site + whoami + checkin (unchanged) + new image generate/history
// endpoints, all in one place.

// Plain === on secrets leaks timing information (a mismatch on the first
// byte returns faster than a mismatch on the last byte). This is a lot of
// ceremony for a bench-testing shared secret, but it's cheap to do right
// and it's the one check standing between the internet and this D1 table.
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

// Devices can't do a Cloudflare Access login, so /api/checkin and
// /api/images/latest/raw have to stay reachable without an Access session.
// This is the substitute: a shared secret only real devices know, sent as
// a header. Fails closed — if the secret isn't configured server-side,
// nothing gets through, rather than accidentally waving everyone in.
function isAuthorizedDevice(request, env) {
  const expected = env.DEVICE_SHARED_SECRET;
  if (!expected) return false;
  const provided = request.headers.get('X-Device-Key');
  if (!provided) return false;
  return timingSafeEqual(provided, expected);
}

function unauthorizedResponse() {
  return new Response(JSON.stringify({ error: 'unauthorized' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  });
}

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
      if (!isAuthorizedDevice(request, env)) return unauthorizedResponse();

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

    // --- Images: raw bytes for the most recent one — this is what the
    //     ESP32 actually polls. Supports If-None-Match so the device can
    //     skip re-downloading (and re-flickering the panel) when nothing
    //     has changed since its last successful fetch. ---
    if (url.pathname === '/api/images/latest/raw' && request.method === 'GET') {
      if (!isAuthorizedDevice(request, env)) return unauthorizedResponse();

      const row = await env.DB.prepare(
        `SELECT id, r2_key FROM images ORDER BY id DESC LIMIT 1`
      ).first();

      if (!row) return new Response('No images yet', { status: 404 });

      const etag = `img-${row.id}`;
      if (request.headers.get('If-None-Match') === etag) {
        return new Response(null, { status: 304, headers: { ETag: etag } });
      }

      const object = await env.IMAGES.get(row.r2_key);
      if (!object) return new Response('Image data missing from storage', { status: 404 });

      return new Response(object.body, {
        headers: { 'Content-Type': 'application/octet-stream', ETag: etag },
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

    // --- Location search for the admin site's autocomplete fields ---
    if (url.pathname === '/api/location-search' && request.method === 'GET') {
      const query = (url.searchParams.get('q') || '').trim();
      if (query.length < 3 || query.length > 200) {
        return new Response(JSON.stringify([]), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const geocodeUrl = new URL('https://nominatim.openstreetmap.org/search');
      geocodeUrl.searchParams.set('q', query);
      geocodeUrl.searchParams.set('format', 'jsonv2');
      geocodeUrl.searchParams.set('limit', '5');
      const geocodeResponse = await fetch(geocodeUrl, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'wall.marketing admin location search',
        },
      });
      if (!geocodeResponse.ok) {
        return new Response(JSON.stringify({ error: 'location search unavailable' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const matches = await geocodeResponse.json();
      return new Response(JSON.stringify(matches.map((match) => ({
        label: match.display_name,
        latitude: Number(match.lat),
        longitude: Number(match.lon),
      })).filter((match) => Number.isFinite(match.latitude) && Number.isFinite(match.longitude))), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Devices: fleet overview — most recent check-in per device,
    //     joined from `devices` (identity) and `checkins` (telemetry) ---
    if (url.pathname === '/api/devices' && request.method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT
           d.device_id,
           d.friendly_name,
           d.site_name,
           d.site_location,
           d.site_latitude,
           d.site_longitude,
           d.target_firmware_version,
           d.created_at AS device_created_at,
           d.last_seen_at,
           c.checked_in_at,
           c.uptime_seconds,
           c.rssi,
           c.free_heap,
           c.image_hash,
           c.error_count,
           c.firmware_version
         FROM devices d
         LEFT JOIN checkins c ON c.id = (
           SELECT id FROM checkins WHERE device_id = d.device_id ORDER BY id DESC LIMIT 1
         )
         ORDER BY d.last_seen_at DESC`
      ).all();

      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Devices: update the site metadata shown in the admin fleet table ---
    const deviceUpdateMatch = url.pathname.match(/^\/api\/devices\/([^/]+)$/);
    if (deviceUpdateMatch && request.method === 'PATCH') {
      const deviceId = decodeURIComponent(deviceUpdateMatch[1]);
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: 'request body must be valid JSON' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: 'request body must be a JSON object' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const fields = ['site_name', 'site_location'];
      for (const field of fields) {
        if (typeof body[field] !== 'string' || body[field].trim().length > 200) {
          return new Response(JSON.stringify({ error: `${field} must be a string of 200 characters or fewer` }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }

      const siteName = body.site_name.trim() || null;
      const siteLocation = body.site_location.trim() || null;
      let latitude = null;
      let longitude = null;
      if (siteLocation) {
        const geocodeUrl = new URL('https://nominatim.openstreetmap.org/search');
        geocodeUrl.searchParams.set('q', siteLocation);
        geocodeUrl.searchParams.set('format', 'jsonv2');
        geocodeUrl.searchParams.set('limit', '1');
        const geocodeResponse = await fetch(geocodeUrl, {
          headers: {
            Accept: 'application/json',
            'User-Agent': 'wall.marketing admin location lookup',
          },
        });
        if (!geocodeResponse.ok) {
          return new Response(JSON.stringify({ error: 'could not look up that site location' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        const matches = await geocodeResponse.json();
        if (!matches.length) {
          return new Response(JSON.stringify({ error: 'site location was not found' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        latitude = Number(matches[0].lat);
        longitude = Number(matches[0].lon);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
          return new Response(JSON.stringify({ error: 'site location returned invalid coordinates' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }
      const result = await env.DB.prepare(
        `UPDATE devices
            SET site_name = ?, site_location = ?, site_latitude = ?, site_longitude = ?
          WHERE device_id = ?`
      ).bind(siteName, siteLocation, latitude, longitude, deviceId).run();

      if (!result.meta.changes) {
        return new Response(JSON.stringify({ error: 'device not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({
        ok: true,
        site_name: siteName,
        site_location: siteLocation,
        site_latitude: latitude,
        site_longitude: longitude,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Devices: full check-in history for one device (admin page's
    //     click-through from the fleet overview row) ---
    const deviceHistoryMatch = url.pathname.match(/^\/api\/devices\/([^/]+)\/checkins$/);
    if (deviceHistoryMatch && request.method === 'GET') {
      const deviceId = decodeURIComponent(deviceHistoryMatch[1]);
      const limitParam = url.searchParams.get('limit');
      const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 200) : 50;

      const { results } = await env.DB.prepare(
        `SELECT id, checked_in_at, uptime_seconds, rssi, free_heap, image_hash, error_count, firmware_version
           FROM checkins WHERE device_id = ? ORDER BY id DESC LIMIT ?`
      ).bind(deviceId, limit).all();

      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Everything else: serve the static site exactly as before.
    return env.ASSETS.fetch(request);
  },
};