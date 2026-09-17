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

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function parseDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : null;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function verifyStripeSignature(payload, signature, secret) {
  const parts = Object.fromEntries(signature.split(',').map((part) => part.split('=')));
  const timestamp = Number(parts.t);
  const received = parts.v1;
  if (!Number.isFinite(timestamp) || !received || Math.abs(Date.now() / 1000 - timestamp) > 300) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signed = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${payload}`));
  const expected = Array.from(new Uint8Array(signed), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return timingSafeEqual(expected, received);
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

    // --- Images: upload a packed bin file from the admin device row ---
    const deviceImageUploadMatch = url.pathname.match(/^\/api\/devices\/([^/]+)\/image$/);
    if (deviceImageUploadMatch && request.method === 'POST') {
      const bytes = await request.arrayBuffer();
      const expectedBytes = 800 * 480 / 2;
      if (bytes.byteLength !== expectedBytes) {
        return new Response(JSON.stringify({ error: `image must be exactly ${expectedBytes} bytes` }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const deviceId = decodeURIComponent(deviceImageUploadMatch[1]);
      const device = await env.DB.prepare(
        `SELECT device_id FROM devices WHERE device_id = ?`
      ).bind(deviceId).first();
      if (!device) return new Response(JSON.stringify({ error: 'device not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });

      const latest = await env.DB.prepare(`SELECT COALESCE(MAX(number), 0) AS number FROM images`).first();
      const number = Number(latest?.number || 0) + 1;
      const r2Key = `images/${Date.now()}-${number}.bin`;
      await env.IMAGES.put(r2Key, bytes);
      const insertResult = await env.DB.prepare(
        `INSERT INTO images (number, r2_key, byte_size) VALUES (?, ?, ?)`
      ).bind(number, r2Key, bytes.byteLength).run();

      return new Response(JSON.stringify({
        ok: true,
        id: insertResult.meta.last_row_id,
        number,
        byte_size: bytes.byteLength,
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // --- Images: the image most recently reported by one device ---
    const deviceImageMatch = url.pathname.match(/^\/api\/devices\/([^/]+)\/image$/);
    if (deviceImageMatch && request.method === 'GET') {
      const deviceId = decodeURIComponent(deviceImageMatch[1]);
      const checkin = await env.DB.prepare(
        `SELECT image_hash FROM checkins WHERE device_id = ? ORDER BY id DESC LIMIT 1`
      ).bind(deviceId).first();
      const imageIdMatch = checkin?.image_hash?.match(/^img-(\d+)$/);
      if (!imageIdMatch) return new Response('No current image reported', { status: 404 });

      const image = await env.DB.prepare(
        `SELECT r2_key FROM images WHERE id = ?`
      ).bind(parseInt(imageIdMatch[1], 10)).first();
      if (!image) return new Response('Image not found', { status: 404 });

      const object = await env.IMAGES.get(image.r2_key);
      if (!object) return new Response('Image data missing from storage', { status: 404 });
      return new Response(object.body, {
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }

    // --- Google Maps browser configuration for the admin map ---
    if (url.pathname === '/api/maps-config' && request.method === 'GET') {
      if (!env.GOOGLE_MAPS_BROWSER_KEY) {
        return new Response(JSON.stringify({ error: 'Google Maps API key is not configured' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ key: env.GOOGLE_MAPS_BROWSER_KEY }), {
        headers: { 'Content-Type': 'application/json' },
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

      if (!env.GOOGLE_MAPS_SERVER_KEY) {
        return new Response(JSON.stringify({ error: 'Google Maps API key is not configured' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const geocodeUrl = new URL('https://maps.googleapis.com/maps/api/place/autocomplete/json');
      geocodeUrl.searchParams.set('input', query);
      geocodeUrl.searchParams.set('types', 'establishment|geocode');
      geocodeUrl.searchParams.set('key', env.GOOGLE_MAPS_SERVER_KEY);
      const geocodeResponse = await fetch(geocodeUrl);
      if (!geocodeResponse.ok) {
        return new Response(JSON.stringify({ error: 'location search unavailable' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const result = await geocodeResponse.json();
      if (result.status !== 'OK' && result.status !== 'ZERO_RESULTS') {
        return new Response(JSON.stringify({ error: 'location search unavailable' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify((result.predictions || []).map((prediction) => ({
        label: prediction.description,
        place_id: prediction.place_id,
      }))), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Structured address details for the checkout invoice form ---
    if (url.pathname === '/api/location-details' && request.method === 'GET') {
      const placeId = (url.searchParams.get('place_id') || '').trim();
      if (!placeId || placeId.length > 300) return jsonResponse({ error: 'place_id is required' }, 400);
      if (!env.GOOGLE_MAPS_SERVER_KEY) return jsonResponse({ error: 'Google Maps API key is not configured' }, 503);

      const detailsUrl = new URL('https://maps.googleapis.com/maps/api/place/details/json');
      detailsUrl.searchParams.set('place_id', placeId);
      detailsUrl.searchParams.set('fields', 'formatted_address,address_components');
      detailsUrl.searchParams.set('key', env.GOOGLE_MAPS_SERVER_KEY);
      const detailsResponse = await fetch(detailsUrl);
      if (!detailsResponse.ok) return jsonResponse({ error: 'location details unavailable' }, 502);
      const details = await detailsResponse.json();
      if (details.status !== 'OK' || !details.result) return jsonResponse({ error: 'location details unavailable' }, 502);

      const components = Object.fromEntries((details.result.address_components || []).flatMap((component) =>
        component.types.map((type) => [type, component.long_name])
      ));
      return jsonResponse({
        address: details.result.formatted_address || '',
        city: components.locality || components.postal_town || components.administrative_area_level_2 || '',
        postcode: components.postal_code || '',
        country: components.country || '',
      });
    }

    // --- Public site map: location and display metadata only ---
    if (url.pathname === '/api/sites' && request.method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT device_id, site_name, site_location, daily_cost_usd, site_latitude, site_longitude, last_seen_at
           FROM devices
          WHERE site_latitude IS NOT NULL AND site_longitude IS NOT NULL
          ORDER BY site_name, device_id`
      ).all();

      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Orders: save the booking before starting payment ---
    if (url.pathname === '/api/orders' && request.method === 'POST') {
      const form = await request.formData();
      const campaignName = String(form.get('campaign_name') || '').trim();
      const contactEmail = String(form.get('contact_email') || '').trim().toLowerCase();
      const invoiceRequired = form.get('invoice_required') === '1';
      const invoiceDetails = {
        businessName: String(form.get('business_name') || '').trim(),
        businessRegistrationNumber: String(form.get('business_registration_number') || '').trim(),
        taxNumber: String(form.get('tax_number') || '').trim(),
        contactName: String(form.get('invoice_contact_name') || '').trim(),
        phone: String(form.get('invoice_phone') || '').trim(),
        address: String(form.get('invoice_address') || '').trim(),
        city: String(form.get('invoice_city') || '').trim(),
        postcode: String(form.get('invoice_postcode') || '').trim(),
        country: String(form.get('invoice_country') || '').trim(),
      };
      const startDate = parseDate(form.get('start_date'));
      const endDate = parseDate(form.get('end_date'));
      let deviceIds;
      try {
        deviceIds = JSON.parse(String(form.get('device_ids') || '[]'));
      } catch {
        return jsonResponse({ error: 'device_ids must be valid JSON' }, 400);
      }
      if (!campaignName || campaignName.length > 200 || !contactEmail || contactEmail.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail) || !startDate || !endDate || !Array.isArray(deviceIds) || !deviceIds.length || deviceIds.length > 100) {
        return jsonResponse({ error: 'campaign, contact email, dates, and at least one device are required' }, 400);
      }
      if (invoiceRequired && Object.values(invoiceDetails).some((value) => !value || value.length > 200)) {
        return jsonResponse({ error: 'all invoice details are required' }, 400);
      }

      const start = new Date(`${startDate}T00:00:00Z`);
      const end = new Date(`${endDate}T00:00:00Z`);
      const days = Math.round((end - start) / 86400000);
      if (!Number.isFinite(days) || days < 5) return jsonResponse({ error: 'booking must be at least 5 days' }, 400);

      const placeholders = deviceIds.map(() => '?').join(', ');
      const { results: devices } = await env.DB.prepare(
        `SELECT device_id, daily_cost_usd FROM devices WHERE device_id IN (${placeholders})`
      ).bind(...deviceIds).all();
      if (devices.length !== deviceIds.length) return jsonResponse({ error: 'one or more devices are unavailable' }, 409);

      const dailyRate = devices.reduce((total, device) => total + Number(device.daily_cost_usd || 0), 0);
      const totalUsd = Math.round(dailyRate * days * 100) / 100;
      const orderId = crypto.randomUUID();
      const checkoutCode = crypto.randomUUID().replaceAll('-', '').slice(0, 10).toUpperCase();
      const advertisement = form.get('advertisement');
      if (!(advertisement instanceof File)) return jsonResponse({ error: 'advertisement file is required' }, 400);
      const expectedBytes = 800 * 480 / 2;
      if (advertisement.size !== expectedBytes) return jsonResponse({ error: `advertisement must be exactly ${expectedBytes} bytes` }, 400);
      const filename = String(form.get('advertisement_filename') || `${checkoutCode}.bin`).replace(/[^A-Za-z0-9._-]/g, '_');
      const r2Key = `orders/${orderId}/${filename}`;

      await env.DB.prepare(
          `INSERT INTO orders (
             id, checkout_code, campaign_name, contact_email, start_date, end_date,
             daily_rate_usd, total_usd, invoice_required, business_name,
             business_registration_number, tax_number, invoice_contact_name,
             invoice_phone, invoice_address, invoice_city, invoice_postcode, invoice_country
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          orderId, checkoutCode, campaignName, contactEmail, startDate, endDate,
          dailyRate, totalUsd, invoiceRequired ? 1 : 0,
          invoiceDetails.businessName || null, invoiceDetails.businessRegistrationNumber || null,
          invoiceDetails.taxNumber || null, invoiceDetails.contactName || null,
          invoiceDetails.phone || null, invoiceDetails.address || null,
          invoiceDetails.city || null, invoiceDetails.postcode || null, invoiceDetails.country || null
        ).run();
      await env.DB.batch(devices.map((device) => env.DB.prepare(
        `INSERT INTO order_items (order_id, device_id, daily_rate_usd, start_date, end_date) VALUES (?, ?, ?, ?, ?)`
      ).bind(orderId, device.device_id, Number(device.daily_cost_usd || 0), startDate, endDate)));
      await env.IMAGES.put(r2Key, await advertisement.arrayBuffer());
      await env.DB.prepare(
        `INSERT INTO advertisements (order_id, filename, r2_key, byte_size) VALUES (?, ?, ?, ?)`
      ).bind(orderId, filename, r2Key, advertisement.size).run();

      if (!env.STRIPE_SECRET_KEY) return jsonResponse({ order_id: orderId, checkout_code: checkoutCode, error: 'payment is not configured' }, 503);
      const origin = new URL(request.url).origin;
      const stripeParams = new URLSearchParams();
      stripeParams.set('mode', 'payment');
      stripeParams.set('customer_email', contactEmail);
      stripeParams.set('success_url', `${origin}/payment-success.html?order=${encodeURIComponent(orderId)}`);
      stripeParams.set('cancel_url', `${origin}/payment-cancelled.html?order=${encodeURIComponent(orderId)}`);
      stripeParams.set('client_reference_id', orderId);
      stripeParams.set('line_items[0][price_data][currency]', 'usd');
      stripeParams.set('line_items[0][price_data][unit_amount]', String(Math.round(totalUsd * 100)));
      stripeParams.set('line_items[0][price_data][product_data][name]', `WALL advertising: ${campaignName}`);
      stripeParams.set('line_items[0][quantity]', '1');
      stripeParams.set('metadata[order_id]', orderId);
      const stripeResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: stripeParams,
      });
      const stripeSession = await stripeResponse.json();
      if (!stripeResponse.ok || !stripeSession.id || !stripeSession.url) {
        return jsonResponse({ order_id: orderId, checkout_code: checkoutCode, error: 'payment session could not be created' }, 502);
      }
      await env.DB.prepare(
        `UPDATE orders SET stripe_checkout_session_id = ?, updated_at = datetime('now') WHERE id = ?`
      ).bind(stripeSession.id, orderId).run();
      return jsonResponse({ order_id: orderId, checkout_code: checkoutCode, checkout_url: stripeSession.url });
    }

    // --- Stripe: payment is authoritative only after webhook verification ---
    if (url.pathname === '/api/stripe/webhook' && request.method === 'POST') {
      if (!env.STRIPE_WEBHOOK_SECRET) return new Response('Webhook not configured', { status: 503 });
      const payload = await request.text();
      const signature = request.headers.get('Stripe-Signature') || '';
      if (!(await verifyStripeSignature(payload, signature, env.STRIPE_WEBHOOK_SECRET))) return new Response('Invalid signature', { status: 400 });
      const event = JSON.parse(payload);
      if ((event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') && event.data.object.payment_status === 'paid') {
        const session = event.data.object;
        const orderId = session.metadata?.order_id || session.client_reference_id;
        if (orderId) {
          await env.DB.prepare(
            `UPDATE orders SET status = 'paid', customer_email = ?, stripe_payment_intent_id = ?, updated_at = datetime('now')
             WHERE id = ? AND status = 'pending_payment'`
          ).bind(session.customer_details?.email || null, session.payment_intent || null, orderId).run();
        }
      }
      return jsonResponse({ received: true });
    }

    // --- Orders: admin view with booking, payment, invoice, and device details ---
    if (url.pathname === '/api/orders' && request.method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT o.id, o.checkout_code, o.campaign_name, o.contact_email,
                o.start_date, o.end_date, o.daily_rate_usd, o.total_usd,
                o.status, o.invoice_required, o.business_name,
                o.business_registration_number, o.tax_number,
                o.invoice_contact_name, o.invoice_phone, o.invoice_address,
                o.invoice_city, o.invoice_postcode, o.invoice_country,
                o.stripe_checkout_session_id, o.stripe_payment_intent_id,
                o.created_at, o.updated_at,
                group_concat(oi.device_id, ', ') AS device_ids,
                a.filename AS advertisement_filename
           FROM orders o
           LEFT JOIN order_items oi ON oi.order_id = o.id
           LEFT JOIN advertisements a ON a.order_id = o.id
          GROUP BY o.id
          ORDER BY o.created_at DESC`
      ).all();
      return jsonResponse(results);
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
           d.daily_cost_usd,
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

      const dailyCostUsd = Number(body.daily_cost_usd);
      if (!Number.isFinite(dailyCostUsd) || dailyCostUsd < 0 || dailyCostUsd > 100000 || Math.round(dailyCostUsd * 100) !== dailyCostUsd * 100) {
        return new Response(JSON.stringify({ error: 'daily_cost_usd must be a non-negative amount with at most two decimal places' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const siteName = body.site_name.trim() || null;
      const siteLocation = body.site_location.trim() || null;
      let latitude = null;
      let longitude = null;
      if (siteLocation) {
        if (!env.GOOGLE_MAPS_SERVER_KEY) {
          return new Response(JSON.stringify({ error: 'Google Maps API key is not configured' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        const geocodeUrl = new URL('https://maps.googleapis.com/maps/api/geocode/json');
        geocodeUrl.searchParams.set('address', siteLocation);
        geocodeUrl.searchParams.set('key', env.GOOGLE_MAPS_SERVER_KEY);
        const geocodeResponse = await fetch(geocodeUrl);
        if (!geocodeResponse.ok) {
          return new Response(JSON.stringify({ error: 'could not look up that site location' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        const result = await geocodeResponse.json();
        if (result.status === 'ZERO_RESULTS' || !result.results?.length) {
          return new Response(JSON.stringify({ error: 'site location was not found' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (result.status !== 'OK') {
          return new Response(JSON.stringify({ error: 'could not look up that site location' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        latitude = Number(result.results[0].geometry.location.lat);
        longitude = Number(result.results[0].geometry.location.lng);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
          return new Response(JSON.stringify({ error: 'site location returned invalid coordinates' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }
      const result = await env.DB.prepare(
        `UPDATE devices
            SET site_name = ?, site_location = ?, daily_cost_usd = ?, site_latitude = ?, site_longitude = ?
          WHERE device_id = ?`
      ).bind(siteName, siteLocation, dailyCostUsd, latitude, longitude, deviceId).run();

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
        daily_cost_usd: dailyCostUsd,
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