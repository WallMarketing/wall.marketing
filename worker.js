import { EmailMessage } from 'cloudflare:email';

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
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function isAdminRequest(request) {
  const hostname = new URL(request.url).hostname;
  if (hostname !== 'wall.marketing' && hostname !== 'www.wall.marketing') return false;
  return Boolean(
    request.headers.get('Cf-Access-Authenticated-User-Email') &&
    request.headers.get('Cf-Access-Jwt-Assertion')
  );
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

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function deviceTokenFromRequest(request, env, deviceId) {
  const token = request.headers.get('X-Device-Token');
  if (!token) return false;
  const device = await env.DB.prepare(
    `SELECT device_token_hash, setup_status FROM devices WHERE device_id = ?`
  ).bind(deviceId).first();
  return Boolean(device && device.setup_status !== 'disabled' && device.device_token_hash && timingSafeEqual(await sha256Hex(token), device.device_token_hash));
}

function pdfEscape(value) {
  return String(value || '').replace(/[\\()]/g, '\\$&').replace(/[^\x20-\x7E]/g, '?');
}

function buildInvoicePdf(order) {
  const lines = [
    'WALL advertising invoice',
    `Order: ${order.checkout_code}`,
    `Campaign: ${order.campaign_name}`,
    `Contact: ${order.contact_email}`,
    `Booking: ${order.start_date} to ${order.end_date}`,
    `Total: USD ${Number(order.total_usd || 0).toFixed(2)}`,
  ];
  if (order.invoice_required) {
    lines.push(
      `Business: ${order.business_name}`,
      `Registration: ${order.business_registration_number}`,
      `Tax number: ${order.tax_number}`,
      `Invoice contact: ${order.invoice_contact_name}`,
      `Phone: ${order.invoice_phone}`,
      `Address: ${order.invoice_address}, ${order.invoice_city}, ${order.invoice_postcode}, ${order.invoice_country}`
    );
  }
  const text = lines.map((line, index) => `BT /F1 ${index === 0 ? 18 : 11} Tf 54 ${750 - index * 28} Td (${pdfEscape(line)}) Tj ET`).join('\n');
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => { pdf += `${String(offset).padStart(10, '0')} 00000 n \n`; });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}

function base64Bytes(bytes) {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}

function makeEmailMessage(from, to, subject, text, pdfBytes, filename) {
  const boundary = `wall-${crypto.randomUUID()}`;
  const attachment = pdfBytes ? `--${boundary}\r\nContent-Type: application/pdf; name="${filename}"\r\nContent-Disposition: attachment; filename="${filename}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Bytes(pdfBytes)}\r\n` : '';
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
    attachment,
    `--${boundary}--`,
    '',
  ].join('\r\n');
}

async function sendOrderEmail(env, order, subject, text, pdfBytes, filename) {
  if (!env.EMAIL || !env.EMAIL_FROM || !order.contact_email) {
    console.error('Order email send skipped: email binding, sender, or recipient is missing', JSON.stringify({
      orderId: order.id,
      hasBinding: Boolean(env.EMAIL),
      hasSender: Boolean(env.EMAIL_FROM),
      hasRecipient: Boolean(order.contact_email),
    }));
    throw new Error('email sending is not configured');
  }
  const raw = makeEmailMessage(env.EMAIL_FROM, order.contact_email, subject, text, pdfBytes, filename);
  try {
    await env.EMAIL.send(new EmailMessage(env.EMAIL_FROM, order.contact_email, raw));
  } catch (error) {
    console.error('Order email send failed', JSON.stringify({
      orderId: order.id,
      recipientDomain: String(order.contact_email).split('@')[1] || null,
      message: error?.message || String(error),
    }));
    throw error;
  }
}

async function sendSuccessEmailForOrder(env, order) {
  const pdf = buildInvoicePdf(order);
  await sendOrderEmail(
    env,
    order,
    `WALL advertisement scheduled - ${order.checkout_code}`,
    `Your WALL advertisement is scheduled.\n\nOrder reference: ${order.checkout_code}\nCampaign: ${order.campaign_name}\nBooking: ${order.start_date} to ${order.end_date}\n\nYour invoice is attached as a PDF.`,
    pdf,
    `invoice-${order.checkout_code}.pdf`
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- Cloudflare Access identity check ---
    if (url.pathname === '/api/whoami') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
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

      const existingDevice = await env.DB.prepare(
        `SELECT device_token_hash, setup_status, site_name, site_location, site_latitude, site_longitude FROM devices WHERE device_id = ?`
      ).bind(deviceId).first();
      if (existingDevice?.setup_status === 'disabled') return jsonResponse({ error: 'device disabled' }, 403);
      const presentedToken = request.headers.get('X-Device-Token');
      if (existingDevice?.device_token_hash && presentedToken && !(await deviceTokenFromRequest(request, env, deviceId))) {
        return jsonResponse({ error: 'device token required' }, 401);
      }
      const issuedToken = presentedToken
        ? null
        : crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
      const issuedTokenHash = issuedToken ? await sha256Hex(issuedToken) : null;

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
      const submittedSiteName = (params.get('site_name') || '').trim();
      const submittedSiteLocation = (params.get('site_location') || '').trim();
      const hasSiteMetadata = submittedSiteName && submittedSiteLocation && submittedSiteName.length <= 200 && submittedSiteLocation.length <= 200;
      let siteName = hasSiteMetadata ? submittedSiteName : null;
      let siteLocation = hasSiteMetadata ? submittedSiteLocation : null;
      let siteLatitude = existingDevice?.site_latitude ?? null;
      let siteLongitude = existingDevice?.site_longitude ?? null;

      if (hasSiteMetadata && submittedSiteLocation !== existingDevice?.site_location) {
        siteLatitude = null;
        siteLongitude = null;
        if (env.GOOGLE_MAPS_SERVER_KEY) {
          const geocodeUrl = new URL('https://maps.googleapis.com/maps/api/geocode/json');
          geocodeUrl.searchParams.set('address', submittedSiteLocation);
          geocodeUrl.searchParams.set('key', env.GOOGLE_MAPS_SERVER_KEY);
          const geocodeResponse = await fetch(geocodeUrl);
          if (geocodeResponse.ok) {
            const geocode = await geocodeResponse.json();
            const location = geocode.results?.[0]?.geometry?.location;
            if (geocode.status === 'OK' && Number.isFinite(Number(location?.lat)) && Number.isFinite(Number(location?.lng))) {
              siteLatitude = Number(location.lat);
              siteLongitude = Number(location.lng);
            }
          }
        }
      }
      if (hasSiteMetadata && submittedSiteLocation !== existingDevice?.site_location && (siteLatitude === null || siteLongitude === null)) {
        siteName = null;
        siteLocation = null;
      }

      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO checkins
             (device_id, uptime_seconds, rssi, free_heap, image_hash, error_count, firmware_version)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(deviceId, uptime, rssi, heap, imageHash, errors, firmwareVersion),

        env.DB.prepare(
          `INSERT INTO devices (device_id, last_seen_at, device_token_hash, registered_at, site_name, site_location, site_latitude, site_longitude)
           VALUES (?, datetime('now'), ?, datetime('now'), ?, ?, ?, ?)
           ON CONFLICT(device_id) DO UPDATE SET
             last_seen_at = datetime('now'),
             device_token_hash = COALESCE(?, devices.device_token_hash),
             site_name = COALESCE(?, devices.site_name),
             site_location = COALESCE(?, devices.site_location),
             site_latitude = COALESCE(?, devices.site_latitude),
             site_longitude = COALESCE(?, devices.site_longitude),
             registered_at = COALESCE(devices.registered_at, datetime('now'))`
        ).bind(deviceId, issuedTokenHash, siteName, siteLocation, siteLatitude, siteLongitude, issuedTokenHash, siteName, siteLocation, siteLatitude, siteLongitude),
      ]);

      return new Response(JSON.stringify({ ok: true, device_token: issuedToken }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Images: list history ---
    if (url.pathname === '/api/images' && request.method === 'GET') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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

    // --- Public site availability: dates only, with no campaign or customer data ---
    if (url.pathname === '/api/site-availability' && request.method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT oi.device_id, oi.start_date, oi.end_date
           FROM order_items oi
           JOIN orders o ON o.id = oi.order_id
          WHERE oi.status = 'scheduled'
            AND o.status IN ('paid', 'scheduled')
          ORDER BY oi.device_id, oi.start_date`
      ).all();
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Orders: save the booking before starting payment ---
    if (url.pathname === '/api/orders' && request.method === 'POST') {
      let form;
      try {
        form = await request.formData();
      } catch {
        return jsonResponse({ error: 'request body must be multipart form data' }, 400);
      }
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

      const { results: conflicts } = await env.DB.prepare(
        `SELECT DISTINCT oi.device_id
           FROM order_items oi
           JOIN orders o ON o.id = oi.order_id
          WHERE oi.device_id IN (${placeholders})
            AND oi.status IN ('pending_payment', 'scheduled')
            AND (o.status IN ('paid', 'scheduled') OR (o.status = 'pending_payment' AND o.created_at >= datetime('now', '-30 minutes')))
            AND oi.start_date < ?
            AND oi.end_date > ?`
      ).bind(...deviceIds, endDate, startDate).all();
      if (conflicts.length) return jsonResponse({ error: 'one or more devices are already booked for those dates', device_ids: conflicts.map((row) => row.device_id) }, 409);

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
      stripeParams.set('payment_intent_data[metadata][order_id]', orderId);
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
      const session = event.data.object;
      const orderId = session.metadata?.order_id || session.client_reference_id;
      const paidEvent = (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') && session.payment_status === 'paid';
      const failedEvent = event.type === 'checkout.session.async_payment_failed' || event.type === 'checkout.session.expired' || event.type === 'payment_intent.payment_failed';
      if (orderId && paidEvent) {
        await env.DB.prepare(
          `UPDATE orders SET status = 'paid', customer_email = ?, stripe_payment_intent_id = ?, last_stripe_event_id = ?, updated_at = datetime('now')
           WHERE id = ? AND status = 'pending_payment'`
        ).bind(session.customer_details?.email || null, session.payment_intent || null, event.id || null, orderId).run();
        await env.DB.prepare(
          `UPDATE order_items SET status = 'scheduled' WHERE order_id = ? AND status = 'pending_payment'`
        ).bind(orderId).run();
        const order = await env.DB.prepare(`SELECT * FROM orders WHERE id = ?`).bind(orderId).first();
        if (order && !order.success_email_sent) {
          await sendSuccessEmailForOrder(env, order);
          await env.DB.prepare(`UPDATE orders SET success_email_sent = 1, updated_at = datetime('now') WHERE id = ?`).bind(orderId).run();
        }
      } else if (orderId && failedEvent) {
        const order = await env.DB.prepare(`SELECT * FROM orders WHERE id = ?`).bind(orderId).first();
        if (order && !order.failure_email_sent) {
          await sendOrderEmail(
            env,
            order,
            `WALL payment not completed - ${order.checkout_code}`,
            `Your WALL booking is still saved, but payment was not completed.\n\nOrder reference: ${order.checkout_code}\nCampaign: ${order.campaign_name}\n\nYou can return to checkout to try again or contact us for help.`
          );
          await env.DB.prepare(`UPDATE orders SET failure_email_sent = 1, last_stripe_event_id = ?, updated_at = datetime('now') WHERE id = ?`).bind(event.id || null, orderId).run();
        }
      }
      return jsonResponse({ received: true });
    }

    // --- Email: retry a paid order's confirmation from the protected admin ---
    const retryOrderEmailMatch = url.pathname.match(/^\/api\/admin\/orders\/([^/]+)\/email$/);
    if (retryOrderEmailMatch && request.method === 'POST') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const orderId = decodeURIComponent(retryOrderEmailMatch[1]);
      const order = await env.DB.prepare(`SELECT * FROM orders WHERE id = ?`).bind(orderId).first();
      if (!order) return jsonResponse({ error: 'order not found' }, 404);
      if (order.status !== 'paid' && order.status !== 'scheduled') return jsonResponse({ error: 'order is not paid' }, 409);
      if (order.success_email_sent) return jsonResponse({ ok: true, already_sent: true });
      try {
        await sendSuccessEmailForOrder(env, order);
        await env.DB.prepare(`UPDATE orders SET success_email_sent = 1, updated_at = datetime('now') WHERE id = ?`).bind(orderId).run();
        return jsonResponse({ ok: true });
      } catch (error) {
        return jsonResponse({ error: error?.message || 'email send failed' }, 502);
      }
    }

    // --- Orders: admin view with booking, payment, invoice, and device details ---
    if (url.pathname === '/api/admin/orders' && request.method === 'GET') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const { results } = await env.DB.prepare(
        `SELECT o.id, o.checkout_code, o.campaign_name, o.contact_email,
                o.start_date, o.end_date, o.daily_rate_usd, o.total_usd,
                o.status, o.invoice_required, o.business_name,
                o.business_registration_number, o.tax_number,
                o.invoice_contact_name, o.invoice_phone, o.invoice_address,
                o.invoice_city, o.invoice_postcode, o.invoice_country,
                o.stripe_checkout_session_id, o.stripe_payment_intent_id,
                o.created_at, o.updated_at,
                o.success_email_sent,
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

    // --- Schedules: admin visibility and test controls ---
    if (url.pathname === '/api/schedules' && request.method === 'GET') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const { results } = await env.DB.prepare(
        `SELECT oi.id, oi.order_id, oi.device_id, oi.start_date, oi.end_date, oi.status,
                o.checkout_code, o.campaign_name, o.status AS order_status,
           a.filename AS advertisement_filename,
           d.site_name, d.site_location
           FROM order_items oi
           JOIN orders o ON o.id = oi.order_id
           LEFT JOIN advertisements a ON a.order_id = oi.order_id
         LEFT JOIN devices d ON d.device_id = oi.device_id
          WHERE oi.status != 'cleared'
          ORDER BY oi.device_id, oi.start_date, oi.id`
      ).all();
      return jsonResponse(results);
    }

    const scheduleActionMatch = url.pathname.match(/^\/api\/schedules\/(\d+)\/(clear|activate)$/);
    if (scheduleActionMatch && request.method === 'POST') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const itemId = Number(scheduleActionMatch[1]);
      const action = scheduleActionMatch[2];
      if (action === 'clear') {
        const result = await env.DB.prepare(
          `UPDATE order_items SET status = 'cleared', cleared_at = datetime('now') WHERE id = ? AND status != 'cleared'`
        ).bind(itemId).run();
        return result.meta.changes ? jsonResponse({ ok: true }) : jsonResponse({ error: 'schedule not found' }, 404);
      }
      const result = await env.DB.prepare(
        `UPDATE order_items SET status = 'scheduled', start_date = date('now')
           WHERE id = ?
             AND status != 'cleared'
             AND order_id IN (SELECT id FROM orders WHERE status IN ('paid', 'scheduled'))`
      ).bind(itemId).run();
      return result.meta.changes ? jsonResponse({ ok: true }) : jsonResponse({ error: 'paid schedule not found' }, 404);
    }

    const orderAdvertisementMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/advertisement\/raw$/);
    if (orderAdvertisementMatch && request.method === 'GET') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const orderId = decodeURIComponent(orderAdvertisementMatch[1]);
      const advertisement = await env.DB.prepare(
        `SELECT r2_key FROM advertisements WHERE order_id = ? ORDER BY id DESC LIMIT 1`
      ).bind(orderId).first();
      if (!advertisement) return new Response('Advertisement not found', { status: 404 });
      const object = await env.IMAGES.get(advertisement.r2_key);
      if (!object) return new Response('Advertisement data missing from storage', { status: 404 });
      return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream' } });
    }

    // --- Devices: return only the active scheduled advertisement for this device ---
    const deviceContentMatch = url.pathname.match(/^\/api\/device-content\/([^/]+)\/raw$/);
    if (deviceContentMatch && request.method === 'GET') {
      const deviceId = decodeURIComponent(deviceContentMatch[1]);
      if (!(await deviceTokenFromRequest(request, env, deviceId))) return unauthorizedResponse();
      const schedule = await env.DB.prepare(
        `SELECT oi.order_id, a.id AS advertisement_id, a.r2_key
           FROM order_items oi
           JOIN orders o ON o.id = oi.order_id
           JOIN advertisements a ON a.order_id = oi.order_id
          WHERE oi.device_id = ?
            AND oi.status = 'scheduled'
            AND o.status IN ('paid', 'scheduled')
            AND date('now') >= oi.start_date
            AND date('now') < oi.end_date
          ORDER BY oi.start_date DESC, oi.id DESC
          LIMIT 1`
      ).bind(deviceId).first();
      if (!schedule) return new Response('No active advertisement', { status: 404 });
      const etag = `order-${schedule.order_id}-${schedule.advertisement_id}`;
      if (request.headers.get('If-None-Match') === etag) return new Response(null, { status: 304, headers: { ETag: etag } });
      const object = await env.IMAGES.get(schedule.r2_key);
      if (!object) return new Response('Advertisement data missing from storage', { status: 404 });
      return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream', ETag: etag } });
    }

    // --- Devices: fleet overview — most recent check-in per device,
    //     joined from `devices` (identity) and `checkins` (telemetry) ---
    if (url.pathname === '/api/devices' && request.method === 'GET') {
      if (!isAdminRequest(request)) return unauthorizedResponse();
      const { results } = await env.DB.prepare(
        `SELECT
           d.device_id,
           d.setup_status,
           d.registered_at,
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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
          SET site_name = ?, site_location = ?, daily_cost_usd = ?, site_latitude = ?, site_longitude = ?,
            setup_status = CASE WHEN setup_status = 'new' THEN 'active' ELSE setup_status END
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
      if (!isAdminRequest(request)) return unauthorizedResponse();
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

    // Everything else: serve the static site with baseline browser protections.
    const assetResponse = await env.ASSETS.fetch(request);
    const headers = new Headers(assetResponse.headers);
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    return new Response(assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers });
  },
};