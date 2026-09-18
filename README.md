# wall.marketing
Main Website

## Orders and Stripe

Apply the order migration to the production D1 database before deploying the
checkout changes:

```sh
npx wrangler d1 migrations apply bots --remote
```

Configure these Worker secrets:

```sh
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
npx wrangler secret put EMAIL_FROM
```

The Worker uses the `EMAIL` Cloudflare Email Sending binding. Set `EMAIL_FROM`
to a verified sender address on the domain.

Create a Stripe webhook for `https://wall.marketing/api/stripe/webhook` and
subscribe it to `checkout.session.completed` and
`checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`,
`checkout.session.expired`, and `payment_intent.payment_failed`. The endpoint verifies the Stripe signature,
sends the success invoice or payment-failure message, stores the customer email,
and changes a matching order from `pending_payment` to `paid`.

The checkout and public site map require Cloudflare Access Public Bypass rules
for `/api/sites*` and `/api/orders` on both `wall.marketing` and
`www.wall.marketing`. The Stripe webhook also needs a Public Bypass rule for
`/api/stripe/webhook`; keep `/api/devices` protected by the owner-only policy.
The admin order list uses `/api/admin/orders` and must remain protected by the
owner-only policy.
Paid orders whose confirmation email failed can be retried with the protected
`POST /api/admin/orders/{order_id}/email` endpoint after fixing Email Sending.
Device firmware downloads require a Public Bypass rule for
`/api/device-content/*`; the Worker still requires the device's own token.

## Device content delivery

The identical firmware image can be flashed to every device. On its first
authenticated check-in, the Worker registers the MAC-derived device ID and
returns a device token. Updated firmware stores that token in Preferences and
sends it on later check-ins and content requests.

Devices fetch only their active scheduled advertisement from:

```text
GET /api/device-content/{device_id}/raw
```

The admin page's Device schedules section can activate a paid schedule
immediately for testing or clear it from a device. The device-specific content
endpoint uses ETags and never serves another device's schedule.
