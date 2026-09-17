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
```

Create a Stripe webhook for `https://wall.marketing/api/stripe/webhook` and
subscribe it to `checkout.session.completed` and
`checkout.session.async_payment_succeeded`. The endpoint verifies the Stripe
signature, stores the customer email, and changes a matching order from
`pending_payment` to `paid`.

The checkout and public site map require Cloudflare Access Public Bypass rules
for `/api/sites*` and `/api/orders` on both `wall.marketing` and
`www.wall.marketing`. The Stripe webhook also needs a Public Bypass rule for
`/api/stripe/webhook`; keep `/api/devices` protected by the owner-only policy.
