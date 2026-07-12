# Payment integration

How real payments credit a customer's account. Credits are applied **only** from
a signature-verified provider webhook — never from a client call (the M18 stub
`/payment/confirm` is not exposed by the production control plane).

## Flow

1. **Open an account** (once): `POST /accounts/open` → `{account}`. In production
   the account is derived from the authenticated Keycloak subject.
2. **Create an intent**: `POST /payment/intent` `{account, credits}` → `{payment}`.
   The `payment` is our `PaymentId`; attach it to the provider's payment intent as
   metadata so it comes back on the webhook.
3. **Customer pays** at the provider (Stripe, etc.) — out of band.
4. **Provider webhook**: the provider POSTs a signed event to
   `POST /payment/webhook`. The control plane verifies the signature, and on
   `status == "succeeded"` credits the account for the intent's credits.
5. **Spend**: `POST /billing/issue` debits credit and mints a routing token.

## Webhook signature scheme

The provider signs the message `"<timestamp>.<raw-body>"` with the shared webhook
secret using HMAC-SHA256, and sends:

| Header | Value |
|--------|-------|
| `X-CT-Webhook-Timestamp` | unix seconds, the `<timestamp>` that was signed |
| `X-CT-Webhook-Signature` | hex HMAC-SHA256 of `"<timestamp>.<raw-body>"` |

The control plane rejects (`401`):

- a signature that does not match (forged or tampered body),
- a timestamp more than **300 seconds** from now (replay protection).

Delivery is **idempotent**: a replayed `succeeded` event returns `200` without
double-crediting. Unknown `payment` → `404`; non-`succeeded` events are acked
`200` without crediting.

The event body must be JSON containing at least:

```json
{ "payment": "<hex PaymentId from step 2>", "status": "succeeded" }
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `CT_PAYMENT_WEBHOOK_SECRET` | The provider's webhook signing secret. Must match the provider dashboard exactly. |

If `CT_PAYMENT_WEBHOOK_SECRET` is unset or empty, the control plane starts with a
random secret and logs `payment webhook disabled` — every webhook then fails
signature verification, so **no credit can be applied** until a real secret is
configured. This is fail-safe: an unconfigured deployment cannot be tricked into
crediting an account. The secret is provided via the deployment environment
(`.env` / Kubernetes Secret), never committed.

## Testing a deployment

1. Set `CT_PAYMENT_WEBHOOK_SECRET` to a known value.
2. `POST /accounts/open`, then `POST /payment/intent {account, credits}` to get a
   `payment` id.
3. Build body `{"payment":"<id>","status":"succeeded"}`, sign
   `"<now>.<body>"` with the secret (HMAC-SHA256, hex), and POST it to
   `/payment/webhook` with the two headers above.
4. Expect `200`; `POST /billing/issue {account, price}` now succeeds against the
   credited balance.

The `credit_via_webhook` test helper in `service.rs` demonstrates exactly this
signing and posting sequence.
