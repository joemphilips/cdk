# cdk-lnbits

CDK Lightning backend for one hosted LNbits wallet. The native unit is `sat`.
The adapter supports amount-bearing BOLT11 invoices only.

This crate is an adapter. It does not select a backend, read configuration
files or resolve secrets. The `cdk-mintd` `lnbits` feature only adds this
crate as a dependency.

## Pinned API profile

The adapter supports one immutable LNbits source revision:

| Item | Value |
| --- | --- |
| Release tag | `v1.6.2` |
| Commit | `9349da153c223b008f7d80453b53a54e09c8ed3d` |
| Commit date | 2026-09-18 |
| Source | `https://github.com/lnbits/lnbits` |

The fixtures in `fixtures/lnbits-v1.6.2/` follow the response models and
route handlers of that commit. They come from source review, not from a live
service. They do not prove the behavior of a hosted service. A hosted
service must be confirmed against this profile before production use.

### Endpoints

| Use | Request | Key |
| --- | --- | --- |
| Create invoice | `POST /api/v1/payments` with `{"out": false, "amount": <sat>, "unit": "sat", "memo"?, "expiry"?}` | invoice |
| Pay invoice | `POST /api/v1/payments` with `{"out": true, "bolt11": "<invoice>"}` | admin |
| Payment status | `GET /api/v1/payments/{payment_hash}` | invoice |
| Fee reserve observation | `GET /api/v1/payments/fee-reserve?invoice=<invoice>` | none |
| Wake hints | websocket `/api/v1/ws/{invoice_key}` | invoice key in path |

The key is sent in the `X-Api-Key` header. The invoice key cannot pay, so a
request that creates an invoice cannot spend funds.

### Response shapes

- `POST /api/v1/payments` returns HTTP 201 and the `Payment` model. Amounts
  and fees are signed msat integers. A negative amount is outgoing.
- A payment error returns HTTP 520 with `{"detail", "status"}`. The status
  value does not prove whether the provider dispatched the payment.
- `GET /api/v1/payments/{payment_hash}` returns HTTP 200. The `details` field
  is present only with a key of the owning wallet:
  - success: `{"paid": true, "preimage", "details"}`;
  - failed: `{"paid": false, "status": "failed", "details"}`;
  - pending: `{"paid": false, "status", "preimage": null, "details"}`;
  - status check error: `{"paid": false, "details"}`.
- An unknown hash returns HTTP 404.
- The fee reserve observation returns `{"fee_reserve": <msat>}`.
- A websocket wallet notification is
  `{"wallet_balance", "payment": <Payment>}`. The channel has no message
  authentication. Any client that knows the invoice key can send a message.

### Facts that the adapter relies on

- The payment record is created before the funding source is called. A
  status read of an accepted payment request finds that record.
- A repeated payment request for the same hash does not dispatch again. It
  returns HTTP 520 with the state of the existing record.
- The provider computes its own routing reserve and passes it to its funding
  source. The payment request has no caller fee limit.
- A `failed` record can later change to `success`. A repeated payment request
  for the same hash rechecks the funding source and can mark the record
  `success`. So `failed` is not a terminal state in this profile.

## Behavior

| Method | Behavior |
| --- | --- |
| `get_settings` | Advertises unit `sat` and BOLT11 without MPP or amountless support. |
| `create_incoming_payment_request` | Sends an integer sat amount and a relative expiry. Verifies the signed invoice amount, network, hash and expiry. |
| `get_payment_quote` | Validates before any request. Quotes the larger of the mint fee policy and the provider fee reserve observation, rounded up to sat. |
| `make_payment` | Sends one payment request and never retries it. Binds the reply to the invoice hash, direction, principal and invoice. Reconciles any other reply through one status read. |
| `check_outgoing_payment` | Requires one durable expectation from the recovery context. Returns `Paid` only with a verified preimage. Never returns `Unpaid` or `Failed`. |
| `check_incoming_payment_status` | Credits only an authenticated, bound, paid incoming record. Rounds msat down to sat. |
| `wait_payment_event` | Owns one websocket. Each message is a wake hint only. The adapter reads the authenticated status before it emits a credit. The stream ends on disconnect or cancellation. The mint stream supervisor reconnects with bounded backoff. |

`Unpaid` and `Failed` allow the mint to release reserved proofs. The adapter
returns `Pending` or `Unknown` for every uncertain outcome, including HTTP
errors, timeouts, missing records, a provider `failed` state and a success
reply without a valid preimage.

## Fees

The pinned API cannot cap the fee of one payment. With
`OutgoingPayments::MintPaysFeeAboveReserve` the adapter reports the actual
total cost. It does not clamp the cost to the quoted reserve. When the actual
fee is larger than the quoted reserve, the adapter emits the warning event
`lnbits_fee_above_reserve` with target `cdk_lnbits::fee_excess` and
increments `LNbits::fee_excess_event_count`. The mint melt path decides how
much of that cost the user pays. `OutgoingPayments::Disabled` refuses melt
quotes and payments before any request.

## Logging

The adapter never logs headers, bodies, preimages, invoices, keys or URLs.
Log fields are limited to payment hashes, HTTP status codes, amounts and fixed
reason values.
