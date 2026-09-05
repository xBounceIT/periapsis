# Notification engine

Status: API, PostgreSQL, notifier, SMTP/webhook, and administration UI implemented  
Decision basis: [ADR-0004](adr/0004-postgresql-outbox.md)

Periapsis derives notifications from committed, versioned tenant outbox facts. Domain
transactions never send email or HTTP. They persist the mutation, activity, append-only
audit event, and minimal outbox fact atomically. A rule projection then creates one
recipient-specific delivery for each authorized audience and pins every value that could
change later: event, rule version, template version, destination, visibility projection,
retry policy, SMTP/webhook configuration version, and webhook signing-key version.

## Trust and tenant boundaries

- Every rule, template, job, delivery, provider override, webhook, and delivery log is
  tenant-owned with `tenant_id NOT NULL`, composite tenant foreign keys, forced RLS, and
  an application-level tenant comparison.
- A private-comment event has an operator-only maximum audience. Planning drops customer
  recipients and customer webhook projection is impossible.
- Customer rendering receives only the precomputed `context.customer` projection. It
  cannot query Alert, Case, comment, or custom-field tables to reconstruct removed data.
- Explicit email recipients require an authorized rule write. Dynamic email fields are
  canonicalized and evaluated only inside the event's own tenant projection.
- The notifier database role can claim and update notification tables only. It has no
  general incident, identity, audit-update, DDL, or `BYPASSRLS` privilege.

## Rule and template model

Rules use a bounded declarative condition tree (`all`, `any`, `not`, and allowlisted
predicates). They select one event/object pair, recipient selectors, channel, priority,
delay, optional IANA-timezone quiet hours, deduplication window, grouping policy, retry
policy, and immutable effective version. Missing facts fail negative predicates closed.

Templates are immutable versions with subject, HTML, optional explicit plaintext, CSS,
language, and an allowlisted placeholder inventory. The in-process language supports only
escaped scalar interpolation plus bounded `if` and `each`; it has no helper dispatch,
JavaScript, filesystem, database, process, or network primitive. Compilation and rendering
bound token count, nesting, iteration, context size, output size, and elapsed time.

HTML is allowlisted and sanitized before and after CSS inlining. Scripts, forms, frames,
event handlers, remote resources, protocol-relative URLs, `url()`, imports, CSS escapes,
legacy CSS execution features, and non-HTTPS/non-mail links are removed or rejected.
Generated plaintext preserves block boundaries. Preview uses the same production renderer,
is body/concurrency limited, returns `Cache-Control: no-store`, and is exposed only at the
bearer-protected internal endpoint; the public Go administration API remains the audited
authorization boundary.

## Delivery state machine

```text
outbox pending/retry -> fanout lease -> committed delivery jobs
                              |                |
                              |                +-> exact replay (no duplicate jobs)
                              +-> safe retry / terminal dead-letter / fenced handoff

pending/retry -> leased -> reserved -> delivered
                     |         |          |
                     |         |          +-> replay-complete after local response loss
                     |         +-> uncertain -> dead-letter
                     +-> safe failure -> retry or dead-letter at attempt ceiling
```

Both fanout and delivery claims use bounded `FOR UPDATE SKIP LOCKED` batches and a unique
fencing token. Fanout validates the tenant event, effective email rules, recipient
inventory, and exact rule/template/SMTP versions before one transaction inserts every
recipient job and marks the outbox fact consumed. A stable per-recipient delivery key makes
an acknowledgement-loss replay return `already_committed` without duplicating jobs. A
temporary clock skew cannot make planning predate the committed event.

Heartbeats,
reservation, completion, retry, and dead-letter updates compare tenant, delivery ID,
expected state, attempt, and fence. A stale worker therefore cannot overwrite a replacement
claim. The stable recipient/channel deduplication key also creates a stable SMTP Message-ID
or webhook delivery ID.

Fanout and delivery have separate concurrency and operation deadlines. Each heartbeat is
also deadline-bound and observes shutdown cancellation, so a stalled database renewal
cannot prevent graceful termination. An iteration still drains already-created delivery
jobs if the independent fanout batch fails.

SMTP has no universal provider idempotency API. Periapsis reserves submission durably
before calling the provider. A failure known to occur before submission may retry with
deterministic exponential backoff and jitter. A timeout or response loss after reservation
is classified as uncertain and dead-lettered for operator reconciliation rather than
blindly resending. Provider receipts contain only counts, response class, and a digest.

Manual retry creates a new audited delivery linked to the failed record. It never clears or
rewrites the original attempt history. Authentication, policy, template, tenant, and
invalid-destination failures are terminal. Explicit transient SMTP codes and retryable HTTP
statuses may retry until the pinned attempt ceiling.

Platform tenant suspension is a transactionally fenced security outcome. Unreserved
queued, retry, and leased deliveries are dead-lettered as `tenant_suspended`, and an
unfinished current attempt is completed as fenced. A delivery already durably reserved for
provider submission is retained because its external outcome may be ambiguous; suspension
does not manufacture a retry or contradictory failure. All claim policies require an active
tenant, and reactivation does not resurrect terminal work. See
[Platform tenant lifecycle](operations/tenant-lifecycle.md).

## Network and secret controls

SMTP and webhook DNS resolution is deployment-owned and checked on every new connection.
All returned addresses must pass policy before dialing; mixed safe/private answers fail the
whole operation. The socket dials a validated literal address, preventing DNS rebinding.
Metadata, link-local, mapped, multicast, documentation, benchmark, unspecified, and
reserved ranges are always denied. Private networks require both an exact hostname and port
allowlist. Plain HTTP is loopback-only; plain SMTP additionally permits an explicitly
enabled local-development service such as Compose Mailpit, still constrained by the exact
deployment hostname and port allowlists. Production rejects the plaintext SMTP opt-in.

TLS requires version 1.2 or newer, certificate verification, and hostname verification.
Redirects and ambient proxy configuration are not used. Webhooks use a canonical v1 JSON
payload and `HMAC-SHA-256` over schema, timestamp, stable delivery ID, and body digest. The
timestamp, delivery ID, key version, and signature are separate fixed headers so receivers
can enforce skew and replay protection.

Production database credentials, the preview bearer, and the independent notification
keyring come only from mounted files. SMTP passwords, DKIM keys, and webhook HMAC keys are
stored as append-only AES-256-GCM envelopes in PostgreSQL; immutable configuration versions
pin their exact secret ID and version. The API encrypts each secret with tenant/platform
scope, secret ID, version, and kind in authenticated data. The notifier resolves only the
pinned envelope, decrypts it in memory with `NOTIFICATION_KEYRING_FILE`, and zeroes every
owned plaintext buffer after provider construction or signing. There is no provider-secret
filesystem-reference fallback.

## Operations and observability

The notifier exposes `/health/live`, dependency-aware `/health/ready`, `/metrics`, and the
protected internal preview endpoint. It stops claims on shutdown, cancels bounded work,
drains HTTP, and closes the Drizzle/PostgreSQL pool. Logs are structured JSON with an
allowlist of non-content fields; recipients, message bodies, templates, endpoint URLs,
credentials, signatures, assertions, and provider response bodies are never logged.

Prometheus metrics cover readiness, queue depth, loop success/failure, fanout claims and
planned jobs, delivery claims/outcomes, retries, uncertainty, and dead letters. Tenant IDs
and recipient addresses are not metric labels. Request/correlation/event/delivery
identifiers carry traces across API, outbox, claim, and provider boundaries; OpenTelemetry
export is deployment-configured.

## Required verification

Unit and live PostgreSQL tests cover rule matching, DST quiet hours, deterministic retry,
template sandboxing and sanitization, private-comment projection, SMTP fixture delivery,
webhook signing and replay identity, mixed-DNS/metadata denial, concurrent claims, fencing,
response-loss recovery, manual retry audit, forced RLS, and schema drift. Deployment tests
add Mailpit capture, notifier non-root/read-only execution, queue-age alerts, and shutdown
recovery.
