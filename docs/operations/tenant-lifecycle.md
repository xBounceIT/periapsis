# Platform tenant lifecycle

Tenant suspension is a platform control-plane boundary, not a UI flag. Only a live
session with `platform.tenant.manage` can call the suspend or reactivate endpoints, and
the database mutation rechecks that exact session and live platform grant while holding
the relevant authorization locks. The API role has no direct `UPDATE` privilege on
`tenants`.

## Operator procedure

1. Confirm the exact tenant and its current strong ETag in the platform tenant inventory.
2. Record a concise, already-redacted reason. The reason is mandatory, must already be in
   canonical form, and is limited to 2,048 UTF-8 bytes. Never include credentials,
   assertions, tokens, private keys, customer content, or other secrets. Pattern rejection
   is defense in depth and is not a redaction mechanism.
3. Submit `POST /api/v1/platform/tenants/{tenantId}/suspend` with the matching `If-Match`
   and lifecycle version. A stale version or duplicate transition fails closed; operators
   must reload and reassess instead of blindly retrying.
4. Verify the returned version, the platform audit event, API/worker readiness, and the
   affected queue counts carried in the audit metadata.
5. Resolve the cause and use the same version-bound procedure at
   `POST /api/v1/platform/tenants/{tenantId}/reactivate`. Reactivation never silently
   retries or resurrects terminal asynchronous work.

## Suspension boundary

The lifecycle transaction increments both the tenant version and tenant authorization
revision. The authorization-state row is the cross-process fence: tenant credential and
Alert/Case write paths take a conflicting lock, so a committed suspension linearizes all
future tenant work.

After suspension commits:

- API, notifier, worker, and dedicated queue-owner RLS policies require an active tenant;
  tenant-scoped rows are therefore neither readable nor writable through runtime roles.
- Alert and Case insert/update triggers independently require an initialized active tenant,
  including when a bounded `SECURITY DEFINER` command is the writer.
- unreserved notification deliveries in queued, retry, or leased state are dead-lettered
  with `tenant_suspended`; their unfinished current attempts are fenced as security
  failures;
- notification deliveries already durably reserved for provider submission are retained.
  SMTP/webhook completion can be ambiguous after reservation, so suspension must not
  fabricate a safe retry or a contradictory terminal result;
- queued, retry, and leased SLA evaluation jobs are dead-lettered with
  `tenant_suspended`; new notifier and SLA claims remain ineligible while suspended;
- current sessions are not trusted as cached authority. Every tenant selection and
  backend authorization decision re-evaluates active tenant state, so existing opaque
  session credentials cannot bypass suspension.

Reactivation restores runtime visibility and permits new work. It deliberately leaves
dead-lettered notification/SLA records terminal and preserves reserved deliveries for
operator reconciliation. Any replay or replacement must use the subsystem's audited,
idempotent recovery path.

## Audit and readiness

Every successful change appends one tamper-evident platform audit event in the same
transaction as the status/version, authorization revision, and queue fencing. Reusing an
audit event identity rolls back the whole lifecycle transaction. The API and worker require
the current sealed journal root plus trusted tenant-lifecycle, identity, ticket, notification,
SLA, and operations dependency probes before reporting ready. The exact functions are pinned
by the candidate binaries; superseded prose versions are not an operational source. The
migration-to-seal interval intentionally leaves current replicas unready, and an incompatible
cutover advertises neither an executable predecessor nor a zero-downtime guarantee.

The PostgreSQL security harnesses prove direct-table denial, session compatibility,
authorization and method failures, exact-reason bounds, concurrent CAS behavior, RLS and
ticket-write fencing, notifier/SLA outcomes, reactivation, and clean/predecessor upgrade
fixtures on PostgreSQL 18.6.
