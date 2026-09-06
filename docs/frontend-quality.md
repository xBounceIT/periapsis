# React Doctor verification

Run React Doctor from the repository root after the normal verification build:

```sh
corepack pnpm verify
npx --yes react-doctor@0.9.13 . --yes --scope full --no-cache --json
```

The pinned scanner checks both `@periapsis/web` and `@periapsis/ui`. Full scope is
required: a scan of changed files alone does not verify newly extracted modules,
cross-file duplication, dependencies, or the browser-delivered artifacts. The
build refreshes `apps/web/dist` before artifact inspection. Check each project's
score, completion flag, and skipped-check list as well as the diagnostic totals.

The 2026-09-06 remediation separates request controllers, editors, inventories,
and pure model helpers; consolidates repeated navigation and table markup; and
keeps session/tenant request ownership in committed React effects. Related editor
fields change atomically. Request cancellation, authorization generations, version
pins, idempotency bindings, and server error handling remain part of each flow.
Strict Zod schemas retain their rejection of unknown properties.

Focused regressions cover interrupted concurrent tenant renders, obsolete
pagination and metadata responses, stable editor-row identity, table selection and
reset callbacks, and a safe route-error fallback. The SAML private-key parser checks
matching envelope labels and the required key type rather than embedding a
PEM-shaped literal in the browser bundle; invalid envelope and base64 cases remain
rejected.

No global React Doctor rule exclusions are configured. The remaining inline
annotations identify specific analyzer limitations and explain the ownership or
lifecycle invariant at the affected line:

- A loading reset already inside `finally` must retain its request-ownership
  condition so an old request cannot clear a newer request's flag.
- A guarded server response may clear its own error or replace an asynchronous
  snapshot; these values cannot be computed from component props.
- Committed authorization-boundary effects cancel work and replace request epochs;
  the table reconciliation effect also handles server-origin version changes.
- The federation mutation executor accepts async commands, not React state
  updater functions.
- A download-capability request does not mutate the attachment inventory, and
  validating a user-supplied time zone requires constructing a formatter for that
  specific value.

Revisit these narrow annotations when upgrading the scanner. A score is static
analysis evidence and supplements the repository tests; it does not replace the
database, deployment, or release acceptance gates tracked in `TASKS.md`.
