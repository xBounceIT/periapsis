# ADR-0012: DFIR relationship ownership is independent of endpoints

- Status: Accepted
- Date: 2026-09-04

## Decision

A general DFIR relationship belongs to one tenant and exactly one persisted Case or
Alert workspace. Its source and target are independent, distinct typed references;
neither endpoint must be the owning ticket. This permits IOC-to-asset, task-to-evidence,
and other investigation links required by the product specification.

The request path, persisted `case_id`/`alert_id`, and immutable command coordinate supply
ownership. No create, read, replay, or retraction path may infer the workspace from either
endpoint. Case-to-Case relationships must likewise retract using the requested owning
Case, not whichever endpoint happens to be first.

Authorization remains deny-by-default. Mutations require the owning root's live
relationship-manage permission and revalidate both endpoints before fresh execution or
receipt replay. Internal child resources must be live and directly associated with that
workspace; other Case/Alert references require their own live permission. External
references are bounded tenant-owned identifiers, not authority to fetch external content.
The database repeats these checks, retains root-scoped uniqueness, and rejects dangling
or unauthorized associations. Retractions preserve immutable endpoints and append their
single terminal history event under CAS.

Alert-to-Alert `duplicate_of` and `correlation` remain exclusive to the dedicated dual-CAS
Alert relation aggregate. General relationships do not merge tickets or update those
dedicated associations.

## Consequences

Workspace projections and client forms accept child-to-child references while preserving
tenant, root-envelope, type, identifier, cardinality, and revision validation. Historical
receipts retain their original relationship projection, but never retain stale endpoint
authorization. An actor losing access cannot recover it by replaying an old command.

Focused Go, contract, and mounted frontend tests cover the new semantics. SQL/runtime
integration, final schema generation, compatibility seals, and release acceptance are
tracked separately in `TASKS.md`; this decision is not a release-readiness claim.
