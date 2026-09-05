# ADR-0011: Shared IOC and asset ownership and visible links

- Status: Accepted
- Date: 2026-09-04

## Decision

An IOC or asset has one tenant-owned identity and revision, and may be actively linked
to multiple Cases and Alerts within that tenant. Modifying it requires the corresponding
manage permission on every active linked root. The path root must be among those links.
Reading it through an authorized root does not grant permission to discover the other
roots. Authorization is repeated for retries before returning an immutable result.

Shared-resource writes use serializable transactions, a resource-row lock, and ordered
root locks. Association changes must serialize on that same resource. The maximum active
root count is 64; reads and writes reject oversized or malformed association sets rather
than silently authorizing a truncated subset.

The workspace returns a separate `sharedResources` projection with one entry per IOC and
asset in its inventory. Each entry contains only related Case/Alert identities that the
current actor may read. It exposes neither hidden identities nor a total that includes
hidden roots. This projection is recomputed from current authority and is not part of an
immutable mutation receipt. The web client verifies inventory binding, UUIDs, root kinds,
uniqueness, cardinality, and the current path association before rendering links.

Attachment uploads on a shared IOC/asset are also shared writes: both initial prepare
and replay require `attachment.manage` on every current root, under the same resource
and ordered root locks. They emit redacted attachment activity to each affected root.
Attachment reads are instead bound to the requested ticket and exact attachment/storage
pair. They never infer a unique Case from the subject. An explicit escalation copy of
an attachment remains independently accessible through its authorized target Case;
copying the entire IOC/asset is not required. Direct inventories omit attachments on
archived IOC/assets, without removing an independently authorized attachment copy.

Explicit link-existing and unlink actions require manage permission on the target and all
current roots, use caller-owned operation identifiers and resource CAS, and record
append-only lifecycle history. Active links remain in the existing link tables so all
existing attachment and timeline queries use the same association boundary. Unlinking the
last root is rejected to avoid an inaccessible orphan. References owned by a root must
remain valid; unlink must reject incompatible root-local dependencies. Mutations emit
activity for every affected root without exposing other root identities to its readers.

Each link/unlink event reserves a durable `shared_link_event` identifier. Imported
associations record the current resource revision without inventing earlier versions.
The generic receipt must have an exact matching immutable lifecycle event before commit.
Runtime association inserts require a current-transaction create/link reservation or the
closed escalation command's exact selected-resource provenance; raw API DML is rejected.
Exact link replay still requires an active path association. Exact unlink replay may use
its immutable receipt after removing that association, but only while current path and
all remaining-root permissions still allow the operation. The returned snapshot never
contains the dynamically authorized list of related tickets.

## Consequences

An operator assigned to only one linked ticket can read the resource there but cannot
change shared content. A manager with authority over all linked tickets can modify it.
Revocation affects retries and related-ticket visibility immediately at the authorization
boundary. Immutable receipts retain their original resource result without preserving a
stale authorization-derived list of related tickets.

The implementation and release evidence for this decision are tracked separately in
`TASKS.md`; an accepted design is not evidence that the lifecycle and database gates pass.
