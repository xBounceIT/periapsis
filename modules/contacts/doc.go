// Package contacts is the deterministic customer-contact and recipient-target
// kernel. It performs no I/O and grants no authority: callers must supply live,
// tenant-bound access and an explicit set of contacts authorized for the
// resource before resolving a customer recipient.
//
// Contact addresses and phone numbers are deliberately absent from String
// representations. Persistence must keep contact, group version, activity,
// redacted audit, outbox intent, and idempotency result in one transaction.
package contacts
