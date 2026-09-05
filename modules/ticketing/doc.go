// Package ticketing is the pure decision kernel shared by Alert and Case use
// cases. It performs no I/O and grants no authority by itself: callers supply a
// live, tenant-bound AuthorizationSnapshot resolved by backend policy.
//
// Allowed mutation plans remain conditional on ExpectedVersion. Persistence
// must compare-and-update the aggregate and atomically write every planned
// activity, audit, SLA, notification, comment, link, and idempotency record.
// Visibility helpers are projection gates, not substitutes for resource
// authorization.
package ticketing
