// Package ldapclient implements bounded, SSRF-resistant LDAP diagnostics and
// directory authentication observations. Upstream errors and values never
// enter diagnostics; directory values cross only the explicitly bounded,
// value-owning observation boundary.
package ldapclient

import (
	"errors"
	"time"
)

// Outcome is the safe persisted result class for a provider diagnostic.
type Outcome string

const (
	OutcomeSuccess      Outcome = "success"
	OutcomeFailure      Outcome = "failure"
	OutcomeInconclusive Outcome = "inconclusive"
)

// Category is a stable, sanitized diagnostic category. Values deliberately
// match the database contract and never contain an upstream message.
type Category string

const (
	CategorySuccess             Category = "success"
	CategoryDNSFailed           Category = "dns_failed"
	CategoryDestinationBlocked  Category = "destination_blocked"
	CategoryConnectTimeout      Category = "connect_timeout"
	CategoryConnectFailed       Category = "connect_failed"
	CategoryTLSFailed           Category = "tls_failed"
	CategoryCertificateRejected Category = "certificate_rejected"
	CategoryBindRejected        Category = "bind_rejected"
	CategoryProtocolFailed      Category = "protocol_failed"
	CategoryCancelled           Category = "cancelled"
	CategoryStaleConfiguration  Category = "stale_configuration"
)

// Diagnostic contains only allowlisted, non-sensitive metadata.
type Diagnostic struct {
	Outcome          Outcome
	Category         Category
	EndpointPriority int
	Duration         time.Duration
}

var (
	// ErrInvalidOptions identifies an invalid deployment-owned client policy.
	ErrInvalidOptions = errors.New("invalid LDAP client options")
	// ErrInvalidConfiguration identifies an invalid provider snapshot without
	// reflecting any endpoint, DN, certificate, filter, attribute, or secret.
	ErrInvalidConfiguration = errors.New("invalid LDAP client configuration")
	// ErrBusy indicates that the fixed global network-work budget is exhausted.
	ErrBusy = errors.New("LDAP diagnostic capacity is exhausted")
)

func newDiagnostic(category Category, endpointPriority int, duration time.Duration) Diagnostic {
	outcome := OutcomeFailure
	if category == CategorySuccess {
		outcome = OutcomeSuccess
	} else if category == CategoryStaleConfiguration {
		outcome = OutcomeInconclusive
	}
	return Diagnostic{
		Outcome:          outcome,
		Category:         category,
		EndpointPriority: endpointPriority,
		Duration:         duration,
	}
}
