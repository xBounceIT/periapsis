package ldapclient

import (
	"testing"
	"time"
)

func TestDiagnosticOutcomeMappingIsClosedAndStable(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		category Category
		outcome  Outcome
	}{
		{category: CategorySuccess, outcome: OutcomeSuccess},
		{category: CategoryDNSFailed, outcome: OutcomeFailure},
		{category: CategoryDestinationBlocked, outcome: OutcomeFailure},
		{category: CategoryConnectTimeout, outcome: OutcomeFailure},
		{category: CategoryConnectFailed, outcome: OutcomeFailure},
		{category: CategoryTLSFailed, outcome: OutcomeFailure},
		{category: CategoryCertificateRejected, outcome: OutcomeFailure},
		{category: CategoryBindRejected, outcome: OutcomeFailure},
		{category: CategoryProtocolFailed, outcome: OutcomeFailure},
		{category: CategoryCancelled, outcome: OutcomeFailure},
		{category: CategoryStaleConfiguration, outcome: OutcomeInconclusive},
	} {
		diagnostic := newDiagnostic(test.category, 3, 7*time.Millisecond)
		if diagnostic.Outcome != test.outcome || diagnostic.Category != test.category ||
			diagnostic.EndpointPriority != 3 || diagnostic.Duration != 7*time.Millisecond {
			t.Fatalf("newDiagnostic(%q) = %#v", test.category, diagnostic)
		}
	}
}
