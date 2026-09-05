package postgres

import "testing"

func TestFederatedPersistenceRevisionUsesJSONSafeCeiling(t *testing.T) {
	t.Parallel()

	maximum := uint64(maximumMFAJSONSafeInteger)
	if !validFederatedRevision(maximum) {
		t.Fatal("last JSON-safe federated revision was rejected")
	}
	if validFederatedRevision(maximum + 1) {
		t.Fatal("federated revision beyond the JSON-safe ceiling was accepted")
	}
	if !validFederatedSuccessorRevision(maximum-1) ||
		validFederatedSuccessorRevision(maximum) {
		t.Fatal("federated successor headroom was not enforced")
	}
}
