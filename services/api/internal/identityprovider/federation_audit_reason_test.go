package identityprovider

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFederationAuditReasonRejectsCredentialShapes(t *testing.T) {
	t.Parallel()

	valid := []string{
		"Approved after security review",
		"Rotate the tenant signing credential",
		"Token policy reviewed without embedding material",
	}
	for _, reason := range valid {
		if !validFederationAuditReason(reason) {
			t.Fatalf("validFederationAuditReason(%q) = false", reason)
		}
	}

	unsafe := []string{
		"-----BEGIN PRIVATE KEY-----",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"Basic YWxhZGRpbjpvcGVuc2VzYW1l",
		"password=correct-horse-battery-staple",
		"client_secret: abcdefghijklmnop",
		"api-key=abcdefghijklmnop",
		"assertion=abcdefghijklmnop",
		"eyJheader12345.eyJpayload12345.signature12345",
		strings.Repeat("x", 501),
	}
	for _, reason := range unsafe {
		if validFederationAuditReason(reason) {
			t.Fatalf("validFederationAuditReason(%q) = true", reason)
		}
	}
}

func TestFederationMutationVersionBoundary(t *testing.T) {
	t.Parallel()

	incrementable := fmt.Sprintf(`"v%d"`, maximumResourceVersion-1)
	version, err := validateIncrementableFederationVersion(testProviderID, &incrementable, testAudit())
	if err != nil || version != maximumResourceVersion-1 {
		t.Fatalf("incrementable boundary = (%d, %v)", version, err)
	}

	exhausted := fmt.Sprintf(`"v%d"`, maximumResourceVersion)
	version, err = validateIncrementableFederationVersion(testProviderID, &exhausted, testAudit())
	if version != 0 || !errors.Is(err, ErrConflict) {
		t.Fatalf("exhausted boundary = (%d, %v), want conflict", version, err)
	}
}
