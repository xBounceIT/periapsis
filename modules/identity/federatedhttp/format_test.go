package federatedhttp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const formattingSecret = "formatting-secret-canary"

type hostileResolver struct{}

func (hostileResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, nil
}

func (hostileResolver) String() string   { return formattingSecret }
func (hostileResolver) GoString() string { return formattingSecret }

type hostileDialer struct{}

func (hostileDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (hostileDialer) String() string   { return formattingSecret }
func (hostileDialer) GoString() string { return formattingSecret }

func TestExportedBoundaryFormattingIsRedacted(t *testing.T) {
	policy, err := NewDeploymentEgressPolicy(
		[]netip.Prefix{netip.MustParsePrefix("10.25.0.0/16")},
		[]uint16{8443},
	)
	if err != nil {
		t.Fatal(err)
	}
	secretBody := []byte(formattingSecret)
	values := []any{
		policy,
		&policy,
		DefaultLimits(),
		Options{
			Resolver:      hostileResolver{},
			Dialer:        hostileDialer{},
			EgressPolicy:  policy,
			Limits:        DefaultLimits(),
			MaxConcurrent: 7,
		},
		DocumentKind(formattingSecret),
		Target{
			kind:         DocumentKind(formattingSecret),
			canonicalURL: "https://" + formattingSecret + ".example/" + formattingSecret,
			host:         formattingSecret + ".example",
			port:         8443,
			valid:        true,
		},
		Category(formattingSecret),
		CacheMetadata{
			RetrievedAt:    time.Unix(1, 0).UTC(),
			FreshUntil:     time.Unix(2, 0).UTC(),
			Cacheable:      true,
			MustRevalidate: true,
		},
		Result{
			Category:  CategorySuccess,
			Kind:      DocumentOIDCJWKS,
			Redirects: 2,
			Body:      secretBody,
			Digest:    sha256.Sum256(secretBody),
			Cache:     CacheMetadata{Cacheable: true},
		},
		Result{
			Category: Category(formattingSecret),
			Kind:     DocumentKind(formattingSecret),
			Body:     secretBody,
			Digest:   sha256.Sum256(secretBody),
		},
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x"}
	for _, value := range values {
		for _, format := range formats {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, formattingSecret) ||
				strings.Contains(formatted, fmt.Sprintf("%x", []byte(formattingSecret))) ||
				strings.Contains(formatted, "10.25.0.0") ||
				strings.Contains(formatted, "8443") {
				t.Fatalf("%T with %q leaked: %s", value, format, formatted)
			}
		}
	}
}

func TestSanitizedErrorsNeverFormatHostileInputs(t *testing.T) {
	errorsToCheck := []error{
		ErrInvalidOptions,
		ErrInvalidTarget,
		ErrInvalidAuthorization,
		ErrBusy,
		categorizedError{category: CategoryDNSFailed},
	}
	for _, err := range errorsToCheck {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(format, err)
			if strings.Contains(formatted, formattingSecret) {
				t.Fatalf("error with %q leaked: %s", format, formatted)
			}
		}
	}
}
