package federatedoidc

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestExportedTrustDocumentFormattingIsRedacted(t *testing.T) {
	canaryURL := "https://" + testHostileSentinel
	canaryDigest := sha256.Sum256([]byte(testHostileSentinel))
	compiler := newCompiler(t)
	client, err := New(Options{HTTP: compiler, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		ClientAuthenticationMode(testHostileSentinel),
		SigningAlgorithm(testHostileSentinel),
		KeyType(testHostileSentinel),
		DefaultLimits(),
		Options{HTTP: compiler, Limits: DefaultLimits()},
		TrustPolicy{
			ClientAuthentication: ClientAuthenticationMode(testHostileSentinel),
			SigningAlgorithms:    []SigningAlgorithm{SigningAlgorithm(testHostileSentinel)},
		},
		DiscoveryRequest{
			Issuer:   canaryURL,
			Revision: 91,
			Policy: TrustPolicy{
				ClientAuthentication: ClientAuthenticationMode(testHostileSentinel),
				SigningAlgorithms:    []SigningAlgorithm{SigningAlgorithm(testHostileSentinel)},
			},
		},
		Endpoints{
			Authorization: canaryURL + "/authorize",
			Token:         canaryURL + "/token",
			JWKS:          canaryURL + "/jwks",
			UserInfo:      canaryURL + "/userinfo",
			Revocation:    canaryURL + "/revoke",
			EndSession:    canaryURL + "/logout",
		},
		DiscoverySnapshot{
			revision: 91, digest: canaryDigest, issuer: canaryURL,
			endpoints:            Endpoints{Authorization: canaryURL, Token: canaryURL, JWKS: canaryURL},
			clientAuthentication: ClientAuthenticationMode(testHostileSentinel),
			signingAlgorithms:    []SigningAlgorithm{SigningAlgorithm(testHostileSentinel)},
			valid:                true,
		},
		KeySummary{
			KeyID: testHostileSentinel, Algorithm: SigningAlgorithm(testHostileSentinel),
			Type: KeyType(testHostileSentinel), Curve: testHostileSentinel,
			Bits: 256, CertificateCount: 2, ThumbprintSHA256: canaryDigest,
		},
		JWKSSnapshot{
			revision: 92, discoveryRevision: 91, discoveryDigest: canaryDigest,
			digest:    canaryDigest,
			summaries: []KeySummary{{KeyID: testHostileSentinel}},
			keys:      []jose.JSONWebKey{{KeyID: testHostileSentinel}},
			valid:     true,
		},
		FetchFailure{document: fetchDocument(255), category: federatedhttp.Category(testHostileSentinel)},
		client,
		(*Client)(nil),
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x"}
	encodedCanary := fmt.Sprintf("%x", []byte(testHostileSentinel))
	for _, value := range values {
		for _, format := range formats {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, testHostileSentinel) ||
				strings.Contains(formatted, encodedCanary) {
				t.Fatalf("%T with %q leaked: %s", value, format, formatted)
			}
		}
	}
}

func TestTrustDocumentErrorsNeverFormatHostileInputs(t *testing.T) {
	errorsToCheck := []error{
		ErrInvalidOptions,
		ErrInvalidRequest,
		ErrDiscoveryFetch,
		ErrDiscoveryRejected,
		ErrIssuerMismatch,
		ErrJWKSFetch,
		ErrJWKSRejected,
		ErrInvalidSnapshot,
		FetchFailure{document: fetchDocument(255), category: federatedhttp.Category(testHostileSentinel)},
	}
	for _, err := range errorsToCheck {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(format, err)
			if strings.Contains(formatted, testHostileSentinel) ||
				strings.Contains(formatted, fmt.Sprintf("%x", []byte(testHostileSentinel))) {
				t.Fatalf("error with %q leaked: %s", format, formatted)
			}
		}
	}
}
