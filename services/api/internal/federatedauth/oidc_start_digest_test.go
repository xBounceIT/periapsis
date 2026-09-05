package federatedauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestOIDCStartDigesterBuildsCanonicalPurposeSeparatedLookup(t *testing.T) {
	key := bytes.Repeat([]byte{0x73}, 32)
	digester, err := NewOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("NewOIDCStartDigester() error = %v", err)
	}
	clear(key)
	receipt := bytes.Repeat([]byte{0xa5}, 32)
	operationID := serviceID(100)
	operationID[6] = operationID[6]&0x0f | 0x70
	operationID[8] = operationID[8]&0x3f | 0x80
	lookup, err := digester.BuildLookup(operationID, receipt, "acme", "primary_oidc", "2001:db8::1")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	wantReceipt := sha256.Sum256(receipt)
	if lookup.OperationRunID != operationID || lookup.TenantSlug != "acme" || lookup.LoginKey != "primary_oidc" ||
		lookup.ReceiptDigest != OIDCStartReceiptDigest(wantReceipt) ||
		lookup.NetworkDigest == OIDCNetworkRateDigest(lookup.AccountDigest) ||
		lookup.NetworkDigest == OIDCNetworkRateDigest(lookup.ProviderDigest) ||
		lookup.AccountDigest == OIDCAccountRateDigest(lookup.ProviderDigest) {
		t.Fatalf("lookup = %s", lookup)
	}
	second, err := digester.BuildLookup(operationID, receipt, "acme", "secondary_oidc", "2001:db8::1")
	if err != nil || second.NetworkDigest != lookup.NetworkDigest || second.AccountDigest != lookup.AccountDigest ||
		second.ProviderDigest == lookup.ProviderDigest {
		t.Fatalf("provider separation = %s, %v", second, err)
	}
}

func TestOIDCStartDigesterRejectsNonCanonicalOrMalformedInputs(t *testing.T) {
	digester, err := NewOIDCStartDigester(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatalf("NewOIDCStartDigester() error = %v", err)
	}
	validID := serviceID(101)
	validID[6] = validID[6]&0x0f | 0x70
	validID[8] = validID[8]&0x3f | 0x80
	receipt := bytes.Repeat([]byte{0x42}, 32)
	type parameters struct {
		operationID identity.EntityID
		receipt     []byte
		tenantSlug  string
		loginKey    string
		network     string
	}
	for name, mutate := range map[string]func(*parameters){
		"uuid version": func(value *parameters) {
			id := value.operationID
			id[6] = 0x40
			value.operationID = id
		},
		"receipt length": func(value *parameters) { value.receipt = []byte("short") },
		"zero receipt":   func(value *parameters) { value.receipt = make([]byte, 32) },
		"tenant slug":    func(value *parameters) { value.tenantSlug = "Acme" },
		"login key":      func(value *parameters) { value.loginKey = "x" },
		"network port":   func(value *parameters) { value.network = "192.0.2.1:443" },
		"network alias":  func(value *parameters) { value.network = "2001:0db8::1" },
		"network zone":   func(value *parameters) { value.network = "fe80::1%eth0" },
	} {
		t.Run(name, func(t *testing.T) {
			values := parameters{
				operationID: validID, receipt: append([]byte(nil), receipt...), tenantSlug: "acme",
				loginKey: "primary_oidc", network: "192.0.2.1",
			}
			mutate(&values)
			_, buildErr := digester.BuildLookup(
				values.operationID, values.receipt, values.tenantSlug, values.loginKey, values.network,
			)
			if !errors.Is(buildErr, ErrInvalidInput) {
				t.Fatalf("BuildLookup() error = %v", buildErr)
			}
		})
	}
}

func TestOIDCStartDigesterCopiesAndRedactsKey(t *testing.T) {
	const canary = "oidc-start-digest-key-canary-1234"
	key := []byte(canary)
	digester, err := NewOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("NewOIDCStartDigester() error = %v", err)
	}
	if len(digester.key) != sha256.Size || bytes.Equal(digester.key, key) {
		t.Fatal("digester retained the source key instead of a purpose-derived key")
	}
	before := digester.digest(oidcNetworkRatePurpose, []byte("192.0.2.1"))
	clear(key)
	after := digester.digest(oidcNetworkRatePurpose, []byte("192.0.2.1"))
	if before != after {
		t.Fatal("digester retained caller-owned key storage")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, digester)
		if strings.Contains(output, canary) || strings.Contains(output, fmt.Sprintf("%x", []byte(canary))) {
			t.Fatalf("digester leaked with %s: %s", format, output)
		}
	}
	if _, err = NewOIDCStartDigester([]byte("short")); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("short key error = %v", err)
	}
	if _, err = NewOIDCStartDigester(make([]byte, 32)); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("zero key error = %v", err)
	}
}
