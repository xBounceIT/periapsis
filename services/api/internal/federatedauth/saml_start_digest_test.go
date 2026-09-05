package federatedauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSAMLStartDigesterBuildsProtocolSeparatedLookup(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x74}, 32)
	digester, err := NewSAMLStartDigester(key)
	if err != nil {
		t.Fatalf("NewSAMLStartDigester() error = %v", err)
	}
	oidc, err := NewOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("NewOIDCStartDigester() error = %v", err)
	}
	if len(digester.key) != sha256.Size || len(oidc.key) != sha256.Size ||
		bytes.Equal(digester.key, key) || bytes.Equal(digester.key, oidc.key) {
		t.Fatal("OIDC and SAML retained or shared start-digest key material")
	}
	clear(key)
	receipt := bytes.Repeat([]byte{0xB5}, 32)
	operationID := serviceID(110)
	operationID[6] = operationID[6]&0x0f | 0x70
	operationID[8] = operationID[8]&0x3f | 0x80
	lookup, err := digester.BuildLookup(operationID, receipt, "acme", "primary_saml", "2001:db8::2")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	wantReceipt := sha256.Sum256(receipt)
	if lookup.OperationRunID != operationID || lookup.ReceiptDigest != SAMLStartReceiptDigest(wantReceipt) ||
		lookup.NetworkDigest == SAMLNetworkRateDigest(lookup.AccountDigest) ||
		lookup.NetworkDigest == SAMLNetworkRateDigest(lookup.ProviderDigest) ||
		lookup.AccountDigest == SAMLAccountRateDigest(lookup.ProviderDigest) {
		t.Fatalf("lookup = %s", lookup)
	}
	oidcLookup, err := oidc.BuildLookup(operationID, receipt, "acme", "primary_saml", "2001:db8::2")
	if err != nil {
		t.Fatalf("OIDC BuildLookup() error = %v", err)
	}
	if [sha256.Size]byte(lookup.NetworkDigest) == [sha256.Size]byte(oidcLookup.NetworkDigest) ||
		[sha256.Size]byte(lookup.AccountDigest) == [sha256.Size]byte(oidcLookup.AccountDigest) ||
		[sha256.Size]byte(lookup.ProviderDigest) == [sha256.Size]byte(oidcLookup.ProviderDigest) {
		t.Fatal("SAML throttle digests were not separated from OIDC")
	}
}

func TestSAMLStartDigesterRejectsMalformedInputsAndRedactsKey(t *testing.T) {
	t.Parallel()
	const canary = "saml-start-digest-key-canary-1234"
	digester, err := NewSAMLStartDigester([]byte(canary))
	if err != nil {
		t.Fatalf("NewSAMLStartDigester() error = %v", err)
	}
	operationID := serviceID(111)
	operationID[6] = operationID[6]&0x0f | 0x70
	operationID[8] = operationID[8]&0x3f | 0x80
	if _, err := digester.BuildLookup(operationID, make([]byte, 32), "acme", "primary_saml", "192.0.2.2"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero receipt error = %v", err)
	}
	if _, err := digester.BuildLookup(operationID, bytes.Repeat([]byte{1}, 32), "Acme", "primary_saml", "192.0.2.2"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("noncanonical tenant error = %v", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, digester)
		if strings.Contains(output, canary) || strings.Contains(output, fmt.Sprintf("%x", []byte(canary))) {
			t.Fatalf("digester leaked with %s: %s", format, output)
		}
	}
	if _, err := NewSAMLStartDigester([]byte("short")); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("short key error = %v", err)
	}
}
