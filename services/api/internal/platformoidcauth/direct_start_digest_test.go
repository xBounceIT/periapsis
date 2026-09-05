package platformoidcauth

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestDirectOIDCStartDigesterIsPurposeSeparatedFromTenantOIDC(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	receipt := bytes.Repeat([]byte{0x52}, 32)
	capability := bytes.Repeat([]byte{0x63}, 32)
	direct, err := NewDirectOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("NewDirectOIDCStartDigester() error = %v", err)
	}
	tenant, err := federatedauth.NewOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("federatedauth.NewOIDCStartDigester() error = %v", err)
	}
	directLookup, err := direct.BuildLookup(
		directTestEntityID(40), receipt, capability, "platform_login", "203.0.113.11",
	)
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	tenantLookup, err := tenant.BuildLookup(
		directTestEntityID(40), receipt, "tenant", "platform_login", "203.0.113.11",
	)
	if err != nil {
		t.Fatalf("tenant BuildLookup() error = %v", err)
	}
	if [32]byte(directLookup.ReceiptDigest) == [32]byte(tenantLookup.ReceiptDigest) ||
		[32]byte(directLookup.NetworkDigest) == [32]byte(tenantLookup.NetworkDigest) ||
		[32]byte(directLookup.AccountDigest) == [32]byte(tenantLookup.AccountDigest) ||
		[32]byte(directLookup.ProviderDigest) == [32]byte(tenantLookup.ProviderDigest) {
		t.Fatal("direct digest was transplantable into tenant OIDC start")
	}
	directDigests := [][32]byte{
		directLookup.ReceiptDigest, directLookup.NetworkDigest, directLookup.AccountDigest,
		directLookup.ProviderDigest, directLookup.BrowserCapabilityDigest,
	}
	for left := range directDigests {
		for right := left + 1; right < len(directDigests); right++ {
			if directDigests[left] == directDigests[right] {
				t.Fatalf("direct purposes %d and %d collided", left, right)
			}
		}
	}
}

func TestDirectOIDCStartDigesterBindsProviderNetworkAndBrowserIndependently(t *testing.T) {
	digester, err := NewDirectOIDCStartDigester(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatalf("NewDirectOIDCStartDigester() error = %v", err)
	}
	receipt := bytes.Repeat([]byte{0x42}, 32)
	capability := bytes.Repeat([]byte{0x53}, 32)
	base, err := digester.BuildLookup(directTestEntityID(41), receipt, capability, "provider_one", "2001:db8::1")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	repeat, _ := digester.BuildLookup(directTestEntityID(41), receipt, capability, "provider_one", "2001:db8::1")
	if base != repeat {
		t.Fatalf("non-deterministic lookup: %#v != %#v", base, repeat)
	}
	providerChanged, _ := digester.BuildLookup(directTestEntityID(41), receipt, capability, "provider_two", "2001:db8::1")
	if providerChanged.ProviderDigest == base.ProviderDigest ||
		providerChanged.NetworkDigest != base.NetworkDigest || providerChanged.AccountDigest != base.AccountDigest ||
		providerChanged.BrowserCapabilityDigest != base.BrowserCapabilityDigest {
		t.Fatalf("provider dimension changed unrelated digests: %#v", providerChanged)
	}
	browserChanged, _ := digester.BuildLookup(
		directTestEntityID(41), receipt, bytes.Repeat([]byte{0x64}, 32), "provider_one", "2001:db8::1",
	)
	if browserChanged.AccountDigest == base.AccountDigest ||
		browserChanged.BrowserCapabilityDigest == base.BrowserCapabilityDigest ||
		browserChanged.ProviderDigest != base.ProviderDigest || browserChanged.NetworkDigest != base.NetworkDigest {
		t.Fatalf("browser dimension was not isolated: %#v", browserChanged)
	}
	digest, err := digester.BrowserCapabilityDigest(capability)
	if err != nil || digest != base.BrowserCapabilityDigest {
		t.Fatalf("BrowserCapabilityDigest() = %x, %v", digest, err)
	}
}

func TestDirectOIDCStartDigesterRejectsMalformedOrNonCanonicalInput(t *testing.T) {
	digester, err := NewDirectOIDCStartDigester(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatalf("NewDirectOIDCStartDigester() error = %v", err)
	}
	validID := directTestEntityID(42)
	validReceipt := bytes.Repeat([]byte{1}, 32)
	validCapability := bytes.Repeat([]byte{2}, 32)
	tests := map[string]func() (DirectOIDCStartLookup, error){
		"zero operation": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup([16]byte{}, validReceipt, validCapability, "provider", "203.0.113.2")
		},
		"future operation": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(directFutureEntityID(), validReceipt, validCapability, "provider", "203.0.113.2")
		},
		"short receipt": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt[:31], validCapability, "provider", "203.0.113.2")
		},
		"zero receipt": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, make([]byte, 32), validCapability, "provider", "203.0.113.2")
		},
		"short capability": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, validCapability[:31], "provider", "203.0.113.2")
		},
		"zero capability": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, make([]byte, 32), "provider", "203.0.113.2")
		},
		"uppercase login key": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, validCapability, "Provider", "203.0.113.2")
		},
		"noncanonical IPv6": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, validCapability, "provider", "2001:0db8::1")
		},
		"zoned network": func() (DirectOIDCStartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, validCapability, "provider", "fe80::1%eth0")
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			lookup, err := build()
			if !errors.Is(err, ErrDirectAuthenticationDenied) || lookup != (DirectOIDCStartLookup{}) {
				t.Fatalf("BuildLookup() = %#v, %v", lookup, err)
			}
		})
	}
	if digest, err := digester.BrowserCapabilityDigest(make([]byte, 32)); !errors.Is(err, ErrDirectAuthenticationDenied) || digest != (DirectBrowserCapabilityDigest{}) {
		t.Fatalf("BrowserCapabilityDigest(zero) = %x, %v", digest, err)
	}
	for _, key := range [][]byte{nil, []byte("short"), make([]byte, 32), bytes.Repeat([]byte{1}, 129)} {
		if value, err := NewDirectOIDCStartDigester(key); !errors.Is(err, ErrDirectAuthenticationDenied) || value != nil {
			t.Fatalf("NewDirectOIDCStartDigester(%d bytes) = %#v, %v", len(key), value, err)
		}
	}
}

func TestDirectOIDCStartDigesterCopiesKeyAndRedactsProviderLocator(t *testing.T) {
	canary := "provider_canary"
	key := bytes.Repeat([]byte{0x21}, 32)
	digester, err := NewDirectOIDCStartDigester(key)
	if err != nil {
		t.Fatalf("NewDirectOIDCStartDigester() error = %v", err)
	}
	before, err := digester.BuildLookup(
		directTestEntityID(43), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), canary, "203.0.113.3",
	)
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	clear(key)
	after, err := digester.BuildLookup(
		directTestEntityID(43), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), canary, "203.0.113.3",
	)
	if err != nil || before != after {
		t.Fatalf("source key mutation affected digester: %#v, %v", after, err)
	}
	for _, value := range []any{digester, before} {
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("format leaked provider locator: %s", rendered)
			}
		}
	}
}
