package platformsamlauth

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestStartDigesterIsPurposeSeparatedFromTenantSAML(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	receipt := bytes.Repeat([]byte{0x52}, 32)
	direct, err := NewStartDigester(key)
	if err != nil {
		t.Fatalf("NewStartDigester() error = %v", err)
	}
	tenant, err := federatedauth.NewSAMLStartDigester(key)
	if err != nil {
		t.Fatalf("NewSAMLStartDigester() error = %v", err)
	}
	directLookup, err := direct.BuildLookup(testID(80), receipt, "workforce_saml", "203.0.113.8")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	tenantLookup, err := tenant.BuildLookup(testID(80), receipt, "tenant", "workforce_saml", "203.0.113.8")
	if err != nil {
		t.Fatalf("tenant BuildLookup() error = %v", err)
	}
	directDigests := [][32]byte{
		directLookup.Begin.ReceiptDigest,
		directLookup.Begin.NetworkDigest,
		directLookup.Begin.AccountDigest,
		directLookup.Begin.ProviderDigest,
	}
	tenantDigests := [][32]byte{
		tenantLookup.ReceiptDigest,
		tenantLookup.NetworkDigest,
		tenantLookup.AccountDigest,
		tenantLookup.ProviderDigest,
	}
	for index := range directDigests {
		if directDigests[index] == tenantDigests[index] {
			t.Fatalf("direct digest %d was transplantable into tenant SAML", index)
		}
		for previous := 0; previous < index; previous++ {
			if directDigests[index] == directDigests[previous] {
				t.Fatalf("direct digest purposes %d and %d collided", previous, index)
			}
		}
	}
}

func TestStartDigesterBindsIndependentAdmissionDimensions(t *testing.T) {
	digester, err := NewStartDigester(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatalf("NewStartDigester() error = %v", err)
	}
	receipt := bytes.Repeat([]byte{0x42}, 32)
	base, err := digester.BuildLookup(testID(81), receipt, "workforce_saml", "2001:db8::1")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	repeat, _ := digester.BuildLookup(testID(81), receipt, "workforce_saml", "2001:db8::1")
	if base != repeat {
		t.Fatalf("lookup is not deterministic: %#v != %#v", base, repeat)
	}
	providerChanged, _ := digester.BuildLookup(testID(81), receipt, "alternate_saml", "2001:db8::1")
	if providerChanged.Begin.ProviderDigest == base.Begin.ProviderDigest ||
		providerChanged.Begin.NetworkDigest != base.Begin.NetworkDigest ||
		providerChanged.Begin.AccountDigest != base.Begin.AccountDigest ||
		providerChanged.Begin.ReceiptDigest != base.Begin.ReceiptDigest {
		t.Fatalf("provider dimension changed unrelated digests: %#v", providerChanged)
	}
	networkChanged, _ := digester.BuildLookup(testID(81), receipt, "workforce_saml", "2001:db8::2")
	if networkChanged.Begin.NetworkDigest == base.Begin.NetworkDigest ||
		networkChanged.Begin.ProviderDigest != base.Begin.ProviderDigest ||
		networkChanged.Begin.AccountDigest != base.Begin.AccountDigest {
		t.Fatalf("network dimension changed unrelated digests: %#v", networkChanged)
	}
	receiptChanged, _ := digester.BuildLookup(
		testID(81), bytes.Repeat([]byte{0x53}, 32), "workforce_saml", "2001:db8::1",
	)
	if receiptChanged.Begin.ReceiptDigest == base.Begin.ReceiptDigest ||
		receiptChanged.Begin.AccountDigest == base.Begin.AccountDigest ||
		receiptChanged.Begin.NetworkDigest != base.Begin.NetworkDigest ||
		receiptChanged.Begin.ProviderDigest != base.Begin.ProviderDigest {
		t.Fatalf("browser receipt dimension changed unrelated digests: %#v", receiptChanged)
	}
}

func TestStartDigesterRejectsMalformedOrNonCanonicalInput(t *testing.T) {
	digester, err := NewStartDigester(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatalf("NewStartDigester() error = %v", err)
	}
	validID := testID(82)
	validReceipt := bytes.Repeat([]byte{1}, 32)
	tests := map[string]func() (StartLookup, error){
		"zero operation": func() (StartLookup, error) {
			return digester.BuildLookup([16]byte{}, validReceipt, "provider", "203.0.113.2")
		},
		"short receipt": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt[:31], "provider", "203.0.113.2")
		},
		"zero receipt": func() (StartLookup, error) {
			return digester.BuildLookup(validID, make([]byte, 32), "provider", "203.0.113.2")
		},
		"one-character key": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "p", "203.0.113.2")
		},
		"digit-start key": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "1provider", "203.0.113.2")
		},
		"leading hyphen": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "-provider", "203.0.113.2")
		},
		"oversized key": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "p"+strings.Repeat("a", 64), "203.0.113.2")
		},
		"uppercase key": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "Provider", "203.0.113.2")
		},
		"noncanonical IPv6": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "provider", "2001:0db8::1")
		},
		"mapped IPv4": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "provider", "::ffff:192.0.2.1")
		},
		"zoned network": func() (StartLookup, error) {
			return digester.BuildLookup(validID, validReceipt, "provider", "fe80::1%eth0")
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			lookup, err := build()
			if !errors.Is(err, ErrAuthenticationDenied) || lookup != (StartLookup{}) {
				t.Fatalf("BuildLookup() = %#v, %v", lookup, err)
			}
		})
	}
	for _, key := range [][]byte{nil, []byte("short"), make([]byte, 32), bytes.Repeat([]byte{1}, 129)} {
		if value, err := NewStartDigester(key); !errors.Is(err, ErrInvalidOptions) || value != nil {
			t.Fatalf("NewStartDigester(%d bytes) = %#v, %v", len(key), value, err)
		}
	}
}

func TestStartDigesterCopiesAndRedactsKeyAndLocator(t *testing.T) {
	const canary = "workforce_saml"
	key := bytes.Repeat([]byte{0x21}, 32)
	digester, err := NewStartDigester(key)
	if err != nil {
		t.Fatalf("NewStartDigester() error = %v", err)
	}
	receipt := bytes.Repeat([]byte{0x32}, 32)
	before, err := digester.BuildLookup(testID(83), receipt, canary, "203.0.113.3")
	if err != nil {
		t.Fatalf("BuildLookup() error = %v", err)
	}
	clear(key)
	after, err := digester.BuildLookup(testID(83), receipt, canary, "203.0.113.3")
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
