package federatedauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

func TestIdentityPKCEVerifierProtectorRoundTripAndContextBinding(t *testing.T) {
	root := bytes.Repeat([]byte{0x91}, 32)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewIdentityPKCEVerifierProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	protection := federatedoidc.TransactionProtectionContext{
		TransactionID: federatedoidc.TransactionID{1},
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: serviceID(1), ProviderID: serviceID(2),
		},
		BindingID: serviceID(3),
	}
	verifier := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
	protected, err := protector.SealPKCE(context.Background(), protection, verifier)
	if err != nil {
		t.Fatalf("SealPKCE() error = %v", err)
	}
	if protected.KeyVersion != 1 || len(protected.Ciphertext) <= len(verifier) || bytes.Contains(protected.Ciphertext, verifier) {
		t.Fatalf("protected verifier has invalid shape: %s", protected)
	}
	opened, err := protector.OpenPKCE(context.Background(), protection, protected)
	if err != nil || !bytes.Equal(opened, verifier) {
		t.Fatalf("OpenPKCE() = %q, %v", opened, err)
	}
	clear(opened)

	changed := protection
	changed.TransactionID[0] ^= 0xff
	if plaintext, openErr := protector.OpenPKCE(context.Background(), changed, protected); !errors.Is(openErr, federatedoidc.ErrCallbackRejected) {
		clear(plaintext)
		t.Fatalf("cross-transaction OpenPKCE() error = %v", openErr)
	}
	protected.Ciphertext[len(protected.Ciphertext)-1] ^= 1
	if plaintext, openErr := protector.OpenPKCE(context.Background(), protection, protected); !errors.Is(openErr, federatedoidc.ErrCallbackRejected) {
		clear(plaintext)
		t.Fatalf("tampered OpenPKCE() error = %v", openErr)
	}
}

func TestIdentityPKCEVerifierProtectorRejectsMalformedInputsAndRedacts(t *testing.T) {
	if _, err := NewIdentityPKCEVerifierProtector(identity.Keyring{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("zero keyring error = %v", err)
	}
	root := bytes.Repeat([]byte{0x92}, 32)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatal(err)
	}
	protector, _ := NewIdentityPKCEVerifierProtector(keyring)
	if _, err := protector.SealPKCE(context.Background(), federatedoidc.TransactionProtectionContext{}, []byte(strings.Repeat("x", 43))); !errors.Is(err, federatedoidc.ErrAuthorizationRejected) {
		t.Fatalf("invalid context error = %v", err)
	}
	if _, err := protector.OpenPKCE(context.Background(), federatedoidc.TransactionProtectionContext{}, federatedoidc.ProtectedVerifier{}); !errors.Is(err, federatedoidc.ErrCallbackRejected) {
		t.Fatalf("invalid protected verifier error = %v", err)
	}
	const canary = "pkce-private-canary"
	for _, value := range []any{
		protector,
		identity.OIDCPKCEVerifierEnvelope{Ciphertext: []byte(canary)},
		identity.OIDCClientSecretEnvelope{Ciphertext: []byte(canary)},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func TestIdentityPKCEVerifierProtectorUsesPlatformAdmissionAAD(t *testing.T) {
	root := bytes.Repeat([]byte{0x93}, 32)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewIdentityPKCEVerifierProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	protection := federatedoidc.TransactionProtectionContext{
		TransactionID: federatedoidc.TransactionID{1},
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(20),
		},
		Admission: identity.TenantAdmissionContext{TenantID: serviceID(21), BindingID: serviceID(22)},
		BindingID: identity.EntityID{},
	}
	verifier := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
	protected, err := protector.SealPKCE(context.Background(), protection, verifier)
	if err != nil {
		t.Fatalf("SealPKCE() error = %v", err)
	}
	opened, err := protector.OpenPKCE(context.Background(), protection, protected)
	if err != nil || !bytes.Equal(opened, verifier) {
		t.Fatalf("OpenPKCE() = %q, %v", opened, err)
	}
	clear(opened)

	changed := protection
	changed.Admission.BindingID = serviceID(23)
	opened, err = protector.OpenPKCE(context.Background(), changed, protected)
	clear(opened)
	if !errors.Is(err, federatedoidc.ErrCallbackRejected) {
		t.Fatalf("admission-substituted OpenPKCE() error = %v", err)
	}
	changed = protection
	changed.BindingID = serviceID(24)
	if _, err = protector.SealPKCE(context.Background(), changed, verifier); !errors.Is(err, federatedoidc.ErrAuthorizationRejected) {
		t.Fatalf("non-zero platform cryptographic binding error = %v", err)
	}
}

func TestIdentityPKCEVerifierProtectorUsesDisjointDirectPlatformAAD(t *testing.T) {
	root := bytes.Repeat([]byte{0x94}, 32)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewIdentityPKCEVerifierProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	direct := federatedoidc.TransactionProtectionContext{
		Authority:     federatedoidc.DirectPlatformCeremonyAuthority,
		TransactionID: federatedoidc.TransactionID{1},
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(30),
		},
		PlatformLoginRevision: 31,
	}
	verifier := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
	directProtected, err := protector.SealPKCE(context.Background(), direct, verifier)
	if err != nil {
		t.Fatalf("SealPKCE(direct) error = %v", err)
	}
	opened, err := protector.OpenPKCE(context.Background(), direct, directProtected)
	if err != nil || !bytes.Equal(opened, verifier) {
		t.Fatalf("OpenPKCE(direct) = %q, %v", opened, err)
	}
	clear(opened)

	tenantPlatform := direct
	tenantPlatform.Authority = federatedoidc.TenantCeremonyAuthority
	tenantPlatform.PlatformLoginRevision = 0
	tenantPlatform.Admission = identity.TenantAdmissionContext{
		TenantID: serviceID(31), BindingID: serviceID(32),
	}
	opened, err = protector.OpenPKCE(context.Background(), tenantPlatform, directProtected)
	clear(opened)
	if !errors.Is(err, federatedoidc.ErrCallbackRejected) {
		t.Fatalf("direct ciphertext opened with tenant-platform authority: %v", err)
	}
	tenantProtected, err := protector.SealPKCE(context.Background(), tenantPlatform, verifier)
	if err != nil {
		t.Fatalf("SealPKCE(tenant platform) error = %v", err)
	}
	opened, err = protector.OpenPKCE(context.Background(), direct, tenantProtected)
	clear(opened)
	if !errors.Is(err, federatedoidc.ErrCallbackRejected) {
		t.Fatalf("tenant-platform ciphertext opened with direct authority: %v", err)
	}

	changedRevision := direct
	changedRevision.PlatformLoginRevision++
	opened, err = protector.OpenPKCE(context.Background(), changedRevision, directProtected)
	clear(opened)
	if !errors.Is(err, federatedoidc.ErrCallbackRejected) {
		t.Fatalf("revision-substituted OpenPKCE() error = %v", err)
	}
}

func TestIdentityPKCEVerifierProtectorRejectsDirectTenantAndRevisionSmuggling(t *testing.T) {
	root := bytes.Repeat([]byte{0x95}, 32)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewIdentityPKCEVerifierProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	verifier := []byte(strings.Repeat("d", 64))
	for name, mutate := range map[string]func(*federatedoidc.TransactionProtectionContext){
		"fake provider tenant": func(value *federatedoidc.TransactionProtectionContext) {
			value.Provider.TenantID = serviceID(40)
		},
		"binding ID": func(value *federatedoidc.TransactionProtectionContext) {
			value.BindingID = serviceID(41)
		},
		"tenant admission": func(value *federatedoidc.TransactionProtectionContext) {
			value.Admission = identity.TenantAdmissionContext{
				TenantID: serviceID(42), BindingID: serviceID(43),
			}
		},
		"zero platform login revision": func(value *federatedoidc.TransactionProtectionContext) {
			value.PlatformLoginRevision = 0
		},
		"platform login revision overflow": func(value *federatedoidc.TransactionProtectionContext) {
			value.PlatformLoginRevision = 9_007_199_254_740_992
		},
	} {
		t.Run(name, func(t *testing.T) {
			protection := federatedoidc.TransactionProtectionContext{
				Authority:     federatedoidc.DirectPlatformCeremonyAuthority,
				TransactionID: federatedoidc.TransactionID{1},
				Provider: identity.ProviderContext{
					Scope: identity.PlatformProviderScope, ProviderID: serviceID(44),
				},
				PlatformLoginRevision: 31,
			}
			mutate(&protection)
			if _, err := protector.SealPKCE(context.Background(), protection, verifier); !errors.Is(err, federatedoidc.ErrAuthorizationRejected) {
				t.Fatalf("SealPKCE() error = %v", err)
			}
		})
	}
}
