package federatedauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type oidcClientSecretEnvelopeSourceFunc func(
	context.Context,
	ClientSecretContext,
) (OIDCClientSecretSnapshot, error)

func (function oidcClientSecretEnvelopeSourceFunc) LoadOIDCClientSecretEnvelope(
	ctx context.Context,
	lookup ClientSecretContext,
) (OIDCClientSecretSnapshot, error) {
	return function(ctx, lookup)
}

type oidcMaintenanceClientSecretEnvelopeSourceFunc func(
	context.Context,
	ClientSecretContext,
) (OIDCClientSecretSnapshot, error)

func (function oidcMaintenanceClientSecretEnvelopeSourceFunc) LoadOIDCMaintenanceClientSecretEnvelope(
	ctx context.Context,
	lookup ClientSecretContext,
) (OIDCClientSecretSnapshot, error) {
	return function(ctx, lookup)
}

func TestKeyringOIDCClientSecretSourceDecryptsExactSnapshotAndClearsEnvelope(t *testing.T) {
	keyring := oidcSecretKeyring(t)
	lookup := oidcSecretLookup()
	secretID := serviceID(93)
	plaintext := []byte("short-lived-client-secret")
	envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
	}, plaintext)
	if err != nil {
		t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
	}
	clear(plaintext)
	sourceEnvelope := envelope.Ciphertext
	source := oidcClientSecretEnvelopeSourceFunc(func(
		_ context.Context,
		got ClientSecretContext,
	) (OIDCClientSecretSnapshot, error) {
		if got != lookup {
			t.Fatalf("lookup = %+v", got)
		}
		return OIDCClientSecretSnapshot{Lookup: got, SecretID: secretID, Envelope: envelope}, nil
	})
	adapter, err := NewKeyringOIDCClientSecretSource(source, keyring)
	if err != nil {
		t.Fatalf("NewKeyringOIDCClientSecretSource() error = %v", err)
	}
	opened, err := adapter.OpenOIDCClientSecret(context.Background(), lookup)
	if err != nil || string(opened) != "short-lived-client-secret" {
		t.Fatalf("OpenOIDCClientSecret() = %q, %v", opened, err)
	}
	clear(opened)
	if !allZero(sourceEnvelope) {
		t.Fatal("adapter retained the transferred ciphertext")
	}
}

func TestKeyringOIDCClientSecretSourceUsesAdmissionOnlyForPlatformPersistenceLookup(t *testing.T) {
	keyring := oidcSecretKeyring(t)
	lookup := platformOIDCSecretLookup()
	secretID := serviceID(104)
	envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
	}, []byte("shared-platform-client-secret"))
	if err != nil {
		t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
	}
	adapter, err := NewKeyringOIDCClientSecretSource(oidcClientSecretEnvelopeSourceFunc(func(
		_ context.Context,
		got ClientSecretContext,
	) (OIDCClientSecretSnapshot, error) {
		if got != lookup {
			t.Fatalf("lookup = %+v, want %+v", got, lookup)
		}
		return OIDCClientSecretSnapshot{Lookup: got, SecretID: secretID, Envelope: envelope}, nil
	}), keyring)
	if err != nil {
		t.Fatalf("NewKeyringOIDCClientSecretSource() error = %v", err)
	}

	opened, err := adapter.OpenOIDCClientSecret(context.Background(), lookup)
	if err != nil || string(opened) != "shared-platform-client-secret" {
		t.Fatalf("OpenOIDCClientSecret() = %q, %v", opened, err)
	}
	clear(opened)
}

func TestKeyringOIDCMaintenanceClientSecretSourceSupportsEveryAuthorityShape(t *testing.T) {
	for name, lookup := range map[string]ClientSecretContext{
		"tenant":            oidcMaintenanceSecretLookup(oidcSecretLookup()),
		"admitted platform": oidcMaintenanceSecretLookup(platformOIDCSecretLookup()),
		"direct platform": oidcMaintenanceSecretLookup(ClientSecretContext{
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(105),
			},
			Revision: 8,
		}),
	} {
		t.Run(name, func(t *testing.T) {
			keyring := oidcSecretKeyring(t)
			secretID := serviceID(106)
			plaintext := []byte("historical-maintenance-client-secret")
			envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
				Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
			}, plaintext)
			if err != nil {
				t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
			}
			clear(plaintext)
			retainedCiphertext := envelope.Ciphertext
			adapter, err := NewKeyringOIDCMaintenanceClientSecretSource(
				oidcMaintenanceClientSecretEnvelopeSourceFunc(func(
					_ context.Context,
					got ClientSecretContext,
				) (OIDCClientSecretSnapshot, error) {
					if got != lookup {
						t.Fatalf("lookup = %+v, want %+v", got, lookup)
					}
					return OIDCClientSecretSnapshot{
						Lookup: got, SecretID: secretID, Envelope: envelope,
					}, nil
				}),
				keyring,
			)
			if err != nil {
				t.Fatalf("NewKeyringOIDCMaintenanceClientSecretSource() error = %v", err)
			}

			opened, err := adapter.OpenOIDCClientSecret(context.Background(), lookup)
			if err != nil || string(opened) != "historical-maintenance-client-secret" {
				t.Fatalf("OpenOIDCClientSecret() = %q, %v", opened, err)
			}
			clear(opened)
			if !allZero(retainedCiphertext) {
				t.Fatal("adapter retained the transferred ciphertext")
			}
		})
	}
}

func TestKeyringOIDCMaintenanceClientSecretSourceRejectsCrossAuthorityLookupsBeforePersistence(t *testing.T) {
	called := false
	adapter, err := NewKeyringOIDCMaintenanceClientSecretSource(
		oidcMaintenanceClientSecretEnvelopeSourceFunc(func(
			context.Context,
			ClientSecretContext,
		) (OIDCClientSecretSnapshot, error) {
			called = true
			return OIDCClientSecretSnapshot{}, nil
		}),
		oidcSecretKeyring(t),
	)
	if err != nil {
		t.Fatalf("NewKeyringOIDCMaintenanceClientSecretSource() error = %v", err)
	}
	for name, lookup := range map[string]ClientSecretContext{
		"tenant admission": {
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: serviceID(107), ProviderID: serviceID(108),
			},
			Admission: identity.TenantAdmissionContext{TenantID: serviceID(109), BindingID: serviceID(110)},
			BindingID: serviceID(111), Revision: 1,
		},
		"platform tenant": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, TenantID: serviceID(107), ProviderID: serviceID(108),
			},
			Revision: 1,
		},
		"platform cryptographic binding": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(108),
			},
			BindingID: serviceID(111), Revision: 1,
		},
		"partial admission": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(108),
			},
			Admission: identity.TenantAdmissionContext{TenantID: serviceID(109)}, Revision: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			lookup.Maintenance = oidcMaintenanceSecretProof()
			if _, openErr := adapter.OpenOIDCClientSecret(context.Background(), lookup); !errors.Is(openErr, ErrAuthentication) {
				t.Fatalf("OpenOIDCClientSecret() error = %v", openErr)
			}
		})
	}
	if called {
		t.Fatal("cross-authority lookup reached persistence")
	}
}

func TestKeyringOIDCClientSecretSourceRejectsMismatchedOrUnreadableSnapshots(t *testing.T) {
	keyring := oidcSecretKeyring(t)
	lookup := oidcSecretLookup()
	secretID := serviceID(94)
	makeEnvelope := func() identity.OIDCClientSecretEnvelope {
		envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
			Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
		}, []byte("client-secret"))
		if err != nil {
			t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
		}
		return envelope
	}
	for name, result := range map[string]func() (OIDCClientSecretSnapshot, error){
		"source error": func() (OIDCClientSecretSnapshot, error) {
			return OIDCClientSecretSnapshot{Envelope: makeEnvelope()}, errors.New("read failed")
		},
		"lookup drift": func() (OIDCClientSecretSnapshot, error) {
			snapshot := OIDCClientSecretSnapshot{Lookup: lookup, SecretID: secretID, Envelope: makeEnvelope()}
			snapshot.Lookup.Revision++
			return snapshot, nil
		},
		"secret row swap": func() (OIDCClientSecretSnapshot, error) {
			return OIDCClientSecretSnapshot{Lookup: lookup, SecretID: serviceID(95), Envelope: makeEnvelope()}, nil
		},
		"ciphertext tamper": func() (OIDCClientSecretSnapshot, error) {
			snapshot := OIDCClientSecretSnapshot{Lookup: lookup, SecretID: secretID, Envelope: makeEnvelope()}
			snapshot.Envelope.Ciphertext[0] ^= 0xff
			return snapshot, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			var returnedCiphertext []byte
			adapter, err := NewKeyringOIDCClientSecretSource(oidcClientSecretEnvelopeSourceFunc(func(
				context.Context,
				ClientSecretContext,
			) (OIDCClientSecretSnapshot, error) {
				snapshot, loadErr := result()
				returnedCiphertext = snapshot.Envelope.Ciphertext
				return snapshot, loadErr
			}), keyring)
			if err != nil {
				t.Fatalf("NewKeyringOIDCClientSecretSource() error = %v", err)
			}
			opened, openErr := adapter.OpenOIDCClientSecret(context.Background(), lookup)
			if !errors.Is(openErr, ErrAuthentication) || len(opened) != 0 || !allZero(returnedCiphertext) {
				t.Fatalf("OpenOIDCClientSecret() = %v, %v, ciphertext=%x", opened, openErr, returnedCiphertext)
			}
		})
	}
}

func TestKeyringOIDCClientSecretSourceRejectsMalformedLookupBeforePersistence(t *testing.T) {
	called := false
	adapter, err := NewKeyringOIDCClientSecretSource(oidcClientSecretEnvelopeSourceFunc(func(
		context.Context,
		ClientSecretContext,
	) (OIDCClientSecretSnapshot, error) {
		called = true
		return OIDCClientSecretSnapshot{}, nil
	}), oidcSecretKeyring(t))
	if err != nil {
		t.Fatalf("NewKeyringOIDCClientSecretSource() error = %v", err)
	}
	for name, mutate := range map[string]func(*ClientSecretContext){
		"zero revision": func(value *ClientSecretContext) { value.Revision = 0 },
		"cross scope": func(value *ClientSecretContext) {
			value.Provider.Scope = identity.PlatformProviderScope
		},
		"tenant admission injection": func(value *ClientSecretContext) {
			value.Admission = identity.TenantAdmissionContext{TenantID: serviceID(97), BindingID: serviceID(98)}
		},
		"platform missing admission": func(value *ClientSecretContext) {
			value.Provider = identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: serviceID(99)}
			value.BindingID = identity.EntityID{}
		},
		"platform cryptographic binding": func(value *ClientSecretContext) {
			*value = platformOIDCSecretLookup()
			value.BindingID = serviceID(103)
		},
		"cancelled": func(*ClientSecretContext) {},
	} {
		t.Run(name, func(t *testing.T) {
			lookup := oidcSecretLookup()
			mutate(&lookup)
			ctx := context.Background()
			if name == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, openErr := adapter.OpenOIDCClientSecret(ctx, lookup); !errors.Is(openErr, ErrAuthentication) {
				t.Fatalf("OpenOIDCClientSecret() error = %v", openErr)
			}
		})
	}
	if called {
		t.Fatal("malformed lookup reached persistence")
	}
}

func TestKeyringOIDCClientSecretSourceHonorsCancellationAfterPersistence(t *testing.T) {
	keyring := oidcSecretKeyring(t)
	lookup := oidcSecretLookup()
	secretID := serviceID(96)
	envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
	}, []byte("must-not-be-returned"))
	if err != nil {
		t.Fatal(err)
	}
	retainedCiphertext := envelope.Ciphertext
	ctx, cancel := context.WithCancel(context.Background())
	adapter, err := NewKeyringOIDCClientSecretSource(oidcClientSecretEnvelopeSourceFunc(func(
		context.Context,
		ClientSecretContext,
	) (OIDCClientSecretSnapshot, error) {
		cancel()
		return OIDCClientSecretSnapshot{Lookup: lookup, SecretID: secretID, Envelope: envelope}, nil
	}), keyring)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := adapter.OpenOIDCClientSecret(ctx, lookup)
	if !errors.Is(err, ErrAuthentication) || len(opened) != 0 || !allZero(retainedCiphertext) {
		t.Fatalf("OpenOIDCClientSecret() = %q, %v", opened, err)
	}
}

func TestOIDCClientSecretAdapterFormattingNeverLeaksMaterial(t *testing.T) {
	const canary = "oidc-client-secret-canary"
	values := []any{
		OIDCClientSecretSnapshot{Envelope: identity.OIDCClientSecretEnvelope{Ciphertext: []byte(canary)}},
		&KeyringOIDCClientSecretSource{},
		&KeyringOIDCMaintenanceClientSecretSource{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) ||
				strings.Contains(output, fmt.Sprintf("%x", []byte(canary))) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func oidcSecretKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	root := bytes.Repeat([]byte{0x9c}, 32)
	defer clear(root)
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func oidcSecretLookup() ClientSecretContext {
	tenantID := serviceID(90)
	return ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(91),
		},
		BindingID: serviceID(92), Revision: 7,
	}
}

func platformOIDCSecretLookup() ClientSecretContext {
	return ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(100),
		},
		Admission: identity.TenantAdmissionContext{
			TenantID: serviceID(101), BindingID: serviceID(102),
		},
		Revision: 7,
	}
}

func oidcMaintenanceSecretProof() OIDCMaintenanceSecretProof {
	return OIDCMaintenanceSecretProof{
		Kind: OIDCMaintenanceSecretRefresh, MaterialID: serviceID(112),
		SessionFamilyID: serviceID(113), ClaimVersion: 4, RefreshGeneration: 5,
	}
}

func oidcMaintenanceSecretLookup(lookup ClientSecretContext) ClientSecretContext {
	lookup.Maintenance = oidcMaintenanceSecretProof()
	return lookup
}
