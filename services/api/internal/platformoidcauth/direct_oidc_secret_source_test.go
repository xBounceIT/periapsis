package platformoidcauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type directOIDCClientSecretEnvelopeSourceFunc func(
	context.Context,
	DirectOIDCClientSecretLookup,
) (DirectOIDCClientSecretSnapshot, error)

func (function directOIDCClientSecretEnvelopeSourceFunc) LoadDirectOIDCClientSecretEnvelope(
	ctx context.Context,
	lookup DirectOIDCClientSecretLookup,
) (DirectOIDCClientSecretSnapshot, error) {
	return function(ctx, lookup)
}

func TestKeyringDirectOIDCClientSecretSourceOpensExactZeroBindingSnapshot(t *testing.T) {
	keyring := directTestKeyring(t)
	lookup := directOIDCClientSecretLookupFixture(t)
	secretID := directTestEntityID(121)
	plaintext := []byte("direct-platform-client-secret")
	envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Pins.Provider, BindingID: identity.EntityID{}, SecretID: secretID,
	}, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	transferredCiphertext := envelope.Ciphertext
	adapter, err := NewKeyringDirectOIDCClientSecretSource(
		directOIDCClientSecretEnvelopeSourceFunc(func(
			_ context.Context,
			observed DirectOIDCClientSecretLookup,
		) (DirectOIDCClientSecretSnapshot, error) {
			if observed != lookup {
				t.Fatalf("lookup = %s, want %s", observed, lookup)
			}
			return DirectOIDCClientSecretSnapshot{
				Lookup: observed, Pins: observed.Pins, SecretID: secretID, Envelope: envelope,
			}, nil
		}),
		keyring,
	)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := adapter.OpenDirectOIDCClientSecret(context.Background(), lookup)
	if err != nil || !bytes.Equal(opened, []byte("direct-platform-client-secret")) {
		t.Fatalf("OpenDirectOIDCClientSecret() = %q, %v", opened, err)
	}
	if allZeroDirectBrowserBytes(opened) {
		t.Fatal("adapter destroyed plaintext before transferring ownership")
	}
	clear(opened)
	if !allZeroDirectBrowserBytes(transferredCiphertext) {
		t.Fatal("adapter retained transferred envelope ciphertext")
	}
}

func TestKeyringDirectOIDCClientSecretSourceRejectsSnapshotRelabelingAndClearsMaterial(t *testing.T) {
	keyring := directTestKeyring(t)
	lookup := directOIDCClientSecretLookupFixture(t)
	secretID := directTestEntityID(122)
	type testCase struct {
		mutate      func(*DirectOIDCClientSecretSnapshot)
		sourceError error
		cancel      bool
	}
	tests := map[string]testCase{
		"lookup provider pin": {mutate: func(snapshot *DirectOIDCClientSecretSnapshot) {
			snapshot.Lookup.Pins.ProviderRevision++
		}},
		"pins echo": {mutate: func(snapshot *DirectOIDCClientSecretSnapshot) {
			snapshot.Pins.SecurityRevision++
		}},
		"secret revision": {mutate: func(snapshot *DirectOIDCClientSecretSnapshot) {
			snapshot.Lookup.Pins.ClientSecretRevision++
			snapshot.Pins.ClientSecretRevision++
		}},
		"secret row": {mutate: func(snapshot *DirectOIDCClientSecretSnapshot) {
			snapshot.SecretID = directTestEntityID(123)
		}},
		"ciphertext": {mutate: func(snapshot *DirectOIDCClientSecretSnapshot) {
			snapshot.Envelope.Ciphertext[0] ^= 0xff
		}},
		"source error":         {sourceError: errors.New("secret persistence oracle")},
		"cancelled after load": {cancel: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			envelope, encryptErr := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
				Provider: lookup.Pins.Provider, BindingID: identity.EntityID{}, SecretID: secretID,
			}, []byte("must-never-escape"))
			if encryptErr != nil {
				t.Fatal(encryptErr)
			}
			transferredCiphertext := envelope.Ciphertext
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter, constructErr := NewKeyringDirectOIDCClientSecretSource(
				directOIDCClientSecretEnvelopeSourceFunc(func(
					context.Context,
					DirectOIDCClientSecretLookup,
				) (DirectOIDCClientSecretSnapshot, error) {
					snapshot := DirectOIDCClientSecretSnapshot{
						Lookup: lookup, Pins: lookup.Pins, SecretID: secretID, Envelope: envelope,
					}
					if test.mutate != nil {
						test.mutate(&snapshot)
					}
					if test.cancel {
						cancel()
					}
					return snapshot, test.sourceError
				}),
				keyring,
			)
			if constructErr != nil {
				t.Fatal(constructErr)
			}
			opened, openErr := adapter.OpenDirectOIDCClientSecret(ctx, lookup)
			if !errors.Is(openErr, ErrDirectAuthenticationDenied) || len(opened) != 0 ||
				!allZeroDirectBrowserBytes(transferredCiphertext) {
				t.Fatalf("OpenDirectOIDCClientSecret() = %q, %v ciphertext=%x", opened, openErr, transferredCiphertext)
			}
		})
	}
}

func TestKeyringDirectOIDCClientSecretSourceRejectsMalformedLookupBeforePersistence(t *testing.T) {
	calls := 0
	adapter, err := NewKeyringDirectOIDCClientSecretSource(
		directOIDCClientSecretEnvelopeSourceFunc(func(
			context.Context,
			DirectOIDCClientSecretLookup,
		) (DirectOIDCClientSecretSnapshot, error) {
			calls++
			return DirectOIDCClientSecretSnapshot{}, nil
		}),
		directTestKeyring(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DirectOIDCClientSecretLookup){
		"tenant family": func(value *DirectOIDCClientSecretLookup) {
			value.Pins.Provider.Scope = identity.TenantProviderScope
			value.Pins.Provider.TenantID = directTestEntityID(124)
		},
		"client secret revision": func(value *DirectOIDCClientSecretLookup) {
			value.Pins.ClientSecretRevision = 0
		},
		"plan revision": func(value *DirectOIDCClientSecretLookup) {
			value.Pins.PlanRevision = 0
		},
		"platform floor": func(value *DirectOIDCClientSecretLookup) {
			value.Pins.PlatformFloorPolicyID = identity.EntityID{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := lookupClone(directOIDCClientSecretLookupFixture(t))
			mutate(&candidate)
			if opened, openErr := adapter.OpenDirectOIDCClientSecret(context.Background(), candidate); !errors.Is(
				openErr, ErrDirectAuthenticationDenied,
			) || len(opened) != 0 {
				t.Fatalf("OpenDirectOIDCClientSecret() = %q, %v", opened, openErr)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, openErr := adapter.OpenDirectOIDCClientSecret(
		cancelled, directOIDCClientSecretLookupFixture(t),
	); !errors.Is(openErr, ErrDirectAuthenticationDenied) {
		t.Fatalf("cancelled OpenDirectOIDCClientSecret() error = %v", openErr)
	}
	if _, openErr := adapter.OpenDirectOIDCClientSecret(
		nil, directOIDCClientSecretLookupFixture(t),
	); !errors.Is(openErr, ErrDirectAuthenticationDenied) {
		t.Fatalf("nil-context OpenDirectOIDCClientSecret() error = %v", openErr)
	}
	if calls != 0 {
		t.Fatalf("malformed lookup reached persistence %d times", calls)
	}
}

func TestKeyringDirectOIDCClientSecretSourceConstructionAndFormattingAreFailClosed(t *testing.T) {
	source := directOIDCClientSecretEnvelopeSourceFunc(func(
		context.Context,
		DirectOIDCClientSecretLookup,
	) (DirectOIDCClientSecretSnapshot, error) {
		return DirectOIDCClientSecretSnapshot{}, nil
	})
	if adapter, err := NewKeyringDirectOIDCClientSecretSource(nil, directTestKeyring(t)); !errors.Is(err, ErrDirectAuthenticationDenied) || adapter != nil {
		t.Fatalf("nil source constructor = %v, %v", adapter, err)
	}
	if adapter, err := NewKeyringDirectOIDCClientSecretSource(source, identity.Keyring{}); !errors.Is(err, ErrDirectAuthenticationDenied) || adapter != nil {
		t.Fatalf("zero keyring constructor = %v, %v", adapter, err)
	}
	const canary = "direct-client-secret-format-canary"
	values := []any{
		DirectOIDCClientSecretSnapshot{Envelope: identity.OIDCClientSecretEnvelope{Ciphertext: []byte(canary)}},
		&KeyringDirectOIDCClientSecretSource{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, canary) || strings.Contains(output, fmt.Sprintf("%x", []byte(canary))) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func directOIDCClientSecretLookupFixture(t *testing.T) DirectOIDCClientSecretLookup {
	t.Helper()
	configuration := directBrowserConfigurationFixture(t)
	return DirectOIDCClientSecretLookup{Pins: directBrowserConfigurationPinsFixture(configuration)}
}

func lookupClone(value DirectOIDCClientSecretLookup) DirectOIDCClientSecretLookup { return value }
