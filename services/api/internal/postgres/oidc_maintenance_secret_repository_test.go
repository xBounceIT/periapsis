package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestFederatedAuthRepositoryLoadsMaintenanceOIDCSecretForEveryAuthorityShape(t *testing.T) {
	tenant := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(121),
			ProviderID: postgresFederatedID(122),
		},
		BindingID: postgresFederatedID(123), Revision: 7,
		Maintenance: postgresOIDCMaintenanceSecretProof(),
	}
	admitted := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(124),
		},
		Admission: identity.TenantAdmissionContext{
			TenantID: postgresFederatedID(125), BindingID: postgresFederatedID(126),
		},
		Revision: 8, Maintenance: postgresOIDCMaintenanceSecretProof(),
	}
	direct := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(127),
		},
		Revision: 9, Maintenance: postgresOIDCMaintenanceSecretProof(),
	}

	for name, lookup := range map[string]federatedauth.ClientSecretContext{
		"tenant": tenant, "admitted platform": admitted, "direct platform": direct,
	} {
		t.Run(name, func(t *testing.T) {
			var retainedPayload, retainedRow []byte
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != loadOIDCMaintenanceClientSecretEnvelopeSQL || len(arguments) != 1 {
					t.Fatalf("maintenance secret query = %q args=%d", query, len(arguments))
				}
				retainedPayload = arguments[0].([]byte)
				var raw map[string]any
				if err := json.Unmarshal(retainedPayload, &raw); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if len(raw) < 8 || len(raw) > 9 || raw["revision"] == nil || raw["kind"] != "refresh" {
					t.Fatalf("maintenance secret request keys = %#v", raw)
				}
				binding, present := raw["bindingId"]
				if !present {
					t.Fatalf("maintenance secret request omitted bindingId: %#v", raw)
				}
				var request oidcMaintenanceClientSecretLookupWire
				if err := json.Unmarshal(retainedPayload, &request); err != nil {
					t.Fatalf("decode typed request: %v", err)
				}
				switch name {
				case "tenant":
					if request.Admission != nil || request.BindingID == nil ||
						*request.BindingID != request.Provider.BindingID || binding == nil {
						t.Fatalf("tenant maintenance lookup = %#v", request)
					}
				case "admitted platform":
					if request.Admission == nil || request.BindingID == nil ||
						*request.BindingID != request.Admission.BindingID || binding == nil {
						t.Fatalf("admitted maintenance lookup = %#v", request)
					}
				case "direct platform":
					if request.Admission != nil || request.BindingID != nil || binding != nil {
						t.Fatalf("direct maintenance lookup = %#v", request)
					}
				}
				retainedRow = mustFederatedJSON(t, oidcMaintenanceClientSecretEnvelopeWire{
					Lookup: request, SecretID: federatedEntityIDString(t, postgresFederatedID(128)),
					KeyVersion: 3, Nonce: bytes.Repeat([]byte{0x51}, oidcClientSecretNonceBytes),
					Ciphertext: bytes.Repeat([]byte{0x52}, 32),
				})
				return federatedAuthJSONRow(retainedRow)
			}}}

			snapshot, err := repository.LoadOIDCMaintenanceClientSecretEnvelope(context.Background(), lookup)
			if err != nil || snapshot.Lookup != lookup || snapshot.SecretID != postgresFederatedID(128) ||
				snapshot.Envelope.KeyVersion != 3 || len(snapshot.Envelope.Ciphertext) != 32 {
				t.Fatalf("LoadOIDCMaintenanceClientSecretEnvelope() = %s, %v", snapshot, err)
			}
			if !allZeroFederatedBytes(retainedPayload) || !allZeroFederatedBytes(retainedRow) {
				t.Fatal("maintenance secret wire retained protected material")
			}
			if allZeroFederatedBytes(snapshot.Envelope.Ciphertext) {
				t.Fatal("returned snapshot aliases cleared database response")
			}
			clear(snapshot.Envelope.Nonce[:])
			clear(snapshot.Envelope.Ciphertext)
		})
	}
}

func TestFederatedAuthRepositoryRejectsInvalidMaintenanceOIDCSecretLookupsBeforePersistence(t *testing.T) {
	called := false
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return federatedAuthJSONRow(nil)
	}}}
	for name, lookup := range map[string]federatedauth.ClientSecretContext{
		"tenant missing binding": {
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(121),
				ProviderID: postgresFederatedID(122),
			},
			Revision: 7,
		},
		"tenant admission": {
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(121),
				ProviderID: postgresFederatedID(122),
			},
			Admission: identity.TenantAdmissionContext{
				TenantID: postgresFederatedID(121), BindingID: postgresFederatedID(123),
			},
			BindingID: postgresFederatedID(123), Revision: 7,
		},
		"platform tenant injection": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, TenantID: postgresFederatedID(121),
				ProviderID: postgresFederatedID(122),
			},
			Revision: 7,
		},
		"platform cryptographic binding": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(122),
			},
			BindingID: postgresFederatedID(123), Revision: 7,
		},
		"partial admission": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(122),
			},
			Admission: identity.TenantAdmissionContext{TenantID: postgresFederatedID(121)}, Revision: 7,
		},
		"counter overflow": {
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(122),
			},
			Revision: 9_000_000_000_000_001,
		},
	} {
		t.Run(name, func(t *testing.T) {
			lookup.Maintenance = postgresOIDCMaintenanceSecretProof()
			if _, err := repository.LoadOIDCMaintenanceClientSecretEnvelope(context.Background(), lookup); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("LoadOIDCMaintenanceClientSecretEnvelope() error = %v", err)
			}
		})
	}
	if called {
		t.Fatal("invalid maintenance secret lookup reached persistence")
	}
}

func TestFederatedAuthRepositoryRejectsDriftedMaintenanceOIDCSecretResponse(t *testing.T) {
	lookup := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(127),
		},
		Revision: 9, Maintenance: postgresOIDCMaintenanceSecretProof(),
	}
	for name, mutate := range map[string]func(*oidcMaintenanceClientSecretEnvelopeWire){
		"lookup drift": func(response *oidcMaintenanceClientSecretEnvelopeWire) {
			response.Lookup.Revision++
		},
		"binding injection": func(response *oidcMaintenanceClientSecretEnvelopeWire) {
			binding := federatedEntityIDString(t, postgresFederatedID(126))
			response.Lookup.BindingID = &binding
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				_ string,
				arguments ...any,
			) pgx.Row {
				var request oidcMaintenanceClientSecretLookupWire
				if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil {
					t.Fatal(err)
				}
				response := oidcMaintenanceClientSecretEnvelopeWire{
					Lookup: request, SecretID: federatedEntityIDString(t, postgresFederatedID(128)),
					KeyVersion: 3, Nonce: bytes.Repeat([]byte{0x51}, oidcClientSecretNonceBytes),
					Ciphertext: bytes.Repeat([]byte{0x52}, 32),
				}
				mutate(&response)
				return federatedAuthJSONRow(mustFederatedJSON(t, response))
			}}}
			if _, err := repository.LoadOIDCMaintenanceClientSecretEnvelope(context.Background(), lookup); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("LoadOIDCMaintenanceClientSecretEnvelope() error = %v", err)
			}
		})
	}
}

func TestOIDCMaintenanceSecretWireFormattingIsRedacted(t *testing.T) {
	const canary = "maintenance-client-secret-canary"
	value := oidcMaintenanceClientSecretEnvelopeWire{Ciphertext: []byte(canary)}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, value)
		if strings.Contains(output, canary) || strings.Contains(output, fmt.Sprintf("%x", []byte(canary))) {
			t.Fatalf("maintenance secret wire leaked with %s: %s", format, output)
		}
	}
}

func TestOIDCMaintenanceSecretAcceptsTheCanonicalTwelveByteNonceBoundary(t *testing.T) {
	lookup := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(127),
		},
		Revision: 9, Maintenance: postgresOIDCMaintenanceSecretProof(),
	}
	wire, err := oidcMaintenanceClientSecretLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := oidcMaintenanceClientSecretEnvelopeFromWire(oidcMaintenanceClientSecretEnvelopeWire{
		Lookup: wire, SecretID: federatedEntityIDString(t, postgresFederatedID(128)), KeyVersion: 3,
		Nonce: make([]byte, oidcClientSecretNonceBytes), Ciphertext: bytes.Repeat([]byte{0x52}, 32),
	})
	if err != nil || snapshot.Lookup != lookup {
		t.Fatalf("zero-valued canonical nonce rejected: %s, %v", snapshot, err)
	}
	clear(snapshot.Envelope.Nonce[:])
	clear(snapshot.Envelope.Ciphertext)
}

func postgresOIDCMaintenanceSecretProof() federatedauth.OIDCMaintenanceSecretProof {
	return federatedauth.OIDCMaintenanceSecretProof{
		Kind:       federatedauth.OIDCMaintenanceSecretRefresh,
		MaterialID: postgresFederatedID(129), SessionFamilyID: postgresFederatedID(130),
		ClaimVersion: 5, RefreshGeneration: 6,
	}
}
