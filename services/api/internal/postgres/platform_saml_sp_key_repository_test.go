package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestPlatformSAMLSPKeyRepositorySeparatesInteractiveAndHistoricalLoaders(t *testing.T) {
	base := federatedsaml.DirectPlatformSPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(201),
		},
		PlatformLoginRevision: 12, KeyRevision: 13,
	}
	for name, test := range map[string]struct {
		request       federatedsaml.DirectPlatformSPKeyRequest
		query         string
		materialIDSet bool
	}{
		"interactive": {request: base, query: loadPlatformSAMLSPKeyEnvelopeSQL},
		"historical logout": {
			request: func() federatedsaml.DirectPlatformSPKeyRequest {
				value := base
				value.LogoutMaterialID = postgresFederatedID(202)
				return value
			}(),
			query: loadPlatformSAMLLogoutSPKeyEnvelopeSQL, materialIDSet: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != test.query || len(arguments) != 1 {
					t.Fatalf("query = %q, arguments = %d", query, len(arguments))
				}
				var request platformSAMLSPKeyLookupWire
				if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil {
					t.Fatal(err)
				}
				if (request.MaterialID != "") != test.materialIDSet ||
					(test.materialIDSet && request.MaterialID != federatedEntityIDString(t, test.request.LogoutMaterialID)) {
					t.Fatalf("material attestation wire = %#v", request)
				}
				return federatedAuthJSONRow(mustFederatedJSON(t, platformSAMLSPKeyProjectionWire{
					Request: request, PlatformLoginRevision: test.request.PlatformLoginRevision,
					Context: platformSAMLSPKeyContextWire{
						Provider: request.Provider, KeyID: federatedEntityIDString(t, postgresFederatedID(203)),
						KeyRevision: test.request.KeyRevision,
					},
					Envelope: platformSAMLSPKeyEnvelopeWire{
						KeyVersion: 4, Nonce: bytes.Repeat([]byte{0x41}, 12), Ciphertext: bytes.Repeat([]byte{0x42}, 32),
					},
					CertificateDER: [][]byte{{0x30, 0x04}}, Live: true,
				}))
			}}}
			snapshot, err := repository.LoadDirectPlatformSAMLSPKeyEnvelope(context.Background(), test.request)
			if err != nil || snapshot.Request != test.request || snapshot.Context.Provider != test.request.Provider ||
				snapshot.Context.KeyRevision != test.request.KeyRevision || snapshot.Context.KeyID != postgresFederatedID(203) {
				t.Fatalf("LoadDirectPlatformSAMLSPKeyEnvelope() = %q, %v", snapshot.String(), err)
			}
		})
	}
}

func TestPlatformSAMLSPKeyRepositoryRejectsMaterialSubstitutionAndMalformedMarker(t *testing.T) {
	request := federatedsaml.DirectPlatformSPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(211),
		},
		PlatformLoginRevision: 21, KeyRevision: 22, LogoutMaterialID: postgresFederatedID(212),
	}
	provider, err := platformSAMLProviderToWire(request.Provider)
	if err != nil {
		t.Fatal(err)
	}
	drifted := platformSAMLSPKeyLookupWire{
		Provider: provider, PlatformLoginRevision: request.PlatformLoginRevision, KeyRevision: request.KeyRevision,
		MaterialID: federatedEntityIDString(t, postgresFederatedID(213)),
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		return federatedAuthJSONRow(mustFederatedJSON(t, platformSAMLSPKeyProjectionWire{
			Request: drifted, PlatformLoginRevision: request.PlatformLoginRevision,
			Context: platformSAMLSPKeyContextWire{
				Provider: provider, KeyID: federatedEntityIDString(t, postgresFederatedID(214)),
				KeyRevision: request.KeyRevision,
			},
			Envelope: platformSAMLSPKeyEnvelopeWire{
				KeyVersion: 4, Nonce: bytes.Repeat([]byte{0x41}, 12), Ciphertext: bytes.Repeat([]byte{0x42}, 32),
			},
			CertificateDER: [][]byte{{0x30, 0x04}}, Live: true,
		}))
	}}}
	if _, err := repository.LoadDirectPlatformSAMLSPKeyEnvelope(context.Background(), request); !errors.Is(err, errPlatformSAMLPersistence) {
		t.Fatalf("material substitution error = %v", err)
	}

	called := false
	repository = &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return federatedAuthJSONRow(nil)
	}}}
	request.LogoutMaterialID = identity.EntityID{1}
	if _, err := repository.LoadDirectPlatformSAMLSPKeyEnvelope(context.Background(), request); !errors.Is(err, errPlatformSAMLPersistence) || called {
		t.Fatalf("malformed marker error = %v, queried = %t", err, called)
	}
}
