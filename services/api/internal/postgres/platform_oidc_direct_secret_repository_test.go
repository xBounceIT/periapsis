package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

func TestFederatedAuthRepositoryLoadsDirectOIDCSecretWithFullPinEchoAndClearedWire(t *testing.T) {
	pins := platformOIDCDirectRuntimePinsFixture()
	lookup := platformoidcauth.DirectOIDCClientSecretLookup{Pins: pins}
	wirePins := platformOIDCDirectRuntimePinsWireFixture(t, pins)
	nonce := platformOIDCDirectBytes(101)
	firstCiphertext := platformOIDCDirectBytes(131)
	secondCiphertext := platformOIDCDirectBytes(171)
	ciphertext := append(append([]byte(nil), firstCiphertext[:]...), secondCiphertext[:]...)
	response := platformOIDCDirectSecretWire{
		Provider: wirePins.Provider, Pins: wirePins,
		SecretID: entityIDWire(platformOIDCDirectRuntimeEntityID("000000000121")),
		Revision: pins.ClientSecretRevision, KeyVersion: 2,
		Nonce: append([]byte(nil), nonce[:12]...), Ciphertext: ciphertext,
	}
	var payloadCopies, retainedPayloads, retainedResponses [][]byte
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != "select app.load_platform_oidc_client_secret_v1($1::jsonb)" {
			t.Fatalf("query = %q", query)
		}
		payload := platformOIDCDirectRuntimePayload(t, arguments)
		retainedPayloads = append(retainedPayloads, payload)
		payloadCopies = append(payloadCopies, append([]byte(nil), payload...))
		object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload, "provider", "pins")
		assertPlatformOIDCDirectRuntimeJSONKeys(t, object["provider"], "scope", "providerId")
		assertPlatformOIDCDirectRuntimePinsKeys(t, object["pins"])
		return platformOIDCDirectRuntimeJSONRow(t, response, &retainedResponses)
	}}}
	for range 2 {
		snapshot, err := repository.LoadDirectOIDCClientSecretEnvelope(context.Background(), lookup)
		if err != nil {
			t.Fatalf("LoadDirectOIDCClientSecretEnvelope() error = %v", err)
		}
		if snapshot.Lookup != lookup || snapshot.Pins != pins ||
			snapshot.SecretID != platformOIDCDirectRuntimeEntityID("000000000121") ||
			snapshot.Envelope.KeyVersion != response.KeyVersion ||
			!bytes.Equal(snapshot.Envelope.Nonce[:], response.Nonce) ||
			!bytes.Equal(snapshot.Envelope.Ciphertext, response.Ciphertext) {
			t.Fatalf("secret snapshot drifted: %s", snapshot)
		}
		clear(snapshot.Envelope.Nonce[:])
		clear(snapshot.Envelope.Ciphertext)
	}
	if len(payloadCopies) != 2 || !bytes.Equal(payloadCopies[0], payloadCopies[1]) {
		t.Fatal("exact secret retry payload drifted")
	}
	assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
	if !bytes.Equal(response.Ciphertext, ciphertext) {
		t.Fatal("repository retained or changed response fixture ciphertext")
	}
}

func TestFederatedAuthRepositoryRejectsDirectOIDCSecretStaleMalformedAndUnknownEchoes(t *testing.T) {
	pins := platformOIDCDirectRuntimePinsFixture()
	lookup := platformoidcauth.DirectOIDCClientSecretLookup{Pins: pins}
	wirePins := platformOIDCDirectRuntimePinsWireFixture(t, pins)
	nonce := platformOIDCDirectBytes(101)
	ciphertext := platformOIDCDirectBytes(131)
	valid := platformOIDCDirectSecretWire{
		Provider: wirePins.Provider, Pins: wirePins,
		SecretID: entityIDWire(platformOIDCDirectRuntimeEntityID("000000000121")),
		Revision: pins.ClientSecretRevision, KeyVersion: 2,
		Nonce: append([]byte(nil), nonce[:12]...), Ciphertext: append([]byte(nil), ciphertext[:]...),
	}
	tests := map[string]func(platformOIDCDirectSecretWire) any{
		"provider drift": func(value platformOIDCDirectSecretWire) any {
			value.Provider.ProviderID = entityIDWire(platformOIDCDirectRuntimeEntityID("000000000122"))
			return value
		},
		"full pin drift": func(value platformOIDCDirectSecretWire) any {
			value.Pins.PlanRevision++
			return value
		},
		"secret revision drift": func(value platformOIDCDirectSecretWire) any {
			value.Revision++
			return value
		},
		"zero nonce": func(value platformOIDCDirectSecretWire) any {
			value.Nonce = make([]byte, 12)
			return value
		},
		"short ciphertext": func(value platformOIDCDirectSecretWire) any {
			value.Ciphertext = make([]byte, 16)
			return value
		},
		"null": func(platformOIDCDirectSecretWire) any { return nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := mutate(valid)
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				_ ...any,
			) pgx.Row {
				if query != "select app.load_platform_oidc_client_secret_v1($1::jsonb)" {
					t.Fatalf("query = %q", query)
				}
				return platformOIDCDirectRuntimeJSONRow(t, response, nil)
			}}}
			snapshot, err := repository.LoadDirectOIDCClientSecretEnvelope(context.Background(), lookup)
			clear(snapshot.Envelope.Nonce[:])
			clear(snapshot.Envelope.Ciphertext)
			if !errors.Is(err, errFederatedAuthPersistence) ||
				snapshot.SecretID != (identity.EntityID{}) || len(snapshot.Envelope.Ciphertext) != 0 {
				t.Fatalf("snapshot = %s, error = %v", snapshot, err)
			}
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		raw := mustFederatedJSON(t, valid)
		raw[len(raw)-1] = ','
		raw = append(raw, []byte(`"secret":"must-not-be-accepted"}`)...)
		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			_ context.Context,
			_ string,
			_ ...any,
		) pgx.Row {
			return federatedAuthJSONRow(raw)
		}}}
		snapshot, err := repository.LoadDirectOIDCClientSecretEnvelope(context.Background(), lookup)
		clear(snapshot.Envelope.Nonce[:])
		clear(snapshot.Envelope.Ciphertext)
		if !errors.Is(err, errFederatedAuthPersistence) ||
			snapshot.SecretID != (identity.EntityID{}) || len(snapshot.Envelope.Ciphertext) != 0 {
			t.Fatalf("snapshot = %s, error = %v", snapshot, err)
		}
	})
}

func TestFederatedAuthRepositoryRedactsDirectOIDCSecretDatabaseFailures(t *testing.T) {
	const canary = "direct-client-secret-database-canary"
	lookup := platformoidcauth.DirectOIDCClientSecretLookup{Pins: platformOIDCDirectRuntimePinsFixture()}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		_ ...any,
	) pgx.Row {
		if query != "select app.load_platform_oidc_client_secret_v1($1::jsonb)" {
			t.Fatalf("query = %q", query)
		}
		return federatedAuthRowFunc(func(...any) error { return errors.New(canary) })
	}}}
	snapshot, err := repository.LoadDirectOIDCClientSecretEnvelope(context.Background(), lookup)
	if !errors.Is(err, errFederatedAuthPersistence) || strings.Contains(err.Error(), canary) ||
		snapshot.SecretID != (identity.EntityID{}) || len(snapshot.Envelope.Ciphertext) != 0 {
		t.Fatalf("snapshot = %s, error = %v", snapshot, err)
	}
}
