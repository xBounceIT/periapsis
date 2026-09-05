package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
)

func TestLDAPAuthenticationBeginDistinguishesDatabaseRateLimitWithoutEnumeration(t *testing.T) {
	request := ldapauth.BeginRequest{
		OperationRunID: mustLDAPAuthenticationUUID(t),
		NetworkRateKey: [sha256.Size]byte{1}, AccountRateKey: [sha256.Size]byte{2},
		ProviderRateKey: [sha256.Size]byte{3},
	}
	for name, blocked := range map[string]bool{
		"blocked":            true,
		"unresolved locator": false,
	} {
		t.Run(name, func(t *testing.T) {
			queries := 0
			repository := &LDAPAuthenticationRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				queries++
				switch query {
				case beginLDAPAuthenticationSQL:
					if len(arguments) != 12 {
						t.Fatalf("begin argument count = %d", len(arguments))
					}
					return federatedAuthRowFunc(func(...any) error { return pgx.ErrNoRows })
				case ldapAuthenticationBlockedSQL:
					if len(arguments) != 3 {
						t.Fatalf("block lookup argument count = %d", len(arguments))
					}
					return federatedAuthRowFunc(func(destinations ...any) error {
						*destinations[0].(*bool) = blocked
						return nil
					})
				default:
					t.Fatalf("unexpected query = %q", query)
					return federatedAuthRowFunc(func(...any) error { return pgx.ErrNoRows })
				}
			}}}
			_, err := repository.Begin(context.Background(), request)
			want := ldapauth.ErrAuthentication
			if blocked {
				want = ldapauth.ErrRateLimited
			}
			if !errors.Is(err, want) || queries != 2 {
				t.Fatalf("Begin() error = %v queries=%d; want %v/2", err, queries, want)
			}
		})
	}
}

func TestLDAPAuthorityReservationUsesDigestOnlyCanonicalWire(t *testing.T) {
	issuedAt := time.Date(2026, time.September, 1, 8, 30, 0, 0, time.UTC)
	token := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)))
	csrf := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID:   identity.EntityID(mustLDAPAuthenticationUUID(t)),
		FamilyID:    identity.EntityID(mustLDAPAuthenticationUUID(t)),
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationLDAP,
		IdleExpiresAt:        issuedAt.Add(time.Hour), AbsoluteExpiresAt: issuedAt.Add(8 * time.Hour),
	}, issuedAt)
	if err != nil {
		t.Fatalf("NewSessionReservation() error = %v", err)
	}
	owned, err := federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
	if err != nil {
		t.Fatalf("NewSessionApplyCredentialReservation() error = %v", err)
	}
	defer owned.Destroy()
	document, disposition, err := ldapAuthorityReservation(ldapauth.ApplyRequest{Session: owned})
	if err != nil || disposition != "session" {
		t.Fatalf("ldapAuthorityReservation() = (%q, %v)", disposition, err)
	}
	defer clear(document)
	if bytes.Contains(document, token) || bytes.Contains(document, csrf) {
		t.Fatal("reservation wire contains plaintext browser credential")
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(document, &wire); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	wantKeys := []string{"sessionId", "familyId", "tokenDigest", "csrfDigest", "authenticationMethod", "idleExpiresAt", "absoluteExpiresAt"}
	if len(wire) != len(wantKeys) {
		t.Fatalf("reservation keys = %v", wire)
	}
	for _, key := range wantKeys {
		if _, ok := wire[key]; !ok {
			t.Fatalf("reservation is missing %q", key)
		}
	}
}

func mustLDAPAuthenticationUUID(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return value
}
