package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

func TestPlatformIdentityProviderCreateUsesOneProtectedTransaction(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	commandID := mustPostgresUUIDv7(t)
	auditID := mustPostgresUUIDv7(t)
	params := platformidentityprovider.CreateParams{
		SessionParams: session,
		CommandID:     commandID,
		ProviderID:    providerID,
		Kind:          platformidentityprovider.ProviderKindOIDC,
		Key:           "platform_oidc_test",
		DisplayName:   "Platform OIDC test",
		Description:   "",
		Configuration: platformidentityprovider.OIDCCreateConfiguration{
			Issuer: "https://idp.example.invalid", ClientID: "periapsis",
			RedirectURI:           "https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback",
			TenantRedirectURI:     "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback",
			PostLogoutRedirectURI: "https://periapsis.example.invalid/signed-out",
			ExtraScopes:           []string{"groups"}, UseUserInfo: true,
		},
		Reason:         "Approved platform identity-provider creation",
		Event:          event,
		ValidateResult: acceptPlatformIdentityProviderCreateResult,
	}
	params.KeyDigest[0] = 0xa1
	params.RequestDigest[0] = 0xb2
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") {
			return errors.New("unexpected platform provider row query")
		}
		if len(destinations) != 4 {
			return errors.New("unexpected create result cardinality")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(providerID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		*destinations[3].(*[]byte) = platformIdentityProviderDetailDocumentWithMetadata(
			t, providerID, "oidc", params.Key, params.DisplayName, params.Description, 1,
			time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC),
		)
		tx.keyDigest = append([]byte(nil), arguments[8].([]byte)...)
		tx.requestDigest = append([]byte(nil), arguments[9].([]byte)...)
		return nil
	}
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)

	result, err := repository.Create(context.Background(), params)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	provider := result.Provider()
	if result.ProviderID() != providerID || result.Version() != 1 || result.Replayed() ||
		provider.ID != providerID || provider.Version != 1 || provider.Key != params.Key {
		t.Fatalf("Create() result = %#v provider=%#v", result, provider)
	}
	assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.create_platform_oidc_auth_provider_v2")
	if len(tx.arguments[1]) != 17 {
		t.Fatalf("create argument count = %d", len(tx.arguments[1]))
	}
	wantPrefix := []any{
		toDatabaseUUID(session.SessionID), toDatabaseUUID(commandID), toDatabaseUUID(providerID),
		params.Key, params.DisplayName, params.Description,
	}
	if !reflect.DeepEqual(tx.arguments[1][:6], wantPrefix) {
		t.Fatalf("create argument prefix = %#v, want %#v", tx.arguments[1][:6], wantPrefix)
	}
	if !reflect.DeepEqual(tx.arguments[1][10], toDatabaseUUID(auditID)) ||
		!reflect.DeepEqual(tx.arguments[1][11], toDatabaseUUID(event.RequestID)) ||
		!reflect.DeepEqual(tx.arguments[1][12], toDatabaseUUID(event.CorrelationID)) ||
		tx.arguments[1][13] != event.RemoteAddress || tx.arguments[1][14] != event.UserAgent ||
		tx.arguments[1][15] != session.AuthenticationMethod || tx.arguments[1][16] != params.Reason {
		t.Fatalf("create audit attribution arguments = %#v", tx.arguments[1][10:])
	}
	var configuration platformidentityprovider.OIDCCreateConfiguration
	if err := json.Unmarshal(tx.arguments[1][6].([]byte), &configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Issuer != "https://idp.example.invalid" || !configuration.UseUserInfo ||
		configuration.TenantRedirectURI != "" || tx.arguments[1][7] != params.Configuration.(platformidentityprovider.OIDCCreateConfiguration).TenantRedirectURI {
		t.Fatalf("create configuration = %#v", configuration)
	}
	keyDigest := tx.keyDigest
	requestDigest := tx.requestDigest
	if len(keyDigest) != 32 || keyDigest[0] != 0xa1 || len(requestDigest) != 32 || requestDigest[0] != 0xb2 {
		t.Fatalf("create digests = %x / %x", keyDigest, requestDigest)
	}
}

func TestPlatformIdentityProviderSAMLCreateUsesProtocolSpecificProtectedABI(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	commandID := mustPostgresUUIDv7(t)
	auditID := mustPostgresUUIDv7(t)
	configuration := platformidentityprovider.SAMLCreateConfiguration{
		ExpectedEntityID:           "https://id.example.test/saml/metadata",
		SPEntityID:                 "https://periapsis.example.test/api/v1/auth/platform/saml/platform_saml_test/metadata",
		ACSURL:                     "https://periapsis.example.test/api/v1/auth/platform/saml/acs",
		RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth,
		EncryptionPolicy:           federatedsaml.EncryptionDisabled,
		DecryptionKeyVersions:      []int16{},
		RequestedAuthnContexts: []string{
			"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		},
		SubjectSource:            federatedsaml.SubjectPersistentNameID,
		ClockSkew:                2 * time.Minute,
		MaximumAuthenticationAge: 8 * time.Hour,
	}
	params := platformidentityprovider.CreateParams{
		SessionParams: session, CommandID: commandID, ProviderID: providerID,
		Kind: platformidentityprovider.ProviderKindSAML, Key: "platform_saml_test",
		DisplayName: "Platform SAML test", Configuration: configuration,
		Reason: "Approved platform SAML provider creation", Event: event,
		ValidateResult: acceptPlatformIdentityProviderCreateResult,
	}
	params.KeyDigest[0] = 0xa1
	params.RequestDigest[0] = 0xb2
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.create_platform_saml_auth_provider_v2") || len(destinations) != 4 {
			return errors.New("unexpected platform SAML create query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(providerID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		*destinations[3].(*[]byte) = platformIdentityProviderDetailDocumentWithMetadata(
			t, providerID, "saml", params.Key, params.DisplayName, params.Description, 1,
			time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC),
		)
		if len(arguments) != 16 {
			return errors.New("unexpected platform SAML create argument count")
		}
		var observed platformidentityprovider.SAMLCreateConfiguration
		if err := json.Unmarshal(arguments[6].([]byte), &observed); err != nil ||
			observed.ExpectedEntityID != configuration.ExpectedEntityID {
			return errors.New("unexpected platform SAML create configuration")
		}
		return nil
	}
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
	result, err := repository.Create(context.Background(), params)
	if err != nil || result.ProviderID() != providerID || result.Provider().SAML == nil {
		t.Fatalf("Create(SAML) result=%#v error=%v", result, err)
	}
	assertPlatformIdentityProviderTransaction(
		t, tx, beginCalls, "app.create_platform_saml_auth_provider_v2",
	)
	if !reflect.DeepEqual(tx.arguments[1][:6], []any{
		toDatabaseUUID(session.SessionID), toDatabaseUUID(commandID), toDatabaseUUID(providerID),
		params.Key, params.DisplayName, params.Description,
	}) {
		t.Fatalf("SAML create argument prefix = %#v", tx.arguments[1][:6])
	}
}

func TestPlatformIdentityProviderCreateReplayKeepsReceiptAndReturnsLiveProjection(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityProviderRepositoryAuthority(t)
	params := validPlatformIdentityProviderCreateParams(t, session)
	replayedProviderID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	document := platformIdentityProviderDetailDocumentWithMetadata(
		t, replayedProviderID, "oidc", "platform_oidc_test", "Renamed OIDC", "Current projection", 4, now,
	)
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") || len(destinations) != 4 {
			return errors.New("unexpected platform provider create query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(replayedProviderID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = true
		*destinations[3].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, mustPostgresUUIDv7(t))

	result, err := repository.Create(context.Background(), params)
	provider := result.Provider()
	if err != nil || !result.Replayed() || result.Version() != 1 ||
		result.ProviderID() != replayedProviderID || provider.Version != 4 || provider.Key != "platform_oidc_test" {
		t.Fatalf("Create() replay result=%#v provider=%#v error=%v", result, provider, err)
	}
	assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.create_platform_oidc_auth_provider_v2")
}

func TestPlatformIdentityProviderReadsDecodeClosedSafeProjections(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityProviderRepositoryAuthority(t)
	oidcID := mustPostgresUUIDv7(t)
	samlID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)

	listTx := &platformIdentityProviderTransaction{
		actorID: session.ActorID,
		documents: [][]byte{
			platformIdentityProviderSummaryDocument(t, oidcID, "oidc", false, now),
			platformIdentityProviderSummaryDocument(t, samlID, "saml", false, now),
		},
	}
	listRepository, listBeginCalls := platformIdentityProviderRepositoryHarness(t, listTx, uuid.Nil)
	summaries, err := listRepository.List(context.Background(), platformidentityprovider.ListParams{
		SessionParams: session, Limit: 51,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(summaries) != 2 || summaries[0].ID != oidcID || summaries[1].ID != samlID ||
		!summaries[0].Configured || summaries[0].SecretPresent {
		t.Fatalf("List() summaries = %#v", summaries)
	}
	assertPlatformIdentityProviderTransaction(t, listTx, listBeginCalls, "app.list_platform_auth_providers_v2")

	for _, test := range []struct {
		name string
		kind string
		id   uuid.UUID
	}{
		{name: "oidc", kind: "oidc", id: oidcID},
		{name: "saml", kind: "saml", id: samlID},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := platformIdentityProviderDetailDocument(t, test.id, test.kind, now)
			tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
			tx.row = platformIdentityProviderDocumentRow("app.get_platform_auth_provider_v2", document)
			repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)
			provider, getErr := repository.Get(context.Background(), platformidentityprovider.GetParams{
				SessionParams: session, ProviderID: test.id,
			})
			if getErr != nil {
				t.Fatalf("Get() error = %v", getErr)
			}
			if provider.ID != test.id || !provider.Configured || provider.SecretPresent ||
				(test.kind == "oidc" && (provider.OIDC == nil || provider.SAML != nil)) ||
				(test.kind == "saml" && (provider.SAML == nil || provider.OIDC != nil)) {
				t.Fatalf("Get() provider = %#v", provider)
			}
			assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.get_platform_auth_provider_v2")
		})
	}
}

func TestPlatformIdentityProviderSAMLProjectionDiscriminantShapes(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	base := platformIdentityProviderDetailDocument(t, providerID, "saml", now)

	for _, test := range []struct {
		name      string
		mutate    func(map[string]any)
		attribute bool
	}{
		{
			name:   "persistent nameid omits attribute fields",
			mutate: func(map[string]any) {},
		},
		{
			name: "immutable attribute requires both fields",
			mutate: func(configuration map[string]any) {
				configuration["subjectSource"] = string(federatedsaml.SubjectImmutableAttribute)
				configuration["subjectAttributeName"] = "urn:example:immutable-id"
				configuration["subjectAttributeNameFormat"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
			},
			attribute: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := mutatePlatformIdentityProviderProjectionConfiguration(t, base, test.mutate)
			tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
			tx.row = platformIdentityProviderDocumentRow("app.get_platform_auth_provider_v2", document)
			repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)
			provider, err := repository.Get(context.Background(), platformidentityprovider.GetParams{
				SessionParams: session, ProviderID: providerID,
			})
			if err != nil || provider.SAML == nil {
				t.Fatalf("Get() provider=%#v error=%v", provider, err)
			}
			if test.attribute {
				if provider.SAML.SubjectAttributeName == nil || provider.SAML.SubjectAttributeNameFormat == nil {
					t.Fatalf("immutable subject projection = %#v", provider.SAML)
				}
			} else if provider.SAML.SubjectAttributeName != nil || provider.SAML.SubjectAttributeNameFormat != nil {
				t.Fatalf("persistent subject projection = %#v", provider.SAML)
			}
			assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.get_platform_auth_provider_v2")
		})
	}

	t.Run("immutable attribute rejects one null field", func(t *testing.T) {
		document := mutatePlatformIdentityProviderProjectionConfiguration(t, base, func(configuration map[string]any) {
			configuration["subjectSource"] = string(federatedsaml.SubjectImmutableAttribute)
			configuration["subjectAttributeName"] = "urn:example:immutable-id"
			configuration["subjectAttributeNameFormat"] = nil
		})
		tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		tx.row = platformIdentityProviderDocumentRow("app.get_platform_auth_provider_v2", document)
		repository, _ := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)
		_, err := repository.Get(context.Background(), platformidentityprovider.GetParams{
			SessionParams: session, ProviderID: providerID,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, tx, err)
	})
}

func TestPlatformIdentityProviderMutationsRestoreReceiptsAndBindAudit(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	secretID := mustPostgresUUIDv7(t)

	t.Run("update", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
		document := platformIdentityProviderDetailDocumentWithMetadata(
			t, providerID, "oidc", "platform_oidc_updated", "Platform OIDC updated", "", 2, now,
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.update_platform_auth_provider_v2", 2, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		result, err := repository.Update(context.Background(), platformidentityprovider.UpdateParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Key: "platform_oidc_updated", DisplayName: "Platform OIDC updated",
			Description: "", Reason: "Approved metadata correction", Event: event,
			ValidateResult: acceptPlatformIdentityProviderUpdateResult,
		})
		provider := result.Provider()
		if err != nil || result.ProviderID() != providerID || result.Version() != 2 ||
			provider.ID != providerID || provider.Version != 2 || provider.Key != "platform_oidc_updated" {
			t.Fatalf("Update() result = %#v provider=%#v, error = %v", result, provider, err)
		}
		assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.update_platform_auth_provider_v2")
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(1),
			"platform_oidc_updated", "Platform OIDC updated", "", toDatabaseUUID(auditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod,
			"Approved metadata correction",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Update() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("archive", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		tx := platformIdentityProviderVersionTransaction(session.ActorID, "app.archive_platform_auth_provider_v1", 3)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		receipt, err := repository.Archive(context.Background(), platformidentityprovider.ArchiveParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 2,
			Reason: "Approved provider retirement", Event: event,
		})
		if err != nil || receipt.ProviderID() != providerID || receipt.Version() != 3 {
			t.Fatalf("Archive() receipt = %#v, error = %v", receipt, err)
		}
		assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.archive_platform_auth_provider_v1")
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(2),
			toDatabaseUUID(auditID), toDatabaseUUID(event.RequestID),
			toDatabaseUUID(event.CorrelationID), event.RemoteAddress, event.UserAgent,
			session.AuthenticationMethod, "Approved provider retirement",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Archive() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("archive non-next transactional version", func(t *testing.T) {
		malformedTx := platformIdentityProviderVersionTransaction(
			session.ActorID, "app.archive_platform_auth_provider_v1", 3,
		)
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(t, malformedTx, mustPostgresUUIDv7(t))
		_, archiveErr := malformedRepository.Archive(context.Background(), platformidentityprovider.ArchiveParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Reason: "Approved archive", Event: event,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, archiveErr)
	})

	t.Run("secret", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		envelope := identity.OIDCClientSecretEnvelope{
			KeyVersion: 7,
			Nonce:      [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			Ciphertext: []byte("seventeen-byte-tag"),
		}
		tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		tx.row = func(query string, arguments []any, destinations []any) error {
			if !strings.Contains(query, "app.replace_platform_oidc_client_secret_v1") {
				return errors.New("unexpected secret query")
			}
			if len(destinations) != 2 {
				return errors.New("unexpected secret receipt cardinality")
			}
			tx.secretNonce = append([]byte(nil), arguments[5].([]byte)...)
			tx.secretCiphertext = append([]byte(nil), arguments[6].([]byte)...)
			*destinations[0].(*int64) = 4
			*destinations[1].(*int64) = 2
			return nil
		}
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		receipt, err := repository.ReplaceOIDCClientSecret(
			context.Background(),
			platformidentityprovider.ReplaceOIDCClientSecretParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 3,
				Secret: platformidentityprovider.EncryptedOIDCClientSecret{
					SecretID: secretID, Envelope: envelope,
				},
				Reason: "Approved secret rotation", Event: event,
			},
		)
		if err != nil || receipt.ProviderID() != providerID || receipt.Version() != 4 || receipt.SecretRevision() != 2 {
			t.Fatalf("ReplaceOIDCClientSecret() receipt = %#v, error = %v", receipt, err)
		}
		assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.replace_platform_oidc_client_secret_v1")
		if !reflect.DeepEqual(tx.secretNonce, envelope.Nonce[:]) ||
			!reflect.DeepEqual(tx.secretCiphertext, envelope.Ciphertext) {
			t.Fatalf("secret envelope was not bound exactly")
		}
		gotArguments := append([]any(nil), tx.arguments[1]...)
		gotArguments[5] = tx.secretNonce
		gotArguments[6] = tx.secretCiphertext
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), toDatabaseUUID(secretID),
			int64(3), int32(7), envelope.Nonce[:], envelope.Ciphertext, toDatabaseUUID(auditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod,
			"Approved secret rotation",
		}
		if !reflect.DeepEqual(gotArguments, wantArguments) {
			t.Fatalf("ReplaceOIDCClientSecret() arguments = %#v, want %#v", gotArguments, wantArguments)
		}
	})

	t.Run("secret non-next transactional version", func(t *testing.T) {
		malformedTx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		malformedTx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.replace_platform_oidc_client_secret_v1") || len(destinations) != 2 {
				return errors.New("unexpected secret query")
			}
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 2
			return nil
		}
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(t, malformedTx, mustPostgresUUIDv7(t))
		_, secretErr := malformedRepository.ReplaceOIDCClientSecret(
			context.Background(),
			platformidentityprovider.ReplaceOIDCClientSecretParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
				Secret: platformidentityprovider.EncryptedOIDCClientSecret{
					SecretID: mustPostgresUUIDv7(t),
					Envelope: identity.OIDCClientSecretEnvelope{
						KeyVersion: 1, Nonce: [12]byte{1}, Ciphertext: []byte("seventeen-byte-tag"),
					},
				},
				Reason: "Approved rotation", Event: event,
			},
		)
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, secretErr)
	})
}

func TestPlatformIdentityProviderTenantExecutionLifecycleBindsCASAuditAndProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 29, 2, 0, 0, 123_456_000, time.UTC)

	t.Run("activate", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityProviderDocument(
			t, platformIdentityProviderDetailDocumentWithMetadata(
				t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
			),
			func(value map[string]any) {
				value["enabled"] = true
				value["accountMode"] = "create"
				value["platformLoginActivationAvailable"] = true
				configuration := value["configuration"].(map[string]any)
				configuration["clientSecretRevision"] = int64(2)
				configuration["clientSecretPresent"] = true
			},
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.activate_platform_auth_provider_tenant_execution_v1", 2, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		result, err := repository.Activate(context.Background(), platformidentityprovider.ActivationParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			AccountMode: platformidentityprovider.AccountModeCreate,
			Reason:      "Approved tenant execution", Event: event,
			ValidateResult: func(result platformidentityprovider.UpdateResult) (platformidentityprovider.UpdateResult, error) {
				if !result.Provider().Enabled || result.Provider().AccountMode != platformidentityprovider.AccountModeCreate {
					return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
				}
				return result, nil
			},
		})
		if err != nil || result.Version() != 2 || !result.Provider().Enabled {
			t.Fatalf("Activate() = %#v, %v", result, err)
		}
		assertPlatformIdentityProviderTransaction(
			t, tx, beginCalls, "app.activate_platform_auth_provider_tenant_execution_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(1), "create",
			toDatabaseUUID(auditID), toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod, "Approved tenant execution",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Activate() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("deactivate", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityProviderDocument(
			t, platformIdentityProviderDetailDocumentWithMetadata(
				t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 3, now,
			),
			func(value map[string]any) {
				value["activationAvailable"] = true
				configuration := value["configuration"].(map[string]any)
				configuration["clientSecretRevision"] = int64(2)
				configuration["clientSecretPresent"] = true
			},
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.deactivate_platform_auth_provider_tenant_execution_v1", 3, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		result, err := repository.Deactivate(context.Background(), platformidentityprovider.DeactivationParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 2,
			Reason: "Approved tenant execution shutdown", Event: event,
			ValidateResult: func(result platformidentityprovider.UpdateResult) (platformidentityprovider.UpdateResult, error) {
				if result.Provider().Enabled || result.Provider().AccountMode != platformidentityprovider.AccountModeDisabled {
					return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
				}
				return result, nil
			},
		})
		if err != nil || result.Version() != 3 || result.Provider().Enabled {
			t.Fatalf("Deactivate() = %#v, %v", result, err)
		}
		assertPlatformIdentityProviderTransaction(
			t, tx, beginCalls, "app.deactivate_platform_auth_provider_tenant_execution_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(2),
			toDatabaseUUID(auditID), toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod,
			"Approved tenant execution shutdown",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Deactivate() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})
}

func TestPlatformIdentityProviderDirectLoginLifecycleBindsCASAuditAndProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 30, 9, 0, 0, 123_456_000, time.UTC)

	t.Run("activate", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityProviderDocument(
			t, platformIdentityProviderDetailDocumentWithMetadata(
				t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
			),
			func(value map[string]any) {
				value["enabled"] = true
				value["platformLoginEnabled"] = true
				value["accountMode"] = "create"
				configuration := value["configuration"].(map[string]any)
				configuration["clientSecretRevision"] = int64(2)
				configuration["clientSecretPresent"] = true
			},
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.activate_platform_direct_login_v2", 2, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		result, err := repository.ActivateDirectLogin(
			context.Background(),
			platformidentityprovider.DirectLoginParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
				Reason: "Approved direct login", Event: event,
				ValidateResult: func(result platformidentityprovider.UpdateResult) (platformidentityprovider.UpdateResult, error) {
					provider := result.Provider()
					if !provider.PlatformLoginEnabled || !provider.Enabled ||
						provider.AccountMode != platformidentityprovider.AccountModeCreate {
						return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
					}
					return result, nil
				},
			},
		)
		provider := result.Provider()
		if err != nil || result.Version() != 2 || !provider.PlatformLoginEnabled ||
			provider.AccountMode != platformidentityprovider.AccountModeCreate ||
			provider.ConfigurationRevision != 1 || provider.SecurityRevision != 1 ||
			provider.PlanRevision != 1 || provider.AssurancePolicyRevision != 1 ||
			provider.OIDC == nil || provider.OIDC.ClientSecretRevision != 2 {
			t.Fatalf("ActivateDirectLogin() = %#v, %v", result, err)
		}
		assertPlatformIdentityProviderTransaction(
			t, tx, beginCalls, "app.activate_platform_direct_login_v2",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(1),
			toDatabaseUUID(auditID), toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod, "Approved direct login",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("ActivateDirectLogin() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("deactivate", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityProviderDocument(
			t, platformIdentityProviderDetailDocumentWithMetadata(
				t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 3, now,
			),
			func(value map[string]any) {
				value["enabled"] = true
				value["accountMode"] = "create"
				value["platformLoginActivationAvailable"] = true
				configuration := value["configuration"].(map[string]any)
				configuration["clientSecretRevision"] = int64(2)
				configuration["clientSecretPresent"] = true
			},
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.deactivate_platform_direct_login_v2", 3, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		result, err := repository.DeactivateDirectLogin(
			context.Background(),
			platformidentityprovider.DirectLoginParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 2,
				Reason: "Approved direct login shutdown", Event: event,
				ValidateResult: func(result platformidentityprovider.UpdateResult) (platformidentityprovider.UpdateResult, error) {
					provider := result.Provider()
					if provider.PlatformLoginEnabled || !provider.Enabled ||
						provider.AccountMode != platformidentityprovider.AccountModeCreate {
						return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
					}
					return result, nil
				},
			},
		)
		provider := result.Provider()
		if err != nil || result.Version() != 3 || provider.PlatformLoginEnabled ||
			!provider.PlatformLoginActivationAvailable ||
			!provider.Enabled || provider.AccountMode != platformidentityprovider.AccountModeCreate ||
			provider.ConfigurationRevision != 1 || provider.SecurityRevision != 1 ||
			provider.PlanRevision != 1 || provider.AssurancePolicyRevision != 1 ||
			provider.OIDC == nil || provider.OIDC.ClientSecretRevision != 2 {
			t.Fatalf("DeactivateDirectLogin() = %#v, %v", result, err)
		}
		assertPlatformIdentityProviderTransaction(
			t, tx, beginCalls, "app.deactivate_platform_direct_login_v2",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), int64(2),
			toDatabaseUUID(auditID), toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod,
			"Approved direct login shutdown",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("DeactivateDirectLogin() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("validator rejection rolls back", func(t *testing.T) {
		auditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityProviderDocument(
			t, platformIdentityProviderDetailDocumentWithMetadata(
				t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
			),
			func(value map[string]any) {
				value["enabled"] = true
				value["platformLoginEnabled"] = true
				value["accountMode"] = "existing_identity"
				configuration := value["configuration"].(map[string]any)
				configuration["clientSecretRevision"] = int64(2)
				configuration["clientSecretPresent"] = true
			},
		)
		tx := platformIdentityProviderProjectionMutationTransaction(
			session.ActorID, "app.activate_platform_direct_login_v2", 2, document,
		)
		repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
		_, err := repository.ActivateDirectLogin(
			context.Background(),
			platformidentityprovider.DirectLoginParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
				Reason: "Approved direct login", Event: event,
				ValidateResult: func(platformidentityprovider.UpdateResult) (platformidentityprovider.UpdateResult, error) {
					return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
				},
			},
		)
		if !errors.Is(err, authentication.ErrUnavailable) || *beginCalls != 1 || tx.committed || !tx.rolledBack {
			t.Fatalf(
				"ActivateDirectLogin() validator error = %v, transaction = begin:%d commit:%t rollback:%t",
				err, *beginCalls, tx.committed, tx.rolledBack,
			)
		}
	})
}

func TestPlatformIdentityProviderAdapterRejectsOpenJSONAndMalformedReceipts(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	document := platformIdentityProviderDetailDocument(t, providerID, "oidc", now)
	document = append(document[:len(document)-1], []byte(`,"unexpected":"secret"}`)...)
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = platformIdentityProviderDocumentRow("app.get_platform_auth_provider_v2", document)
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)
	_, err := repository.Get(context.Background(), platformidentityprovider.GetParams{
		SessionParams: session, ProviderID: providerID,
	})
	if !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Get() error = %v, want unavailable", err)
	}
	if *beginCalls != 1 || tx.committed || !tx.rolledBack {
		t.Fatalf("transaction state = begin:%d commit:%t rollback:%t", *beginCalls, tx.committed, tx.rolledBack)
	}

	createTx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	createTx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") {
			return errors.New("unexpected query")
		}
		*destinations[0].(*pgtype.UUID) = pgtype.UUID{}
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		if len(destinations) != 4 {
			return errors.New("unexpected create result cardinality")
		}
		return nil
	}
	createRepository, _ := platformIdentityProviderRepositoryHarness(t, createTx, mustPostgresUUIDv7(t))
	_, err = createRepository.Create(context.Background(), validPlatformIdentityProviderCreateParams(t, session))
	if !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Create() malformed receipt error = %v, want unavailable", err)
	}
	if createTx.committed || !createTx.rolledBack {
		t.Fatalf("Create() malformed receipt transaction = commit:%t rollback:%t", createTx.committed, createTx.rolledBack)
	}

	t.Run("create malformed transactional projection", func(t *testing.T) {
		params := validPlatformIdentityProviderCreateParams(t, session)
		malformedTx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		malformedTx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") || len(destinations) != 4 {
				return errors.New("unexpected create query")
			}
			*destinations[0].(*pgtype.UUID) = toDatabaseUUID(params.ProviderID)
			*destinations[1].(*int64) = 1
			*destinations[2].(*bool) = false
			*destinations[3].(*[]byte) = []byte(`{"id":`)
			return nil
		}
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(
			t, malformedTx, mustPostgresUUIDv7(t),
		)
		_, createErr := malformedRepository.Create(context.Background(), params)
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, createErr)
	})

	t.Run("update malformed transactional projection", func(t *testing.T) {
		malformedTx := platformIdentityProviderUpdateTransaction(
			session.ActorID, 2, []byte(`{"id":`),
		)
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(
			t, malformedTx, mustPostgresUUIDv7(t),
		)
		_, updateErr := malformedRepository.Update(context.Background(), platformidentityprovider.UpdateParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Key: "platform_oidc", DisplayName: "Platform OIDC", Reason: "Approved update", Event: event,
			ValidateResult: acceptPlatformIdentityProviderUpdateResult,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, updateErr)
	})

	t.Run("create projection identity mismatch", func(t *testing.T) {
		params := validPlatformIdentityProviderCreateParams(t, session)
		otherID := mustPostgresUUIDv7(t)
		document := platformIdentityProviderDetailDocument(t, otherID, "oidc", now)
		mismatchTx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		mismatchTx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") || len(destinations) != 4 {
				return errors.New("unexpected create query")
			}
			*destinations[0].(*pgtype.UUID) = toDatabaseUUID(params.ProviderID)
			*destinations[1].(*int64) = 1
			*destinations[2].(*bool) = false
			*destinations[3].(*[]byte) = append([]byte(nil), document...)
			return nil
		}
		mismatchRepository, _ := platformIdentityProviderRepositoryHarness(
			t, mismatchTx, mustPostgresUUIDv7(t),
		)
		_, createErr := mismatchRepository.Create(context.Background(), params)
		assertPlatformIdentityProviderMalformedReceipt(t, mismatchTx, createErr)
	})

	t.Run("update projection identity mismatch", func(t *testing.T) {
		otherID := mustPostgresUUIDv7(t)
		document := platformIdentityProviderDetailDocumentWithMetadata(
			t, otherID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
		)
		mismatchTx := platformIdentityProviderUpdateTransaction(session.ActorID, 2, document)
		mismatchRepository, _ := platformIdentityProviderRepositoryHarness(
			t, mismatchTx, mustPostgresUUIDv7(t),
		)
		_, updateErr := mismatchRepository.Update(context.Background(), platformidentityprovider.UpdateParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Key: "platform_oidc", DisplayName: "Platform OIDC", Reason: "Approved update", Event: event,
			ValidateResult: acceptPlatformIdentityProviderUpdateResult,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, mismatchTx, updateErr)
	})

	t.Run("update", func(t *testing.T) {
		malformedDocument := platformIdentityProviderDetailDocument(t, providerID, "oidc", now)
		malformedTx := platformIdentityProviderUpdateTransaction(session.ActorID, 1, malformedDocument)
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(t, malformedTx, mustPostgresUUIDv7(t))
		_, updateErr := malformedRepository.Update(context.Background(), platformidentityprovider.UpdateParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Key: "platform_oidc", DisplayName: "Platform OIDC", Reason: "Approved update", Event: event,
			ValidateResult: acceptPlatformIdentityProviderUpdateResult,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, updateErr)
	})

	t.Run("archive", func(t *testing.T) {
		malformedTx := platformIdentityProviderVersionTransaction(
			session.ActorID, "app.archive_platform_auth_provider_v1", 1,
		)
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(t, malformedTx, mustPostgresUUIDv7(t))
		_, archiveErr := malformedRepository.Archive(context.Background(), platformidentityprovider.ArchiveParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Reason: "Approved archive", Event: event,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, archiveErr)
	})

	t.Run("secret", func(t *testing.T) {
		malformedTx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		malformedTx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.replace_platform_oidc_client_secret_v1") || len(destinations) != 2 {
				return errors.New("unexpected secret query")
			}
			*destinations[0].(*int64) = 2
			*destinations[1].(*int64) = 1
			return nil
		}
		malformedRepository, _ := platformIdentityProviderRepositoryHarness(t, malformedTx, mustPostgresUUIDv7(t))
		_, secretErr := malformedRepository.ReplaceOIDCClientSecret(
			context.Background(),
			platformidentityprovider.ReplaceOIDCClientSecretParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
				Secret: platformidentityprovider.EncryptedOIDCClientSecret{
					SecretID: mustPostgresUUIDv7(t),
					Envelope: identity.OIDCClientSecretEnvelope{
						KeyVersion: 1, Nonce: [12]byte{1}, Ciphertext: []byte("seventeen-byte-tag"),
					},
				},
				Reason: "Approved rotation", Event: event,
			},
		)
		assertPlatformIdentityProviderMalformedReceipt(t, malformedTx, secretErr)
	})
}

func TestPlatformIdentityProviderActivationAvailabilityProjectionIsStrict(t *testing.T) {
	t.Parallel()
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 30, 9, 30, 0, 123_456_000, time.UTC)

	for _, projection := range []struct {
		name   string
		base   []byte
		decode func([]byte) error
	}{
		{
			name: "summary",
			base: platformIdentityProviderSummaryDocument(t, providerID, "oidc", false, now),
			decode: func(document []byte) error {
				_, err := decodePlatformIdentityProviderSummary(document)
				return err
			},
		},
		{
			name: "detail",
			base: platformIdentityProviderDetailDocument(t, providerID, "oidc", now),
			decode: func(document []byte) error {
				_, err := decodePlatformIdentityProvider(document)
				return err
			},
		},
	} {
		projection := projection
		t.Run(projection.name, func(t *testing.T) {
			t.Parallel()
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{
					name: "missing",
					mutate: func(value map[string]any) {
						delete(value, "platformLoginActivationAvailable")
					},
				},
				{
					name: "wrong type",
					mutate: func(value map[string]any) {
						value["platformLoginActivationAvailable"] = "true"
					},
				},
			} {
				test := test
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()
					document := mutatePlatformIdentityProviderDocument(t, projection.base, test.mutate)
					if err := projection.decode(document); err == nil {
						t.Fatal("decoder accepted a non-strict activation availability projection")
					}
				})
			}
		})
	}

	readyDocument := mutatePlatformIdentityProviderDocument(
		t,
		platformIdentityProviderDetailDocument(t, providerID, "oidc", now),
		func(value map[string]any) {
			value["enabled"] = true
			value["platformLoginActivationAvailable"] = true
			value["accountMode"] = "existing_identity"
			configuration := value["configuration"].(map[string]any)
			configuration["clientSecretPresent"] = true
			configuration["clientSecretRevision"] = int64(2)
		},
	)
	ready, err := decodePlatformIdentityProvider(readyDocument)
	if err != nil || !ready.PlatformLoginActivationAvailable || ready.PlatformLoginEnabled {
		t.Fatalf("decode ready projection = %#v, %v", ready, err)
	}

	saml, err := decodePlatformIdentityProvider(
		platformIdentityProviderDetailDocument(t, providerID, "saml", now),
	)
	if err != nil || saml.PlatformLoginActivationAvailable {
		t.Fatalf("decode SAML projection = %#v, %v", saml, err)
	}
}

func TestPlatformIdentityProviderSemanticProjectionValidationRollsBackMutations(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	unsafeProjection := func(document []byte) []byte {
		t.Helper()
		updated := bytes.ReplaceAll(
			document,
			[]byte("https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback"),
			[]byte("https://attacker.example.invalid/auth/oidc/callback"),
		)
		if bytes.Equal(updated, document) {
			t.Fatal("test projection did not contain the canonical redirect URI")
		}
		return updated
	}
	rejectUnsafeCreate := func(result platformidentityprovider.CreateResult) (
		platformidentityprovider.CreateResult,
		error,
	) {
		provider := result.Provider()
		if provider.OIDC == nil || provider.OIDC.RedirectURI !=
			"https://attacker.example.invalid/auth/oidc/callback" {
			t.Fatalf("create validator projection = %#v", provider)
		}
		return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
	}
	rejectUnsafeUpdate := func(result platformidentityprovider.UpdateResult) (
		platformidentityprovider.UpdateResult,
		error,
	) {
		provider := result.Provider()
		if provider.OIDC == nil || provider.OIDC.RedirectURI !=
			"https://attacker.example.invalid/auth/oidc/callback" {
			t.Fatalf("update validator projection = %#v", provider)
		}
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}

	t.Run("create", func(t *testing.T) {
		params := validPlatformIdentityProviderCreateParams(t, session)
		params.ProviderID = providerID
		params.ValidateResult = rejectUnsafeCreate
		document := unsafeProjection(platformIdentityProviderDetailDocumentWithMetadata(
			t, providerID, "oidc", params.Key, params.DisplayName, params.Description, 1, now,
		))
		tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
		tx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") || len(destinations) != 4 {
				return errors.New("unexpected create query")
			}
			*destinations[0].(*pgtype.UUID) = toDatabaseUUID(providerID)
			*destinations[1].(*int64) = 1
			*destinations[2].(*bool) = false
			*destinations[3].(*[]byte) = append([]byte(nil), document...)
			return nil
		}
		repository, _ := platformIdentityProviderRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
		_, err := repository.Create(context.Background(), params)
		assertPlatformIdentityProviderMalformedReceipt(t, tx, err)
	})

	t.Run("update", func(t *testing.T) {
		document := unsafeProjection(platformIdentityProviderDetailDocumentWithMetadata(
			t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
		))
		tx := platformIdentityProviderUpdateTransaction(session.ActorID, 2, document)
		repository, _ := platformIdentityProviderRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
		_, err := repository.Update(context.Background(), platformidentityprovider.UpdateParams{
			SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
			Key: "platform_oidc", DisplayName: "Platform OIDC", Reason: "Approved update", Event: event,
			ValidateResult: rejectUnsafeUpdate,
		})
		assertPlatformIdentityProviderMalformedReceipt(t, tx, err)
	})
}

func TestPlatformIdentityProviderProjectionShapeValidationRollsBackMutations(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	baseCreateDocument := platformIdentityProviderDetailDocumentWithMetadata(
		t, providerID, "oidc", "platform_oidc_receipt", "Platform OIDC receipt", "", 1, now,
	)
	baseUpdateDocument := platformIdentityProviderDetailDocumentWithMetadata(
		t, providerID, "oidc", "platform_oidc", "Platform OIDC", "", 2, now,
	)

	for _, test := range []struct {
		name   string
		create bool
		mutate func(map[string]any)
	}{
		{
			name: "create explicit-null required boolean", create: true,
			mutate: func(configuration map[string]any) { configuration["allowRefreshToken"] = nil },
		},
		{
			name: "create missing required boolean", create: true,
			mutate: func(configuration map[string]any) { delete(configuration, "useUserInfo") },
		},
		{
			name:   "update explicit-null required presence flag",
			mutate: func(configuration map[string]any) { configuration["clientSecretPresent"] = nil },
		},
		{
			name:   "update missing required boolean",
			mutate: func(configuration map[string]any) { delete(configuration, "allowRefreshToken") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := baseUpdateDocument
			if test.create {
				base = baseCreateDocument
			}
			document := mutatePlatformIdentityProviderProjectionConfiguration(t, base, test.mutate)
			if test.create {
				params := validPlatformIdentityProviderCreateParams(t, session)
				params.ProviderID = providerID
				tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
				tx.row = func(query string, _ []any, destinations []any) error {
					if !strings.Contains(query, "app.create_platform_oidc_auth_provider_v2") || len(destinations) != 4 {
						return errors.New("unexpected create query")
					}
					*destinations[0].(*pgtype.UUID) = toDatabaseUUID(providerID)
					*destinations[1].(*int64) = 1
					*destinations[2].(*bool) = false
					*destinations[3].(*[]byte) = append([]byte(nil), document...)
					return nil
				}
				repository, _ := platformIdentityProviderRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
				_, err := repository.Create(context.Background(), params)
				assertPlatformIdentityProviderMalformedReceipt(t, tx, err)
				return
			}

			tx := platformIdentityProviderUpdateTransaction(session.ActorID, 2, document)
			repository, _ := platformIdentityProviderRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
			_, err := repository.Update(context.Background(), platformidentityprovider.UpdateParams{
				SessionParams: session, ProviderID: providerID, ExpectedVersion: 1,
				Key: "platform_oidc", DisplayName: "Platform OIDC", Reason: "Approved update", Event: event,
				ValidateResult: acceptPlatformIdentityProviderUpdateResult,
			})
			assertPlatformIdentityProviderMalformedReceipt(t, tx, err)
		})
	}
}

func TestMapPlatformIdentityProviderDatabaseErrorIsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "forbidden", err: &pgconn.PgError{Code: "42501"}, want: authentication.ErrForbidden},
		{name: "not found", err: &pgconn.PgError{Code: "P0002"}, want: authentication.ErrNotFound},
		{name: "no rows", err: pgx.ErrNoRows, want: authentication.ErrNotFound},
		{
			name: "precondition",
			err: &pgconn.PgError{
				Code: "40001", Message: platformIdentityProviderRevisionConflictMessage,
			},
			want: platformidentityprovider.ErrPreconditionFailed,
		},
		{
			name: "serialization retry",
			err:  &pgconn.PgError{Code: "40001", Message: "could not serialize access"},
			want: authentication.ErrUnavailable,
		},
		{name: "state conflict", err: &pgconn.PgError{Code: "55000"}, want: authentication.ErrConflict},
		{name: "idempotency conflict", err: &pgconn.PgError{Code: "23505"}, want: authentication.ErrConflict},
		{name: "invalid argument", err: &pgconn.PgError{Code: "22023"}, want: authentication.ErrInvalidInput},
		{name: "constraint", err: &pgconn.PgError{Code: "23514"}, want: authentication.ErrInvalidInput},
		{name: "unknown", err: errors.New("private database diagnostic"), want: authentication.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := mapPlatformIdentityProviderDatabaseError(test.err); !errors.Is(got, test.want) {
				t.Fatalf("mapped error = %v, want %v", got, test.want)
			}
		})
	}
	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
		if got := mapPlatformIdentityProviderDatabaseError(cancellation); !errors.Is(got, cancellation) {
			t.Fatalf("cancellation = %v, got %v", cancellation, got)
		}
	}
}

func TestPlatformIdentityProviderCanceledContextDoesNotBegin(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityProviderRepositoryAuthority(t)
	beginCalls := 0
	repository := &PlatformIdentityProviderRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			return nil, errors.New("unexpected transaction")
		},
		newID: uuid.NewV7,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := repository.List(ctx, platformidentityprovider.ListParams{SessionParams: session, Limit: 1})
	if !errors.Is(err, context.Canceled) || beginCalls != 0 {
		t.Fatalf("List() error = %v, begin calls = %d", err, beginCalls)
	}
}

type platformIdentityProviderTransaction struct {
	recordingTransaction
	actorID          uuid.UUID
	row              func(string, []any, []any) error
	documents        [][]byte
	queries          []string
	arguments        [][]any
	keyDigest        []byte
	requestDigest    []byte
	secretNonce      []byte
	secretCiphertext []byte
}

func (tx *platformIdentityProviderTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if strings.Contains(query, "set_config('app.user_id'") {
		return platformIdentityProviderRow(func(destinations ...any) error {
			if len(destinations) != 1 {
				return errors.New("unexpected user context cardinality")
			}
			*destinations[0].(*string) = tx.actorID.String()
			return nil
		})
	}
	return platformIdentityProviderRow(func(destinations ...any) error {
		if tx.row == nil {
			return errors.New("unexpected platform identity-provider QueryRow")
		}
		return tx.row(query, arguments, destinations)
	})
}

func (tx *platformIdentityProviderTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (pgx.Rows, error) {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if !strings.Contains(query, "app.list_platform_auth_providers_v2") {
		return nil, errors.New("unexpected platform identity-provider Query")
	}
	return &platformIdentityProviderRows{documents: tx.documents}, nil
}

type platformIdentityProviderRow func(...any) error

func (row platformIdentityProviderRow) Scan(destinations ...any) error {
	return row(destinations...)
}

type platformIdentityProviderRows struct {
	documents [][]byte
	index     int
}

func (*platformIdentityProviderRows) Close()                                       {}
func (*platformIdentityProviderRows) Err() error                                   { return nil }
func (*platformIdentityProviderRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (*platformIdentityProviderRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *platformIdentityProviderRows) Next() bool {
	if rows.index >= len(rows.documents) {
		return false
	}
	rows.index++
	return true
}
func (rows *platformIdentityProviderRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.documents) || len(destinations) != 1 {
		return errors.New("invalid platform identity-provider row scan")
	}
	value, ok := destinations[0].(*[]byte)
	if !ok {
		return errors.New("invalid platform identity-provider scan destination")
	}
	*value = append((*value)[:0], rows.documents[rows.index-1]...)
	return nil
}
func (rows *platformIdentityProviderRows) Values() ([]any, error) {
	if rows.index == 0 || rows.index > len(rows.documents) {
		return nil, errors.New("platform identity-provider row is not current")
	}
	return []any{rows.documents[rows.index-1]}, nil
}
func (*platformIdentityProviderRows) RawValues() [][]byte { return nil }
func (*platformIdentityProviderRows) Conn() *pgx.Conn     { return nil }

func platformIdentityProviderRepositoryHarness(
	t testing.TB,
	tx *platformIdentityProviderTransaction,
	auditID uuid.UUID,
) (*PlatformIdentityProviderRepository, *int) {
	t.Helper()
	beginCalls := 0
	repository := &PlatformIdentityProviderRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			if options.IsoLevel != pgx.ReadCommitted {
				t.Fatalf("transaction isolation = %q", options.IsoLevel)
			}
			return tx, nil
		},
		newID: func() (uuid.UUID, error) { return auditID, nil },
	}
	return repository, &beginCalls
}

func assertPlatformIdentityProviderTransaction(
	t testing.TB,
	tx *platformIdentityProviderTransaction,
	beginCalls *int,
	abi string,
) {
	t.Helper()
	if *beginCalls != 1 || !tx.committed || !tx.rolledBack {
		t.Fatalf("transaction state = begin:%d commit:%t rollback:%t", *beginCalls, tx.committed, tx.rolledBack)
	}
	if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "set_config('app.user_id'") ||
		!strings.Contains(tx.queries[1], abi) {
		t.Fatalf("queries = %#v", tx.queries)
	}
	if len(tx.arguments[0]) != 1 || !reflect.DeepEqual(tx.arguments[0][0], toDatabaseUUID(tx.actorID)) {
		t.Fatalf("user context arguments = %#v", tx.arguments[0])
	}
}

func assertPlatformIdentityProviderMalformedReceipt(
	t testing.TB,
	tx *platformIdentityProviderTransaction,
	err error,
) {
	t.Helper()
	if !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("malformed receipt error = %v, want unavailable", err)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("malformed receipt transaction = commit:%t rollback:%t", tx.committed, tx.rolledBack)
	}
}

func platformIdentityProviderRepositoryAuthority(
	t testing.TB,
) (platformidentityprovider.SessionParams, authentication.EventContext) {
	t.Helper()
	return platformidentityprovider.SessionParams{
			ActorID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t), AuthenticationMethod: "passkey",
		}, authentication.EventContext{
			RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("198.51.100.45"), UserAgent: "platform-identity-provider-adapter-test/1",
		}
}

func platformIdentityProviderVersionTransaction(
	actorID uuid.UUID,
	abi string,
	version int64,
) *platformIdentityProviderTransaction {
	tx := &platformIdentityProviderTransaction{actorID: actorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, abi) || len(destinations) != 1 {
			return errors.New("unexpected platform provider version query")
		}
		*destinations[0].(*int64) = version
		return nil
	}
	return tx
}

func platformIdentityProviderUpdateTransaction(
	actorID uuid.UUID,
	version int64,
	document []byte,
) *platformIdentityProviderTransaction {
	return platformIdentityProviderProjectionMutationTransaction(
		actorID, "app.update_platform_auth_provider_v2", version, document,
	)
}

func platformIdentityProviderProjectionMutationTransaction(
	actorID uuid.UUID,
	abi string,
	version int64,
	document []byte,
) *platformIdentityProviderTransaction {
	tx := &platformIdentityProviderTransaction{actorID: actorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, abi) || len(destinations) != 2 {
			return errors.New("unexpected platform provider update query")
		}
		*destinations[0].(*int64) = version
		*destinations[1].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
	return tx
}

func platformIdentityProviderDocumentRow(
	abi string,
	document []byte,
) func(string, []any, []any) error {
	return func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, abi) || len(destinations) != 1 {
			return errors.New("unexpected platform provider document query")
		}
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
}

func platformIdentityProviderSummaryDocument(
	t testing.TB,
	id uuid.UUID,
	kind string,
	secretPresent bool,
	now time.Time,
) []byte {
	t.Helper()
	return platformIdentityProviderJSON(t, map[string]any{
		"id": id, "key": "platform_" + kind, "displayName": "Platform " + strings.ToUpper(kind),
		"description": "Safe summary", "kind": kind, "enabled": false,
		"platformLoginActivationAvailable": false, "platformLoginEnabled": false, "activationAvailable": false,
		"configured": true, "secretPresent": secretPresent,
		"archivedAt": nil, "version": int64(1), "createdAt": now, "updatedAt": now,
	})
}

func platformIdentityProviderDetailDocument(
	t testing.TB,
	id uuid.UUID,
	kind string,
	now time.Time,
) []byte {
	t.Helper()
	return platformIdentityProviderDetailDocumentWithMetadata(
		t, id, kind, "platform_"+kind, "Platform "+strings.ToUpper(kind), "Safe detail", 1, now,
	)
}

func platformIdentityProviderDetailDocumentWithMetadata(
	t testing.TB,
	id uuid.UUID,
	kind string,
	key string,
	displayName string,
	description string,
	version int64,
	now time.Time,
) []byte {
	t.Helper()
	var configuration map[string]any
	if kind == "oidc" {
		configuration = map[string]any{
			"issuer": "https://idp.example.invalid", "clientId": "periapsis",
			"redirectUri":           "https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback",
			"tenantRedirectUri":     "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback",
			"postLogoutRedirectUri": "https://periapsis.example.invalid/signed-out",
			"extraScopes":           []string{"groups"}, "allowRefreshToken": false, "useUserInfo": true,
			"clientSecretRevision": int64(1), "clientSecretPresent": false,
			"discoveryRevision": int64(1), "jwksRevision": int64(1),
		}
	} else {
		configuration = map[string]any{
			"expectedEntityId": "https://saml.example.invalid/metadata",
			"spEntityId":       "https://periapsis.example.invalid/auth/saml/metadata",
			"acsUrl":           "https://periapsis.example.invalid/auth/saml/acs",
			"spKeyRevision":    int64(1), "spKeyPresent": false, "metadataRevision": int64(1),
			"redirectSignatureAlgorithm":      string(federatedsaml.RedirectRSASHA256),
			"signaturePolicy":                 string(federatedsaml.SignedAssertion),
			"encryptionPolicy":                string(federatedsaml.EncryptionDisabled),
			"requestedAuthnContexts":          []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
			"subjectSource":                   string(federatedsaml.SubjectPersistentNameID),
			"clockSkewNanoseconds":            int64(30 * time.Second),
			"maxAuthenticationAgeNanoseconds": int64(time.Hour),
		}
	}
	return platformIdentityProviderJSON(t, map[string]any{
		"id": id, "key": key, "displayName": displayName,
		"description": description, "kind": kind, "enabled": false,
		"platformLoginActivationAvailable": false, "platformLoginEnabled": false, "activationAvailable": false,
		"configurationRevision": int64(1),
		"securityRevision":      int64(1), "planRevision": int64(1),
		"assurancePolicyRevision": int64(1), "accountMode": "disabled",
		"configuration": configuration, "archivedAt": nil, "version": version,
		"createdAt": now, "updatedAt": now,
	})
}

func platformIdentityProviderJSON(t testing.TB, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func mutatePlatformIdentityProviderProjectionConfiguration(
	t testing.TB,
	document []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	var projection map[string]any
	if err := json.Unmarshal(document, &projection); err != nil {
		t.Fatal(err)
	}
	configuration, ok := projection["configuration"].(map[string]any)
	if !ok {
		t.Fatalf("projection configuration = %#v", projection["configuration"])
	}
	mutate(configuration)
	return platformIdentityProviderJSON(t, projection)
}

func mutatePlatformIdentityProviderDocument(
	t testing.TB,
	document []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	var projection map[string]any
	if err := json.Unmarshal(document, &projection); err != nil {
		t.Fatal(err)
	}
	mutate(projection)
	return platformIdentityProviderJSON(t, projection)
}

func validPlatformIdentityProviderCreateParams(
	t testing.TB,
	session platformidentityprovider.SessionParams,
) platformidentityprovider.CreateParams {
	t.Helper()
	_, event := platformIdentityProviderRepositoryAuthority(t)
	return platformidentityprovider.CreateParams{
		SessionParams: session, CommandID: mustPostgresUUIDv7(t), ProviderID: mustPostgresUUIDv7(t),
		Kind: platformidentityprovider.ProviderKindOIDC, Key: "platform_oidc_receipt",
		DisplayName: "Platform OIDC receipt", Configuration: platformidentityprovider.OIDCCreateConfiguration{
			Issuer: "https://idp.example.invalid", ClientID: "periapsis",
			RedirectURI:           "https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback",
			TenantRedirectURI:     "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback",
			PostLogoutRedirectURI: "https://periapsis.example.invalid/signed-out",
		},
		Reason: "Approved receipt test", Event: event,
		ValidateResult: acceptPlatformIdentityProviderCreateResult,
	}
}

func acceptPlatformIdentityProviderCreateResult(
	result platformidentityprovider.CreateResult,
) (platformidentityprovider.CreateResult, error) {
	return result, nil
}

func acceptPlatformIdentityProviderUpdateResult(
	result platformidentityprovider.UpdateResult,
) (platformidentityprovider.UpdateResult, error) {
	return result, nil
}
