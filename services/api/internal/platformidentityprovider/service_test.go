package platformidentityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const testPublicOrigin = "https://periapsis.example.test"

func TestServiceCreatesTypedDisabledProvidersWithCanonicalDigests(t *testing.T) {
	tests := []struct {
		name          string
		configuration CreateConfiguration
		kind          ProviderKind
		assertConfig  func(testing.TB, CreateConfiguration)
	}{
		{
			name: "OIDC", kind: ProviderKindOIDC,
			configuration: OIDCCreateConfiguration{
				Issuer: "https://id.example.test/issuer", ClientID: "periapsis-platform",
				RedirectURI:           "https://periapsis.example.test/api/v1/auth/platform/oidc/callback",
				TenantRedirectURI:     "https://periapsis.example.test/api/v1/auth/federated/oidc/callback",
				PostLogoutRedirectURI: "https://periapsis.example.test/signed-out",
				ExtraScopes:           []string{"profile", "email"}, UseUserInfo: true,
			},
			assertConfig: func(t testing.TB, raw CreateConfiguration) {
				t.Helper()
				configuration, ok := raw.(OIDCCreateConfiguration)
				if !ok || !slices.Equal(configuration.ExtraScopes, []string{"email", "profile"}) {
					t.Fatalf("configuration = %#v", raw)
				}
			},
		},
		{
			name: "SAML", kind: ProviderKindSAML,
			configuration: SAMLCreateConfiguration{
				ExpectedEntityID:           "https://id.example.test/saml/metadata",
				SPEntityID:                 "https://periapsis.example.test/api/v1/auth/platform/saml/corporate_sso/metadata",
				ACSURL:                     "https://periapsis.example.test/api/v1/auth/platform/saml/acs",
				RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
				SignaturePolicy:            federatedsaml.SignedBoth,
				EncryptionPolicy:           federatedsaml.EncryptionDisabled,
				RequestedAuthnContexts: []string{
					"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
					"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
				SubjectSource: federatedsaml.SubjectPersistentNameID,
				ClockSkew:     2 * time.Minute, MaximumAuthenticationAge: 8 * time.Hour,
			},
			assertConfig: func(t testing.TB, raw CreateConfiguration) {
				t.Helper()
				configuration, ok := raw.(SAMLCreateConfiguration)
				if !ok || configuration.DecryptionKeyVersions == nil || len(configuration.DecryptionKeyVersions) != 0 ||
					!slices.IsSorted(configuration.RequestedAuthnContexts) {
					t.Fatalf("configuration = %#v", raw)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandID, providerID := mustUUIDv7(t), mustUUIDv7(t)
			repository := &repositoryStub{}
			repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
				if params.CommandID != commandID || params.ProviderID != providerID || params.Kind != test.kind ||
					params.Key != "corporate_sso" || params.DisplayName != "Corporate SSO" ||
					params.Description != "Global workforce provider" || params.Reason != "Approved by IAM" ||
					params.SessionID == uuid.Nil || params.ActorID == uuid.Nil || params.AuthenticationMethod != "passkey" {
					t.Fatalf("Create() params = %#v", params)
				}
				test.assertConfig(t, params.Configuration)
				wantKeyDigest := sha256.Sum256([]byte("platform-provider-create-0001"))
				if params.KeyDigest != wantKeyDigest || params.RequestDigest == ([sha256.Size]byte{}) {
					t.Fatalf("digests = %x / %x", params.KeyDigest, params.RequestDigest)
				}
				return mustCreateResult(t, providerID, false, providerFromCreateParams(t, params, 1)), nil
			}
			service := mustService(t, repository)
			ids := []uuid.UUID{commandID, providerID}
			service.newID = func() (uuid.UUID, error) {
				id := ids[0]
				ids = ids[1:]
				return id, nil
			}
			result, err := service.Create(context.Background(), manageSession(t), CreateInput{
				Key: " corporate_sso ", DisplayName: " Corporate SSO ",
				Description: " Global workforce provider ", Configuration: test.configuration,
				Reason: " Approved by IAM ", IdempotencyKey: "platform-provider-create-0001", Event: testEvent(t),
			})
			if err != nil || result.ProviderID() != providerID || result.Version() != 1 || result.Replayed() ||
				result.Provider().Version != 1 || result.Provider().Kind != test.kind {
				t.Fatalf("Create() = %#v, %v", result, err)
			}
		})
	}
}

func TestCreateRequestDigestBindsCanonicalBusinessPayloadOnly(t *testing.T) {
	first := validOIDCCreateInput(t)
	first.Configuration = mutateOIDC(validOIDCConfigurationFixture(), func(value *OIDCCreateConfiguration) {
		value.ExtraScopes = []string{"profile", "email"}
	})
	endpoints := mustEndpointPolicy(t, testPublicOrigin)
	_, firstKind, firstDigest, err := normalizeCreate(first, endpoints)
	if err != nil {
		t.Fatalf("normalizeCreate(first) error = %v", err)
	}
	second := first
	second.Configuration = validOIDCConfigurationFixture()
	second.IdempotencyKey = "platform-provider-create-0002"
	second.Event = testEvent(t)
	_, secondKind, secondDigest, err := normalizeCreate(second, endpoints)
	if err != nil {
		t.Fatalf("normalizeCreate(second) error = %v", err)
	}
	if firstKind != ProviderKindOIDC || secondKind != firstKind || firstDigest != secondDigest {
		t.Fatalf("canonical digests differ: %x / %x", firstDigest, secondDigest)
	}
	changed := second
	changed.Configuration = mutateOIDC(validOIDCConfigurationFixture(), func(value *OIDCCreateConfiguration) {
		value.ClientID = "another-client"
	})
	_, _, changedDigest, err := normalizeCreate(changed, endpoints)
	if err != nil || changedDigest == secondDigest {
		t.Fatalf("changed digest = %x, %v", changedDigest, err)
	}
}

func TestServiceCreateReplayKeepsStableReceiptAndReturnsCurrentDefensiveProjection(t *testing.T) {
	commandID, generatedProviderID, replayedProviderID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	repository := &repositoryStub{}
	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		projection := providerFromCreateParams(t, params, 4)
		projection.ID = replayedProviderID
		projection.Key = "first_sso"
		projection.DisplayName = "Renamed SSO"
		projection.Description = "Changed after creation"
		projection.OIDC.ClientSecretPresent = true
		projection.OIDC.ClientSecretRevision = 2
		projection.SecretPresent = true
		projection.UpdatedAt = projection.UpdatedAt.Add(time.Second)
		return mustCreateResult(t, replayedProviderID, true, projection), nil
	}
	service := mustService(t, repository)
	ids := []uuid.UUID{commandID, generatedProviderID}
	service.newID = func() (uuid.UUID, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	result, err := service.Create(context.Background(), manageSession(t), validOIDCCreateInput(t))
	if err != nil || !result.Replayed() || result.Version() != 1 || result.ProviderID() != replayedProviderID ||
		result.Provider().Version != 4 || result.Provider().Key != "first_sso" {
		t.Fatalf("Create() replay = %#v, %v", result, err)
	}
	projection := result.Provider()
	projection.OIDC.ExtraScopes[0] = "tampered"
	if result.Provider().OIDC.ExtraScopes[0] != "email" {
		t.Fatalf("CreateResult.Provider() did not defensively copy: %#v", result.Provider().OIDC.ExtraScopes)
	}
}

func TestCanonicalEndpointPolicyDerivesOnlyDeploymentOwnedPlatformEndpoints(t *testing.T) {
	policy := mustEndpointPolicy(t, "https://periapsis.example.test:8443")
	if policy.oidcRedirectURI != "https://periapsis.example.test:8443/api/v1/auth/platform/oidc/callback" ||
		policy.tenantOIDCRedirectURI != "https://periapsis.example.test:8443/api/v1/auth/federated/oidc/callback" ||
		policy.oidcPostLogoutRedirectURI != "https://periapsis.example.test:8443/signed-out" ||
		policy.samlMetadataBase != "https://periapsis.example.test:8443/api/v1/auth/platform/saml/" ||
		policy.samlACSURL != "https://periapsis.example.test:8443/api/v1/auth/platform/saml/acs" {
		t.Fatalf("policy = %#v", policy)
	}
	localPolicy := mustEndpointPolicy(t, "https://localhost:8443")
	if localPolicy.oidcRedirectURI != "https://localhost:8443/api/v1/auth/platform/oidc/callback" ||
		localPolicy.tenantOIDCRedirectURI != "https://localhost:8443/api/v1/auth/federated/oidc/callback" ||
		localPolicy.samlACSURL != "https://localhost:8443/api/v1/auth/platform/saml/acs" {
		t.Fatalf("local policy = %#v", localPolicy)
	}

	for _, invalid := range []string{
		"", " https://periapsis.example.test", "HTTPS://periapsis.example.test",
		"http://periapsis.example.test", "http://localhost:8081",
		"https://user@periapsis.example.test", "https://periapsis.example.test/",
		"https://periapsis.example.test/base", "https://periapsis.example.test?next=/",
		"https://periapsis.example.test#fragment", "https://periapsis.example.test:443",
		"https://periapsis.example.test:",
	} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := newCanonicalEndpointPolicy(invalid); err == nil {
				t.Fatalf("newCanonicalEndpointPolicy(%q) succeeded", invalid)
			}
		})
	}
}

func TestNewServiceRejectsInsecurePublicOrigin(t *testing.T) {
	if _, err := NewService(&repositoryStub{}, testKeyring(t), "http://localhost:8081"); err == nil {
		t.Fatal("NewService() accepted an insecure public origin")
	}
	if _, err := NewService(&repositoryStub{}, testKeyring(t), "https://localhost:8443"); err != nil {
		t.Fatalf("NewService() rejected a canonical local HTTPS origin: %v", err)
	}
}

func TestPlatformProviderURIsMatchTheProtectedCanonicalGrammar(t *testing.T) {
	for _, valid := range []string{
		"https://idp.example.test/issuer",
		"https://127.0.0.1:8443/issuer?tenant=one",
		"https://[2001:db8::1]/issuer",
	} {
		if !validHTTPSURL(valid, false, maximumFederationEndpointURIBytes) {
			t.Fatalf("validHTTPSURL(%q) rejected canonical URI", valid)
		}
	}
	for _, invalid := range []string{
		"https://IDP.example.test/issuer",
		"https://idp.example.test:0443/issuer",
		"https://127.000.0.1/issuer",
		"https://[2001:0db8:0:0:0:0:0:1]/issuer",
		"https://idp_example.test/issuer",
	} {
		if validHTTPSURL(invalid, false, maximumFederationEndpointURIBytes) {
			t.Fatalf("validHTTPSURL(%q) accepted noncanonical authority", invalid)
		}
	}

	if !validAbsoluteURI("urn:oasis:names:tc:SAML:2.0:ac:classes:Password", 2048) {
		t.Fatal("validAbsoluteURI() rejected canonical URN")
	}
	for _, invalid := range []string{"URN:example:test", "urn:example:bad\\value"} {
		if validAbsoluteURI(invalid, 2048) {
			t.Fatalf("validAbsoluteURI(%q) accepted noncanonical URI", invalid)
		}
	}
}

func TestOIDCCreateConfigurationEnforcesIssuerUTF8ByteLimitIndependentlyOfEndpoints(t *testing.T) {
	issuerPrefix := "https://idp.example.test/"
	issuerAtLimit := issuerPrefix + strings.Repeat("a", maximumOIDCIssuerBytes-len(issuerPrefix))
	issuerOverLimit := issuerAtLimit + "a"
	multibyteIssuer := issuerPrefix + strings.Repeat("é", maximumOIDCIssuerBytes/2)
	if len(issuerAtLimit) != maximumOIDCIssuerBytes || len(issuerOverLimit) != maximumOIDCIssuerBytes+1 ||
		utf8.RuneCountInString(multibyteIssuer) >= maximumOIDCIssuerBytes ||
		len(multibyteIssuer) <= maximumOIDCIssuerBytes {
		t.Fatal("issuer fixtures do not isolate the 2048 UTF-8 byte limit")
	}

	atLimit := validOIDCConfigurationFixture()
	atLimit.Issuer = issuerAtLimit
	if _, err := normalizeOIDCCreateConfiguration(atLimit); err != nil {
		t.Fatalf("normalizeOIDCCreateConfiguration() rejected a 2048-byte ASCII issuer: %v", err)
	}
	for name, issuer := range map[string]string{
		"2049-byte ASCII":      issuerOverLimit,
		"multibyte over limit": multibyteIssuer,
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validOIDCConfigurationFixture()
			configuration.Issuer = issuer
			if _, err := normalizeOIDCCreateConfiguration(configuration); err != authentication.ErrInvalidInput {
				t.Fatalf("normalizeOIDCCreateConfiguration() error = %v", err)
			}
		})
	}

	endpointOverIssuerLimit := validOIDCConfigurationFixture()
	endpointOverIssuerLimit.RedirectURI = issuerOverLimit
	if _, err := normalizeOIDCCreateConfiguration(endpointOverIssuerLimit); err != nil {
		t.Fatalf("normalizeOIDCCreateConfiguration() applied the issuer limit to a 4096-byte endpoint: %v", err)
	}
	if !validCanonicalURIText(multibyteIssuer, maximumFederationEndpointURIBytes) ||
		validCanonicalURIText(multibyteIssuer, maximumOIDCIssuerBytes) {
		t.Fatal("canonical URI text validation did not enforce the multibyte UTF-8 byte limit")
	}
}

func TestServiceListsReadsUpdatesAndArchivesThroughExactProtectedParams(t *testing.T) {
	firstID, secondID, thirdID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	ids := []uuid.UUID{firstID, secondID, thirdID}
	slices.SortFunc(ids, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	firstID, secondID, thirdID = ids[0], ids[1], ids[2]
	repository := &repositoryStub{}
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	repository.list = func(_ context.Context, params ListParams) ([]ProviderSummary, error) {
		if params.Limit != 3 || params.After == nil || *params.After != firstID || !params.IncludeArchived ||
			params.ActorID == uuid.Nil || params.SessionID == uuid.Nil || params.AuthenticationMethod != "passkey" {
			t.Fatalf("List() params = %#v", params)
		}
		return []ProviderSummary{
			{ID: secondID, Key: "first_sso", DisplayName: "First SSO", Kind: ProviderKindOIDC, Configured: true, Version: 1, CreatedAt: now, UpdatedAt: now},
			{ID: thirdID, Key: "second_sso", DisplayName: "Second SSO", Kind: ProviderKindSAML, Configured: true, Version: 1, CreatedAt: now, UpdatedAt: now},
			{ID: mustLargerUUIDv7(t, thirdID), Key: "third_sso", DisplayName: "Third SSO", Kind: ProviderKindOIDC, Configured: true, Version: 1, CreatedAt: now, UpdatedAt: now},
		}, nil
	}
	service := mustService(t, repository)
	page, err := service.List(context.Background(), readSession(t), ListInput{
		After: &firstID, Limit: 2, IncludeArchived: true,
	})
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != secondID || page.Items[1].ID != thirdID ||
		page.NextCursor == nil || *page.NextCursor != thirdID {
		t.Fatalf("List() = %#v, %v", page, err)
	}

	provider := validOIDCProvider(t, secondID)
	repository.get = func(_ context.Context, params GetParams) (Provider, error) {
		if params.ProviderID != secondID || params.ActorID == uuid.Nil || params.SessionID == uuid.Nil {
			t.Fatalf("Get() params = %#v", params)
		}
		return provider, nil
	}
	detail, err := service.Get(context.Background(), readSession(t), secondID)
	if err != nil || detail.ID != secondID || detail.Enabled || detail.PlatformLoginEnabled || detail.OIDC == nil {
		t.Fatalf("Get() = %#v, %v", detail, err)
	}

	updateTag := mustEntityTag(t, 3)
	repository.update = func(_ context.Context, params UpdateParams) (UpdateResult, error) {
		if params.ProviderID != secondID || params.ExpectedVersion != 3 || params.Key != "first_sso" ||
			params.DisplayName != "Renamed SSO" || params.Description != "Updated" ||
			params.Reason != "Approved metadata update" || params.Event.RequestID == uuid.Nil {
			t.Fatalf("Update() params = %#v", params)
		}
		projection := validOIDCProvider(t, secondID)
		projection.Version = 4
		projection.Key = params.Key
		projection.DisplayName = params.DisplayName
		projection.Description = params.Description
		return mustUpdateResult(t, projection), nil
	}
	updated, err := service.Update(context.Background(), manageSession(t), secondID, UpdateInput{
		Key: " first_sso ", DisplayName: " Renamed SSO ", Description: " Updated ",
		Reason: " Approved metadata update ", ExpectedEntityTag: &updateTag, Event: testEvent(t),
	})
	if err != nil || updated.ProviderID() != secondID || updated.Version() != 4 {
		t.Fatalf("Update() = %#v, %v", updated, err)
	}

	archiveTag := mustEntityTag(t, 4)
	repository.archive = func(_ context.Context, params ArchiveParams) (MutationReceipt, error) {
		if params.ProviderID != secondID || params.ExpectedVersion != 4 || params.Reason != "Provider retired" ||
			params.Event.CorrelationID == uuid.Nil {
			t.Fatalf("Archive() params = %#v", params)
		}
		return mustMutationReceipt(t, secondID, 5), nil
	}
	archived, err := service.Archive(context.Background(), manageSession(t), secondID, ArchiveInput{
		Reason: " Provider retired ", ExpectedEntityTag: &archiveTag, Event: testEvent(t),
	})
	if err != nil || archived.ProviderID() != secondID || archived.Version() != 5 {
		t.Fatalf("Archive() = %#v, %v", archived, err)
	}
}

func TestServicePermissionChecksAreDenyByDefaultAndPrecedeValidation(t *testing.T) {
	repository := &repositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)
	session.Permissions = nil

	if _, err := service.List(nil, session, ListInput{Limit: -1}); err != authentication.ErrForbidden {
		t.Fatalf("List() error = %v", err)
	}
	if _, err := service.Get(nil, session, uuid.Nil); err != authentication.ErrForbidden {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := service.Create(nil, session, CreateInput{}); err != authentication.ErrForbidden {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := service.Update(nil, session, uuid.Nil, UpdateInput{}); err != authentication.ErrForbidden {
		t.Fatalf("Update() error = %v", err)
	}
	if _, err := service.Archive(nil, session, uuid.Nil, ArchiveInput{}); err != authentication.ErrForbidden {
		t.Fatalf("Archive() error = %v", err)
	}
	if _, err := service.ActivateDirectLogin(nil, session, uuid.Nil, DirectLoginInput{}); err != authentication.ErrForbidden {
		t.Fatalf("ActivateDirectLogin() error = %v", err)
	}
	if _, err := service.DeactivateDirectLogin(nil, session, uuid.Nil, DirectLoginInput{}); err != authentication.ErrForbidden {
		t.Fatalf("DeactivateDirectLogin() error = %v", err)
	}
	secret := []byte("must-be-cleared-on-denial")
	if _, err := service.ReplaceOIDCClientSecret(nil, session, uuid.Nil, ReplaceOIDCClientSecretInput{Secret: secret}); err != authentication.ErrForbidden {
		t.Fatalf("ReplaceOIDCClientSecret() error = %v", err)
	}
	if !allZero(secret) {
		t.Fatalf("denied plaintext was not cleared: %x", secret)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want zero", repository.calls)
	}

	readOnly := manageSession(t)
	readOnly.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityProviderRead}
	if _, err := service.Create(context.Background(), readOnly, validOIDCCreateInput(t)); err != authentication.ErrForbidden {
		t.Fatalf("read permission allowed create: %v", err)
	}
	manageOnly := manageSession(t)
	manageOnly.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityProviderManage}
	if _, err := service.List(context.Background(), manageOnly, ListInput{}); err != authentication.ErrForbidden {
		t.Fatalf("manage permission implied read: %v", err)
	}
	if _, err := service.Create(context.Background(), manageOnly, validOIDCCreateInput(t)); err != authentication.ErrForbidden {
		t.Fatalf("create without read permission = %v", err)
	}
	if _, err := service.Update(context.Background(), manageOnly, mustUUIDv7(t), UpdateInput{}); err != authentication.ErrForbidden {
		t.Fatalf("update without read permission = %v", err)
	}
	if _, err := service.ActivateDirectLogin(context.Background(), manageOnly, mustUUIDv7(t), DirectLoginInput{}); err != authentication.ErrForbidden {
		t.Fatalf("direct login activation without read permission = %v", err)
	}
	if _, err := service.DeactivateDirectLogin(context.Background(), manageOnly, mustUUIDv7(t), DirectLoginInput{}); err != authentication.ErrForbidden {
		t.Fatalf("direct login deactivation without read permission = %v", err)
	}
}

func TestServicePreservesCanceledAndExpiredContextsBeforePersistence(t *testing.T) {
	providerID := mustUUIDv7(t)
	tag := mustEntityTag(t, 3)
	tests := []struct {
		name string
		call func(context.Context, *Service) error
	}{
		{name: "list", call: func(ctx context.Context, service *Service) error {
			_, err := service.List(ctx, readSession(t), ListInput{})
			return err
		}},
		{name: "get", call: func(ctx context.Context, service *Service) error {
			_, err := service.Get(ctx, readSession(t), providerID)
			return err
		}},
		{name: "create", call: func(ctx context.Context, service *Service) error {
			_, err := service.Create(ctx, manageSession(t), validOIDCCreateInput(t))
			return err
		}},
		{name: "update", call: func(ctx context.Context, service *Service) error {
			_, err := service.Update(ctx, manageSession(t), providerID, validUpdateInput(t, tag))
			return err
		}},
		{name: "archive", call: func(ctx context.Context, service *Service) error {
			_, err := service.Archive(ctx, manageSession(t), providerID, ArchiveInput{
				Reason: "Retired", ExpectedEntityTag: &tag, Event: testEvent(t),
			})
			return err
		}},
		{name: "replace secret", call: func(ctx context.Context, service *Service) error {
			_, err := service.ReplaceOIDCClientSecret(ctx, manageSession(t), providerID, ReplaceOIDCClientSecretInput{
				Secret: []byte("secret"), Reason: "Rotated", ExpectedEntityTag: &tag, Event: testEvent(t),
			})
			return err
		}},
		{name: "activate direct login", call: func(ctx context.Context, service *Service) error {
			_, err := service.ActivateDirectLogin(ctx, manageSession(t), providerID, DirectLoginInput{
				Reason: "Enable direct login", ExpectedEntityTag: &tag, Event: testEvent(t),
			})
			return err
		}},
		{name: "deactivate direct login", call: func(ctx context.Context, service *Service) error {
			_, err := service.DeactivateDirectLogin(ctx, manageSession(t), providerID, DirectLoginInput{
				Reason: "Disable direct login", ExpectedEntityTag: &tag, Event: testEvent(t),
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			service := mustService(t, repository)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := test.call(ctx, service); err != context.Canceled {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want zero", repository.calls)
			}
		})
	}

	repository := &repositoryStub{}
	service := mustService(t, repository)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := service.Get(expired, readSession(t), providerID); err != context.DeadlineExceeded {
		t.Fatalf("Get() expired context error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want zero", repository.calls)
	}
}

func TestServicePreservesCancellationReturnedInFlightByRepository(t *testing.T) {
	providerID := mustUUIDv7(t)
	started := make(chan struct{})
	repository := &repositoryStub{}
	repository.get = func(ctx context.Context, _ GetParams) (Provider, error) {
		close(started)
		<-ctx.Done()
		return Provider{}, fmt.Errorf("repository get interrupted: %w", ctx.Err())
	}
	service := mustService(t, repository)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	session := readSession(t)
	go func() {
		_, err := service.Get(ctx, session, providerID)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("repository call did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Get() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Get() did not return after cancellation")
	}
}

func TestReplaceOIDCClientSecretUsesPlatformAADClearsPlaintextAndRedactsDiagnostics(t *testing.T) {
	providerID, secretID, otherProviderID, otherSecretID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	keyring := testKeyring(t)
	repository := &repositoryStub{}
	var captured ReplaceOIDCClientSecretParams
	repository.replace = func(_ context.Context, params ReplaceOIDCClientSecretParams) (SecretMutationReceipt, error) {
		captured = params
		captured.Secret.Envelope.Ciphertext = append([]byte(nil), params.Secret.Envelope.Ciphertext...)
		return mustSecretReceipt(t, providerID, 8, 2), nil
	}
	service, err := NewService(repository, keyring, testPublicOrigin)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.newID = func() (uuid.UUID, error) { return secretID, nil }
	tag := mustEntityTag(t, 7)
	plaintest := []byte("super-sensitive-platform-client-secret")
	wantPlaintext := append([]byte(nil), plaintest...)
	input := ReplaceOIDCClientSecretInput{
		Secret: plaintest, Reason: "Rotate after upstream change", ExpectedEntityTag: &tag, Event: testEvent(t),
	}
	receipt, err := service.ReplaceOIDCClientSecret(
		context.Background(), manageSession(t), providerID, input,
	)
	if err != nil || receipt.ProviderID() != providerID || receipt.Version() != 8 || receipt.SecretRevision() != 2 {
		t.Fatalf("ReplaceOIDCClientSecret() = %#v, %v", receipt, err)
	}
	if !allZero(plaintest) {
		t.Fatalf("plaintext was not cleared: %x", plaintest)
	}
	if captured.ProviderID != providerID || captured.Secret.SecretID != secretID || captured.ExpectedVersion != 7 ||
		captured.Secret.Envelope.KeyVersion != keyring.ActiveVersion() {
		t.Fatalf("params = %#v", captured)
	}
	plaintext, err := keyring.DecryptOIDCClientSecret(
		platformOIDCClientSecretContext(providerID, secretID), captured.Secret.Envelope,
	)
	if err != nil || !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatalf("DecryptOIDCClientSecret() = %q, %v", plaintext, err)
	}
	clear(plaintext)
	for name, context := range map[string]identity.OIDCClientSecretContext{
		"provider substitution": platformOIDCClientSecretContext(otherProviderID, secretID),
		"secret substitution":   platformOIDCClientSecretContext(providerID, otherSecretID),
	} {
		t.Run(name, func(t *testing.T) {
			plaintext, err := keyring.DecryptOIDCClientSecret(context, captured.Secret.Envelope)
			clear(plaintext)
			if !errors.Is(err, identity.ErrInvalidEncryptedOIDCClientSecret) {
				t.Fatalf("DecryptOIDCClientSecret() error = %v", err)
			}
		})
	}

	secretText := string(wantPlaintext)
	ciphertextText := fmt.Sprintf("%x", captured.Secret.Envelope.Ciphertext)
	for _, diagnostic := range []string{
		input.String(), input.GoString(), fmt.Sprintf("%#v", input),
		captured.Secret.String(), captured.Secret.GoString(), fmt.Sprintf("%#v", captured.Secret),
		captured.String(), captured.GoString(), fmt.Sprintf("%#v", captured), service.String(), service.GoString(),
	} {
		if strings.Contains(diagnostic, secretText) || strings.Contains(diagnostic, ciphertextText) ||
			strings.Contains(diagnostic, providerID.String()) || strings.Contains(diagnostic, secretID.String()) ||
			!strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func TestServiceRejectsMalformedOIDCAndSAMLConfigurationsBeforePersistence(t *testing.T) {
	validOIDC := validOIDCConfigurationFixture()
	validSAML := validSAMLConfigurationFixture()
	longClientID := strings.Repeat("a", 513)
	tests := []struct {
		name          string
		configuration CreateConfiguration
	}{
		{name: "nil configuration"},
		{name: "typed pointer", configuration: &validOIDC},
		{name: "OIDC insecure issuer", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.Issuer = "http://id.example.test" })},
		{name: "OIDC issuer query", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.Issuer += "?tenant=platform" })},
		{name: "OIDC empty client", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ClientID = " " })},
		{name: "OIDC long client", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ClientID = longClientID })},
		{name: "OIDC redirect fragment", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.RedirectURI += "#next" })},
		{name: "OIDC duplicate scope", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ExtraScopes = []string{"email", "email"} })},
		{name: "OIDC implicit scope", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ExtraScopes = []string{"openid"} })},
		{name: "OIDC quote in scope", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ExtraScopes = []string{"bad\"scope"} })},
		{name: "OIDC non ASCII scope", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) { value.ExtraScopes = []string{"profilé"} })},
		{name: "SAML relative entity", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.ExpectedEntityID = "relative" })},
		{name: "SAML insecure ACS", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.ACSURL = "http://periapsis.example.test/acs" })},
		{name: "SAML unknown redirect algorithm", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.RedirectSignatureAlgorithm = "rsa-sha1" })},
		{name: "SAML unknown signature policy", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.SignaturePolicy = "either" })},
		{name: "SAML disabled encryption with key", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.DecryptionKeyVersions = []int16{1} })},
		{name: "SAML required encryption without key", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.EncryptionPolicy = federatedsaml.EncryptionRequired })},
		{name: "SAML optional encryption with future key", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.EncryptionPolicy = federatedsaml.EncryptionOptional
			value.DecryptionKeyVersions = []int16{1}
		})},
		{name: "SAML duplicate key", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.EncryptionPolicy = federatedsaml.EncryptionOptional
			value.DecryptionKeyVersions = []int16{1, 1}
		})},
		{name: "SAML empty authn contexts", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.RequestedAuthnContexts = nil })},
		{name: "SAML unknown subject", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.SubjectSource = "email" })},
		{name: "SAML persistent subject attribute", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.SubjectAttributeName = pointer("subject") })},
		{name: "SAML immutable subject without format", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.SubjectSource = federatedsaml.SubjectImmutableAttribute
			value.SubjectAttributeName = pointer("subject")
		})},
		{name: "SAML excessive skew", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.ClockSkew = 5*time.Minute + time.Nanosecond })},
		{name: "SAML short authentication age", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) { value.MaximumAuthenticationAge = time.Minute - 1 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			service := mustService(t, repository)
			input := validOIDCCreateInput(t)
			input.Configuration = test.configuration
			if _, err := service.Create(context.Background(), manageSession(t), input); err != authentication.ErrInvalidInput {
				t.Fatalf("Create() error = %v", err)
			}
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d", repository.calls)
			}
		})
	}
}

func TestServiceRejectsCallerControlledPlatformEndpointAlternatives(t *testing.T) {
	validOIDC := validOIDCConfigurationFixture()
	validSAML := validSAMLConfigurationFixture()
	tests := []struct {
		name          string
		configuration CreateConfiguration
	}{
		{name: "OIDC callback host", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.RedirectURI = "https://attacker.example.test/api/v1/auth/platform/oidc/callback"
		})},
		{name: "OIDC callback path", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.RedirectURI = "https://periapsis.example.test/api/v1/auth/federated/oidc/callback"
		})},
		{name: "OIDC callback port", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.RedirectURI = "https://periapsis.example.test:444/api/v1/auth/platform/oidc/callback"
		})},
		{name: "OIDC callback surrounding space", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.RedirectURI = " " + value.RedirectURI
		})},
		{name: "OIDC post-logout host", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.PostLogoutRedirectURI = "https://attacker.example.test/signed-out"
		})},
		{name: "OIDC post-logout path", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.PostLogoutRedirectURI = "https://periapsis.example.test/logout"
		})},
		{name: "OIDC post-logout port", configuration: mutateOIDC(validOIDC, func(value *OIDCCreateConfiguration) {
			value.PostLogoutRedirectURI = "https://periapsis.example.test:444/signed-out"
		})},
		{name: "SAML SP entity host", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.SPEntityID = "https://attacker.example.test/api/v1/auth/platform/saml/corporate_sso/metadata"
		})},
		{name: "SAML SP entity path", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.SPEntityID = "https://periapsis.example.test/saml/platform"
		})},
		{name: "SAML SP entity belongs to another provider", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.SPEntityID = "https://periapsis.example.test/api/v1/auth/platform/saml/other_sso/metadata"
		})},
		{name: "SAML SP entity port", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.SPEntityID = "https://periapsis.example.test:444/api/v1/auth/platform/saml/corporate_sso/metadata"
		})},
		{name: "SAML ACS host", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.ACSURL = "https://attacker.example.test/api/v1/auth/platform/saml/acs"
		})},
		{name: "SAML ACS path", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.ACSURL = "https://periapsis.example.test/api/v1/auth/federated/saml/acs"
		})},
		{name: "SAML ACS port", configuration: mutateSAML(validSAML, func(value *SAMLCreateConfiguration) {
			value.ACSURL = "https://periapsis.example.test:444/api/v1/auth/platform/saml/acs"
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			service := mustService(t, repository)
			input := validOIDCCreateInput(t)
			input.Configuration = test.configuration
			if _, err := service.Create(context.Background(), manageSession(t), input); err != authentication.ErrInvalidInput {
				t.Fatalf("Create() error = %v", err)
			}
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want zero", repository.calls)
			}
		})
	}
}

func TestServiceRejectsMalformedSessionEventMetadataAndETags(t *testing.T) {
	providerID := mustUUIDv7(t)
	repository := &repositoryStub{}
	service := mustService(t, repository)
	tag := mustEntityTag(t, 3)
	valid := UpdateInput{
		Key: "corporate_sso", DisplayName: "Corporate SSO", Description: "Provider",
		Reason: "Approved change", ExpectedEntityTag: &tag, Event: testEvent(t),
	}

	invalidSessions := []authentication.Session{manageSession(t), manageSession(t), manageSession(t)}
	invalidSessions[0].ID = uuid.Nil
	invalidSessions[1].User.ID = uuid.New()
	invalidSessions[2].AuthenticationMethod = "oidc bearer"
	for _, session := range invalidSessions {
		if _, err := service.Update(context.Background(), session, providerID, valid); err != authentication.ErrUnavailable {
			t.Fatalf("Update() invalid session error = %v", err)
		}
	}

	badTags := []*string{
		nil,
		pointer("v3"),
		pointer("W/\"v3\""),
		pointer("\"v03\""),
		pointer("\"v0\""),
		pointer("\"v3\", \"v4\""),
		pointer("\"v2147483647\""),
	}
	for _, badTag := range badTags {
		input := valid
		input.ExpectedEntityTag = badTag
		if _, err := service.Update(context.Background(), manageSession(t), providerID, input); err != authentication.ErrInvalidInput {
			t.Fatalf("Update() ETag %v error = %v", badTag, err)
		}
	}

	badEvents := []authentication.EventContext{valid.Event, valid.Event, valid.Event, valid.Event}
	badEvents[0].RequestID = uuid.New()
	badEvents[1].RemoteAddress = netip.MustParseAddr("fe80::1%eth0")
	badEvents[2].UserAgent = "line\nbreak"
	badEvents[3].UserAgent = strings.Repeat("a", 513)
	for _, event := range badEvents {
		input := valid
		input.Event = event
		if _, err := service.Update(context.Background(), manageSession(t), providerID, input); err != authentication.ErrInvalidInput {
			t.Fatalf("Update() invalid event error = %v", err)
		}
	}

	for _, reason := range []string{"", "line\nbreak", "spoof\u202etext", strings.Repeat("a", maximumReasonBytes+1)} {
		input := valid
		input.Reason = reason
		if _, err := service.Update(context.Background(), manageSession(t), providerID, input); err != authentication.ErrInvalidInput {
			t.Fatalf("Update() reason %q error = %v", reason, err)
		}
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d", repository.calls)
	}
}

func TestServiceValidatesEveryRepositoryReceipt(t *testing.T) {
	providerID, otherID := mustUUIDv7(t), mustUUIDv7(t)
	tag := mustEntityTag(t, 4)
	tests := []struct {
		name string
		run  func(*Service) error
	}{
		{
			name: "zero create receipt",
			run: func(service *Service) error {
				_, err := service.Create(context.Background(), manageSession(t), validOIDCCreateInput(t))
				return err
			},
		},
		{
			name: "non replayed create substitutes provider",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).create = func(context.Context, CreateParams) (CreateResult, error) {
					projection := validOIDCProvider(t, otherID)
					projection.Version = 1
					return mustCreateResult(t, otherID, false, projection), nil
				}
				_, err := service.Create(context.Background(), manageSession(t), validOIDCCreateInput(t))
				return err
			},
		},
		{
			name: "create returns unsafe projection",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).create = func(_ context.Context, params CreateParams) (CreateResult, error) {
					projection := providerFromCreateParams(t, params, 1)
					projection.Enabled = true
					return mustCreateResult(t, params.ProviderID, false, projection), nil
				}
				_, err := service.Create(context.Background(), manageSession(t), validOIDCCreateInput(t))
				return err
			},
		},
		{
			name: "update wrong provider",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).update = func(context.Context, UpdateParams) (UpdateResult, error) {
					projection := validOIDCProvider(t, otherID)
					projection.Version = 5
					return mustUpdateResult(t, projection), nil
				}
				_, err := service.Update(context.Background(), manageSession(t), providerID, validUpdateInput(t, tag))
				return err
			},
		},
		{
			name: "update returns stale metadata",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).update = func(context.Context, UpdateParams) (UpdateResult, error) {
					projection := validOIDCProvider(t, providerID)
					projection.Version = 5
					projection.DisplayName = "Stale name"
					return mustUpdateResult(t, projection), nil
				}
				_, err := service.Update(context.Background(), manageSession(t), providerID, validUpdateInput(t, tag))
				return err
			},
		},
		{
			name: "archive wrong version",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).archive = func(context.Context, ArchiveParams) (MutationReceipt, error) {
					return mustMutationReceipt(t, providerID, 6), nil
				}
				_, err := service.Archive(context.Background(), manageSession(t), providerID, ArchiveInput{
					Reason: "Retired", ExpectedEntityTag: &tag, Event: testEvent(t),
				})
				return err
			},
		},
		{
			name: "secret zero revision",
			run: func(service *Service) error {
				service.repository.(*repositoryStub).replace = func(context.Context, ReplaceOIDCClientSecretParams) (SecretMutationReceipt, error) {
					return SecretMutationReceipt{providerID: providerID, version: 5}, nil
				}
				_, err := service.ReplaceOIDCClientSecret(context.Background(), manageSession(t), providerID, ReplaceOIDCClientSecretInput{
					Secret: []byte("secret"), Reason: "Rotate", ExpectedEntityTag: &tag, Event: testEvent(t),
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			service := mustService(t, repository)
			ids := []uuid.UUID{mustUUIDv7(t), providerID, mustUUIDv7(t)}
			service.newID = func() (uuid.UUID, error) {
				id := ids[0]
				ids = ids[1:]
				return id, nil
			}
			if err := test.run(service); err != authentication.ErrUnavailable {
				t.Fatalf("error = %v, want unavailable", err)
			}
		})
	}
}

func TestServiceRejectsUnsafeRepositoryProjectionsAndDefensivelyCopies(t *testing.T) {
	providerID := mustUUIDv7(t)
	repository := &repositoryStub{}
	repository.get = func(context.Context, GetParams) (Provider, error) {
		return validOIDCProvider(t, providerID), nil
	}
	service := mustService(t, repository)
	provider, err := service.Get(context.Background(), readSession(t), providerID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	provider.OIDC.ExtraScopes[0] = "tampered"
	fresh, err := service.Get(context.Background(), readSession(t), providerID)
	if err != nil || fresh.OIDC.ExtraScopes[0] != "email" {
		t.Fatalf("Get() defensive copy = %#v, %v", fresh.OIDC, err)
	}

	repository.get = func(context.Context, GetParams) (Provider, error) {
		value := validOIDCProvider(t, providerID)
		value.Enabled = true
		return value, nil
	}
	if _, err := service.Get(context.Background(), readSession(t), providerID); err != authentication.ErrUnavailable {
		t.Fatalf("Get() enabled projection error = %v", err)
	}
	repository.get = func(context.Context, GetParams) (Provider, error) {
		value := validOIDCProvider(t, providerID)
		value.PlatformLoginEnabled = true
		return value, nil
	}
	if _, err := service.Get(context.Background(), readSession(t), providerID); err != authentication.ErrUnavailable {
		t.Fatalf("Get() login-enabled projection error = %v", err)
	}
	repository.get = func(context.Context, GetParams) (Provider, error) {
		value := validOIDCProvider(t, providerID)
		value.Enabled = true
		value.PlatformLoginEnabled = true
		value.SecretPresent = true
		value.AccountMode = AccountModeExistingIdentity
		value.OIDC.ClientSecretPresent = true
		value.OIDC.ClientSecretRevision = 2
		return value, nil
	}
	if direct, err := service.Get(context.Background(), readSession(t), providerID); err != nil || !direct.PlatformLoginEnabled {
		t.Fatalf("Get() valid direct-login projection = %#v, %v", direct, err)
	}
	repository.get = func(context.Context, GetParams) (Provider, error) {
		value := validOIDCProvider(t, providerID)
		value.OIDC.ExtraScopes = []string{"profile", "email"}
		return value, nil
	}
	if _, err := service.Get(context.Background(), readSession(t), providerID); err != authentication.ErrUnavailable {
		t.Fatalf("Get() noncanonical projection error = %v", err)
	}
	repository.get = func(context.Context, GetParams) (Provider, error) {
		value := validOIDCProvider(t, providerID)
		value.OIDC.RedirectURI = "https://attacker.example.test/api/v1/auth/platform/oidc/callback"
		return value, nil
	}
	if _, err := service.Get(context.Background(), readSession(t), providerID); err != authentication.ErrUnavailable {
		t.Fatalf("Get() caller-controlled endpoint projection error = %v", err)
	}
}

func TestServiceMapsOnlyClosedRepositoryErrors(t *testing.T) {
	providerID := mustUUIDv7(t)
	tests := []struct {
		in   error
		want error
	}{
		{authentication.ErrForbidden, authentication.ErrForbidden},
		{authentication.ErrNotFound, authentication.ErrNotFound},
		{authentication.ErrConflict, authentication.ErrConflict},
		{authentication.ErrInvalidInput, authentication.ErrInvalidInput},
		{ErrPreconditionFailed, ErrPreconditionFailed},
		{context.Canceled, context.Canceled},
		{context.DeadlineExceeded, context.DeadlineExceeded},
		{authentication.ErrUnavailable, authentication.ErrUnavailable},
		{fmt.Errorf("wrapped: %w", ErrPreconditionFailed), ErrPreconditionFailed},
		{fmt.Errorf("wrapped: %w", context.Canceled), context.Canceled},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), context.DeadlineExceeded},
		{fmt.Errorf("wrapped: %w", authentication.ErrNotFound), authentication.ErrNotFound},
		{errors.New("secret database diagnostic"), authentication.ErrUnavailable},
	}
	for _, test := range tests {
		repository := &repositoryStub{getError: test.in}
		service := mustService(t, repository)
		_, err := service.Get(context.Background(), readSession(t), providerID)
		if err != test.want {
			t.Fatalf("Get() error = %v, want exact %v", err, test.want)
		}
	}
}

func TestReceiptRestorationAndEntityTagsAreClosed(t *testing.T) {
	providerID := mustUUIDv7(t)
	if _, err := RestoreCreateReceipt(CreateReceiptInput{ProviderID: uuid.New(), Version: 1}); err == nil {
		t.Fatal("RestoreCreateReceipt() accepted UUIDv4")
	}
	if _, err := RestoreCreateReceipt(CreateReceiptInput{ProviderID: providerID, Version: 2}); err == nil {
		t.Fatal("RestoreCreateReceipt() accepted non-initial version")
	}
	if _, err := RestoreMutationReceipt(MutationReceiptInput{ProviderID: providerID, Version: 1}); err == nil {
		t.Fatal("RestoreMutationReceipt() accepted initial version")
	}
	if _, err := RestoreSecretMutationReceipt(SecretMutationReceiptInput{ProviderID: providerID, Version: 2, SecretRevision: 1}); err == nil {
		t.Fatal("RestoreSecretMutationReceipt() accepted initial secret revision")
	}
	for _, version := range []int64{1, 17, 2_147_483_647} {
		tag, err := EntityTag(version)
		if err != nil {
			t.Fatalf("EntityTag(%d) error = %v", version, err)
		}
		parsed, err := parseEntityTag(tag)
		if err != nil || parsed != version {
			t.Fatalf("parseEntityTag(%q) = %d, %v", tag, parsed, err)
		}
	}
	for _, value := range []string{"", "v1", "W/\"v1\"", "\"v0\"", "\"v01\"", "\"v1x\"", "\"v2147483648\"", "\"v9223372036854775807\""} {
		if _, err := parseEntityTag(value); err == nil {
			t.Fatalf("parseEntityTag(%q) succeeded", value)
		}
	}
}

func TestInternalProviderRevisionsHonorContractRange(t *testing.T) {
	providerID := mustUUIDv7(t)
	provider := validOIDCProvider(t, providerID)
	provider.ConfigurationRevision = maximumProviderRevision
	provider.SecurityRevision = maximumProviderRevision
	provider.PlanRevision = maximumProviderRevision
	provider.AssurancePolicyRevision = maximumProviderRevision
	provider.OIDC.ClientSecretRevision = maximumProviderRevision
	provider.OIDC.DiscoveryRevision = maximumProviderRevision
	provider.OIDC.JWKSRevision = maximumProviderRevision
	endpoints, err := newCanonicalEndpointPolicy("https://periapsis.example.test")
	if err != nil {
		t.Fatalf("newCanonicalEndpointPolicy() error = %v", err)
	}
	if !validProvider(provider, endpoints) {
		t.Fatal("validProvider() rejected schema-valid maximum internal revisions")
	}
	provider.OIDC.JWKSRevision = maximumProviderRevision + 1
	if validProvider(provider, endpoints) {
		t.Fatal("validProvider() accepted an internal revision above the contract maximum")
	}
	if _, err := RestoreSecretMutationReceipt(SecretMutationReceiptInput{
		ProviderID: providerID, Version: 2, SecretRevision: maximumProviderRevision,
	}); err != nil {
		t.Fatalf("RestoreSecretMutationReceipt() rejected maximum secret revision: %v", err)
	}
	if _, err := RestoreSecretMutationReceipt(SecretMutationReceiptInput{
		ProviderID: providerID, Version: 2, SecretRevision: maximumProviderRevision + 1,
	}); err == nil {
		t.Fatal("RestoreSecretMutationReceipt() accepted secret revision above the contract maximum")
	}
}

func TestPlatformLoginActivationAvailabilityIsAuthoritativeAndFailClosed(t *testing.T) {
	provider := validOIDCProvider(t, mustUUIDv7(t))
	provider.Enabled = true
	provider.AccountMode = AccountModeExistingIdentity
	provider.SecretPresent = true
	provider.OIDC.ClientSecretPresent = true
	provider.OIDC.ClientSecretRevision = 2
	provider.PlatformLoginActivationAvailable = true
	if !validProviderSummary(provider.ProviderSummary) {
		t.Fatal("validProviderSummary() rejected an authoritative ready projection")
	}

	provider.PlatformLoginActivationAvailable = false
	if !validProviderSummary(provider.ProviderSummary) {
		t.Fatal("validProviderSummary() rejected an authoritative unavailable projection")
	}

	provider.PlatformLoginEnabled = true
	if !validProviderSummary(provider.ProviderSummary) {
		t.Fatal("validProviderSummary() rejected an active projection with activation unavailable")
	}
	provider.PlatformLoginActivationAvailable = true
	if validProviderSummary(provider.ProviderSummary) {
		t.Fatal("validProviderSummary() accepted activation availability while direct login is active")
	}

	saml := validSAMLProvider(t, mustUUIDv7(t))
	saml.Enabled = true
	saml.AccountMode = AccountModeExistingIdentity
	saml.SecretPresent = true
	saml.SAML.SPKeyPresent = true
	saml.SAML.SPKeyRevision = 2
	saml.PlatformLoginActivationAvailable = true
	if !validProviderSummary(saml.ProviderSummary) || !validProvider(saml, mustEndpointPolicy(t, "https://periapsis.example.test")) {
		t.Fatal("SAML readiness projection was not admitted after SP-key staging")
	}
	saml.SecretPresent = false
	if validProviderSummary(saml.ProviderSummary) {
		t.Fatal("validProviderSummary() accepted SAML activation availability without a staged SP key")
	}
}

func TestServiceActivatesReadyOIDCForTenantExecutionAndDeactivatesIt(t *testing.T) {
	providerID := mustUUIDv7(t)
	repository := &repositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)

	ready := validOIDCProvider(t, providerID)
	ready.Version = 3
	ready.SecretPresent = true
	ready.OIDC.ClientSecretPresent = true
	ready.OIDC.ClientSecretRevision = 2
	ready.ActivationAvailable = true
	activateTag, err := EntityTag(ready.Version)
	if err != nil {
		t.Fatalf("EntityTag() error = %v", err)
	}
	repository.activate = func(_ context.Context, params ActivationParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 3 ||
			params.AccountMode != AccountModeCreate || params.Reason != "Enable tenant execution" ||
			params.ValidateResult == nil {
			t.Fatalf("Activate() params = %#v", params)
		}
		active := cloneProvider(ready)
		active.Version = 4
		active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
		active.Enabled = true
		active.ActivationAvailable = false
		active.AccountMode = AccountModeCreate
		return mustUpdateResult(t, active), nil
	}
	activated, err := service.Activate(context.Background(), session, providerID, ActivateInput{
		AccountMode: AccountModeCreate, Reason: " Enable tenant execution ",
		ExpectedEntityTag: &activateTag, Event: testEvent(t),
	})
	if err != nil || !activated.Provider().Enabled || activated.Provider().AccountMode != AccountModeCreate ||
		activated.Version() != 4 {
		t.Fatalf("Activate() = %#v, %v", activated, err)
	}

	deactivateTag, err := EntityTag(4)
	if err != nil {
		t.Fatalf("EntityTag() error = %v", err)
	}
	repository.deactivate = func(_ context.Context, params DeactivationParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 4 ||
			params.Reason != "Disable tenant execution" || params.ValidateResult == nil {
			t.Fatalf("Deactivate() params = %#v", params)
		}
		disabled := cloneProvider(activated.Provider())
		disabled.Version = 5
		disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
		disabled.Enabled = false
		disabled.ActivationAvailable = true
		disabled.AccountMode = AccountModeDisabled
		return mustUpdateResult(t, disabled), nil
	}
	deactivated, err := service.Deactivate(context.Background(), session, providerID, DeactivateInput{
		Reason: " Disable tenant execution ", ExpectedEntityTag: &deactivateTag, Event: testEvent(t),
	})
	if err != nil || deactivated.Provider().Enabled ||
		deactivated.Provider().AccountMode != AccountModeDisabled || deactivated.Version() != 5 {
		t.Fatalf("Deactivate() = %#v, %v", deactivated, err)
	}
}

func TestServiceTenantActivationValidatorDoesNotHardcodeDirectLoginFalse(t *testing.T) {
	providerID := mustUUIDv7(t)
	tag := mustEntityTag(t, 1)
	repository := &repositoryStub{}
	repository.activate = func(context.Context, ActivationParams) (UpdateResult, error) {
		provider := validOIDCProvider(t, providerID)
		provider.Version = 2
		provider.Enabled = true
		provider.PlatformLoginEnabled = true
		provider.AccountMode = AccountModeExistingIdentity
		provider.SecretPresent = true
		provider.OIDC.ClientSecretPresent = true
		provider.OIDC.ClientSecretRevision = 2
		return mustUpdateResult(t, provider), nil
	}
	result, err := mustService(t, repository).Activate(
		context.Background(), manageSession(t), providerID,
		ActivateInput{
			AccountMode: AccountModeExistingIdentity, Reason: "Enable tenant execution",
			ExpectedEntityTag: &tag, Event: testEvent(t),
		},
	)
	if err != nil || !result.Provider().PlatformLoginEnabled {
		t.Fatalf("Activate() = %#v, %v", result, err)
	}
}

func TestServiceActivatesAndDeactivatesDirectOIDCLoginWithoutChangingTenantMode(t *testing.T) {
	providerID := mustUUIDv7(t)
	repository := &repositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)

	ready := validOIDCProvider(t, providerID)
	ready.Version = 7
	ready.Enabled = true
	ready.AccountMode = AccountModeCreate
	ready.SecretPresent = true
	ready.OIDC.ClientSecretPresent = true
	ready.OIDC.ClientSecretRevision = 2
	ready.PlatformLoginActivationAvailable = true
	activateTag := mustEntityTag(t, ready.Version)
	repository.activateDirect = func(_ context.Context, params DirectLoginParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 7 ||
			params.Reason != "Enable existing identity direct login" || params.ValidateResult == nil ||
			params.AuthenticationMethod != session.AuthenticationMethod {
			t.Fatalf("ActivateDirectLogin() params = %#v", params)
		}
		active := cloneProvider(ready)
		active.Version = 8
		active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
		active.PlatformLoginEnabled = true
		active.PlatformLoginActivationAvailable = false
		return mustUpdateResult(t, active), nil
	}
	activated, err := service.ActivateDirectLogin(context.Background(), session, providerID, DirectLoginInput{
		Reason: " Enable existing identity direct login ", ExpectedEntityTag: &activateTag, Event: testEvent(t),
	})
	if err != nil || !activated.Provider().PlatformLoginEnabled || !activated.Provider().Enabled ||
		activated.Provider().AccountMode != AccountModeCreate || activated.Version() != 8 {
		t.Fatalf("ActivateDirectLogin() = %#v, %v", activated, err)
	}

	deactivateTag := mustEntityTag(t, activated.Version())
	repository.deactivateDirect = func(_ context.Context, params DirectLoginParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 8 ||
			params.Reason != "Disable direct login" || params.ValidateResult == nil {
			t.Fatalf("DeactivateDirectLogin() params = %#v", params)
		}
		disabled := cloneProvider(activated.Provider())
		disabled.Version = 9
		disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
		disabled.PlatformLoginEnabled = false
		disabled.PlatformLoginActivationAvailable = true
		return mustUpdateResult(t, disabled), nil
	}
	deactivated, err := service.DeactivateDirectLogin(context.Background(), session, providerID, DirectLoginInput{
		Reason: " Disable direct login ", ExpectedEntityTag: &deactivateTag, Event: testEvent(t),
	})
	if err != nil || deactivated.Provider().PlatformLoginEnabled ||
		!deactivated.Provider().PlatformLoginActivationAvailable || !deactivated.Provider().Enabled ||
		deactivated.Provider().AccountMode != AccountModeCreate || deactivated.Version() != 9 {
		t.Fatalf("DeactivateDirectLogin() = %#v, %v", deactivated, err)
	}
}

func TestServiceActivatesReadySAMLForTenantAndDirectExecution(t *testing.T) {
	providerID := mustUUIDv7(t)
	repository := &repositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)

	ready := validSAMLProvider(t, providerID)
	ready.Version = 11
	ready.SecretPresent = true
	ready.SAML.SPKeyPresent = true
	ready.SAML.SPKeyRevision = 2
	ready.ActivationAvailable = true
	activateTag := mustEntityTag(t, ready.Version)
	repository.activate = func(_ context.Context, params ActivationParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 11 ||
			params.AccountMode != AccountModeExistingIdentity || params.ValidateResult == nil {
			t.Fatalf("Activate(SAML) params = %#v", params)
		}
		active := cloneProvider(ready)
		active.Version = 12
		active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
		active.Enabled = true
		active.ActivationAvailable = false
		active.PlatformLoginActivationAvailable = true
		active.AccountMode = AccountModeExistingIdentity
		return mustUpdateResult(t, active), nil
	}
	activated, err := service.Activate(context.Background(), session, providerID, ActivateInput{
		AccountMode: AccountModeExistingIdentity, Reason: "Enable SAML tenant execution",
		ExpectedEntityTag: &activateTag, Event: testEvent(t),
	})
	if err != nil || activated.Provider().Kind != ProviderKindSAML || !activated.Provider().Enabled ||
		!activated.Provider().PlatformLoginActivationAvailable || activated.Version() != 12 {
		t.Fatalf("Activate(SAML) = %#v, %v", activated, err)
	}

	directTag := mustEntityTag(t, activated.Version())
	repository.activateDirect = func(_ context.Context, params DirectLoginParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 12 || params.ValidateResult == nil {
			t.Fatalf("ActivateDirectLogin(SAML) params = %#v", params)
		}
		active := cloneProvider(activated.Provider())
		active.Version = 13
		active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
		active.PlatformLoginEnabled = true
		active.PlatformLoginActivationAvailable = false
		return mustUpdateResult(t, active), nil
	}
	direct, err := service.ActivateDirectLogin(context.Background(), session, providerID, DirectLoginInput{
		Reason: "Enable direct SAML login", ExpectedEntityTag: &directTag, Event: testEvent(t),
	})
	if err != nil || !direct.Provider().PlatformLoginEnabled || direct.Provider().Kind != ProviderKindSAML ||
		direct.Version() != 13 {
		t.Fatalf("ActivateDirectLogin(SAML) = %#v, %v", direct, err)
	}
}

func TestServiceDirectLoginRejectsUnreadyAndMalformedRepositoryResults(t *testing.T) {
	providerID := mustUUIDv7(t)
	tag := mustEntityTag(t, 3)
	tests := []struct {
		name   string
		mutate func(*Provider)
	}{
		{name: "not enabled", mutate: func(value *Provider) { value.Enabled = false; value.AccountMode = AccountModeDisabled }},
		{name: "secret absent", mutate: func(value *Provider) {
			value.SecretPresent = false
			value.OIDC.ClientSecretPresent = false
			value.OIDC.ClientSecretRevision = 1
		}},
		{name: "wrong lifecycle outcome", mutate: func(value *Provider) { value.PlatformLoginEnabled = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			repository.activateDirect = func(context.Context, DirectLoginParams) (UpdateResult, error) {
				value := validOIDCProvider(t, providerID)
				value.Version = 4
				value.Enabled = true
				value.AccountMode = AccountModeExistingIdentity
				value.SecretPresent = true
				value.OIDC.ClientSecretPresent = true
				value.OIDC.ClientSecretRevision = 2
				value.PlatformLoginEnabled = true
				test.mutate(&value)
				return mustUpdateResult(t, value), nil
			}
			_, err := mustService(t, repository).ActivateDirectLogin(
				context.Background(), manageSession(t), providerID,
				DirectLoginInput{Reason: "Enable direct login", ExpectedEntityTag: &tag, Event: testEvent(t)},
			)
			if err != authentication.ErrUnavailable {
				t.Fatalf("ActivateDirectLogin() error = %v", err)
			}
		})
	}

	t.Run("deactivation cannot disable tenant execution", func(t *testing.T) {
		repository := &repositoryStub{}
		repository.deactivateDirect = func(context.Context, DirectLoginParams) (UpdateResult, error) {
			value := validOIDCProvider(t, providerID)
			value.Version = 4
			return mustUpdateResult(t, value), nil
		}
		_, err := mustService(t, repository).DeactivateDirectLogin(
			context.Background(), manageSession(t), providerID,
			DirectLoginInput{Reason: "Disable direct login", ExpectedEntityTag: &tag, Event: testEvent(t)},
		)
		if err != authentication.ErrUnavailable {
			t.Fatalf("DeactivateDirectLogin() error = %v", err)
		}
	})
}

func TestServiceActivationRejectsDisabledAccountModeBeforePersistence(t *testing.T) {
	providerID := mustUUIDv7(t)
	tag, err := EntityTag(1)
	if err != nil {
		t.Fatalf("EntityTag() error = %v", err)
	}
	repository := &repositoryStub{}
	_, err = mustService(t, repository).Activate(
		context.Background(), manageSession(t), providerID,
		ActivateInput{
			AccountMode: AccountModeDisabled, Reason: "Invalid activation",
			ExpectedEntityTag: &tag, Event: testEvent(t),
		},
	)
	if !errors.Is(err, authentication.ErrInvalidInput) || repository.calls != 0 {
		t.Fatalf("Activate() error = %v, calls = %d", err, repository.calls)
	}
}

type repositoryStub struct {
	calls            int
	list             func(context.Context, ListParams) ([]ProviderSummary, error)
	create           func(context.Context, CreateParams) (CreateResult, error)
	update           func(context.Context, UpdateParams) (UpdateResult, error)
	archive          func(context.Context, ArchiveParams) (MutationReceipt, error)
	replace          func(context.Context, ReplaceOIDCClientSecretParams) (SecretMutationReceipt, error)
	activate         func(context.Context, ActivationParams) (UpdateResult, error)
	deactivate       func(context.Context, DeactivationParams) (UpdateResult, error)
	activateDirect   func(context.Context, DirectLoginParams) (UpdateResult, error)
	deactivateDirect func(context.Context, DirectLoginParams) (UpdateResult, error)
	get              func(context.Context, GetParams) (Provider, error)
	getError         error
}

func (repository *repositoryStub) ActivateDirectLogin(ctx context.Context, params DirectLoginParams) (UpdateResult, error) {
	repository.calls++
	if repository.activateDirect != nil {
		result, err := repository.activateDirect(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return UpdateResult{}, nil
}

func (repository *repositoryStub) DeactivateDirectLogin(ctx context.Context, params DirectLoginParams) (UpdateResult, error) {
	repository.calls++
	if repository.deactivateDirect != nil {
		result, err := repository.deactivateDirect(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return UpdateResult{}, nil
}

func (repository *repositoryStub) Activate(ctx context.Context, params ActivationParams) (UpdateResult, error) {
	repository.calls++
	if repository.activate != nil {
		result, err := repository.activate(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return UpdateResult{}, nil
}

func (repository *repositoryStub) Deactivate(ctx context.Context, params DeactivationParams) (UpdateResult, error) {
	repository.calls++
	if repository.deactivate != nil {
		result, err := repository.deactivate(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return UpdateResult{}, nil
}

func (repository *repositoryStub) List(ctx context.Context, params ListParams) ([]ProviderSummary, error) {
	repository.calls++
	if repository.list != nil {
		return repository.list(ctx, params)
	}
	return nil, nil
}

func (repository *repositoryStub) Get(ctx context.Context, params GetParams) (Provider, error) {
	repository.calls++
	if repository.getError != nil {
		return Provider{}, repository.getError
	}
	if repository.get != nil {
		return repository.get(ctx, params)
	}
	return Provider{}, nil
}

func (repository *repositoryStub) Create(ctx context.Context, params CreateParams) (CreateResult, error) {
	repository.calls++
	if repository.create != nil {
		result, err := repository.create(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return CreateResult{}, nil
}

func (repository *repositoryStub) Update(ctx context.Context, params UpdateParams) (UpdateResult, error) {
	repository.calls++
	if repository.update != nil {
		result, err := repository.update(ctx, params)
		if err != nil || params.ValidateResult == nil {
			return result, err
		}
		return params.ValidateResult(result)
	}
	return UpdateResult{}, nil
}

func (repository *repositoryStub) Archive(ctx context.Context, params ArchiveParams) (MutationReceipt, error) {
	repository.calls++
	if repository.archive != nil {
		return repository.archive(ctx, params)
	}
	return MutationReceipt{}, nil
}

func (repository *repositoryStub) ReplaceOIDCClientSecret(
	ctx context.Context,
	params ReplaceOIDCClientSecretParams,
) (SecretMutationReceipt, error) {
	repository.calls++
	if repository.replace != nil {
		return repository.replace(ctx, params)
	}
	return SecretMutationReceipt{}, nil
}

func mustService(t testing.TB, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, testKeyring(t), testPublicOrigin)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func mustEndpointPolicy(t testing.TB, publicOrigin string) canonicalEndpointPolicy {
	t.Helper()
	policy, err := newCanonicalEndpointPolicy(publicOrigin)
	if err != nil {
		t.Fatalf("newCanonicalEndpointPolicy() error = %v", err)
	}
	return policy
}

func testKeyring(t testing.TB) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x5a}, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func manageSession(t testing.TB) authentication.Session {
	t.Helper()
	return authentication.Session{
		ID: mustUUIDv7(t), User: authentication.User{ID: mustUUIDv7(t)},
		Permissions: []authorization.Permission{
			authorization.PermissionPlatformIdentityProviderManage,
			authorization.PermissionPlatformIdentityProviderRead,
		},
		AuthenticationMethod: "passkey",
	}
}

func readSession(t testing.TB) authentication.Session {
	t.Helper()
	session := manageSession(t)
	session.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityProviderRead}
	return session
}

func testEvent(t testing.TB) authentication.EventContext {
	t.Helper()
	return authentication.EventContext{
		RequestID: mustUUIDv7(t), CorrelationID: mustUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("198.51.100.17"), UserAgent: "platform-provider-test/1",
	}
}

func validOIDCCreateInput(t testing.TB) CreateInput {
	t.Helper()
	return CreateInput{
		Key: "corporate_sso", DisplayName: "Corporate SSO", Description: "Provider",
		Configuration: validOIDCConfigurationFixture(), Reason: "Approved by IAM",
		IdempotencyKey: "platform-provider-create-0001", Event: testEvent(t),
	}
}

func validOIDCConfigurationFixture() OIDCCreateConfiguration {
	return OIDCCreateConfiguration{
		Issuer: "https://id.example.test/issuer", ClientID: "periapsis-platform",
		RedirectURI:           "https://periapsis.example.test/api/v1/auth/platform/oidc/callback",
		TenantRedirectURI:     "https://periapsis.example.test/api/v1/auth/federated/oidc/callback",
		PostLogoutRedirectURI: "https://periapsis.example.test/signed-out",
		ExtraScopes:           []string{"email", "profile"}, UseUserInfo: true,
	}
}

func validSAMLConfigurationFixture() SAMLCreateConfiguration {
	return SAMLCreateConfiguration{
		ExpectedEntityID:           "https://id.example.test/saml/metadata",
		SPEntityID:                 "https://periapsis.example.test/api/v1/auth/platform/saml/corporate_sso/metadata",
		ACSURL:                     "https://periapsis.example.test/api/v1/auth/platform/saml/acs",
		RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
		RequestedAuthnContexts: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
		SubjectSource:          federatedsaml.SubjectPersistentNameID,
		ClockSkew:              2 * time.Minute, MaximumAuthenticationAge: 8 * time.Hour,
	}
}

func providerFromCreateParams(t testing.TB, params CreateParams, version int64) Provider {
	t.Helper()
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	provider := Provider{
		ProviderSummary: ProviderSummary{
			ID: params.ProviderID, Key: params.Key, DisplayName: params.DisplayName,
			Description: params.Description, Kind: params.Kind, Configured: true,
			Version: version, CreatedAt: now, UpdatedAt: now,
		},
		ConfigurationRevision: 1, SecurityRevision: 1, PlanRevision: 1,
		AssurancePolicyRevision: 1, AccountMode: AccountModeDisabled,
	}
	switch configuration := params.Configuration.(type) {
	case OIDCCreateConfiguration:
		provider.OIDC = &OIDCConfiguration{
			Issuer: configuration.Issuer, ClientID: configuration.ClientID,
			RedirectURI:           configuration.RedirectURI,
			TenantRedirectURI:     configuration.TenantRedirectURI,
			PostLogoutRedirectURI: configuration.PostLogoutRedirectURI,
			ExtraScopes:           append([]string(nil), configuration.ExtraScopes...),
			AllowRefreshToken:     configuration.AllowRefreshToken, UseUserInfo: configuration.UseUserInfo,
			ClientSecretRevision: 1, DiscoveryRevision: 1, JWKSRevision: 1,
		}
	case SAMLCreateConfiguration:
		provider.SAML = &SAMLConfiguration{
			ExpectedEntityID: configuration.ExpectedEntityID, SPEntityID: configuration.SPEntityID,
			ACSURL: configuration.ACSURL, SPKeyRevision: 1, MetadataRevision: 1,
			RedirectSignatureAlgorithm: configuration.RedirectSignatureAlgorithm,
			SignaturePolicy:            configuration.SignaturePolicy, EncryptionPolicy: configuration.EncryptionPolicy,
			RequestedAuthnContexts:     append([]string(nil), configuration.RequestedAuthnContexts...),
			SubjectSource:              configuration.SubjectSource,
			SubjectAttributeName:       cloneString(configuration.SubjectAttributeName),
			SubjectAttributeNameFormat: cloneString(configuration.SubjectAttributeNameFormat),
			ClockSkew:                  configuration.ClockSkew, MaximumAuthenticationAge: configuration.MaximumAuthenticationAge,
		}
	default:
		t.Fatalf("unsupported configuration %T", params.Configuration)
	}
	return provider
}

func validUpdateInput(t testing.TB, tag string) UpdateInput {
	t.Helper()
	return UpdateInput{
		Key: "corporate_sso", DisplayName: "Corporate SSO", Description: "Provider",
		Reason: "Approved change", ExpectedEntityTag: &tag, Event: testEvent(t),
	}
}

func validOIDCProvider(t testing.TB, providerID uuid.UUID) Provider {
	t.Helper()
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	return Provider{
		ProviderSummary: ProviderSummary{
			ID: providerID, Key: "corporate_sso", DisplayName: "Corporate SSO", Description: "Provider",
			Kind: ProviderKindOIDC, Configured: true, Version: 3, CreatedAt: now, UpdatedAt: now,
		},
		ConfigurationRevision: 1, SecurityRevision: 1, PlanRevision: 1,
		AssurancePolicyRevision: 1, AccountMode: AccountModeDisabled,
		OIDC: &OIDCConfiguration{
			Issuer: "https://id.example.test/issuer", ClientID: "periapsis-platform",
			RedirectURI:           "https://periapsis.example.test/api/v1/auth/platform/oidc/callback",
			TenantRedirectURI:     "https://periapsis.example.test/api/v1/auth/federated/oidc/callback",
			PostLogoutRedirectURI: "https://periapsis.example.test/signed-out",
			ExtraScopes:           []string{"email", "profile"}, ClientSecretRevision: 1,
			DiscoveryRevision: 1, JWKSRevision: 1,
		},
	}
}

func validSAMLProvider(t testing.TB, providerID uuid.UUID) Provider {
	t.Helper()
	configuration := validSAMLConfigurationFixture()
	now := time.Date(2026, 8, 27, 18, 30, 0, 123_456_000, time.UTC)
	return Provider{
		ProviderSummary: ProviderSummary{
			ID: providerID, Key: "corporate_sso", DisplayName: "Corporate SSO", Description: "Provider",
			Kind: ProviderKindSAML, Configured: true, Version: 3, CreatedAt: now, UpdatedAt: now,
		},
		ConfigurationRevision: 1, SecurityRevision: 1, PlanRevision: 1,
		AssurancePolicyRevision: 1, AccountMode: AccountModeDisabled,
		SAML: &SAMLConfiguration{
			ExpectedEntityID: configuration.ExpectedEntityID, SPEntityID: configuration.SPEntityID,
			ACSURL: configuration.ACSURL, SPKeyRevision: 1, MetadataRevision: 1,
			RedirectSignatureAlgorithm: configuration.RedirectSignatureAlgorithm,
			SignaturePolicy:            configuration.SignaturePolicy, EncryptionPolicy: configuration.EncryptionPolicy,
			RequestedAuthnContexts: append([]string(nil), configuration.RequestedAuthnContexts...),
			SubjectSource:          configuration.SubjectSource, ClockSkew: configuration.ClockSkew,
			MaximumAuthenticationAge: configuration.MaximumAuthenticationAge,
		},
	}
}

func mustCreateReceipt(t testing.TB, providerID uuid.UUID, replayed bool) CreateReceipt {
	t.Helper()
	receipt, err := RestoreCreateReceipt(CreateReceiptInput{ProviderID: providerID, Version: 1, Replayed: replayed})
	if err != nil {
		t.Fatalf("RestoreCreateReceipt() error = %v", err)
	}
	return receipt
}

func mustCreateResult(t testing.TB, providerID uuid.UUID, replayed bool, provider Provider) CreateResult {
	t.Helper()
	result, err := RestoreCreateResult(CreateResultInput{
		ProviderID: providerID,
		Version:    1,
		Replayed:   replayed,
		Provider:   provider,
	})
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	return result
}

func mustUpdateResult(t testing.TB, provider Provider) UpdateResult {
	t.Helper()
	result, err := RestoreUpdateResult(UpdateResultInput{
		ProviderID: provider.ID,
		Version:    provider.Version,
		Provider:   provider,
	})
	if err != nil {
		t.Fatalf("RestoreUpdateResult() error = %v", err)
	}
	return result
}

func mustMutationReceipt(t testing.TB, providerID uuid.UUID, version int64) MutationReceipt {
	t.Helper()
	receipt, err := RestoreMutationReceipt(MutationReceiptInput{ProviderID: providerID, Version: version})
	if err != nil {
		t.Fatalf("RestoreMutationReceipt() error = %v", err)
	}
	return receipt
}

func mustSecretReceipt(t testing.TB, providerID uuid.UUID, version, secretRevision int64) SecretMutationReceipt {
	t.Helper()
	receipt, err := RestoreSecretMutationReceipt(SecretMutationReceiptInput{
		ProviderID: providerID, Version: version, SecretRevision: secretRevision,
	})
	if err != nil {
		t.Fatalf("RestoreSecretMutationReceipt() error = %v", err)
	}
	return receipt
}

func mustEntityTag(t testing.TB, version int64) string {
	t.Helper()
	tag, err := EntityTag(version)
	if err != nil {
		t.Fatalf("EntityTag() error = %v", err)
	}
	return tag
}

func mustUUIDv7(t testing.TB) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("NewV7() error = %v", err)
	}
	return id
}

func mustLargerUUIDv7(t testing.TB, lower uuid.UUID) uuid.UUID {
	t.Helper()
	for {
		candidate := mustUUIDv7(t)
		if bytes.Compare(candidate[:], lower[:]) > 0 {
			return candidate
		}
	}
}

func mutateOIDC(value OIDCCreateConfiguration, mutate func(*OIDCCreateConfiguration)) OIDCCreateConfiguration {
	value.ExtraScopes = append([]string(nil), value.ExtraScopes...)
	mutate(&value)
	return value
}

func mutateSAML(value SAMLCreateConfiguration, mutate func(*SAMLCreateConfiguration)) SAMLCreateConfiguration {
	value.DecryptionKeyVersions = append([]int16(nil), value.DecryptionKeyVersions...)
	value.RequestedAuthnContexts = append([]string(nil), value.RequestedAuthnContexts...)
	mutate(&value)
	return value
}

func pointer[T any](value T) *T { return &value }

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
