package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testFederationBindingID     = uuid.MustParse("00000000-0000-7000-8000-00000000010a")
	testFederationCommandID     = uuid.MustParse("00000000-0000-7000-8000-00000000010b")
	testFederationOtherTenantID = uuid.MustParse("00000000-0000-7000-8000-00000000010c")
)

func TestFederationServiceCreatePinsTenantAuthorityAndDeploymentEndpoints(t *testing.T) {
	t.Parallel()

	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(_ context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		if params.Actor != testActor() || params.TenantID != testTenantID {
			t.Fatalf("authority params = %#v", params)
		}
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	repository.create = func(_ context.Context, params FederationCreateParams) (FederationCreateResult, error) {
		if params.CommandID != testFederationCommandID || params.ProviderID != testProviderID ||
			params.BindingID != testFederationBindingID || params.MembershipID != testMembershipID ||
			params.OIDCRedirectURI != "https://soc.example.com/api/v1/auth/federated/oidc/callback" ||
			params.SAMLACSURL != "https://soc.example.com/api/v1/auth/federated/saml/acs" ||
			params.SAMLSPMetadataBaseURL != "https://soc.example.com/api/v1/auth/federated/saml" {
			t.Fatalf("create params = %#v", params)
		}
		if params.Input.IdempotencyKey != "federation-create-0001" {
			t.Fatalf("raw idempotency key changed before protected writer")
		}
		return FederationCreateResult{Provider: federationOIDCTestProvider(
			params.ProviderID, params.BindingID, params.Input, params.OIDCRedirectURI,
		)}, nil
	}
	service := testFederationService(t, repository, repository)
	ids := []uuid.UUID{testFederationCommandID, testProviderID, testFederationBindingID}
	service.newID = func() (uuid.UUID, error) {
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}

	result, err := service.Create(context.Background(), testActor(), testTenantID, FederationCreateInput{
		Kind: FederationProviderOIDC, Key: "workforce_oidc", LoginKey: "workforce",
		DisplayName: "Workforce SSO", Description: "Primary tenant login",
		JITMode: JITModeDisabled, NoMatchPolicy: NoMatchPolicyDeny,
		OIDC: &FederationOIDCCreateConfiguration{
			Issuer: "https://id.example.com", ClientID: "periapsis-tenant",
			PostLogoutRedirectURI: "https://soc.example.com/signed-out",
			ExtraScopes:           []string{"profile", "offline_access", "email"}, AllowRefreshToken: true,
		},
		Reason: "approved change", IdempotencyKey: "federation-create-0001", Audit: testAudit(),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Provider.Enabled || result.Provider.Binding.Enabled || result.Provider.Configured ||
		result.Provider.ID != testProviderID || result.Provider.Binding.ID != testFederationBindingID ||
		result.Provider.OIDC == nil || result.Provider.OIDC.ClientSecretPresent {
		t.Fatalf("Create() result = %#v", result)
	}
	if got := result.Provider.OIDC.ExtraScopes; len(got) != 3 || got[0] != "email" ||
		got[1] != "offline_access" || got[2] != "profile" {
		t.Fatalf("canonical scopes = %#v", got)
	}
}

func TestFederationServiceRejectsTenantControlledOIDCPostLogoutRedirect(t *testing.T) {
	t.Parallel()

	for name, postLogoutRedirectURI := range map[string]string{
		"foreign origin": "https://attacker.example.test/signed-out",
		"foreign path":   "https://soc.example.com/logout/complete",
		"query":          "https://soc.example.com/signed-out?next=/admin",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repository := &federationAdministrationRepositoryStub{
				resolve: func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
					t.Fatal("deployment redirect mismatch reached authority resolution")
					return authorization.TenantAuthority{}, ErrUnavailable
				},
			}
			service := testFederationService(t, repository, repository)

			create := validFederationCreateInput()
			create.OIDC.PostLogoutRedirectURI = postLogoutRedirectURI
			if _, err := service.Create(context.Background(), testActor(), testTenantID, create); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Create() error = %v", err)
			}

			update := validFederationUpdateInput()
			update.OIDC.PostLogoutRedirectURI = postLogoutRedirectURI
			if _, err := service.Update(
				context.Background(), testActor(), testTenantID, testProviderID, update,
			); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Update() error = %v", err)
			}
		})
	}
}

func TestFederationServiceGetRejectsPersistedOIDCEndpointDrift(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*FederationOIDCConfiguration){
		"login redirect": func(configuration *FederationOIDCConfiguration) {
			configuration.RedirectURI = "https://soc.example.com/other-callback"
		},
		"post logout redirect": func(configuration *FederationOIDCConfiguration) {
			configuration.PostLogoutRedirectURI = "https://soc.example.com/logout/complete"
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repository := &federationAdministrationRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
			}
			repository.get = func(context.Context, FederationGetParams) (FederationProvider, error) {
				provider := federationOIDCTestProvider(
					testProviderID, testFederationBindingID, validFederationCreateInput(),
					"https://soc.example.com/api/v1/auth/federated/oidc/callback",
				)
				mutate(provider.OIDC)
				return provider, nil
			}
			service := testFederationService(t, repository, repository)

			if _, err := service.Get(
				context.Background(), testActor(), testTenantID, testProviderID,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Get() error = %v", err)
			}
		})
	}
}

func TestFederationServiceReadsEnabledProviderWhileTrustRefreshIsRequired(t *testing.T) {
	t.Parallel()

	provider := federationOIDCTestProvider(
		testProviderID,
		testFederationBindingID,
		validFederationCreateInput(),
		"https://soc.example.com/api/v1/auth/federated/oidc/callback",
	)
	provider.Enabled = true
	provider.Binding.Enabled = true
	provider.Configured = false
	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	repository.list = func(context.Context, FederationListParams) ([]FederationProviderSummary, error) {
		return []FederationProviderSummary{provider.FederationProviderSummary}, nil
	}
	repository.get = func(context.Context, FederationGetParams) (FederationProvider, error) {
		return provider, nil
	}
	service := testFederationService(t, repository, repository)

	page, err := service.List(
		context.Background(), testActor(), testTenantID, FederationListInput{},
	)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 1 || !page.Items[0].Enabled || page.Items[0].Configured {
		t.Fatalf("List() items = %#v", page.Items)
	}
	result, err := service.Get(
		context.Background(), testActor(), testTenantID, testProviderID,
	)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !result.Enabled || result.Configured {
		t.Fatalf("Get() result = %#v", result)
	}
}

func TestFederationServiceCreateIdempotencyBindsOnlySemanticPayload(t *testing.T) {
	t.Parallel()

	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	var firstRequestDigest, firstIdempotencyDigest [32]byte
	var stored FederationProvider
	calls := 0
	repository.create = func(_ context.Context, params FederationCreateParams) (FederationCreateResult, error) {
		calls++
		switch calls {
		case 1:
			firstRequestDigest, firstIdempotencyDigest = params.RequestDigest, params.IdempotencyKeyDigest
			stored = federationOIDCTestProvider(params.ProviderID, params.BindingID, params.Input, params.OIDCRedirectURI)
			return FederationCreateResult{Provider: stored}, nil
		case 2:
			if params.RequestDigest != firstRequestDigest || params.IdempotencyKeyDigest != firstIdempotencyDigest {
				t.Fatalf("retry digests changed: request=%x key=%x", params.RequestDigest, params.IdempotencyKeyDigest)
			}
			return FederationCreateResult{Provider: stored, Replayed: true}, nil
		case 3:
			if params.RequestDigest == firstRequestDigest {
				t.Fatal("semantic payload change did not change request digest")
			}
			return FederationCreateResult{}, ErrConflict
		default:
			t.Fatalf("unexpected create call %d", calls)
			return FederationCreateResult{}, ErrUnavailable
		}
	}

	service := testFederationService(t, repository, repository)
	service.newID = uuid.NewV7
	input := validFederationCreateInput()
	first, err := service.Create(context.Background(), testActor(), testTenantID, input)
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	retry := input
	retry.Audit.RequestID = uuid.Must(uuid.NewV7())
	retry.Audit.CorrelationID = uuid.Must(uuid.NewV7())
	retry.Audit.UserAgent = "identity-provider-retry"
	second, err := service.Create(context.Background(), testActor(), testTenantID, retry)
	if err != nil || !second.Replayed || second.Provider.ID != first.Provider.ID {
		t.Fatalf("retry Create() = %#v, %v", second, err)
	}
	different := retry
	different.Description = "semantically different provider"
	if _, err := service.Create(context.Background(), testActor(), testTenantID, different); !errors.Is(err, ErrConflict) {
		t.Fatalf("different Create() error = %v", err)
	}
}

func TestFederationServiceRejectsCreateRepositoryStateDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*FederationProvider)
	}{
		{name: "display name", mutate: func(provider *FederationProvider) { provider.DisplayName = "Different provider" }},
		{name: "login key", mutate: func(provider *FederationProvider) { provider.Binding.LoginKey = "different-login" }},
		{name: "OIDC issuer", mutate: func(provider *FederationProvider) { provider.OIDC.Issuer = "https://other.example.com" }},
		{name: "OIDC scopes", mutate: func(provider *FederationProvider) { provider.OIDC.ExtraScopes = []string{"profile"} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &federationAdministrationRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
			}
			repository.create = func(_ context.Context, params FederationCreateParams) (FederationCreateResult, error) {
				provider := federationOIDCTestProvider(params.ProviderID, params.BindingID, params.Input, params.OIDCRedirectURI)
				test.mutate(&provider)
				return FederationCreateResult{Provider: provider}, nil
			}
			service := testFederationService(t, repository, repository)
			ids := []uuid.UUID{testFederationCommandID, testProviderID, testFederationBindingID}
			service.newID = func() (uuid.UUID, error) {
				value := ids[0]
				ids = ids[1:]
				return value, nil
			}
			if _, err := service.Create(context.Background(), testActor(), testTenantID, validFederationCreateInput()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Create() error = %v", err)
			}
		})
	}
}

func TestFederationServiceRejectsUpdateRepositoryStateDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*FederationProvider)
	}{
		{name: "description", mutate: func(provider *FederationProvider) { provider.Description = "Different description" }},
		{name: "JIT mode", mutate: func(provider *FederationProvider) { provider.JITMode = JITModeDisabled }},
		{name: "client id", mutate: func(provider *FederationProvider) { provider.OIDC.ClientID = "wrong-client" }},
		{name: "redirect URI", mutate: func(provider *FederationProvider) { provider.OIDC.RedirectURI = "https://other.example.com/callback" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &federationAdministrationRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
			}
			input := validFederationUpdateInput()
			repository.update = func(_ context.Context, params FederationUpdateParams) (FederationProvider, error) {
				createInput := validFederationCreateInput()
				createInput.DisplayName = params.Input.DisplayName
				createInput.Description = params.Input.Description
				createInput.JITMode = params.Input.JITMode
				createInput.NoMatchPolicy = params.Input.NoMatchPolicy
				createInput.OIDC = params.Input.OIDC
				provider := federationOIDCTestProvider(params.ProviderID, testFederationBindingID, createInput, params.OIDCRedirectURI)
				provider.Version = params.ExpectedVersion + 1
				test.mutate(&provider)
				return provider, nil
			}
			service := testFederationService(t, repository, repository)
			if _, err := service.Update(context.Background(), testActor(), testTenantID, testProviderID, input); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Update() error = %v", err)
			}
		})
	}
}

func TestFederationServiceEncryptsOIDCSecretWithExactTenantBindingAADAndClearsCallerBuffer(t *testing.T) {
	t.Parallel()

	keyring := testIdentityKeyring(t)
	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	repository.prepareSecret = func(_ context.Context, params FederationPrepareOIDCSecretParams) (FederationSecretPreparation, error) {
		if params.ProviderID != testProviderID || params.ExpectedVersion != 4 {
			t.Fatalf("prepare params = %#v", params)
		}
		return FederationSecretPreparation{
			TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
			NextSecretRevision: 2,
		}, nil
	}
	repository.replaceSecret = func(_ context.Context, params FederationReplaceOIDCSecretParams) (FederationSecretMutationReceipt, error) {
		if params.ProviderID != testProviderID || params.BindingID != testFederationBindingID ||
			params.ExpectedVersion != 4 || params.ExpectedRevision != 2 || params.Secret.SecretID != testSecretID {
			t.Fatalf("replace params = %#v", params)
		}
		plaintext, decryptErr := keyring.DecryptOIDCClientSecret(identity.OIDCClientSecretContext{
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: identity.EntityID(testTenantID),
				ProviderID: identity.EntityID(testProviderID),
			},
			BindingID: identity.EntityID(testFederationBindingID), SecretID: identity.EntityID(testSecretID),
		}, params.Secret.Envelope)
		if decryptErr != nil || string(plaintext) != "rotated-secret" {
			clear(plaintext)
			t.Fatalf("decrypt = %q, %v", plaintext, decryptErr)
		}
		clear(plaintext)
		return FederationSecretMutationReceipt{
			ProviderID: testProviderID, ProviderVersion: 5, SecretRevision: 2,
		}, nil
	}
	service := testFederationServiceWithKeyring(t, repository, repository, keyring)
	service.newID = func() (uuid.UUID, error) { return testSecretID, nil }
	secret := []byte("rotated-secret")
	receipt, err := service.ReplaceOIDCClientSecret(
		context.Background(), testActor(), testTenantID, testProviderID,
		FederationReplaceOIDCSecretInput{
			Secret: secret, Reason: "credential rotation", ExpectedEntityTag: federationStringPointer(`"v4"`),
			Audit: testAudit(),
		},
	)
	if err != nil {
		t.Fatalf("ReplaceOIDCClientSecret() error = %v", err)
	}
	if receipt.ProviderVersion != 5 || receipt.SecretRevision != 2 {
		t.Fatalf("receipt = %#v", receipt)
	}
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("secret[%d] was not cleared", index)
		}
	}
}

func TestFederationServiceDeniesBeforeRepositoryAndFailsClosedWithoutAdapter(t *testing.T) {
	t.Parallel()

	authority := &federationAdministrationRepositoryStub{}
	authority.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	service := testFederationService(t, authority, nil)
	_, err := service.Create(context.Background(), testActor(), testTenantID, FederationCreateInput{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid input error = %v", err)
	}
	_, err = service.List(context.Background(), testActor(), testTenantID, FederationListInput{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil adapter error = %v", err)
	}
	authority.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		t.Fatal("authority repository called for a mismatched active tenant")
		return authorization.TenantAuthority{}, nil
	}
	_, err = service.List(
		context.Background(), testActor(), testFederationOtherTenantID, FederationListInput{},
	)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant error = %v", err)
	}

	denied := &federationAdministrationRepositoryStub{}
	denied.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	denied.create = func(context.Context, FederationCreateParams) (FederationCreateResult, error) {
		t.Fatal("protected writer called without manage permission")
		return FederationCreateResult{}, nil
	}
	service = testFederationService(t, denied, denied)
	_, err = service.Create(context.Background(), testActor(), testTenantID, validFederationCreateInput())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("permission error = %v", err)
	}
}

func TestFederationSAMLEntityIDMatchesTheRuntimeAndDatabaseByteBoundary(t *testing.T) {
	t.Parallel()

	entityID := func(size int) string {
		const prefix = "https://id.example.com/"
		return prefix + strings.Repeat("a", size-len(prefix))
	}
	configuration := func(size int) FederationSAMLCreateConfiguration {
		return FederationSAMLCreateConfiguration{
			ExpectedEntityID: entityID(size), RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
			SignaturePolicy: federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
			RequestedAuthnContexts: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
			SubjectSource:          federatedsaml.SubjectPersistentNameID, ClockSkew: 2 * time.Minute,
			MaximumAuthenticationAge: time.Hour,
		}
	}
	for _, size := range []int{2048, 2049} {
		t.Run(fmt.Sprintf("create_%d_bytes", size), func(t *testing.T) {
			input := validFederationCreateInput()
			saml := configuration(size)
			input.Kind, input.OIDC, input.SAML = FederationProviderSAML, nil, &saml
			_, err := normalizeFederationCreate(input)
			if (size == 2048) != (err == nil) {
				t.Fatalf("normalizeFederationCreate(%d bytes) error = %v", size, err)
			}
		})
		t.Run(fmt.Sprintf("update_%d_bytes", size), func(t *testing.T) {
			input := validFederationUpdateInput()
			saml := configuration(size)
			input.OIDC, input.SAML = nil, &saml
			_, _, err := normalizeFederationUpdate(testProviderID, input)
			if (size == 2048) != (err == nil) {
				t.Fatalf("normalizeFederationUpdate(%d bytes) error = %v", size, err)
			}
		})
	}
}

func TestFederationOIDCClientIDMatchesTheDatabaseUTF8ByteBoundary(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		clientID string
		wantErr  bool
	}{
		{name: "exact ASCII boundary", clientID: strings.Repeat("a", 512)},
		{name: "exact multibyte boundary", clientID: strings.Repeat("é", 256)},
		{name: "oversized ASCII", clientID: strings.Repeat("a", 513), wantErr: true},
		{name: "oversized multibyte", clientID: strings.Repeat("界", 171), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validFederationCreateInput()
			input.OIDC.ClientID = test.clientID
			_, err := normalizeFederationCreate(input)
			if test.wantErr != (err != nil) {
				t.Fatalf("normalizeFederationCreate(%d bytes) error = %v", len(test.clientID), err)
			}

			update := validFederationUpdateInput()
			update.OIDC.ClientID = test.clientID
			_, _, err = normalizeFederationUpdate(testProviderID, update)
			if test.wantErr != (err != nil) {
				t.Fatalf("normalizeFederationUpdate(%d bytes) error = %v", len(test.clientID), err)
			}
		})
	}
}

func TestFederationSAMLTextLimitsMatchRuntimeUTF8ByteBoundaries(t *testing.T) {
	t.Parallel()

	base := FederationSAMLCreateConfiguration{
		ExpectedEntityID:           "https://id.example.com/saml/metadata",
		RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
		RequestedAuthnContexts: []string{"urn:example:mfa"}, SubjectSource: federatedsaml.SubjectImmutableAttribute,
		ClockSkew: 2 * time.Minute, MaximumAuthenticationAge: time.Hour,
	}
	attributeFormat := "urn:example:" + strings.Repeat("f", 512-len("urn:example:"))
	base.SubjectAttributeNameFormat = &attributeFormat
	tests := []struct {
		name    string
		mutate  func(*FederationSAMLCreateConfiguration)
		wantErr bool
	}{
		{name: "attribute name at 512 bytes", mutate: func(value *FederationSAMLCreateConfiguration) {
			name := strings.Repeat("é", 256)
			value.SubjectAttributeName = &name
		}},
		{name: "attribute name above 512 bytes", wantErr: true, mutate: func(value *FederationSAMLCreateConfiguration) {
			name := strings.Repeat("é", 257)
			value.SubjectAttributeName = &name
		}},
		{name: "attribute format above 512 bytes", wantErr: true, mutate: func(value *FederationSAMLCreateConfiguration) {
			name := "uid"
			format := "urn:example:" + strings.Repeat("f", 513-len("urn:example:"))
			value.SubjectAttributeName, value.SubjectAttributeNameFormat = &name, &format
		}},
		{name: "authentication context at 2048 bytes", mutate: func(value *FederationSAMLCreateConfiguration) {
			name := "uid"
			value.SubjectAttributeName = &name
			value.RequestedAuthnContexts = []string{"urn:example:" + strings.Repeat("c", 2048-len("urn:example:"))}
		}},
		{name: "authentication context above 2048 bytes", wantErr: true, mutate: func(value *FederationSAMLCreateConfiguration) {
			name := "uid"
			value.SubjectAttributeName = &name
			value.RequestedAuthnContexts = []string{"urn:example:" + strings.Repeat("c", 2049-len("urn:example:"))}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.RequestedAuthnContexts = append([]string(nil), base.RequestedAuthnContexts...)
			test.mutate(&input)
			_, err := normalizeFederationSAML(input)
			if test.wantErr != (err != nil) {
				t.Fatalf("normalizeFederationSAML() error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}

func TestFederationMappingMutationRequiresGrantAndExactOperatorTeamAuthorityBeforeRepository(t *testing.T) {
	t.Parallel()

	operatorTeamID := uuid.MustParse("00000000-0000-7000-8000-00000000010d")
	assignmentEpochID := uuid.MustParse("00000000-0000-7000-8000-00000000010e")
	otherAssignmentEpochID := uuid.MustParse("00000000-0000-7000-8000-00000000010f")
	groupID := uuid.MustParse("00000000-0000-7000-8000-000000000110")
	roleID := uuid.MustParse("00000000-0000-7000-8000-000000000111")
	ruleID := uuid.MustParse("00000000-0000-7000-8000-000000000112")
	input := FederationReplaceMappingPolicyInput{
		Kind: FederationProviderOIDC,
		OIDCClaimRules: []FederationOIDCClaimRule{
			{Source: "id_token", Kind: "profile", ClaimName: "preferred_username", ProfileField: federationStringPointer("username"), Required: true},
			{Source: "id_token", Kind: "groups", ClaimName: "roles"},
			{Source: "id_token", Kind: "amr", ClaimName: "amr"},
		},
		Rules: []FederationMappingRule{{
			RuleID: ruleID, Priority: 10, MatcherKind: "group_equals", MatcherValue: "analyst",
			ReconciliationMode: "authoritative", TenantSecurityGroupID: groupID, RoleIDs: []uuid.UUID{roleID},
			OperatorTeamID: &operatorTeamID, OperatorTeamAssignmentEpochID: &assignmentEpochID, Enabled: true,
		}},
		Reason: "replace exact role mapping", ExpectedEntityTag: federationStringPointer(`"v4"`), Audit: testAudit(),
	}
	permission := func(value authorization.TenantPermission, scope authorization.Scope) authorization.ScopedPermission {
		return authorization.ScopedPermission{Permission: value, Scope: scope}
	}
	tests := []struct {
		name          string
		permissions   []authorization.ScopedPermission
		relationships []authorization.OperatorTeamRelationship
		wantAllowed   bool
	}{
		{
			name: "missing identity mapping manage",
			permissions: []authorization.ScopedPermission{
				permission(authorization.TenantPermissionRoleGrant, authorization.ScopeTenant),
				permission(authorization.TenantPermissionOperatorTeamRosterManage, authorization.ScopeOperatorTeam),
			},
			relationships: []authorization.OperatorTeamRelationship{{OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID}},
		},
		{
			name: "missing role grant",
			permissions: []authorization.ScopedPermission{
				permission(authorization.TenantPermissionIdentityMappingManage, authorization.ScopeTenant),
				permission(authorization.TenantPermissionOperatorTeamRosterManage, authorization.ScopeOperatorTeam),
			},
			relationships: []authorization.OperatorTeamRelationship{{OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID}},
		},
		{
			name: "missing roster permission",
			permissions: []authorization.ScopedPermission{
				permission(authorization.TenantPermissionIdentityMappingManage, authorization.ScopeTenant),
				permission(authorization.TenantPermissionRoleGrant, authorization.ScopeTenant),
			},
			relationships: []authorization.OperatorTeamRelationship{{OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID}},
		},
		{
			name: "wrong assignment epoch",
			permissions: []authorization.ScopedPermission{
				permission(authorization.TenantPermissionIdentityMappingManage, authorization.ScopeTenant),
				permission(authorization.TenantPermissionRoleGrant, authorization.ScopeTenant),
				permission(authorization.TenantPermissionOperatorTeamRosterManage, authorization.ScopeOperatorTeam),
			},
			relationships: []authorization.OperatorTeamRelationship{{OperatorTeamID: operatorTeamID, AssignmentEpochID: otherAssignmentEpochID}},
		},
		{
			name: "exact relationship",
			permissions: []authorization.ScopedPermission{
				permission(authorization.TenantPermissionIdentityMappingManage, authorization.ScopeTenant),
				permission(authorization.TenantPermissionRoleGrant, authorization.ScopeTenant),
				permission(authorization.TenantPermissionOperatorTeamRosterManage, authorization.ScopeOperatorTeam),
			},
			relationships: []authorization.OperatorTeamRelationship{{OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID}},
			wantAllowed:   true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			repository := &federationAdministrationRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				authority := testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead)
				authority.Permissions = append([]authorization.ScopedPermission(nil), test.permissions...)
				authority.OperatorTeamRelationships = append([]authorization.OperatorTeamRelationship(nil), test.relationships...)
				return authority, nil
			}
			repository.replaceMapping = func(context.Context, FederationReplaceMappingPolicyParams) (FederationPolicyMutationReceipt, error) {
				calls++
				return FederationPolicyMutationReceipt{ProviderID: testProviderID, ProviderVersion: 5, MappingRevision: 2}, nil
			}
			service := testFederationService(t, repository, repository)
			_, err := service.ReplaceMappingPolicy(context.Background(), testActor(), testTenantID, testProviderID, input)
			if test.wantAllowed {
				if err != nil || calls != 1 {
					t.Fatalf("ReplaceMappingPolicy() error = %v, repository calls = %d", err, calls)
				}
				return
			}
			if !errors.Is(err, ErrForbidden) || calls != 0 {
				t.Fatalf("ReplaceMappingPolicy() error = %v, repository calls = %d", err, calls)
			}
		})
	}
}

func TestNormalizeFederationMappingPolicyIsConcurrentAndDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	roleA := uuid.MustParse("00000000-0000-7000-8000-000000000121")
	roleB := uuid.MustParse("00000000-0000-7000-8000-000000000120")
	operatorTeamID := uuid.MustParse("00000000-0000-7000-8000-000000000122")
	assignmentEpochID := uuid.MustParse("00000000-0000-7000-8000-000000000123")
	groupID := uuid.MustParse("00000000-0000-7000-8000-000000000124")
	ruleID := uuid.MustParse("00000000-0000-7000-8000-000000000125")
	profileField := " username "
	expectedEntityTag := `"v4"`
	input := FederationReplaceMappingPolicyInput{
		Kind: FederationProviderOIDC,
		OIDCClaimRules: []FederationOIDCClaimRule{
			{Source: " id_token ", Kind: " profile ", ClaimName: " preferred_username ", ProfileField: &profileField, Required: true},
			{Source: " id_token ", Kind: " groups ", ClaimName: " roles "},
			{Source: " id_token ", Kind: " amr ", ClaimName: " amr "},
		},
		Rules: []FederationMappingRule{{
			RuleID: ruleID, Priority: 10, MatcherKind: " group_equals ", MatcherValue: " analyst ",
			ReconciliationMode: " authoritative ", TenantSecurityGroupID: groupID,
			RoleIDs: []uuid.UUID{roleA, roleB}, OperatorTeamID: &operatorTeamID,
			OperatorTeamAssignmentEpochID: &assignmentEpochID, Enabled: true,
		}},
		Reason: " concurrent normalization ", ExpectedEntityTag: &expectedEntityTag, Audit: testAudit(),
	}

	const workers = 32
	start := make(chan struct{})
	results := make(chan error, workers)
	for range workers {
		go func() {
			<-start
			normalized, version, err := normalizeFederationMappingPolicy(testProviderID, input)
			if err != nil {
				results <- err
				return
			}
			if version != 4 || normalized.Reason != "concurrent normalization" ||
				normalized.OIDCClaimRules[0].Source != "id_token" ||
				normalized.OIDCClaimRules[0].ProfileField == nil ||
				*normalized.OIDCClaimRules[0].ProfileField != "username" ||
				normalized.Rules[0].MatcherKind != "group_equals" ||
				normalized.Rules[0].MatcherValue != "analyst" ||
				normalized.Rules[0].ReconciliationMode != "authoritative" ||
				len(normalized.Rules[0].RoleIDs) != 2 || normalized.Rules[0].RoleIDs[0] != roleB ||
				normalized.Rules[0].RoleIDs[1] != roleA {
				results <- fmt.Errorf("unexpected normalized mapping input: %#v", normalized)
				return
			}
			if normalized.OIDCClaimRules[0].ProfileField == input.OIDCClaimRules[0].ProfileField ||
				normalized.Rules[0].OperatorTeamID == input.Rules[0].OperatorTeamID ||
				normalized.Rules[0].OperatorTeamAssignmentEpochID == input.Rules[0].OperatorTeamAssignmentEpochID ||
				normalized.ExpectedEntityTag == input.ExpectedEntityTag {
				results <- errors.New("normalized mapping input retained caller-owned pointers")
				return
			}
			results <- nil
		}()
	}
	close(start)
	for range workers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	if input.Reason != " concurrent normalization " || input.OIDCClaimRules[0].Source != " id_token " ||
		input.OIDCClaimRules[0].ProfileField != &profileField || *input.OIDCClaimRules[0].ProfileField != " username " ||
		input.Rules[0].MatcherKind != " group_equals " || input.Rules[0].MatcherValue != " analyst " ||
		input.Rules[0].ReconciliationMode != " authoritative " ||
		len(input.Rules[0].RoleIDs) != 2 || input.Rules[0].RoleIDs[0] != roleA || input.Rules[0].RoleIDs[1] != roleB ||
		input.ExpectedEntityTag != &expectedEntityTag {
		t.Fatalf("caller input was mutated: %#v", input)
	}
}

func TestFederationPolicyReadbackRejectsMalformedProviderBeforeAuthority(t *testing.T) {
	t.Parallel()

	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		t.Fatal("authority repository called for malformed provider identifier")
		return authorization.TenantAuthority{}, nil
	}
	service := testFederationService(t, repository, repository)
	if _, err := service.GetMappingPolicy(context.Background(), testActor(), testTenantID, uuid.New()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("GetMappingPolicy() error = %v", err)
	}
	if _, err := service.GetAssurancePolicy(context.Background(), testActor(), testTenantID, uuid.New()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("GetAssurancePolicy() error = %v", err)
	}
}

func TestFederationPolicyReadbackRejectsCrossTenantProjection(t *testing.T) {
	t.Parallel()

	repository := &federationAdministrationRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		authority := testIdentityProviderAuthority(authorization.TenantPermissionIdentityMappingRead)
		authority.Permissions = append(authority.Permissions, authorization.ScopedPermission{
			Permission: authorization.TenantPermissionIdentityPolicyRead,
			Scope:      authorization.ScopeTenant,
		})
		return authority, nil
	}
	repository.getMapping = func(context.Context, FederationGetParams) (FederationMappingPolicy, error) {
		return FederationMappingPolicy{
			TenantID: testFederationOtherTenantID, ProviderID: testProviderID,
			Kind: FederationProviderOIDC, ProviderVersion: 4, MappingRevision: 1,
		}, nil
	}
	repository.getAssurance = func(context.Context, FederationGetParams) (FederationAssurancePolicy, error) {
		return FederationAssurancePolicy{
			TenantID: testFederationOtherTenantID, ProviderID: testProviderID,
			Kind: FederationProviderOIDC, ProviderVersion: 4, AssurancePolicyRevision: 1,
		}, nil
	}
	service := testFederationService(t, repository, repository)
	if _, err := service.GetMappingPolicy(context.Background(), testActor(), testTenantID, testProviderID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetMappingPolicy() error = %v", err)
	}
	if _, err := service.GetAssurancePolicy(context.Background(), testActor(), testTenantID, testProviderID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetAssurancePolicy() error = %v", err)
	}
}

func TestFederationServiceClearOIDCSecretDistinguishesMalformedStateFromAbsentSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		preparation FederationSecretPreparation
		want        error
	}{
		{
			name: "malformed repository projection",
			preparation: FederationSecretPreparation{
				TenantID: uuid.Nil, ProviderID: testProviderID, BindingID: testFederationBindingID,
				CurrentSecretID: &testSecretID, NextSecretRevision: 3,
			},
			want: ErrUnavailable,
		},
		{
			name: "no installed secret",
			preparation: FederationSecretPreparation{
				TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
				NextSecretRevision: 2,
			},
			want: ErrConflict,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &federationAdministrationRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
			}
			repository.prepareSecret = func(context.Context, FederationPrepareOIDCSecretParams) (FederationSecretPreparation, error) {
				return test.preparation, nil
			}
			repository.clearSecret = func(context.Context, FederationClearOIDCSecretParams) (FederationSecretMutationReceipt, error) {
				t.Fatal("clear writer called for rejected preparation")
				return FederationSecretMutationReceipt{}, nil
			}
			service := testFederationService(t, repository, repository)

			_, err := service.ClearOIDCClientSecret(
				context.Background(), testActor(), testTenantID, testProviderID,
				FederationClearOIDCSecretInput{
					Reason: "retire old secret", ExpectedEntityTag: federationStringPointer(`"v4"`), Audit: testAudit(),
				},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ClearOIDCClientSecret() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestFederationProviderProjectionAcceptsTrustRefreshStateAndRejectsImpossibleArchiveTime(t *testing.T) {
	t.Parallel()

	provider := federationOIDCTestProvider(
		testProviderID,
		testFederationBindingID,
		validFederationCreateInput(),
		"https://soc.example.com/api/v1/auth/federated/oidc/callback",
	)
	provider.Configured = true
	provider.Enabled = true
	provider.Binding.Enabled = true
	if !validFederationProvider(provider, testTenantID) {
		t.Fatal("ready enabled provider was rejected")
	}

	provider.Configured = false
	if !validFederationProvider(provider, testTenantID) {
		t.Fatal("enabled provider awaiting trust refresh was rejected")
	}

	provider.Enabled = false
	provider.Binding.Enabled = false
	archivedAt := provider.UpdatedAt.Add(time.Second)
	provider.ArchivedAt = &archivedAt
	if validFederationProvider(provider, testTenantID) {
		t.Fatal("archive timestamp after the resource update was accepted")
	}
}

type federationAdministrationRepositoryStub struct {
	resolve          func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
	list             func(context.Context, FederationListParams) ([]FederationProviderSummary, error)
	get              func(context.Context, FederationGetParams) (FederationProvider, error)
	create           func(context.Context, FederationCreateParams) (FederationCreateResult, error)
	update           func(context.Context, FederationUpdateParams) (FederationProvider, error)
	archive          func(context.Context, FederationArchiveParams) (int64, error)
	prepareSecret    func(context.Context, FederationPrepareOIDCSecretParams) (FederationSecretPreparation, error)
	replaceSecret    func(context.Context, FederationReplaceOIDCSecretParams) (FederationSecretMutationReceipt, error)
	clearSecret      func(context.Context, FederationClearOIDCSecretParams) (FederationSecretMutationReceipt, error)
	getMapping       func(context.Context, FederationGetParams) (FederationMappingPolicy, error)
	replaceMapping   func(context.Context, FederationReplaceMappingPolicyParams) (FederationPolicyMutationReceipt, error)
	getAssurance     func(context.Context, FederationGetParams) (FederationAssurancePolicy, error)
	replaceAssurance func(context.Context, FederationReplaceAssurancePolicyParams) (FederationPolicyMutationReceipt, error)
	prepareTrust     func(context.Context, FederationPrepareOIDCTrustParams) (FederationOIDCTrustPreparation, error)
	commitTrust      func(context.Context, FederationCommitOIDCTrustParams) (FederationOIDCTrustDocumentsReceipt, error)
}

func (stub *federationAdministrationRepositoryStub) ResolveHumanAuthority(ctx context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	return stub.resolve(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ListFederatedProviders(ctx context.Context, params FederationListParams) ([]FederationProviderSummary, error) {
	return stub.list(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) GetFederatedProvider(ctx context.Context, params FederationGetParams) (FederationProvider, error) {
	return stub.get(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) CreateFederatedProvider(ctx context.Context, params FederationCreateParams) (FederationCreateResult, error) {
	return stub.create(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) UpdateFederatedProvider(ctx context.Context, params FederationUpdateParams) (FederationProvider, error) {
	return stub.update(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ArchiveFederatedProvider(ctx context.Context, params FederationArchiveParams) (int64, error) {
	return stub.archive(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) PrepareOIDCClientSecretReplacement(ctx context.Context, params FederationPrepareOIDCSecretParams) (FederationSecretPreparation, error) {
	return stub.prepareSecret(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ReplaceOIDCClientSecret(ctx context.Context, params FederationReplaceOIDCSecretParams) (FederationSecretMutationReceipt, error) {
	return stub.replaceSecret(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ClearOIDCClientSecret(ctx context.Context, params FederationClearOIDCSecretParams) (FederationSecretMutationReceipt, error) {
	return stub.clearSecret(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) GetFederatedMappingPolicy(ctx context.Context, params FederationGetParams) (FederationMappingPolicy, error) {
	return stub.getMapping(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ReplaceFederatedMappingPolicy(ctx context.Context, params FederationReplaceMappingPolicyParams) (FederationPolicyMutationReceipt, error) {
	return stub.replaceMapping(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) GetFederatedAssurancePolicy(ctx context.Context, params FederationGetParams) (FederationAssurancePolicy, error) {
	return stub.getAssurance(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) ReplaceFederatedAssurancePolicy(ctx context.Context, params FederationReplaceAssurancePolicyParams) (FederationPolicyMutationReceipt, error) {
	return stub.replaceAssurance(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) PrepareOIDCTrustDocuments(ctx context.Context, params FederationPrepareOIDCTrustParams) (FederationOIDCTrustPreparation, error) {
	return stub.prepareTrust(ctx, params)
}

func (stub *federationAdministrationRepositoryStub) CommitOIDCTrustDocuments(ctx context.Context, params FederationCommitOIDCTrustParams) (FederationOIDCTrustDocumentsReceipt, error) {
	return stub.commitTrust(ctx, params)
}

func testFederationService(
	t *testing.T,
	authority FederationAuthorityRepository,
	repository FederationAdministrationRepository,
) *FederationService {
	t.Helper()
	return testFederationServiceWithKeyring(t, authority, repository, testIdentityKeyring(t))
}

func testFederationServiceWithKeyring(
	t *testing.T,
	authority FederationAuthorityRepository,
	repository FederationAdministrationRepository,
	keyring identity.Keyring,
) *FederationService {
	t.Helper()
	service, err := NewFederationService(authority, repository, keyring, "https://soc.example.com")
	if err != nil {
		t.Fatalf("NewFederationService() error = %v", err)
	}
	service.now = func() time.Time { return testNow }
	return service
}

func validFederationCreateInput() FederationCreateInput {
	return FederationCreateInput{
		Kind: FederationProviderOIDC, Key: "workforce_oidc", LoginKey: "workforce",
		DisplayName: "Workforce SSO", Description: "Primary tenant login",
		JITMode: JITModeDisabled, NoMatchPolicy: NoMatchPolicyDeny,
		OIDC: &FederationOIDCCreateConfiguration{
			Issuer: "https://id.example.com", ClientID: "periapsis-tenant",
			PostLogoutRedirectURI: "https://soc.example.com/signed-out", ExtraScopes: []string{"email"},
		},
		Reason: "approved change", IdempotencyKey: "federation-create-0001", Audit: testAudit(),
	}
}

func validFederationUpdateInput() FederationUpdateInput {
	return FederationUpdateInput{
		DisplayName: "Updated Workforce SSO", Description: "Updated primary tenant login",
		JITMode: JITModeCreate, NoMatchPolicy: NoMatchPolicyProviderAccessOnly,
		OIDC: &FederationOIDCCreateConfiguration{
			Issuer: "https://id.example.com", ClientID: "updated-periapsis-tenant",
			PostLogoutRedirectURI: "https://soc.example.com/signed-out", ExtraScopes: []string{"email", "offline_access", "profile"},
			AllowRefreshToken: true, UseUserInfo: true,
		},
		Reason: "approved provider update", ExpectedEntityTag: federationStringPointer(`"v4"`), Audit: testAudit(),
	}
}

func federationOIDCTestProvider(
	providerID, bindingID uuid.UUID,
	input FederationCreateInput,
	redirectURI string,
) FederationProvider {
	return FederationProvider{
		FederationProviderSummary: FederationProviderSummary{
			ID: providerID, TenantID: testTenantID, Key: input.Key, DisplayName: input.DisplayName,
			Description: input.Description, Kind: FederationProviderOIDC, Configured: false,
			Binding: FederationBinding{ID: bindingID, LoginKey: input.LoginKey, Version: 1, UpdatedAt: testNow},
			Version: 1, CreatedAt: testNow, UpdatedAt: testNow,
		},
		ConfigurationRevision: 1, SecurityRevision: 1, PlanRevision: 1, AssurancePolicyRevision: 1,
		JITMode: input.JITMode, NoMatchPolicy: input.NoMatchPolicy,
		OIDC: &FederationOIDCConfiguration{
			Issuer: input.OIDC.Issuer, ClientID: input.OIDC.ClientID, RedirectURI: redirectURI,
			PostLogoutRedirectURI: input.OIDC.PostLogoutRedirectURI,
			ExtraScopes:           append([]string(nil), input.OIDC.ExtraScopes...), AllowRefreshToken: input.OIDC.AllowRefreshToken,
			UseUserInfo: input.OIDC.UseUserInfo, ClientSecretRevision: 1, DiscoveryRevision: 1, JWKSRevision: 1,
		},
	}
}

func federationStringPointer(value string) *string { return &value }
