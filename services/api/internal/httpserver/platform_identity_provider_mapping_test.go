package httpserver

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

func TestPlatformSAMLProviderMappingPreservesAuthoritativeLifecycleState(t *testing.T) {
	base := platformSAMLProviderMappingFixture(t)
	for _, test := range []struct {
		name     string
		mutate   func(*platformidentityprovider.Provider)
		enabled  bool
		direct   bool
		ready    bool
		activate bool
	}{
		{
			name: "tenant ready", activate: true,
			mutate: func(provider *platformidentityprovider.Provider) {
				provider.ActivationAvailable = true
			},
		},
		{
			name: "direct ready", enabled: true, ready: true,
			mutate: func(provider *platformidentityprovider.Provider) {
				provider.Enabled = true
				provider.PlatformLoginActivationAvailable = true
				provider.AccountMode = platformidentityprovider.AccountModeExistingIdentity
			},
		},
		{
			name: "direct active", enabled: true, direct: true,
			mutate: func(provider *platformidentityprovider.Provider) {
				provider.Enabled = true
				provider.PlatformLoginEnabled = true
				provider.AccountMode = platformidentityprovider.AccountModeCreate
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := base
			test.mutate(&provider)

			summary, err := mapPlatformAuthProviderSummary(provider.ProviderSummary)
			if err != nil || summary.Kind != "saml" || summary.Enabled != test.enabled ||
				summary.PlatformLoginEnabled != test.direct ||
				summary.PlatformLoginActivationAvailable != test.ready ||
				summary.ActivationAvailable != test.activate || !summary.SecretPresent {
				t.Fatalf("summary = %#v, %v", summary, err)
			}
			union, err := mapPlatformAuthProvider(provider)
			if err != nil {
				t.Fatalf("detail mapping: %v", err)
			}
			detail, err := union.AsPlatformSAMLAuthProvider()
			if err != nil || detail.Enabled != test.enabled ||
				detail.PlatformLoginEnabled != test.direct ||
				detail.PlatformLoginActivationAvailable != test.ready ||
				detail.ActivationAvailable != test.activate || !detail.SecretPresent {
				t.Fatalf("detail = %#v, %v", detail, err)
			}
		})
	}
}

func TestPlatformSAMLProviderSummaryMappingRejectsImpossibleLifecycleState(t *testing.T) {
	base := platformSAMLProviderMappingFixture(t).ProviderSummary
	for _, mutate := range []func(*platformidentityprovider.ProviderSummary){
		func(provider *platformidentityprovider.ProviderSummary) {
			provider.PlatformLoginEnabled = true
		},
		func(provider *platformidentityprovider.ProviderSummary) {
			provider.Enabled = true
			provider.ActivationAvailable = true
		},
		func(provider *platformidentityprovider.ProviderSummary) {
			provider.Enabled = true
			provider.SecretPresent = false
			provider.PlatformLoginActivationAvailable = true
		},
	} {
		provider := base
		mutate(&provider)
		if _, err := mapPlatformAuthProviderSummary(provider); err == nil {
			t.Fatalf("impossible SAML lifecycle was mapped: %#v", provider)
		}
	}
}

func TestPlatformSAMLProviderDetailMappingRejectsPoisonedKeyProjection(t *testing.T) {
	for name, mutate := range map[string]func(*platformidentityprovider.Provider){
		"summary and configuration disagree": func(provider *platformidentityprovider.Provider) {
			provider.SecretPresent = false
		},
		"present key has pre-rotation revision": func(provider *platformidentityprovider.Provider) {
			provider.SAML.SPKeyRevision = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := platformSAMLProviderMappingFixture(t)
			mutate(&provider)
			if _, err := mapPlatformAuthProvider(provider); err == nil {
				t.Fatalf("poisoned SAML key projection was mapped: %#v", provider)
			}
		})
	}
}

func platformSAMLProviderMappingFixture(t testing.TB) platformidentityprovider.Provider {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	return platformidentityprovider.Provider{
		ProviderSummary: platformidentityprovider.ProviderSummary{
			ID: uuid.Must(uuid.NewV7()), Key: "workforce_saml", DisplayName: "Workforce SAML",
			Description: "Corporate workforce SAML", Kind: platformidentityprovider.ProviderKindSAML,
			Configured: true, SecretPresent: true, Version: 7, CreatedAt: now, UpdatedAt: now,
		},
		ConfigurationRevision: 2, SecurityRevision: 2, PlanRevision: 2, AssurancePolicyRevision: 2,
		AccountMode: platformidentityprovider.AccountModeDisabled,
		SAML: &platformidentityprovider.SAMLConfiguration{
			ExpectedEntityID: "https://idp.example.test/entity",
			SPEntityID:       "https://app.example.test/api/v1/auth/platform/saml/workforce_saml/metadata",
			ACSURL:           "https://app.example.test/api/v1/auth/platform/saml/acs",
			SPKeyRevision:    2, SPKeyPresent: true, MetadataRevision: 2,
			RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
			SignaturePolicy:            federatedsaml.SignedBoth,
			EncryptionPolicy:           federatedsaml.EncryptionDisabled,
			RequestedAuthnContexts: []string{
				"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
			SubjectSource: federatedsaml.SubjectPersistentNameID,
			ClockSkew:     2 * time.Minute, MaximumAuthenticationAge: 8 * time.Hour,
		},
	}
}
