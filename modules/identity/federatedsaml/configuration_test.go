package federatedsaml

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestNewAndConfigurationValidationAreFailClosed(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(empty) error = %v", err)
	}
	fixture := newTestFixture(t)
	baseSignerCalls := len(fixture.signer.requests)
	tests := map[string]func(*Configuration){
		"tenant missing tenant ID":   func(configuration *Configuration) { configuration.Provider.TenantID = identity.EntityID{} },
		"platform carries tenant ID": func(configuration *Configuration) { configuration.Provider.Scope = identity.PlatformProviderScope },
		"zero binding":               func(configuration *Configuration) { configuration.BindingID = identity.EntityID{} },
		"wrong ACS path":             func(configuration *Configuration) { configuration.ACSURL = "https://sp.example.test/callback" },
		"duplicate context": func(configuration *Configuration) {
			configuration.RequestedAuthnContexts = append(configuration.RequestedAuthnContexts, configuration.RequestedAuthnContexts[0])
		},
		"unrequested trust context": func(configuration *Configuration) { configuration.TrustRules[0].ClassRef = "urn:test:other" },
		"trust rule cannot restate primary assurance": func(configuration *Configuration) {
			configuration.TrustRules[0].Level = identity.AssurancePrimary
		},
		"duplicate scalar mapping": func(configuration *Configuration) {
			configuration.Mapping.Scalars = append(configuration.Mapping.Scalars, configuration.Mapping.Scalars[0])
		},
		"ambiguous scalar name across formats": func(configuration *Configuration) {
			copyValue := configuration.Mapping.Scalars[0]
			copyValue.NameFormat = "urn:test:other-format"
			configuration.Mapping.Scalars = append(configuration.Mapping.Scalars, copyValue)
		},
		"unsorted decryption keys": func(configuration *Configuration) {
			configuration.EncryptionPolicy = EncryptionRequired
			configuration.DecryptionKeyVersions = []uint32{2, 1}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			configuration := fixture.config
			configuration.RequestedAuthnContexts = append([]string(nil), fixture.config.RequestedAuthnContexts...)
			configuration.TrustRules = append([]AuthnContextTrustRule(nil), fixture.config.TrustRules...)
			configuration.Mapping.Scalars = append([]ScalarAttributeRule(nil), fixture.config.Mapping.Scalars...)
			mutate(&configuration)
			if _, err := fixture.kernel.StartAuthentication(context.Background(), StartRequest{Begin: testAuthenticationBegin(2), Configuration: configuration, ReturnPath: "/safe"}); !errors.Is(err, ErrAuthenticationStart) {
				t.Fatalf("StartAuthentication() error = %v", err)
			}
		})
	}
	if len(fixture.signer.requests) != baseSignerCalls {
		t.Fatalf("invalid configuration reached signer: before=%d after=%d", baseSignerCalls, len(fixture.signer.requests))
	}
}

func TestConfigurationNormalizationSortsAuthnContextsDeterministically(t *testing.T) {
	fixture := newTestFixture(t)
	configuration := fixture.config
	configuration.RequestedAuthnContexts = []string{"urn:test:z", "urn:test:a"}
	configuration.TrustRules = []AuthnContextTrustRule{
		{ClassRef: "urn:test:z", Level: identity.AssuranceMFA, Revision: 2, MaxAge: time.Hour},
		{ClassRef: "urn:test:a", Level: identity.AssurancePhishingResistant, Revision: 1, MaxAge: time.Hour},
	}
	reversed := configuration
	reversed.RequestedAuthnContexts = slices.Clone(configuration.RequestedAuthnContexts)
	slices.Reverse(reversed.RequestedAuthnContexts)
	normalized, digest, err := normalizeConfiguration(configuration, fixtureTime, DefaultLimits())
	other, otherDigest, otherErr := normalizeConfiguration(reversed, fixtureTime, DefaultLimits())
	if err != nil || otherErr != nil || digest != otherDigest ||
		!slices.Equal(normalized.RequestedAuthnContexts, []string{"urn:test:a", "urn:test:z"}) ||
		!slices.Equal(normalized.RequestedAuthnContexts, other.RequestedAuthnContexts) {
		t.Fatalf("normalized=%v other=%v err=%v/%v digest_equal=%t", normalized.RequestedAuthnContexts, other.RequestedAuthnContexts, err, otherErr, digest == otherDigest)
	}
}
