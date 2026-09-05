package federatedsaml

import (
	"errors"
	"testing"
	"time"
)

func TestValidatePinnedConfigurationRejectsAnySnapshotDrift(t *testing.T) {
	fixture := newTestFixture(t)
	pins := fixture.repo.current().Pins
	if err := ValidatePinnedConfiguration(fixture.config, pins, fixtureTime); err != nil {
		t.Fatalf("ValidatePinnedConfiguration() error=%v", err)
	}
	for name, mutate := range map[string]func(*Configuration){
		"binding revision": func(value *Configuration) { value.BindingRevision++ },
		"mapping rule":     func(value *Configuration) { value.Mapping.Scalars[0].Required = !value.Mapping.Scalars[0].Required },
		"trust rule":       func(value *Configuration) { value.TrustRules[0].MaxAge += time.Minute },
		"sp entity":        func(value *Configuration) { value.SPEntityID = "https://other.example.test/saml" },
	} {
		t.Run(name, func(t *testing.T) {
			configuration := fixture.config
			configuration.Mapping.Scalars = append([]ScalarAttributeRule(nil), fixture.config.Mapping.Scalars...)
			configuration.TrustRules = append([]AuthnContextTrustRule(nil), fixture.config.TrustRules...)
			mutate(&configuration)
			if err := ValidatePinnedConfiguration(configuration, pins, fixtureTime); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("ValidatePinnedConfiguration() error=%v", err)
			}
		})
	}
}
