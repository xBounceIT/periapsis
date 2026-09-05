package federatedoidc

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectPlatformCeremonyPinsAndProtectsOnlyDirectAuthority(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		makeDirectPlatformConfiguration(configuration)
	})
	_, bundle := exchangedBundle(t, fixture)
	defer bundle.Destroy()

	fixture.repository.mu.Lock()
	if len(fixture.repository.created) != 1 {
		fixture.repository.mu.Unlock()
		t.Fatalf("created transactions = %d", len(fixture.repository.created))
	}
	pins := fixture.repository.created[0].Current.Pins
	fixture.repository.mu.Unlock()
	if pins.Authority != DirectPlatformCeremonyAuthority ||
		pins.Provider.Scope != identity.PlatformProviderScope ||
		pins.Provider.TenantID != (identity.EntityID{}) || pins.BindingID != (identity.EntityID{}) ||
		pins.Admission != (identity.TenantAdmissionContext{}) || pins.BindingRevision != 0 ||
		pins.MappingRevision != 0 || pins.AuthorizationRevision != 0 ||
		pins.PlatformLoginRevision != 19 {
		t.Fatalf("direct pins retained tenant authority: %s", pins)
	}
	if _, valid := pins.TenantAdmission(); valid {
		t.Fatal("direct pins exposed tenant admission")
	}
	if revision, valid := pins.DirectPlatformLogin(); !valid || revision != 19 {
		t.Fatalf("DirectPlatformLogin() = %d, %t", revision, valid)
	}

	fixture.protector.mu.Lock()
	contexts := append([]TransactionProtectionContext(nil), fixture.protector.contexts...)
	fixture.protector.mu.Unlock()
	if len(contexts) != 2 || contexts[0] != contexts[1] {
		t.Fatalf("PKCE contexts = %v", contexts)
	}
	if _, valid := contexts[0].TenantAdmission(); valid {
		t.Fatal("direct PKCE context exposed tenant admission")
	}
	if revision, valid := contexts[0].DirectPlatformLogin(); !valid || revision != 19 {
		t.Fatalf("PKCE DirectPlatformLogin() = %d, %t", revision, valid)
	}
}

func TestDirectPlatformCeremonyRejectsTenantAuthorityAndRevisionSmuggling(t *testing.T) {
	tests := map[string]func(*AuthorizationConfiguration){
		"tenant provider": func(value *AuthorizationConfiguration) {
			value.Provider.Scope = identity.TenantProviderScope
			value.Provider.TenantID = authorityEntityID(20)
		},
		"fake provider tenant": func(value *AuthorizationConfiguration) {
			value.Provider.TenantID = authorityEntityID(21)
		},
		"binding ID": func(value *AuthorizationConfiguration) {
			value.BindingID = authorityEntityID(22)
		},
		"admission tenant only": func(value *AuthorizationConfiguration) {
			value.Admission.TenantID = authorityEntityID(23)
		},
		"admission binding only": func(value *AuthorizationConfiguration) {
			value.Admission.BindingID = authorityEntityID(24)
		},
		"complete tenant admission": func(value *AuthorizationConfiguration) {
			value.Admission = identity.TenantAdmissionContext{
				TenantID: authorityEntityID(25), BindingID: authorityEntityID(26),
			}
		},
		"binding revision": func(value *AuthorizationConfiguration) { value.BindingRevision = 1 },
		"mapping revision": func(value *AuthorizationConfiguration) { value.MappingRevision = 1 },
		"authorization revision": func(value *AuthorizationConfiguration) {
			value.AuthorizationRevision = 1
		},
		"zero platform login revision": func(value *AuthorizationConfiguration) {
			value.PlatformLoginRevision = 0
		},
		"platform login revision overflow": func(value *AuthorizationConfiguration) {
			value.PlatformLoginRevision = maximumPersistentRevision + 1
		},
		"unknown authority": func(value *AuthorizationConfiguration) { value.Authority = CeremonyAuthority(2) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
				makeDirectPlatformConfiguration(configuration)
				mutate(configuration)
			})
			if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			}); !errors.Is(err, ErrAuthorizationRejected) {
				t.Fatalf("StartAuthorization() error = %v", err)
			}
			if len(fixture.repository.created) != 0 || fixture.protector.sealCount != 0 {
				t.Fatalf("invalid direct authority reached persistence/crypto: creates=%d seals=%d",
					len(fixture.repository.created), fixture.protector.sealCount)
			}
		})
	}
}

func TestDirectPlatformCeremonyAcceptsPlatformLoginRevisionBounds(t *testing.T) {
	for name, revision := range map[string]uint64{
		"minimum": 1,
		"maximum": maximumPersistentRevision,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
				makeDirectPlatformConfiguration(configuration)
				configuration.PlatformLoginRevision = revision
			})
			if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			}); err != nil {
				t.Fatalf("StartAuthorization() error = %v", err)
			}
			if len(fixture.repository.created) != 1 ||
				fixture.repository.created[0].Current.Pins.PlatformLoginRevision != revision {
				t.Fatalf("persisted revision = %d", fixture.repository.created[0].Current.Pins.PlatformLoginRevision)
			}
		})
	}
}

func TestDirectPlatformCallbackRejectsRevisionAndAuthorityFamilySubstitution(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizationConfiguration){
		"platform login revision": func(value *AuthorizationConfiguration) {
			value.PlatformLoginRevision++
		},
		"tenant platform authority": func(value *AuthorizationConfiguration) {
			value.Authority = TenantCeremonyAuthority
			value.Admission = identity.TenantAdmissionContext{
				TenantID: authorityEntityID(30), BindingID: authorityEntityID(31),
			}
			value.BindingRevision = 12
			value.MappingRevision = 15
			value.AuthorizationRevision = 16
			value.PlatformLoginRevision = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
				makeDirectPlatformConfiguration(configuration)
			})
			start, callback := startResolvedCallback(t, fixture)
			substituted := fixture.configuration
			mutate(&substituted)
			_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
				RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
				return substituted, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) {
				t.Fatalf("ClaimCallbackResolved() error = %v", err)
			}
		})
	}
}

func TestTenantCeremonyRejectsDirectPlatformRevision(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.PlatformLoginRevision = 1
	})
	if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthorizationRejected) {
		t.Fatalf("StartAuthorization() error = %v", err)
	}
	if len(fixture.repository.created) != 0 || fixture.protector.sealCount != 0 {
		t.Fatal("tenant ceremony with direct revision reached persistence/crypto")
	}
}

func TestDirectPlatformCeremonyRetainsOperationAndClockGuards(t *testing.T) {
	t.Run("UUID variant", func(t *testing.T) {
		fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
			makeDirectPlatformConfiguration(configuration)
		})
		begin := testAuthorizationBegin()
		begin.OperationRunID[8] = 0x40
		if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
			Begin: begin, Configuration: fixture.configuration, ReturnPath: "/",
		}); !errors.Is(err, ErrAuthorizationRejected) {
			t.Fatalf("StartAuthorization() error = %v", err)
		}
		if len(fixture.repository.created) != 0 || fixture.protector.sealCount != 0 {
			t.Fatal("wrong UUID variant reached persistence/crypto")
		}
	})

	for name, invalidNow := range map[string]time.Time{
		"non UTC":               flowTestNow.In(time.FixedZone("fake", 3600)),
		"sub-millisecond clock": flowTestNow.Add(time.Nanosecond),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
				makeDirectPlatformConfiguration(configuration)
			})
			*fixture.now = invalidNow
			if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			}); !errors.Is(err, ErrAuthorizationRejected) {
				t.Fatalf("StartAuthorization() error = %v", err)
			}
			if len(fixture.repository.created) != 0 || fixture.protector.sealCount != 0 {
				t.Fatal("invalid clock reached persistence/crypto")
			}
		})
	}
}

func makeDirectPlatformConfiguration(configuration *AuthorizationConfiguration) {
	configuration.Authority = DirectPlatformCeremonyAuthority
	configuration.Provider.Scope = identity.PlatformProviderScope
	configuration.Provider.TenantID = identity.EntityID{}
	configuration.Admission = identity.TenantAdmissionContext{}
	configuration.BindingID = identity.EntityID{}
	configuration.BindingRevision = 0
	configuration.MappingRevision = 0
	configuration.AuthorizationRevision = 0
	configuration.PlatformLoginRevision = 19
	configuration.PlanRevision = 20
	configuration.PlatformFloorPolicyID = authorityEntityID(21)
	configuration.PlatformFloorRevision = 22
}

func authorityEntityID(value byte) identity.EntityID {
	var id identity.EntityID
	for index := range id {
		id[index] = value
	}
	return id
}
