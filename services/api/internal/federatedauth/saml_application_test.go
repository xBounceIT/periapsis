package federatedauth

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type samlPlannerFunc func(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error)

func (function samlPlannerFunc) PlanSAMLAuthentication(
	ctx context.Context,
	request SAMLPlanningRequest,
) (AuthenticationPlan, error) {
	return function(ctx, request)
}

type samlApplierFunc func(context.Context, SAMLApplyRequest) (ApplyResult, error)

func (function samlApplierFunc) ApplySAMLAuthentication(
	ctx context.Context,
	request SAMLApplyRequest,
) (ApplyResult, error) {
	return function(ctx, request)
}

type samlConsumptionFlowFunc func(
	context.Context,
	*federatedsaml.ValidatedAuthentication,
	federatedsaml.AuthenticationConsumer,
) (federatedsaml.ConsumptionResult, error)

func (function samlConsumptionFlowFunc) Consume(
	ctx context.Context,
	validated *federatedsaml.ValidatedAuthentication,
	consumer federatedsaml.AuthenticationConsumer,
) (federatedsaml.ConsumptionResult, error) {
	return function(ctx, validated, consumer)
}

type samlConsumerFunc func(context.Context, federatedsaml.ConsumptionRequest) (federatedsaml.ConsumptionResult, error)

func (function samlConsumerFunc) ConsumeSAML(
	ctx context.Context,
	request federatedsaml.ConsumptionRequest,
) (federatedsaml.ConsumptionResult, error) {
	return function(ctx, request)
}

func TestSAMLApplicationAtomicallyAppliesPrimaryAndTrustedMFAEvidence(t *testing.T) {
	fixture := newSAMLKernelFixture(t, false)
	configuration := fixture.configuration.Authentication
	mapping := oidcMappingPlanFixture(t, configuration.Provider.TenantID, configuration.Provider, configuration.BindingID)
	plan := samlAuthenticationPlanFixture(t, configuration, mapping, identity.EntityID{}, 0)
	var planned SAMLPlanningRequest
	var applied []SAMLApplyRequest
	application, err := NewSAMLApplication(SAMLApplicationOptions{
		Planner: samlPlannerFunc(func(_ context.Context, request SAMLPlanningRequest) (AuthenticationPlan, error) {
			planned = request
			return clonePlan(plan), nil
		}),
		Applier: samlApplierFunc(func(_ context.Context, request SAMLApplyRequest) (ApplyResult, error) {
			applied = append(applied, cloneSAMLApplyRequest(request))
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(61), SessionID: request.Apply.Session.SessionID(), ReturnPath: "/cases",
			}, nil
		}),
		Credentials:      testApplyCredentialIssuer(),
		OperationTimeout: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := application.ApplySAML(context.Background(), fixture.kernel, fixture.configuration, fixture.validated)
	if err != nil || result.SessionID == (identity.EntityID{}) || planned.Action != "session.create" || len(applied) != 1 {
		t.Fatalf("ApplySAML()=%v,%v planned=%v applied=%d", result, err, planned, len(applied))
	}
	evidence := planned.Authentication.Evidence
	if len(evidence) != 2 || evidence[0].Level != identity.AssurancePrimary ||
		evidence[1].Level != identity.AssuranceMFA || evidence[0].Source != evidence[1].Source ||
		evidence[0].TrustRuleRevision == nil || evidence[1].TrustRuleRevision == nil ||
		*evidence[0].TrustRuleRevision != int64(configuration.SecurityRevision) ||
		*evidence[1].TrustRuleRevision != int64(configuration.SecurityRevision) ||
		applied[0].Apply.Authentication.SAMLConsumption == nil || applied[0].Apply.Authentication.OIDCCompletion != nil ||
		applied[0].Apply.Disposition != ApplySession || applied[0].Apply.Assurance != identity.AssuranceSatisfied ||
		applied[0].MaterialID != applied[0].Apply.Authentication.SAMLConsumption.MaterialID ||
		applied[0].MaterialID == applied[0].Apply.Session.SessionID() ||
		applied[0].SessionMaterial.NameID != "subject-secret" ||
		applied[0].SessionMaterial.SessionIndex != "session-secret" {
		t.Fatalf("evidence=%#v apply=%v", evidence, applied[0])
	}
	if planned.Authentication.Subject.Source != federatedsaml.SubjectPersistentNameID ||
		planned.Authentication.Subject.Value != "subject-secret" ||
		!slices.Equal(planned.Authentication.Groups, []string{"incident-command"}) {
		t.Fatalf("projection=%v", planned.Authentication)
	}
}

func TestSAMLApplicationRetriesTheExactAtomicRequestAfterLostResponse(t *testing.T) {
	fixture := newSAMLKernelFixture(t, false)
	configuration := fixture.configuration.Authentication
	mapping := oidcMappingPlanFixture(t, configuration.Provider.TenantID, configuration.Provider, configuration.BindingID)
	plan := samlAuthenticationPlanFixture(t, configuration, mapping, identity.EntityID{}, 0)
	var calls []SAMLApplyRequest
	application, err := NewSAMLApplication(SAMLApplicationOptions{
		Planner: samlPlannerFunc(func(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error) {
			return clonePlan(plan), nil
		}),
		Applier: samlApplierFunc(func(_ context.Context, request SAMLApplyRequest) (ApplyResult, error) {
			calls = append(calls, cloneSAMLApplyRequest(request))
			if len(calls) == 1 {
				return ApplyResult{}, errors.New("commit response lost")
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(63), SessionID: request.Apply.Session.SessionID(), ReturnPath: "/cases",
			}, nil
		}),
		Credentials:      testApplyCredentialIssuer(),
		OperationTimeout: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := application.ApplySAML(context.Background(), fixture.kernel, fixture.configuration, fixture.validated)
	if err != nil || result.SessionID == (identity.EntityID{}) || len(calls) != 2 || !reflect.DeepEqual(calls[0], calls[1]) {
		t.Fatalf("ApplySAML()=%v,%v calls=%d exact=%t", result, err, len(calls), len(calls) == 2 && reflect.DeepEqual(calls[0], calls[1]))
	}
}

func TestSAMLApplicationFirstJITCollisionConvergesOnlyToSameSubject(t *testing.T) {
	fixture := newSAMLKernelFixture(t, false)
	configuration := fixture.configuration.Authentication
	createMapping := oidcMappingPlanFixture(t, configuration.Provider.TenantID, configuration.Provider, configuration.BindingID)
	existingMapping := oidcExistingMappingPlanFixture(t, configuration.Provider.TenantID, configuration.Provider, configuration.BindingID)
	first := samlAuthenticationPlanFixture(t, configuration, createMapping, identity.EntityID{}, 0)
	second := samlAuthenticationPlanFixture(t, configuration, existingMapping, serviceID(71), 2)
	second.Subject = first.Subject
	planningCalls, applyCalls := 0, 0
	application, err := NewSAMLApplication(SAMLApplicationOptions{
		Planner: samlPlannerFunc(func(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error) {
			planningCalls++
			if planningCalls == 1 {
				return clonePlan(first), nil
			}
			return clonePlan(second), nil
		}),
		Applier: samlApplierFunc(func(_ context.Context, request SAMLApplyRequest) (ApplyResult, error) {
			applyCalls++
			if applyCalls == 1 {
				return ApplyResult{Category: ApplyCollision}, nil
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(71), SessionID: request.Apply.Session.SessionID(), ReturnPath: "/cases",
			}, nil
		}),
		Credentials:      testApplyCredentialIssuer(),
		OperationTimeout: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := application.ApplySAML(context.Background(), fixture.kernel, fixture.configuration, fixture.validated)
	if err != nil || result.UserID != serviceID(71) || planningCalls != 2 || applyCalls != 2 {
		t.Fatalf("ApplySAML()=%v,%v planning=%d apply=%d", result, err, planningCalls, applyCalls)
	}
}

func TestSAMLApplicationLocalRequiredPolicyCreatesRestrictedContinuation(t *testing.T) {
	fixture := newSAMLKernelFixture(t, false)
	configuration := fixture.configuration.Authentication
	mapping := oidcMappingPlanFixture(t, configuration.Provider.TenantID, configuration.Provider, configuration.BindingID)
	plan := samlAuthenticationPlanFixture(t, configuration, mapping, identity.EntityID{}, 0)
	plan.Requirement.Level = identity.AssuranceMFA
	plan.Requirement.LocalRequired = true
	plan.HasEnrollableFactor = true
	application, err := NewSAMLApplication(SAMLApplicationOptions{
		Planner: samlPlannerFunc(func(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error) {
			return clonePlan(plan), nil
		}),
		Applier: samlApplierFunc(func(_ context.Context, request SAMLApplyRequest) (ApplyResult, error) {
			if request.Apply.Disposition != ApplyContinuation || request.Apply.Assurance != identity.AssuranceStepUpRequired {
				return ApplyResult{}, errors.New("expected local step-up")
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(81), ContinuationID: request.Apply.Continuation.ContinuationID(), ReturnPath: "/cases",
			}, nil
		}),
		Credentials:      testApplyCredentialIssuer(),
		OperationTimeout: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := application.ApplySAML(context.Background(), fixture.kernel, fixture.configuration, fixture.validated)
	if err != nil || result.ContinuationID == (identity.EntityID{}) || result.SessionID != (identity.EntityID{}) {
		t.Fatalf("ApplySAML()=%v,%v", result, err)
	}
}

func TestSAMLApplicationRejectsPinDriftAndFalseConsumerSuccess(t *testing.T) {
	for name, mutate := range map[string]func(*federatedsaml.ConsumptionRequest){
		"missing material identity": func(value *federatedsaml.ConsumptionRequest) { value.MaterialID = identity.EntityID{} },
		"non-v7 material identity":  func(value *federatedsaml.ConsumptionRequest) { value.MaterialID[6] = 0x40 },
		"binding revision":          func(value *federatedsaml.ConsumptionRequest) { value.Pins.BindingRevision++ },
		"authorization revision":    func(value *federatedsaml.ConsumptionRequest) { value.Pins.AuthorizationRevision++ },
		"response replay":           func(value *federatedsaml.ConsumptionRequest) { value.ResponseID = value.AssertionID },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSAMLKernelFixture(t, false)
			application := rejectingSAMLApplicationFixture(t, fixture)
			flow := samlConsumptionFlowFunc(func(
				ctx context.Context,
				validated *federatedsaml.ValidatedAuthentication,
				consumer federatedsaml.AuthenticationConsumer,
			) (federatedsaml.ConsumptionResult, error) {
				return fixture.kernel.Consume(ctx, validated, samlConsumerFunc(func(
					ctx context.Context,
					request federatedsaml.ConsumptionRequest,
				) (federatedsaml.ConsumptionResult, error) {
					mutate(&request)
					return consumer.ConsumeSAML(ctx, request)
				}))
			})
			if _, err := application.ApplySAML(context.Background(), flow, fixture.configuration, fixture.validated); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("ApplySAML() error=%v", err)
			}
		})
	}

	fixture := newSAMLKernelFixture(t, false)
	application := rejectingSAMLApplicationFixture(t, fixture)
	falseSuccess := samlConsumptionFlowFunc(func(
		context.Context,
		*federatedsaml.ValidatedAuthentication,
		federatedsaml.AuthenticationConsumer,
	) (federatedsaml.ConsumptionResult, error) {
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerSuccess}, nil
	})
	if _, err := application.ApplySAML(context.Background(), falseSuccess, fixture.configuration, fixture.validated); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("false success error=%v", err)
	}

	fixture = newSAMLKernelFixture(t, false)
	application = rejectingSAMLApplicationFixture(t, fixture)
	drifted := cloneTenantSAMLConfiguration(fixture.configuration)
	drifted.Authentication.Mapping.Scalars[0].Required = !drifted.Authentication.Mapping.Scalars[0].Required
	if _, err := application.ApplySAML(context.Background(), fixture.kernel, drifted, fixture.validated); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("digest-equivalent revision drift error=%v", err)
	}
}

func TestSAMLApplicationFormattingRedactsProofAndReplayMaterial(t *testing.T) {
	projection := SAMLAuthenticationProjection{
		Issuer: "issuer-secret", Subject: SAMLSubjectIdentity{
			Source: federatedsaml.SubjectPersistentNameID, Name: "NameID", Format: testSAMLPersistentNameID,
			Value: "subject-secret",
		},
		Groups: []string{"group-secret"}, Evidence: make([]identity.AssuranceEvidence, 1),
	}
	values := []string{projection.String(), projection.Subject.String(), SAMLPlanningRequest{Authentication: projection, Action: "session.create"}.String()}
	values = append(values, SAMLApplyRequest{
		Apply: ApplyRequest{}, SessionMaterial: federatedsaml.SessionMaterial{
			NameID: "subject-secret", NameIDFormat: testSAMLPersistentNameID, SessionIndex: "session-secret",
		},
	}.String())
	for _, formatted := range values {
		for _, secret := range []string{"issuer-secret", "subject-secret", "session-secret", "group-secret"} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("format leaked %q: %s", secret, formatted)
			}
		}
	}
}

func rejectingSAMLApplicationFixture(t *testing.T, fixture samlKernelFixture) *SAMLApplication {
	t.Helper()
	application, err := NewSAMLApplication(SAMLApplicationOptions{
		Planner: samlPlannerFunc(func(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error) {
			return AuthenticationPlan{}, errors.New("must not plan")
		}),
		Applier: samlApplierFunc(func(context.Context, SAMLApplyRequest) (ApplyResult, error) {
			return ApplyResult{}, errors.New("must not apply")
		}),
		Credentials:      testApplyCredentialIssuer(),
		OperationTimeout: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func samlAuthenticationPlanFixture(
	t *testing.T,
	configuration federatedsaml.Configuration,
	mapping *identity.FederatedMappingPlan,
	userID identity.EntityID,
	identityEpoch uint64,
) AuthenticationPlan {
	t.Helper()
	return AuthenticationPlan{
		PlanRevision: 1, TenantID: configuration.Provider.TenantID, UserID: userID, IdentityEpoch: identityEpoch,
		ProviderRevision: configuration.ProviderRevision, BindingRevision: configuration.BindingRevision,
		ConfigurationRevision: configuration.ConfigurationRevision, SecurityRevision: configuration.SecurityRevision,
		MappingRevision: configuration.MappingRevision, AuthorizationRevision: configuration.AuthorizationRevision,
		PolicyRevision: configuration.AssurancePolicyRevision,
		RoleIDs:        mapping.ProspectiveRoleIDs(), SecurityGroupIDs: mapping.ProspectiveSecurityGroupIDs(),
		Subject: protectedFederatedSubjectFixture(serviceID(91)), Mapping: mapping,
		Requirement: identity.EffectiveAssuranceRequirement{
			Level: identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{
				PolicyID: serviceID(92), Revision: int64(configuration.AssurancePolicyRevision),
			}},
		},
		HasEnrollableFactor: true,
	}
}
