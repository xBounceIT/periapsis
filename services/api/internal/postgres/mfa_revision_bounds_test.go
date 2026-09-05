package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

func TestMFAJSONRevisionCeilingIsInclusiveOnlyForStoredValues(t *testing.T) {
	const wantMaximum = int64(9_007_199_254_740_991)
	if maximumMFAJSONSafeInteger != wantMaximum {
		t.Fatalf("maximumMFAJSONSafeInteger = %d", maximumMFAJSONSafeInteger)
	}
	if !validMFAJSONRevision(wantMaximum) || validMFAJSONRevision(wantMaximum+1) ||
		!validMFAJSONVersion(uint64(wantMaximum)) || validMFAJSONVersion(uint64(wantMaximum+1)) {
		t.Fatal("stored revision ceiling is not inclusive and JSON-safe")
	}
	if !validMFAJSONSuccessorRevision(wantMaximum-1) || validMFAJSONSuccessorRevision(wantMaximum) ||
		!validMFAJSONSuccessorVersion(uint64(wantMaximum-1)) || validMFAJSONSuccessorVersion(uint64(wantMaximum)) {
		t.Fatal("successor revision did not retain one unit of headroom")
	}
}

func TestMFARequirementAndEvidenceWireRejectMaximumPlusOne(t *testing.T) {
	requirement := mfaPendingChallengeFixture().Binding.Requirement
	requirement.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), requirement.PolicyRevisions...)
	requirement.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger
	requirementWire, err := requirementToWire(requirement)
	if err != nil {
		t.Fatalf("maximum policy revision to wire: %v", err)
	}
	if _, err = requirementFromWire(requirementWire); err != nil {
		t.Fatalf("maximum policy revision from wire: %v", err)
	}
	requirement.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger + 1
	if _, err = requirementToWire(requirement); !errors.Is(err, errInvalidMFAWire) {
		t.Fatalf("maximum+1 policy revision to wire error = %v", err)
	}
	requirementWire.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger + 1
	if _, err = requirementFromWire(requirementWire); !errors.Is(err, errInvalidMFAWire) {
		t.Fatalf("maximum+1 policy revision from wire error = %v", err)
	}

	revision := maximumMFAJSONSafeInteger
	evidence := []identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: mfaPersistenceTestNow,
		FactorRevision: &revision,
	}}
	evidenceWire, err := evidenceToWire(evidence)
	if err != nil {
		t.Fatalf("maximum factor revision to wire: %v", err)
	}
	if _, err = evidenceFromWire(evidenceWire); err != nil {
		t.Fatalf("maximum factor revision from wire: %v", err)
	}
	revision++
	if _, err = evidenceToWire(evidence); !errors.Is(err, errInvalidMFAWire) {
		t.Fatalf("maximum+1 factor revision to wire error = %v", err)
	}
	evidenceWire[0].FactorRevision = &revision
	if _, err = evidenceFromWire(evidenceWire); !errors.Is(err, errInvalidMFAWire) {
		t.Fatalf("maximum+1 factor revision from wire error = %v", err)
	}
}

func TestMFAStepUpBindingWireAcceptsMaximumPinsAndRequiresAnchorHeadroom(t *testing.T) {
	newBinding := func() mfa.StepUpBinding {
		binding := mfaPendingChallengeFixture().Binding
		binding.IdentityEpoch = uint64(maximumMFAJSONSafeInteger)
		binding.AnchorVersion = uint64(maximumMFAJSONSafeInteger - 1)
		binding.Requirement.PolicyRevisions = append(
			[]identity.AssurancePolicyRevision(nil), binding.Requirement.PolicyRevisions...,
		)
		binding.Requirement.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger
		binding.BaselineEvidence = append([]identity.AssuranceEvidence(nil), binding.BaselineEvidence...)
		revision := maximumMFAJSONSafeInteger
		binding.BaselineEvidence[0].FactorRevision = &revision
		return binding
	}
	newWire := func(t *testing.T) stepUpBindingWire {
		t.Helper()
		wire, err := stepUpBindingToWire(newBinding())
		if err != nil {
			t.Fatalf("maximum step-up binding to wire: %v", err)
		}
		return wire
	}

	wire := newWire(t)
	if _, err := stepUpBindingFromWire(wire); err != nil {
		t.Fatalf("maximum step-up binding from wire: %v", err)
	}

	for name, mutate := range map[string]func(*mfa.StepUpBinding){
		"identity above maximum": func(value *mfa.StepUpBinding) {
			value.IdentityEpoch = uint64(maximumMFAJSONSafeInteger + 1)
		},
		"anchor without headroom": func(value *mfa.StepUpBinding) {
			value.AnchorVersion = uint64(maximumMFAJSONSafeInteger)
		},
		"policy above maximum": func(value *mfa.StepUpBinding) {
			value.Requirement.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger + 1
		},
		"evidence above maximum": func(value *mfa.StepUpBinding) {
			revision := maximumMFAJSONSafeInteger + 1
			value.BaselineEvidence[0].FactorRevision = &revision
		},
	} {
		t.Run("to wire "+name, func(t *testing.T) {
			binding := newBinding()
			mutate(&binding)
			if _, err := stepUpBindingToWire(binding); !errors.Is(err, errInvalidMFAWire) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(*stepUpBindingWire){
		"identity above maximum": func(value *stepUpBindingWire) {
			value.IdentityEpoch = maximumMFAJSONSafeInteger + 1
		},
		"anchor without headroom": func(value *stepUpBindingWire) {
			value.AnchorVersion = maximumMFAJSONSafeInteger
		},
		"policy above maximum": func(value *stepUpBindingWire) {
			value.Requirement.PolicyRevisions[0].Revision = maximumMFAJSONSafeInteger + 1
		},
		"evidence above maximum": func(value *stepUpBindingWire) {
			revision := maximumMFAJSONSafeInteger + 1
			value.BaselineEvidence[0].FactorRevision = &revision
		},
	} {
		t.Run("from wire "+name, func(t *testing.T) {
			candidate := newWire(t)
			mutate(&candidate)
			if _, err := stepUpBindingFromWire(candidate); !errors.Is(err, errInvalidMFAWire) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMFACompletionWireReservesHeadroomForBothVersionIncrements(t *testing.T) {
	binding := mfaPendingChallengeFixture().Binding
	binding.AnchorVersion = uint64(maximumMFAJSONSafeInteger - 1)
	counter := int64(17)
	encode := func(challengeVersion, factorVersion uint64, securityRevision int64) error {
		_, err := completeFactorToWire(
			mfaPendingChallengeFixture().ID, challengeVersion, binding, mfaPersistenceID(8),
			factorVersion, securityRevision, &counter, identity.EntityID{}, nil,
			mfaPersistenceTestNow, mfa.CompletionIntent{
				Session: mfa.StepUpSessionRotate, Audit: mfa.AuditTOTPStepUpCompleted,
			},
		)
		return err
	}
	if err := encode(
		uint64(maximumMFAJSONSafeInteger-1), uint64(maximumMFAJSONSafeInteger-1), maximumMFAJSONSafeInteger,
	); err != nil {
		t.Fatalf("last safe completion increment was rejected: %v", err)
	}
	for name, values := range map[string]struct {
		challenge uint64
		factor    uint64
		security  int64
	}{
		"challenge without headroom": {
			uint64(maximumMFAJSONSafeInteger), uint64(maximumMFAJSONSafeInteger - 1), maximumMFAJSONSafeInteger,
		},
		"factor without headroom": {
			uint64(maximumMFAJSONSafeInteger - 1), uint64(maximumMFAJSONSafeInteger), maximumMFAJSONSafeInteger,
		},
		"security above maximum": {
			uint64(maximumMFAJSONSafeInteger - 1), uint64(maximumMFAJSONSafeInteger - 1), maximumMFAJSONSafeInteger + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := encode(values.challenge, values.factor, values.security); !errors.Is(err, errInvalidMFAWire) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMFADeviceRepositoryRejectsMutationWithoutVersionHeadroom(t *testing.T) {
	called := false
	repository := &MFADeviceRepository{queryer: mfaQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return mfaRowFunc(func(...any) error { return nil })
	}}}
	_, err := repository.RenamePasskey(context.Background(), mfaauth.DeviceMutation{
		Authority: mfaDeviceAuthorityFixture(), DeviceID: mfaPersistenceID(4), Kind: mfaauth.DevicePasskey,
		DisplayName: "Key", ExpectedVersion: uint64(maximumMFAJSONSafeInteger),
		OccurredAt: mfaPersistenceTestNow,
	})
	if !errors.Is(err, mfaauth.ErrInvalidInput) || called {
		t.Fatalf("error = %v, database called = %t", err, called)
	}
}
