package mfaauth

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func TestAuthorityRevisionCeilingAcceptsMaximumPinsAndRequiresMutationHeadroom(t *testing.T) {
	const wantMaximum = uint64(9_007_199_254_740_991)
	if maximumStoredVersion != wantMaximum {
		t.Fatalf("maximumStoredVersion = %d", maximumStoredVersion)
	}

	newInput := func() AuthoritySnapshotInput {
		revision := int64(maximumStoredVersion)
		input := authorityInput([]identity.AssuranceEvidence{{
			Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
			Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow,
			FactorRevision: &revision,
		}}, false, mfa.FlowExistingSession)
		input.IdentityEpoch = maximumStoredVersion
		input.AnchorVersion = maximumStoredVersion - 1
		input.RecoverySetVersion = maximumStoredVersion - 1
		input.Policies[0].Policy.Revision = int64(maximumStoredVersion)
		return input
	}

	if _, err := NewAuthoritySnapshot(newInput()); err != nil {
		t.Fatalf("maximum passive pins with successor headroom were rejected: %v", err)
	}

	for name, mutate := range map[string]func(*AuthoritySnapshotInput){
		"identity above maximum": func(value *AuthoritySnapshotInput) {
			value.IdentityEpoch = maximumStoredVersion + 1
		},
		"anchor without headroom": func(value *AuthoritySnapshotInput) {
			value.AnchorVersion = maximumStoredVersion
		},
		"recovery set without headroom": func(value *AuthoritySnapshotInput) {
			value.RecoverySetVersion = maximumStoredVersion
		},
		"policy above maximum": func(value *AuthoritySnapshotInput) {
			value.Policies[0].Policy.Revision = int64(maximumStoredVersion + 1)
		},
		"evidence above maximum": func(value *AuthoritySnapshotInput) {
			*value.BaselineEvidence[0].FactorRevision = int64(maximumStoredVersion + 1)
		},
		"sub-millisecond anchor deadline": func(value *AuthoritySnapshotInput) {
			value.AnchorExpiresAt = value.AnchorExpiresAt.Add(time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := newInput()
			mutate(&input)
			if _, err := NewAuthoritySnapshot(input); err == nil {
				t.Fatal("unsafe revision was accepted")
			}
		})
	}
}

func TestDeviceRevisionCeilingSeparatesStoredProjectionFromMutationVersion(t *testing.T) {
	projection := DeviceProjection{
		ID: deviceTestID(3), Kind: DeviceTOTP, Status: DeviceActive,
		Version: maximumStoredVersion, CreatedAt: testNow,
	}
	if _, err := NewDevice(projection); err != nil {
		t.Fatalf("maximum stored device version was rejected: %v", err)
	}
	projection.Version = maximumStoredVersion + 1
	if _, err := NewDevice(projection); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("maximum+1 device version error = %v", err)
	}

	deviceID := deviceTestID(7)
	repository := &deviceRepositoryStub{renameResult: DeviceMutationResult{
		Device: mustPasskeyDevice(t, deviceID, maximumStoredVersion, "Travel key", testNow),
	}}
	manager, err := NewDeviceManager(repository, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.RenamePasskey(
		context.Background(), deviceAuthority(), deviceID, "Travel key", maximumStoredVersion-1,
	); err != nil {
		t.Fatalf("last safe device increment was rejected: %v", err)
	}

	repository.mutation = DeviceMutation{}
	if _, err = manager.RenamePasskey(
		context.Background(), deviceAuthority(), deviceID, "Travel key", maximumStoredVersion,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("device mutation without version headroom error = %v", err)
	}
	if repository.mutation != (DeviceMutation{}) {
		t.Fatal("unsafe device mutation reached the repository")
	}
}

func TestEnrollmentClaimRevisionRequiresCompletionHeadroom(t *testing.T) {
	service, store, lookup := newFactorEnrollmentService(t)
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	claimed := ClaimedTOTPEnrollment{
		EnrollmentID: store.start.EnrollmentID, FactorID: store.start.FactorID,
		Version: maximumStoredVersion - 1, BrowserDigest: store.start.BrowserDigest,
		Binding: store.start.Binding, ProtectedSecret: cloneProtectedSecret(store.start.ProtectedSecret),
		CreatedAt: store.start.CreatedAt, ExpiresAt: store.start.ExpiresAt, ClaimedAt: testNow,
	}
	store.mu.Unlock()
	if !validClaimedTOTPEnrollment(
		claimed, start.EnrollmentID(), claimed.BrowserDigest, testNow, testNow, time.Second,
	) {
		t.Fatal("claimed enrollment with completion headroom was rejected")
	}
	claimed.Version = maximumStoredVersion
	if validClaimedTOTPEnrollment(
		claimed, start.EnrollmentID(), claimed.BrowserDigest, testNow, testNow, time.Second,
	) {
		t.Fatal("claimed enrollment without completion headroom was accepted")
	}
}

func TestLocalStepUpArtifactAcceptsMaximumPinsAndRejectsMaximumPlusOne(t *testing.T) {
	revision := int64(maximumStoredVersion)
	newArtifact := func() mfa.StepUpArtifact {
		return mfa.StepUpArtifact{
			TenantID: testID(1), UserID: testID(2), IdentityEpoch: maximumStoredVersion,
			SessionID: testID(3), SessionFamilyID: testID(4), NewSessionID: testID(20),
			NewSessionFamilyID: testID(4), Action: "case.export", Audience: "tenant-console",
			SessionVersion: maximumStoredVersion,
			NewEvidence: identity.AssuranceEvidence{
				Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow,
				FactorRevision: &revision,
			},
		}
	}

	if !validLocalStepUpArtifact(newArtifact(), testNow.Add(-time.Second), testNow, false) {
		t.Fatal("maximum stored local step-up revisions were rejected")
	}
	for name, mutate := range map[string]func(*mfa.StepUpArtifact){
		"identity": func(value *mfa.StepUpArtifact) { value.IdentityEpoch = maximumStoredVersion + 1 },
		"session":  func(value *mfa.StepUpArtifact) { value.SessionVersion = maximumStoredVersion + 1 },
		"factor": func(value *mfa.StepUpArtifact) {
			factorRevision := int64(maximumStoredVersion + 1)
			value.NewEvidence.FactorRevision = &factorRevision
		},
	} {
		t.Run(name, func(t *testing.T) {
			artifact := newArtifact()
			mutate(&artifact)
			if validLocalStepUpArtifact(artifact, testNow.Add(-time.Second), testNow, false) {
				t.Fatal("maximum+1 local step-up revision was accepted")
			}
		})
	}
}
