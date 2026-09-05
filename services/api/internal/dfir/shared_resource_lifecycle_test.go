package dfir

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestSharedLinkCommandsBindRootResourceCallerEventAndCAS(t *testing.T) {
	t.Parallel()
	tenant := testUUID(180)
	actor := testActor(tenant, PrincipalHuman)
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		resolveAlertAccess: func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	seen := make(map[[32]byte]bool)
	for _, kind := range []kernel.EntityKind{kernel.EntityCase, kernel.EntityAlert} {
		for _, prefix := range []string{"dfir.ioc", "dfir.asset"} {
			for _, linked := range []bool{false, true} {
				command := SharedResourceLinkCommand{RootKind: kind, RootID: testEntityID(t, 181),
					ResourceID: testEntityID(t, 182), EventID: testEntityID(t, 183), ExpectedVersion: 3_000_000_000,
					Linked: linked, Envelope: testEnvelope(184)}
				capability := CapabilityIOCManage
				if prefix == "dfir.asset" {
					capability = CapabilityAssetManage
				}
				write, err := service.sharedResourceLinkWrite(context.Background(), actor, tenant, command, capability, prefix)
				if err != nil {
					t.Fatal(err)
				}
				if write.EventID != command.EventID || write.ResourceID != command.ResourceID || write.ExpectedVersion != command.ExpectedVersion || write.Linked != linked {
					t.Fatal("link command lost a caller-owned coordinate")
				}
				if (kind == kernel.EntityCase && write.CaseID != command.RootID) || (kind == kernel.EntityAlert && write.AlertID != command.RootID) {
					t.Fatal("link command lost its root kind")
				}
				if seen[write.Command.RequestDigest] {
					t.Fatal("different root/action/resource type share a fingerprint")
				}
				seen[write.Command.RequestDigest] = true
				for _, changed := range []SharedResourceLinkCommand{
					func() SharedResourceLinkCommand { v := command; v.RootID = testEntityID(t, 185); return v }(),
					func() SharedResourceLinkCommand { v := command; v.ResourceID = testEntityID(t, 185); return v }(),
					func() SharedResourceLinkCommand { v := command; v.EventID = testEntityID(t, 185); return v }(),
					func() SharedResourceLinkCommand { v := command; v.ExpectedVersion++; return v }(),
				} {
					other, err := service.sharedResourceLinkWrite(context.Background(), actor, tenant, changed, capability, prefix)
					if err != nil || other.Command.RequestDigest == write.Command.RequestDigest || other.Command.KeyDigest != write.Command.KeyDigest {
						t.Fatalf("changed request did not remain key-bound: %v", err)
					}
				}
			}
		}
	}
}

type sharedLinkRepositoryStub struct {
	*fakeRepository
	indicator func(context.Context, SharedResourceLinkWrite) (MutationResult[kernel.Indicator], error)
}

func (r *sharedLinkRepositoryStub) ChangeIndicatorLink(ctx context.Context, write SharedResourceLinkWrite) (MutationResult[kernel.Indicator], error) {
	return r.indicator(ctx, write)
}
func (*sharedLinkRepositoryStub) ChangeAssetLink(context.Context, SharedResourceLinkWrite) (MutationResult[kernel.Asset], error) {
	return MutationResult[kernel.Asset]{}, ErrRepositoryForbidden
}

func TestSharedLinkReplayRechecksLivePathPermissionAndProjection(t *testing.T) {
	t.Parallel()
	tenant := testUUID(190)
	actor := testActor(tenant, PrincipalHuman)
	indicator, err := kernel.NewIndicator(indicatorInput(t, tenant, 191))
	if err != nil {
		t.Fatal(err)
	}
	allowed, calls := true, 0
	repository := &sharedLinkRepositoryStub{fakeRepository: &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			if !allowed {
				return Access{}, ErrRepositoryForbidden
			}
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
	}, indicator: func(context.Context, SharedResourceLinkWrite) (MutationResult[kernel.Indicator], error) {
		calls++
		return MutationResult[kernel.Indicator]{Resource: indicator, Replayed: true}, nil
	}}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	command := SharedResourceLinkCommand{RootKind: kernel.EntityCase, RootID: testEntityID(t, 192), ResourceID: indicator.ID(),
		EventID: testEntityID(t, 193), ExpectedVersion: 1, Linked: false, Envelope: testEnvelope(194)}
	if result, err := service.ChangeIndicatorLink(context.Background(), actor, tenant, command); err != nil || !result.Replayed {
		t.Fatalf("exact unlink replay failed: %v", err)
	}
	allowed = false
	if _, err := service.ChangeIndicatorLink(context.Background(), actor, tenant, command); !errors.Is(err, ErrForbidden) || calls != 1 {
		t.Fatalf("revoked path reached receipt: %v calls=%d", err, calls)
	}
	allowed = true
	command.ResourceID = testEntityID(t, 195)
	if _, err := service.ChangeIndicatorLink(context.Background(), actor, tenant, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong resource snapshot returned: %v", err)
	}
	for _, version := range []uint64{0, kernel.MaximumResourceVersion, kernel.MaximumResourceVersion + 1} {
		command.ExpectedVersion = version
		if _, err := service.ChangeIndicatorLink(context.Background(), actor, tenant, command); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("non-incrementable version accepted: %d %v", version, err)
		}
	}
}
