package platformidentitybinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestServiceBindingCRUDUsesExplicitHumanAuthorityAndClosedInputs(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	bindingID := mustUUIDv7(t)
	commandID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	ids := []uuid.UUID{commandID, bindingID}
	service.newID = func() (uuid.UUID, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	session := manageSession(t)
	input := validCreateInput(t, tenantID)
	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		if params.ActorID != session.User.ID || params.SessionID != session.ID ||
			params.AuthenticationMethod != session.AuthenticationMethod || params.CommandID != commandID ||
			params.BindingID != bindingID || params.ProviderID != providerID || params.TenantID != tenantID ||
			params.LoginKey != "corporate_login" || params.ProfilePriority != 42 ||
			params.Reason != "Approved tenant admission" || params.ValidateResult == nil {
			t.Fatalf("Create() params = %#v", params)
		}
		if params.KeyDigest != sha256For("platform-binding-create-0001") || allZero(params.RequestDigest[:]) {
			t.Fatalf("Create() digests were not bound")
		}
		result := mustCreateResult(t, bindingID, false, validBindingFixture(providerID, tenantID, bindingID, 1))
		return params.ValidateResult(result)
	}
	created, err := service.Create(context.Background(), session, providerID, input)
	if err != nil || created.BindingID() != bindingID || created.Version() != 1 || created.Replayed() {
		t.Fatalf("Create() = %#v, %v", created, err)
	}

	updateTag := mustEntityTag(t, 1, 11)
	repository.update = func(_ context.Context, params UpdateParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.BindingID != bindingID || params.ExpectedVersion != 1 ||
			params.ExpectedTenantVersion != 11 ||
			params.LoginKey != "renamed_login" || params.ProfilePriority != 77 ||
			params.Reason != "Approved login-code change" || params.ValidateResult == nil {
			t.Fatalf("Update() params = %#v", params)
		}
		binding := validBindingFixture(providerID, tenantID, bindingID, 2)
		binding.LoginKey = params.LoginKey
		binding.ProfilePriority = params.ProfilePriority
		binding.UpdatedAt = binding.UpdatedAt.Add(time.Microsecond)
		return params.ValidateResult(mustUpdateResult(t, binding))
	}
	updated, err := service.Update(context.Background(), session, providerID, bindingID, UpdateInput{
		LoginKey: "renamed_login", ProfilePriority: 77, Reason: " Approved login-code change ",
		ExpectedEntityTag: &updateTag, Event: testEvent(t),
	})
	if err != nil || updated.Version() != 2 || updated.Binding().LoginKey != "renamed_login" {
		t.Fatalf("Update() = %#v, %v", updated, err)
	}

	archiveTag := mustEntityTag(t, 2, 11)
	repository.archive = func(_ context.Context, params ArchiveParams) (MutationReceipt, error) {
		if params.ProviderID != providerID || params.BindingID != bindingID || params.ExpectedVersion != 2 ||
			params.ExpectedTenantVersion != 11 ||
			params.Reason != "Retire duplicate tenant binding" {
			t.Fatalf("Archive() params = %#v", params)
		}
		return mustMutationReceipt(t, bindingID, 3, 11), nil
	}
	receipt, err := service.Archive(context.Background(), session, providerID, bindingID, ArchiveInput{
		Reason: " Retire duplicate tenant binding ", ExpectedEntityTag: &archiveTag, Event: testEvent(t),
	})
	if err != nil || receipt.BindingID() != bindingID || receipt.Version() != 3 ||
		receipt.TenantVersion() != 11 {
		t.Fatalf("Archive() = %#v, %v", receipt, err)
	}
}

func TestServiceCreateAcceptsTruthfulActivationAvailability(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	bindingID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	ids := []uuid.UUID{mustUUIDv7(t), bindingID}
	service.newID = func() (uuid.UUID, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		binding := validBindingFixture(providerID, tenantID, bindingID, 1)
		binding.ActivationAvailable = true
		return params.ValidateResult(mustCreateResult(t, bindingID, false, binding))
	}

	result, err := service.Create(
		context.Background(), manageSession(t), providerID, validCreateInput(t, tenantID),
	)
	if err != nil || !result.Binding().ActivationAvailable {
		t.Fatalf("Create() = %#v, %v, want live activation availability", result, err)
	}
}

func TestServiceListAndGetValidateProviderScopeOrderLifecycleAndCopies(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	firstID := mustUUIDv7(t)
	secondID := largerUUIDv7(t, firstID)
	thirdID := largerUUIDv7(t, secondID)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	repository.list = func(_ context.Context, params ListParams) ([]Binding, error) {
		if params.ProviderID != providerID || params.Limit != 3 || params.IncludeArchived {
			t.Fatalf("List() params = %#v", params)
		}
		return []Binding{
			validBindingFixture(providerID, tenantID, firstID, 1),
			validBindingFixture(providerID, tenantID, secondID, 1),
			validBindingFixture(providerID, tenantID, thirdID, 1),
		}, nil
	}
	page, err := service.List(context.Background(), readSession(t), providerID, ListInput{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != secondID {
		t.Fatalf("List() = %#v, %v", page, err)
	}
	page.Items[0].Tenant.Name = "tampered"
	page.Items[0].ArchivedAt = pointer(time.Now())

	repository.get = func(_ context.Context, params GetParams) (Binding, error) {
		if params.ProviderID != providerID || params.BindingID != firstID {
			t.Fatalf("Get() params = %#v", params)
		}
		return validBindingFixture(providerID, tenantID, firstID, 1), nil
	}
	binding, err := service.Get(context.Background(), readSession(t), providerID, firstID)
	if err != nil || binding.ID != firstID || binding.Tenant.Name != "Acme Security" {
		t.Fatalf("Get() = %#v, %v", binding, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "wrong provider", mutate: func(value *Binding) { value.ProviderID = mustUUIDv7(t) }},
		{name: "enabled", mutate: func(value *Binding) { value.Enabled = true }},
		{name: "latent epoch", mutate: func(value *Binding) { value.CurrentAccessEpochID = pointer(mustUUIDv7(t)) }},
		{name: "zero mapping revision", mutate: func(value *Binding) { value.MappingRevision = 0 }},
		{name: "bad tenant", mutate: func(value *Binding) { value.Tenant.Status = "deleted" }},
		{name: "unversioned tenant", mutate: func(value *Binding) { value.Tenant.Version = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository.get = func(context.Context, GetParams) (Binding, error) {
				value := validBindingFixture(providerID, tenantID, firstID, 1)
				test.mutate(&value)
				return value, nil
			}
			if _, getErr := service.Get(context.Background(), readSession(t), providerID, firstID); !errors.Is(getErr, authentication.ErrUnavailable) {
				t.Fatalf("Get() unsafe projection error = %v", getErr)
			}
		})
	}

	repository.list = func(context.Context, ListParams) ([]Binding, error) {
		return []Binding{
			validBindingFixture(providerID, tenantID, secondID, 1),
			validBindingFixture(providerID, tenantID, firstID, 1),
		}, nil
	}
	if _, listErr := service.List(context.Background(), readSession(t), providerID, ListInput{Limit: 2}); !errors.Is(listErr, authentication.ErrUnavailable) {
		t.Fatalf("List() non-monotonic error = %v", listErr)
	}
}

func TestServiceCreateReplayKeepsImmutableTenantAndAllowsCurrentMutableProjection(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	replayedID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	service.newID = uuid.NewV7
	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		binding := validBindingFixture(providerID, tenantID, replayedID, 5)
		binding.LoginKey = "renamed_later"
		binding.ProfilePriority = 91
		binding.UpdatedAt = binding.UpdatedAt.Add(time.Microsecond)
		return params.ValidateResult(mustCreateResult(t, replayedID, true, binding))
	}
	result, err := service.Create(context.Background(), manageSession(t), providerID, validCreateInput(t, tenantID))
	if err != nil || !result.Replayed() || result.BindingID() != replayedID ||
		result.Binding().LoginKey != "renamed_later" {
		t.Fatalf("Create() replay = %#v, %v", result, err)
	}

	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		binding := validBindingFixture(providerID, mustUUIDv7(t), replayedID, 5)
		return params.ValidateResult(mustCreateResult(t, replayedID, true, binding))
	}
	if _, err := service.Create(context.Background(), manageSession(t), providerID, validCreateInput(t, tenantID)); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Create() cross-tenant replay error = %v", err)
	}
}

func TestServiceMutationsRejectTenantVersionDrift(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	bindingID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	tag := mustEntityTag(t, 1, 11)

	repository.update = func(_ context.Context, params UpdateParams) (UpdateResult, error) {
		if params.ExpectedVersion != 1 || params.ExpectedTenantVersion != 11 {
			t.Fatalf("Update() CAS params = %#v", params)
		}
		binding := validBindingFixture(providerID, tenantID, bindingID, 2)
		binding.Tenant.Version = 12
		binding.UpdatedAt = binding.UpdatedAt.Add(time.Microsecond)
		return params.ValidateResult(mustUpdateResult(t, binding))
	}
	if _, err := service.Update(
		context.Background(), manageSession(t), providerID, bindingID,
		UpdateInput{
			LoginKey: "corporate_login", ProfilePriority: 42, Reason: "Approved",
			ExpectedEntityTag: &tag, Event: testEvent(t),
		},
	); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Update() tenant-version drift error = %v", err)
	}

	repository.archive = func(_ context.Context, params ArchiveParams) (MutationReceipt, error) {
		if params.ExpectedVersion != 1 || params.ExpectedTenantVersion != 11 {
			t.Fatalf("Archive() CAS params = %#v", params)
		}
		return mustMutationReceipt(t, bindingID, 2, 12), nil
	}
	if _, err := service.Archive(
		context.Background(), manageSession(t), providerID, bindingID,
		ArchiveInput{Reason: "Approved", ExpectedEntityTag: &tag, Event: testEvent(t)},
	); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Archive() tenant-version drift error = %v", err)
	}
}

func TestServicePermissionsSessionsCancellationAndClosedErrors(t *testing.T) {
	providerID := mustUUIDv7(t)
	bindingID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)

	if _, err := service.List(context.Background(), authentication.Session{}, providerID, ListInput{}); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("List() permission error = %v", err)
	}
	manageOnly := manageSession(t)
	manageOnly.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityBindingManage}
	if _, err := service.Create(context.Background(), manageOnly, providerID, validCreateInput(t, tenantID)); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("Create() missing read permission error = %v", err)
	}
	invalidSession := readSession(t)
	invalidSession.AuthenticationMethod = "bearer"
	if _, err := service.Get(context.Background(), invalidSession, providerID, bindingID); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Get() invalid session error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.List(canceled, readSession(t), providerID, ListInput{}); !errors.Is(err, context.Canceled) || repository.calls != 0 {
		t.Fatalf("List() cancellation = %v, repository calls = %d", err, repository.calls)
	}
	if _, err := service.List(nil, readSession(t), providerID, ListInput{}); !errors.Is(err, authentication.ErrUnavailable) || repository.calls != 0 {
		t.Fatalf("List(nil) = %v, repository calls = %d", err, repository.calls)
	}

	for _, test := range []struct {
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
		{fmt.Errorf("wrapped: %w", ErrPreconditionFailed), ErrPreconditionFailed},
		{errors.New("private database diagnostic"), authentication.ErrUnavailable},
	} {
		repository.getError = test.in
		_, err := service.Get(context.Background(), readSession(t), providerID, bindingID)
		if !errors.Is(err, test.want) {
			t.Fatalf("Get() mapped error = %v, want %v", err, test.want)
		}
	}
}

func TestServiceRejectsMalformedInputsBeforeRepository(t *testing.T) {
	providerID := mustUUIDv7(t)
	tenantID := mustUUIDv7(t)
	bindingID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)

	createCases := []CreateInput{
		func() CreateInput { value := validCreateInput(t, tenantID); value.TenantID = uuid.New(); return value }(),
		func() CreateInput { value := validCreateInput(t, tenantID); value.LoginKey = "Bad Key"; return value }(),
		func() CreateInput {
			value := validCreateInput(t, tenantID)
			value.LoginKey = " corporate_login"
			return value
		}(),
		func() CreateInput { value := validCreateInput(t, tenantID); value.ProfilePriority = -1; return value }(),
		func() CreateInput {
			value := validCreateInput(t, tenantID)
			value.ProfilePriority = maximumProfilePriority + 1
			return value
		}(),
		func() CreateInput { value := validCreateInput(t, tenantID); value.Reason = ""; return value }(),
		func() CreateInput {
			value := validCreateInput(t, tenantID)
			value.IdempotencyKey = "short"
			return value
		}(),
		func() CreateInput {
			value := validCreateInput(t, tenantID)
			value.Event.UserAgent = "bad\nagent"
			return value
		}(),
	}
	for _, input := range createCases {
		if _, err := service.Create(context.Background(), session, providerID, input); !errors.Is(err, authentication.ErrInvalidInput) {
			t.Fatalf("Create() malformed input error = %v", err)
		}
	}

	invalidTag := `W/"v1"`
	if _, err := service.Update(context.Background(), session, providerID, bindingID, UpdateInput{
		LoginKey: "valid_key", ProfilePriority: 0, Reason: "Approved", ExpectedEntityTag: &invalidTag,
		Event: testEvent(t),
	}); !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("Update() weak ETag error = %v", err)
	}
	validTag := mustEntityTag(t, 1, 11)
	if _, err := service.Update(context.Background(), session, providerID, bindingID, UpdateInput{
		LoginKey: "valid_key ", ProfilePriority: 0, Reason: "Approved", ExpectedEntityTag: &validTag,
		Event: testEvent(t),
	}); !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("Update() non-canonical login key error = %v", err)
	}
	if _, err := service.Archive(context.Background(), session, providerID, bindingID, ArchiveInput{
		Reason: "Approved", Event: testEvent(t),
	}); !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("Archive() missing ETag error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d", repository.calls)
	}
}

func TestReceiptsAndEntityTagsAreClosed(t *testing.T) {
	bindingID := mustUUIDv7(t)
	if _, err := RestoreCreateReceipt(CreateReceiptInput{BindingID: uuid.New(), Version: 1}); err == nil {
		t.Fatal("RestoreCreateReceipt() accepted UUIDv4")
	}
	if _, err := RestoreCreateReceipt(CreateReceiptInput{BindingID: bindingID, Version: 2}); err == nil {
		t.Fatal("RestoreCreateReceipt() accepted non-initial version")
	}
	if _, err := RestoreMutationReceipt(MutationReceiptInput{
		BindingID: bindingID, Version: 1, TenantVersion: 11,
	}); err == nil {
		t.Fatal("RestoreMutationReceipt() accepted initial version")
	}
	if _, err := RestoreMutationReceipt(MutationReceiptInput{
		BindingID: bindingID, Version: 2,
	}); err == nil {
		t.Fatal("RestoreMutationReceipt() accepted missing tenant version")
	}
	for _, versions := range [][2]int64{{1, 1}, {17, 29}, {maximumResourceVersion, maximumResourceVersion}} {
		tag, err := EntityTag(versions[0], versions[1])
		if err != nil {
			t.Fatalf("EntityTag(%d, %d) error = %v", versions[0], versions[1], err)
		}
		bindingVersion, tenantVersion, err := ParseEntityTag(tag)
		if err != nil || bindingVersion != versions[0] || tenantVersion != versions[1] {
			t.Fatalf(
				"ParseEntityTag(%q) = %d, %d, %v", tag, bindingVersion, tenantVersion, err,
			)
		}
	}
	for _, value := range []string{
		"", "v1-t1", "*", `W/"v1-t1"`, `"v0-t1"`, `"v1-t0"`, `"v01-t1"`,
		`"v1-t01"`, `"V1-t1"`, `"v1-T1"`, `"v1-t1 "`, ` "v1-t1"`,
		`"v1-t1","v2-t1"`, `"v1-t1"\t`, `"v1-t1-t2"`, `"v1x-t1"`,
		`"v2147483648-t1"`, `"v1-t2147483648"`,
	} {
		if _, _, err := ParseEntityTag(value); err == nil {
			t.Fatalf("ParseEntityTag(%q) succeeded", value)
		}
	}
}

func TestServiceBindingActivationCreatesExactEpochProjectionAndDeactivationClosesIt(t *testing.T) {
	providerID, tenantID, bindingID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	epochID := mustUUIDv7(t)
	repository := &bindingRepositoryStub{}
	service := mustService(t, repository)
	session := manageSession(t)

	draft := validBindingFixture(providerID, tenantID, bindingID, 2)
	draft.ActivationAvailable = true
	tag := mustEntityTag(t, 2, draft.Tenant.Version)
	repository.activate = func(_ context.Context, params ActivationParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.BindingID != bindingID ||
			params.ExpectedVersion != 2 || params.ExpectedTenantVersion != draft.Tenant.Version ||
			params.JITMode != JITModeCreate || params.NoMatchPolicy != NoMatchPolicyProviderAccessOnly ||
			params.Reason != "Enable tenant OIDC" || params.ValidateResult == nil {
			t.Fatalf("Activate() params = %#v", params)
		}
		active := cloneBinding(draft)
		active.Version = 3
		active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
		active.Enabled = true
		active.ActivationAvailable = false
		active.CurrentAccessEpochID = &epochID
		active.JITMode = JITModeCreate
		active.NoMatchPolicy = NoMatchPolicyProviderAccessOnly
		active.AuthRevision++
		return mustUpdateResult(t, active), nil
	}
	activated, err := service.Activate(
		context.Background(), session, providerID, bindingID,
		ActivateInput{
			JITMode: JITModeCreate, NoMatchPolicy: NoMatchPolicyProviderAccessOnly,
			Reason: " Enable tenant OIDC ", ExpectedEntityTag: &tag, Event: testEvent(t),
		},
	)
	if err != nil || !activated.Binding().Enabled || activated.Binding().CurrentAccessEpochID == nil ||
		*activated.Binding().CurrentAccessEpochID != epochID || activated.Version() != 3 {
		t.Fatalf("Activate() = %#v, %v", activated, err)
	}

	tag = mustEntityTag(t, 3, draft.Tenant.Version)
	repository.deactivate = func(_ context.Context, params DeactivationParams) (UpdateResult, error) {
		if params.ProviderID != providerID || params.BindingID != bindingID ||
			params.ExpectedVersion != 3 || params.ExpectedTenantVersion != draft.Tenant.Version ||
			params.Reason != "Disable tenant OIDC" || params.ValidateResult == nil {
			t.Fatalf("Deactivate() params = %#v", params)
		}
		disabled := cloneBinding(activated.Binding())
		disabled.Version = 4
		disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
		disabled.Enabled = false
		disabled.ActivationAvailable = true
		disabled.CurrentAccessEpochID = nil
		disabled.JITMode = JITModeDisabled
		disabled.NoMatchPolicy = NoMatchPolicyDeny
		disabled.AuthRevision++
		return mustUpdateResult(t, disabled), nil
	}
	deactivated, err := service.Deactivate(
		context.Background(), session, providerID, bindingID,
		DeactivateInput{
			Reason: " Disable tenant OIDC ", ExpectedEntityTag: &tag, Event: testEvent(t),
		},
	)
	if err != nil || deactivated.Binding().Enabled || deactivated.Binding().CurrentAccessEpochID != nil ||
		deactivated.Binding().JITMode != JITModeDisabled ||
		deactivated.Binding().NoMatchPolicy != NoMatchPolicyDeny || deactivated.Version() != 4 {
		t.Fatalf("Deactivate() = %#v, %v", deactivated, err)
	}
}

func TestServiceBindingDeactivationRejectsRetainedAdmissionPolicy(t *testing.T) {
	providerID, tenantID, bindingID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	epochID := mustUUIDv7(t)
	active := validBindingFixture(providerID, tenantID, bindingID, 3)
	active.Enabled = true
	active.CurrentAccessEpochID = &epochID
	active.JITMode = JITModeCreate
	active.NoMatchPolicy = NoMatchPolicyProviderAccessOnly

	repository := &bindingRepositoryStub{}
	repository.deactivate = func(_ context.Context, _ DeactivationParams) (UpdateResult, error) {
		poisoned := cloneBinding(active)
		poisoned.Version++
		poisoned.UpdatedAt = poisoned.UpdatedAt.Add(time.Microsecond)
		poisoned.Enabled = false
		poisoned.ActivationAvailable = true
		poisoned.CurrentAccessEpochID = nil
		poisoned.AuthRevision++
		return mustUpdateResult(t, poisoned), nil
	}
	service := mustService(t, repository)
	tag := mustEntityTag(t, active.Version, active.Tenant.Version)

	_, err := service.Deactivate(
		context.Background(), manageSession(t), providerID, bindingID,
		DeactivateInput{Reason: "Disable tenant OIDC", ExpectedEntityTag: &tag, Event: testEvent(t)},
	)
	if !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Deactivate() error = %v, want unavailable", err)
	}
}

type bindingRepositoryStub struct {
	calls      int
	list       func(context.Context, ListParams) ([]Binding, error)
	get        func(context.Context, GetParams) (Binding, error)
	create     func(context.Context, CreateParams) (CreateResult, error)
	update     func(context.Context, UpdateParams) (UpdateResult, error)
	archive    func(context.Context, ArchiveParams) (MutationReceipt, error)
	activate   func(context.Context, ActivationParams) (UpdateResult, error)
	deactivate func(context.Context, DeactivationParams) (UpdateResult, error)
	getError   error
}

func (repository *bindingRepositoryStub) Activate(ctx context.Context, params ActivationParams) (UpdateResult, error) {
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

func (repository *bindingRepositoryStub) Deactivate(ctx context.Context, params DeactivationParams) (UpdateResult, error) {
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

func (repository *bindingRepositoryStub) List(ctx context.Context, params ListParams) ([]Binding, error) {
	repository.calls++
	if repository.list != nil {
		return repository.list(ctx, params)
	}
	return nil, nil
}

func (repository *bindingRepositoryStub) Get(ctx context.Context, params GetParams) (Binding, error) {
	repository.calls++
	if repository.getError != nil {
		return Binding{}, repository.getError
	}
	if repository.get != nil {
		return repository.get(ctx, params)
	}
	return Binding{}, nil
}

func (repository *bindingRepositoryStub) Create(ctx context.Context, params CreateParams) (CreateResult, error) {
	repository.calls++
	if repository.create != nil {
		return repository.create(ctx, params)
	}
	return CreateResult{}, nil
}

func (repository *bindingRepositoryStub) Update(ctx context.Context, params UpdateParams) (UpdateResult, error) {
	repository.calls++
	if repository.update != nil {
		return repository.update(ctx, params)
	}
	return UpdateResult{}, nil
}

func (repository *bindingRepositoryStub) Archive(ctx context.Context, params ArchiveParams) (MutationReceipt, error) {
	repository.calls++
	if repository.archive != nil {
		return repository.archive(ctx, params)
	}
	return MutationReceipt{}, nil
}

func mustService(t testing.TB, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func manageSession(t testing.TB) authentication.Session {
	t.Helper()
	return authentication.Session{
		ID: mustUUIDv7(t), User: authentication.User{ID: mustUUIDv7(t)},
		Permissions: []authorization.Permission{
			authorization.PermissionPlatformIdentityBindingManage,
			authorization.PermissionPlatformIdentityBindingRead,
		},
		AuthenticationMethod: "passkey",
	}
}

func readSession(t testing.TB) authentication.Session {
	t.Helper()
	session := manageSession(t)
	session.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityBindingRead}
	return session
}

func testEvent(t testing.TB) authentication.EventContext {
	t.Helper()
	return authentication.EventContext{
		RequestID: mustUUIDv7(t), CorrelationID: mustUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("198.51.100.27"), UserAgent: "platform-binding-test/1",
	}
}

func validCreateInput(t testing.TB, tenantID uuid.UUID) CreateInput {
	t.Helper()
	return CreateInput{
		TenantID: tenantID, LoginKey: "corporate_login", ProfilePriority: 42,
		Reason: " Approved tenant admission ", IdempotencyKey: "platform-binding-create-0001",
		Event: testEvent(t),
	}
}

func validBindingFixture(providerID, tenantID, bindingID uuid.UUID, version int64) Binding {
	now := time.Date(2026, 8, 28, 10, 30, 0, 123_456_000, time.UTC)
	return Binding{
		ID: bindingID, ProviderID: providerID,
		Tenant: TenantSummary{
			ID: tenantID, Slug: "acme-security", Name: "Acme Security",
			Status: TenantStatusActive, Version: 11,
		},
		LoginKey: "corporate_login", ProfilePriority: 42,
		JITMode: JITModeDisabled, NoMatchPolicy: NoMatchPolicyDeny,
		AuthRevision: 1, MappingRevision: 1,
		Version: version, CreatedAt: now, UpdatedAt: now,
	}
}

func mustCreateResult(t testing.TB, bindingID uuid.UUID, replayed bool, binding Binding) CreateResult {
	t.Helper()
	result, err := RestoreCreateResult(CreateResultInput{
		BindingID: bindingID, Version: 1, Replayed: replayed, Binding: binding,
	})
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	return result
}

func mustUpdateResult(t testing.TB, binding Binding) UpdateResult {
	t.Helper()
	result, err := RestoreUpdateResult(UpdateResultInput{
		BindingID: binding.ID, Version: binding.Version, Binding: binding,
	})
	if err != nil {
		t.Fatalf("RestoreUpdateResult() error = %v", err)
	}
	return result
}

func mustMutationReceipt(
	t testing.TB,
	bindingID uuid.UUID,
	version, tenantVersion int64,
) MutationReceipt {
	t.Helper()
	receipt, err := RestoreMutationReceipt(MutationReceiptInput{
		BindingID: bindingID, Version: version, TenantVersion: tenantVersion,
	})
	if err != nil {
		t.Fatalf("RestoreMutationReceipt() error = %v", err)
	}
	return receipt
}

func mustEntityTag(t testing.TB, version, tenantVersion int64) string {
	t.Helper()
	tag, err := EntityTag(version, tenantVersion)
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

func largerUUIDv7(t testing.TB, lower uuid.UUID) uuid.UUID {
	t.Helper()
	for {
		candidate := mustUUIDv7(t)
		if bytes.Compare(candidate[:], lower[:]) > 0 {
			return candidate
		}
	}
}

func sha256For(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func pointer[T any](value T) *T { return &value }
