package customfields

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

func TestNewServiceFailsClosedWithoutRepository(t *testing.T) {
	t.Parallel()
	if _, err := NewService(nil); err == nil {
		t.Fatal("NewService(nil) succeeded")
	}
}

func TestCreateDefinitionRequiresTenantManageAndBindsIdempotency(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(1)
	actor := testActor(tenantID, PrincipalHuman)
	definitionInput := testDefinitionInput(t, tenantID, true)
	repository := &fakeRepository{
		resolveAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability) (Access, error) {
			if got != actor || gotTenant != tenantID || capability != CapabilityManage {
				t.Fatal("unexpected access request")
			}
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		createDefinition: func(_ context.Context, write DefinitionWrite) (DefinitionResult, error) {
			if write.Command.Operation != operationDefinitionCreate ||
				write.Command.KeyDigest != commandKeyDigest("definition-create-1") ||
				write.Command.RequestDigest == ([32]byte{}) {
				t.Fatal("idempotency key was not bound to the write")
			}
			if write.Actor != actor || write.Audit != actor.Audit || write.ExpectedVersion != 0 {
				t.Fatal("write lost actor, audit, or create precondition")
			}
			return DefinitionResult{Definition: write.Definition}, nil
		},
	}
	service := mustService(t, repository)
	result, err := service.CreateDefinition(context.Background(), actor, tenantID, CreateDefinitionInput{
		Definition: definitionInput, IdempotencyKey: "definition-create-1", Audit: actor.Audit,
	})
	if err != nil {
		t.Fatalf("CreateDefinition() error = %v", err)
	}
	if result.Definition.Key().String() != "triage_code" || result.Definition.SchemaVersion() != 1 {
		t.Fatalf("unexpected definition result: %s", result.Definition)
	}

	customer := testActor(tenantID, PrincipalCustomer)
	repository.resolveAccess = func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
		return Access{Audience: kernel.AudienceCustomer, Scope: ScopeTenant}, nil
	}
	if _, err := service.CreateDefinition(context.Background(), customer, tenantID, CreateDefinitionInput{
		Definition: definitionInput, IdempotencyKey: "definition-create-2", Audit: customer.Audit,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer CreateDefinition() error = %v, want forbidden", err)
	}
}

func TestCreateDefinitionRejectsMalformedRepositoryProjection(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(2)
	actor := testActor(tenantID, PrincipalHuman)
	input := testDefinitionInput(t, tenantID, true)
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		createDefinition: func(_ context.Context, write DefinitionWrite) (DefinitionResult, error) {
			drifted := input
			drifted.Label = "Drifted repository label"
			definition, err := kernel.NewDefinition(drifted)
			if err != nil {
				t.Fatal(err)
			}
			if sameDefinitionProjection(definition, write.Definition) {
				t.Fatal("test fixture did not drift")
			}
			return DefinitionResult{Definition: definition}, nil
		},
	}
	service := mustService(t, repository)
	_, err := service.CreateDefinition(context.Background(), actor, tenantID, CreateDefinitionInput{
		Definition: input, IdempotencyKey: "definition-projection-1", Audit: actor.Audit,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed repository projection error = %v", err)
	}
}

func TestListDefinitionsRejectsVisibilityAndTenantProjectionDrift(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(10)
	actor := testActor(tenantID, PrincipalCustomer)
	hiddenInput := testDefinitionInput(t, tenantID, false)
	hidden, err := kernel.NewDefinition(hiddenInput)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
			return Access{Audience: kernel.AudienceCustomer, Scope: ScopeTenant}, nil
		},
		listDefinitions: func(context.Context, uuid.UUID, DefinitionListInput, Access) (DefinitionPage, error) {
			return DefinitionPage{Items: []kernel.Definition{hidden}}, nil
		},
	}
	service := mustService(t, repository)
	_, err = service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{
		ObjectType: kernel.ObjectCase,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("visibility drift error = %v, want unavailable", err)
	}

	otherTenant := testUUID(11)
	otherInput := testDefinitionInput(t, otherTenant, true)
	other, err := kernel.NewDefinition(otherInput)
	if err != nil {
		t.Fatal(err)
	}
	repository.listDefinitions = func(context.Context, uuid.UUID, DefinitionListInput, Access) (DefinitionPage, error) {
		return DefinitionPage{Items: []kernel.Definition{other}}, nil
	}
	_, err = service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{
		ObjectType: kernel.ObjectCase,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-tenant projection error = %v, want unavailable", err)
	}
}

func TestDefinitionInventoryCompoundAccessPreservesAdministrativeAndReadOnlyProjections(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(12)
	actor := testActor(tenantID, PrincipalHuman)
	input := testDefinitionInput(t, tenantID, true)
	input.Visibility.Operator = false
	input.EditPolicy.OperatorCreate = false
	input.EditPolicy.OperatorUpdate = false
	customerOnly, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("read and manage can administer customer-only", func(t *testing.T) {
		repository := &fakeRepository{
			resolveDefinitionAccess: func(context.Context, Actor, uuid.UUID) (Access, error) {
				return Access{
					Audience: kernel.AudienceOperator, Scope: ScopeTenant,
					DefinitionInventory: true, Manage: true,
				}, nil
			},
			listDefinitions: func(_ context.Context, _ uuid.UUID, _ DefinitionListInput, access Access) (DefinitionPage, error) {
				if !access.DefinitionInventory || !access.Manage {
					t.Fatalf("administrative inventory access = %#v", access)
				}
				return DefinitionPage{Items: []kernel.Definition{customerOnly}}, nil
			},
			getDefinition: func(_ context.Context, _ uuid.UUID, _ kernel.ObjectType, _ kernel.EntityID, access Access) (kernel.Definition, error) {
				if !access.DefinitionInventory || !access.Manage {
					t.Fatalf("administrative definition access = %#v", access)
				}
				return customerOnly, nil
			},
		}
		service := mustService(t, repository)
		page, listErr := service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{ObjectType: kernel.ObjectCase})
		got, getErr := service.GetDefinition(context.Background(), actor, tenantID, kernel.ObjectCase, customerOnly.ID())
		if listErr != nil || getErr != nil || len(page.Items) != 1 || got.ID() != customerOnly.ID() {
			t.Fatalf("administrative customer-only inventory = (page=%#v, definition=%#v, listErr=%v, getErr=%v)", page, got, listErr, getErr)
		}
	})

	t.Run("read only remains audience filtered", func(t *testing.T) {
		repository := &fakeRepository{
			resolveDefinitionAccess: func(context.Context, Actor, uuid.UUID) (Access, error) {
				return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant, DefinitionInventory: true}, nil
			},
			listDefinitions: func(_ context.Context, _ uuid.UUID, _ DefinitionListInput, access Access) (DefinitionPage, error) {
				if access.Manage {
					t.Fatalf("read-only inventory was elevated: %#v", access)
				}
				return DefinitionPage{Items: []kernel.Definition{}}, nil
			},
			getDefinition: func(context.Context, uuid.UUID, kernel.ObjectType, kernel.EntityID, Access) (kernel.Definition, error) {
				return kernel.Definition{}, ErrRepositoryNotFound
			},
		}
		service := mustService(t, repository)
		page, listErr := service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{ObjectType: kernel.ObjectCase})
		_, getErr := service.GetDefinition(context.Background(), actor, tenantID, kernel.ObjectCase, customerOnly.ID())
		if listErr != nil || len(page.Items) != 0 || !errors.Is(getErr, ErrNotFound) {
			t.Fatalf("read-only customer-only inventory = (page=%#v, listErr=%v, getErr=%v)", page, listErr, getErr)
		}
	})

	t.Run("manage only cannot read inventory", func(t *testing.T) {
		calls := 0
		repository := &fakeRepository{
			resolveDefinitionAccess: func(context.Context, Actor, uuid.UUID) (Access, error) {
				return Access{}, ErrRepositoryForbidden
			},
			listDefinitions: func(context.Context, uuid.UUID, DefinitionListInput, Access) (DefinitionPage, error) {
				calls++
				return DefinitionPage{}, nil
			},
			getDefinition: func(context.Context, uuid.UUID, kernel.ObjectType, kernel.EntityID, Access) (kernel.Definition, error) {
				calls++
				return kernel.Definition{}, nil
			},
		}
		service := mustService(t, repository)
		_, listErr := service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{ObjectType: kernel.ObjectCase})
		_, getErr := service.GetDefinition(context.Background(), actor, tenantID, kernel.ObjectCase, customerOnly.ID())
		if !errors.Is(listErr, ErrForbidden) || !errors.Is(getErr, ErrForbidden) || calls != 0 {
			t.Fatalf("manage-only inventory = (listErr=%v, getErr=%v, calls=%d)", listErr, getErr, calls)
		}
	})
}

func TestReplaceDefinitionChecksCurrentVersionBeforeRepositoryMutation(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(20)
	actor := testActor(tenantID, PrincipalHuman)
	currentInput := testDefinitionInput(t, tenantID, true)
	current, err := kernel.NewDefinition(currentInput)
	if err != nil {
		t.Fatal(err)
	}
	mutated := false
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		getDefinition: func(context.Context, uuid.UUID, kernel.ObjectType, kernel.EntityID, Access) (kernel.Definition, error) {
			return current, nil
		},
		replaceDefinition: func(context.Context, DefinitionWrite) (DefinitionResult, error) {
			mutated = true
			return DefinitionResult{}, nil
		},
	}
	service := mustService(t, repository)
	next := currentInput
	next.SchemaVersion = 2
	next.Label = "Updated label"
	_, err = service.ReplaceDefinition(context.Background(), actor, tenantID, current.ID(), ReplaceDefinitionInput{
		Definition: next, ExpectedVersion: 9, IdempotencyKey: "definition-replace-1", Audit: actor.Audit,
	})
	if !errors.Is(err, ErrPreconditionFailed) || mutated {
		t.Fatalf("ReplaceDefinition() error = %v, mutated = %t", err, mutated)
	}
}

func TestValidateAndCommitObjectFieldsIsAllOrNothingAndAudienceBound(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(30)
	objectID := testUUID(31)
	actor := testActor(tenantID, PrincipalCustomer)
	definitionInput := testDefinitionInput(t, tenantID, true)
	definition, err := kernel.NewDefinition(definitionInput)
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	repository := &fakeRepository{
		resolveObjectWriteAccess: func(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error) {
			return Access{Audience: kernel.AudienceCustomer, Scope: ScopeTenant, Write: true}, nil
		},
		loadObjectFields: func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
			return []kernel.Definition{definition}, nil, 7, nil
		},
		commitObjectFields: func(_ context.Context, write ObjectFieldWrite) (ObjectWriteResult, error) {
			commits++
			if write.ExpectedVersion != 7 || len(write.Values) != 1 ||
				write.Command.Operation != operationValuesReplace ||
				write.Command.KeyDigest != commandKeyDigest("object-fields-0001") ||
				write.Command.RequestDigest == ([32]byte{}) {
				t.Fatal("invalid object field write")
			}
			return ObjectWriteResult{Values: write.Values, Version: 8}, nil
		},
	}
	service := mustService(t, repository)
	result, err := service.ValidateAndCommitObjectFields(context.Background(), actor, tenantID, ObjectWriteInput{
		ObjectType: kernel.ObjectCase, ObjectID: objectID, Phase: kernel.PhaseCreate,
		Fields:          []RawFieldInput{{Key: "triage_code", RawJSON: []byte(`"P1"`), Present: true}},
		ExpectedVersion: 7, IdempotencyKey: "object-fields-0001", Audit: actor.Audit,
	})
	if err != nil || result.Version != 8 || commits != 1 {
		t.Fatalf("ValidateAndCommitObjectFields() = (%+v, %v), commits = %d", result, err, commits)
	}

	_, err = service.ValidateAndCommitObjectFields(context.Background(), actor, tenantID, ObjectWriteInput{
		ObjectType: kernel.ObjectCase, ObjectID: objectID, Phase: kernel.PhaseCreate,
		Fields: []RawFieldInput{
			{Key: "triage_code", RawJSON: []byte(`"P1"`), Present: true},
			{Key: "triage_code", RawJSON: []byte(`"P2"`), Present: true},
		},
		ExpectedVersion: 7, IdempotencyKey: "object-fields-0002", Audit: actor.Audit,
	})
	var validationError *FieldValidationError
	if !errors.As(err, &validationError) || len(validationError.Fields) != 1 ||
		validationError.Fields[0].Code != "duplicate" || commits != 1 {
		t.Fatalf("duplicate validation error = %#v, commits = %d", err, commits)
	}
}

func TestCommitObjectFieldsRejectsValueProjectionDrift(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(32)
	objectID := testUUID(33)
	actor := testActor(tenantID, PrincipalCustomer)
	definition, err := kernel.NewDefinition(testDefinitionInput(t, tenantID, true))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		resolveObjectWriteAccess: func(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error) {
			return Access{Audience: kernel.AudienceCustomer, Scope: ScopeTenant, Write: true}, nil
		},
		loadObjectFields: func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
			return []kernel.Definition{definition}, nil, 3, nil
		},
		commitObjectFields: func(_ context.Context, write ObjectFieldWrite) (ObjectWriteResult, error) {
			drifted, fieldErrors, validationErr := kernel.ValidateSet(
				[]kernel.Definition{definition},
				[]kernel.FieldInput{{Key: definition.Key(), Value: kernel.JSONInputValue([]byte(`"P2"`))}},
				kernel.ValidationContext{
					TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
					Audience: kernel.AudienceCustomer, Phase: kernel.PhaseCreate,
				},
			)
			if validationErr != nil || len(fieldErrors) != 0 || sameFieldValueProjection(drifted, write.Values) {
				t.Fatal("failed to construct drifted persisted values")
			}
			return ObjectWriteResult{Values: drifted, Version: 4}, nil
		},
	}
	service := mustService(t, repository)
	_, err = service.ValidateAndCommitObjectFields(context.Background(), actor, tenantID, ObjectWriteInput{
		ObjectType: kernel.ObjectCase, ObjectID: objectID, Phase: kernel.PhaseCreate,
		Fields:          []RawFieldInput{{Key: "triage_code", RawJSON: []byte(`"P1"`), Present: true}},
		ExpectedVersion: 3, IdempotencyKey: "object-projection-1", Audit: actor.Audit,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("drifted persisted value error = %v", err)
	}
}

func TestUpdateObjectFieldsReplacesOnlyAuthorizedDetailEditProjection(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(36)
	objectID := testUUID(37)
	actor := testActor(tenantID, PrincipalHuman)
	visibleInput := testDefinitionInput(t, tenantID, true)
	visible, err := kernel.NewDefinition(visibleInput)
	if err != nil {
		t.Fatal(err)
	}
	hiddenInput := visibleInput
	hiddenInput.ID, err = kernel.ParseEntityID(testUUID(38).String())
	if err != nil {
		t.Fatal(err)
	}
	hiddenInput.Key, err = kernel.NewKey("hidden_update_value")
	if err != nil {
		t.Fatal(err)
	}
	hiddenInput.Placement.ShowInDetail = false
	hidden, err := kernel.NewDefinition(hiddenInput)
	if err != nil {
		t.Fatal(err)
	}
	definitions := []kernel.Definition{visible, hidden}
	existing, fieldErrors, err := kernel.ValidateSet(
		definitions,
		[]kernel.FieldInput{
			{Key: visible.Key(), Value: kernel.JSONInputValue([]byte(`"delete me"`))},
			{Key: hidden.Key(), Value: kernel.JSONInputValue([]byte(`"retain me"`))},
		},
		kernel.ValidationContext{
			TenantID: visible.TenantID(), ObjectType: visible.ObjectType(),
			Audience: kernel.AudienceOperator, Phase: kernel.PhaseUpdate,
		},
	)
	if err != nil || len(fieldErrors) != 0 || len(existing) != 2 {
		t.Fatalf("build existing values: err=%v fields=%v values=%d", err, fieldErrors, len(existing))
	}
	commits := 0
	repository := &fakeRepository{
		resolveObjectWriteAccess: func(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant, Write: true}, nil
		},
		loadObjectFields: func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
			return definitions, existing, 9, nil
		},
		commitObjectFields: func(_ context.Context, write ObjectFieldWrite) (ObjectWriteResult, error) {
			commits++
			if len(write.Values) != 1 || write.Values[0].DefinitionID() != hidden.ID() ||
				string(write.Values[0].Value().CanonicalJSON()) != `"retain me"` {
				t.Fatalf("replacement escaped authorized detail projection: %#v", write.Values)
			}
			return ObjectWriteResult{Values: write.Values, Version: 10}, nil
		},
	}
	result, err := mustService(t, repository).ValidateAndCommitObjectFields(
		context.Background(), actor, tenantID, ObjectWriteInput{
			ObjectType: kernel.ObjectCase, ObjectID: objectID, Phase: kernel.PhaseUpdate,
			Fields: nil, ExpectedVersion: 9, IdempotencyKey: "object-detail-replace-0001", Audit: actor.Audit,
		},
	)
	if err != nil || result.Version != 10 || len(result.Values) != 1 || result.Values[0].DefinitionID() != hidden.ID() {
		t.Fatalf("detail replacement = (%#v, %v)", result, err)
	}
	_, err = mustService(t, repository).ValidateAndCommitObjectFields(
		context.Background(), actor, tenantID, ObjectWriteInput{
			ObjectType: kernel.ObjectCase, ObjectID: objectID, Phase: kernel.PhaseUpdate,
			Fields: []RawFieldInput{{
				Key: "hidden_update_value", RawJSON: []byte(`"overwrite"`), Present: true,
			}},
			ExpectedVersion: 9, IdempotencyKey: "object-detail-replace-0002", Audit: actor.Audit,
		},
	)
	var validationError *FieldValidationError
	if !errors.As(err, &validationError) || len(validationError.Fields) != 1 ||
		validationError.Fields[0].Code != "unknown" || commits != 1 {
		t.Fatalf("hidden explicit update error=%#v commits=%d", err, commits)
	}
}

func TestUpdateObjectFieldsRejectsOversizedHiddenDefinitionProjection(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(39)
	actor := testActor(tenantID, PrincipalHuman)
	input := testDefinitionInput(t, tenantID, true)
	input.Placement.ShowInDetail = false
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	definitions := make([]kernel.Definition, maximumObjectFieldCount+1)
	for index := range definitions {
		definitions[index] = definition
	}
	commits := 0
	repository := &fakeRepository{
		resolveObjectWriteAccess: func(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant, Write: true}, nil
		},
		loadObjectFields: func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
			return definitions, nil, 1, nil
		},
		commitObjectFields: func(context.Context, ObjectFieldWrite) (ObjectWriteResult, error) {
			commits++
			return ObjectWriteResult{}, nil
		},
	}
	_, err = mustService(t, repository).ValidateAndCommitObjectFields(
		context.Background(), actor, tenantID, ObjectWriteInput{
			ObjectType: kernel.ObjectCase, ObjectID: testUUID(40), Phase: kernel.PhaseUpdate,
			ExpectedVersion: 1, IdempotencyKey: "object-hidden-bound-0001", Audit: actor.Audit,
		},
	)
	if !errors.Is(err, ErrUnavailable) || commits != 0 {
		t.Fatalf("oversized hidden projection error=%v commits=%d", err, commits)
	}
}

func TestProjectionOmitsDefinitionHiddenFromRequestedSurface(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(34)
	actor := testActor(tenantID, PrincipalHuman)
	input := testDefinitionInput(t, tenantID, true)
	input.Placement.ShowInDetail = false
	input.Placement.ShowInExport = true
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		loadObjectFields: func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
			return []kernel.Definition{definition}, nil, 1, nil
		},
	}
	service := mustService(t, repository)
	projection, err := service.ProjectObjectFields(context.Background(), actor, tenantID, ProjectionInput{
		ObjectType: kernel.ObjectCase, ObjectID: testUUID(35), Surface: kernel.SurfaceDetail,
	})
	if err != nil || len(projection.Definitions) != 0 || len(projection.Values) != 0 {
		t.Fatalf("hidden detail projection = (%+v, %v)", projection, err)
	}
}

func TestRepositoryErrorsAreRedactedAndMapped(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(40)
	actor := testActor(tenantID, PrincipalHuman)
	for name, testCase := range map[string]struct {
		repositoryError error
		want            error
	}{
		"forbidden":    {ErrRepositoryForbidden, ErrForbidden},
		"not found":    {ErrRepositoryNotFound, ErrNotFound},
		"conflict":     {ErrRepositoryConflict, ErrConflict},
		"precondition": {ErrRepositoryPrecondition, ErrPreconditionFailed},
		"unknown":      {errors.New("postgres: secret statement and customer value"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{
				resolveAccess: func(context.Context, Actor, uuid.UUID, Capability) (Access, error) {
					return Access{}, testCase.repositoryError
				},
			}
			service := mustService(t, repository)
			_, err := service.ListDefinitions(context.Background(), actor, tenantID, DefinitionListInput{
				ObjectType: kernel.ObjectCase,
			})
			if !errors.Is(err, testCase.want) || err.Error() != testCase.want.Error() {
				t.Fatalf("mapped error = %q, want %q", err, testCase.want)
			}
		})
	}
}

func TestStrongETagChangesWithDefinitionVersion(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(50)
	firstInput := testDefinitionInput(t, tenantID, true)
	first, err := kernel.NewDefinition(firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := firstInput
	secondInput.SchemaVersion = 2
	second, err := kernel.NewDefinition(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if StrongETag(first) == StrongETag(second) || StrongETag(first)[0] != '"' {
		t.Fatal("strong entity tag is not version-bound")
	}
}

func TestCommandBindingSeparatesKeyIdentityFromNormalizedPayload(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(51)
	first, err := kernel.NewDefinition(testDefinitionInput(t, tenantID, true))
	if err != nil {
		t.Fatal(err)
	}
	changedInput := testDefinitionInput(t, tenantID, true)
	changedInput.Label = "Changed label"
	changed, err := kernel.NewDefinition(changedInput)
	if err != nil {
		t.Fatal(err)
	}
	firstBinding, err := bindDefinitionCommand(operationDefinitionCreate, "definition-binding-0001", first)
	if err != nil {
		t.Fatal(err)
	}
	changedBinding, err := bindDefinitionCommand(operationDefinitionCreate, "definition-binding-0001", changed)
	if err != nil {
		t.Fatal(err)
	}
	if firstBinding.KeyDigest != changedBinding.KeyDigest || firstBinding.RequestDigest == changedBinding.RequestDigest {
		t.Fatal("same key with payload drift was not represented as an idempotency conflict")
	}
}

func TestPreserveNonEditableValuesRetainsHiddenStoredState(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(61)
	input := testDefinitionInput(t, tenantID, true)
	input.EditPolicy = kernel.EditPolicy{OperatorCreate: true, OperatorUpdate: true}
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	existing, fieldErrors, err := kernel.ValidateSet(
		[]kernel.Definition{definition},
		[]kernel.FieldInput{{Key: definition.Key(), Value: kernel.JSONInputValue([]byte(`"retained"`))}},
		kernel.ValidationContext{
			TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
			Audience: kernel.AudienceSystem, Phase: kernel.PhaseUpdate,
		},
	)
	if err != nil || len(fieldErrors) != 0 || len(existing) != 1 {
		t.Fatalf("build stored value: %v, fields=%v, count=%d", err, fieldErrors, len(existing))
	}
	retained, err := preserveNonEditableValues(
		[]kernel.Definition{definition}, existing, nil,
		kernel.AudienceCustomer, kernel.PhaseUpdate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || string(retained[0].Value().CanonicalJSON()) != `"retained"` {
		t.Fatalf("hidden value was not retained: %#v", retained)
	}
}

func TestPreserveNonEditableValuesRetainsOmittedEditableValueOutsideDetail(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(62)
	input := testDefinitionInput(t, tenantID, true)
	input.Placement.ShowInDetail = false
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	existing, fieldErrors, err := kernel.ValidateSet(
		[]kernel.Definition{definition},
		[]kernel.FieldInput{{Key: definition.Key(), Value: kernel.JSONInputValue([]byte(`"retained"`))}},
		kernel.ValidationContext{
			TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
			Audience: kernel.AudienceOperator, Phase: kernel.PhaseUpdate,
		},
	)
	if err != nil || len(fieldErrors) != 0 || len(existing) != 1 {
		t.Fatalf("build stored value: %v, fields=%v, count=%d", err, fieldErrors, len(existing))
	}
	retained, err := preserveNonEditableValues(
		[]kernel.Definition{definition}, existing, nil,
		kernel.AudienceOperator, kernel.PhaseUpdate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || string(retained[0].Value().CanonicalJSON()) != `"retained"` {
		t.Fatalf("editable value outside detail was not retained: %#v", retained)
	}

	transitionValues, err := preserveNonEditableValues(
		[]kernel.Definition{definition}, existing, nil,
		kernel.AudienceOperator, kernel.PhaseTransition,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(transitionValues) != 0 {
		t.Fatalf("detail projection leaked into transition semantics: %#v", transitionValues)
	}
}

func TestObjectValueCommandBindingDistinguishesMissingFromExplicitNull(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(63)
	input := testDefinitionInput(t, tenantID, true)
	input.Nullable = true
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	nullValues, fieldErrors, err := kernel.ValidateSet(
		[]kernel.Definition{definition},
		[]kernel.FieldInput{{Key: definition.Key(), Value: kernel.NullInputValue()}},
		kernel.ValidationContext{
			TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
			Audience: kernel.AudienceOperator, Phase: kernel.PhaseUpdate,
		},
	)
	if err != nil || len(fieldErrors) != 0 || len(nullValues) != 1 {
		t.Fatalf("validate null: %v, fields=%v, count=%d", err, fieldErrors, len(nullValues))
	}
	base := ObjectFieldWrite{
		TenantID: tenantID, ObjectType: definition.ObjectType(), ObjectID: testUUID(64),
		ExpectedVersion: 7,
	}
	missing, err := bindObjectValues("values-null-binding", base)
	if err != nil {
		t.Fatal(err)
	}
	base.Values = nullValues
	explicitNull, err := bindObjectValues("values-null-binding", base)
	if err != nil {
		t.Fatal(err)
	}
	if missing.KeyDigest != explicitNull.KeyDigest || missing.RequestDigest == explicitNull.RequestDigest {
		t.Fatal("command binding collapsed omitted and explicit-null values")
	}
}

func TestPreserveNonEditableValuesRejectsDuplicateStoredProjection(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(65)
	input := testDefinitionInput(t, tenantID, true)
	input.Placement.ShowInDetail = false
	definition, err := kernel.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	existing, fieldErrors, err := kernel.ValidateSet(
		[]kernel.Definition{definition},
		[]kernel.FieldInput{{Key: definition.Key(), Value: kernel.JSONInputValue([]byte(`"retained"`))}},
		kernel.ValidationContext{
			TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
			Audience: kernel.AudienceOperator, Phase: kernel.PhaseUpdate,
		},
	)
	if err != nil || len(fieldErrors) != 0 || len(existing) != 1 {
		t.Fatalf("build stored value: %v, fields=%v, count=%d", err, fieldErrors, len(existing))
	}
	if _, err := preserveNonEditableValues(
		[]kernel.Definition{definition},
		[]kernel.FieldValue{existing[0], existing[0]}, nil,
		kernel.AudienceOperator, kernel.PhaseUpdate,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate stored projection error = %v", err)
	}
}

type fakeRepository struct {
	resolveAccess            func(context.Context, Actor, uuid.UUID, Capability) (Access, error)
	resolveDefinitionAccess  func(context.Context, Actor, uuid.UUID) (Access, error)
	listDefinitions          func(context.Context, uuid.UUID, DefinitionListInput, Access) (DefinitionPage, error)
	getDefinition            func(context.Context, uuid.UUID, kernel.ObjectType, kernel.EntityID, Access) (kernel.Definition, error)
	inspectDefinitionUpdate  func(context.Context, uuid.UUID, kernel.Definition, kernel.DefinitionInput, uint64) (kernel.DefinitionUpdateState, error)
	createDefinition         func(context.Context, DefinitionWrite) (DefinitionResult, error)
	replaceDefinition        func(context.Context, DefinitionWrite) (DefinitionResult, error)
	archiveDefinition        func(context.Context, DefinitionArchive) (DefinitionResult, error)
	resolveObjectWriteAccess func(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error)
	loadObjectFields         func(context.Context, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error)
	commitObjectFields       func(context.Context, ObjectFieldWrite) (ObjectWriteResult, error)
}

func (repository *fakeRepository) ResolveAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability) (Access, error) {
	if repository.resolveAccess == nil {
		return Access{}, ErrRepositoryForbidden
	}
	return repository.resolveAccess(ctx, actor, tenantID, capability)
}

func (repository *fakeRepository) ResolveDefinitionInventoryAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
) (Access, error) {
	if repository.resolveDefinitionAccess != nil {
		return repository.resolveDefinitionAccess(ctx, actor, tenantID)
	}
	access, err := repository.ResolveAccess(ctx, actor, tenantID, CapabilityRead)
	if err == nil {
		access.DefinitionInventory = true
	}
	return access, err
}

func (repository *fakeRepository) ListDefinitions(ctx context.Context, _ Actor, tenantID uuid.UUID, input DefinitionListInput, access Access) (DefinitionPage, error) {
	return repository.listDefinitions(ctx, tenantID, input, access)
}

func (repository *fakeRepository) GetDefinition(ctx context.Context, _ Actor, tenantID uuid.UUID, objectType kernel.ObjectType, id kernel.EntityID, access Access) (kernel.Definition, error) {
	return repository.getDefinition(ctx, tenantID, objectType, id, access)
}

func (repository *fakeRepository) InspectDefinitionUpdate(
	ctx context.Context,
	_ Actor,
	tenantID uuid.UUID,
	definition kernel.Definition,
	proposed kernel.DefinitionInput,
	expectedVersion uint64,
) (kernel.DefinitionUpdateState, error) {
	return repository.inspectDefinitionUpdate(ctx, tenantID, definition, proposed, expectedVersion)
}

func (repository *fakeRepository) CreateDefinition(ctx context.Context, write DefinitionWrite) (DefinitionResult, error) {
	return repository.createDefinition(ctx, write)
}

func (repository *fakeRepository) ReplaceDefinition(ctx context.Context, write DefinitionWrite) (DefinitionResult, error) {
	return repository.replaceDefinition(ctx, write)
}

func (repository *fakeRepository) ArchiveDefinition(ctx context.Context, write DefinitionArchive) (DefinitionResult, error) {
	return repository.archiveDefinition(ctx, write)
}

func (repository *fakeRepository) ResolveObjectWriteAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, objectType kernel.ObjectType, objectID uuid.UUID) (Access, error) {
	return repository.resolveObjectWriteAccess(ctx, actor, tenantID, objectType, objectID)
}

func (repository *fakeRepository) LoadObjectFields(ctx context.Context, _ Actor, tenantID uuid.UUID, objectType kernel.ObjectType, objectID uuid.UUID, access Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
	return repository.loadObjectFields(ctx, tenantID, objectType, objectID, access)
}

func (repository *fakeRepository) CommitObjectFields(ctx context.Context, write ObjectFieldWrite) (ObjectWriteResult, error) {
	return repository.commitObjectFields(ctx, write)
}

func mustService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testDefinitionInput(t *testing.T, tenantID uuid.UUID, customerVisible bool) kernel.DefinitionInput {
	t.Helper()
	definitionID, err := kernel.ParseEntityID(testUUID(90).String())
	if err != nil {
		t.Fatal(err)
	}
	kernelTenant, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := kernel.NewKey("triage_code")
	if err != nil {
		t.Fatal(err)
	}
	return kernel.DefinitionInput{
		ID: definitionID, TenantID: kernelTenant, ObjectType: kernel.ObjectCase,
		Key: key, Label: "Triage code", DataType: kernel.TypeShortText,
		Visibility: kernel.Visibility{Customer: customerVisible, Operator: true},
		EditPolicy: kernel.EditPolicy{
			CustomerCreate: customerVisible, CustomerUpdate: customerVisible,
			OperatorCreate: true, OperatorUpdate: true,
		},
		Placement:     kernel.Placement{ShowInCreate: true, ShowInDetail: true},
		SchemaVersion: 1,
	}
}

func testActor(tenantID uuid.UUID, kind PrincipalKind) Actor {
	audit := AuditContext{
		RequestID: testUUID(70), CorrelationID: testUUID(71),
		IPAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "phase4-test",
		AuthenticationMethod: "password",
	}
	return Actor{
		TenantID: tenantID, UserID: testUUID(72), SessionID: testUUID(74), ActiveTenantID: tenantID,
		MembershipID: testUUID(73), AuthenticationMethod: "password", Kind: kind, Audit: audit,
	}
}

func testUUID(seed byte) uuid.UUID {
	value := uuid.UUID{0x01, 0x9d, 0x01, 0x00, 0x00, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
	return value
}

func commandKeyDigest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}
