package customfields

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

type Service struct {
	repository Repository
}

const maximumObjectFieldCount = 512

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("custom-field repository is required")
	}
	return &Service{repository: repository}, nil
}

func (service *Service) ListDefinitions(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input DefinitionListInput,
) (DefinitionPage, error) {
	if !validActor(actor, tenantID) {
		return DefinitionPage{}, ErrForbidden
	}
	input, err := normalizeListInput(input)
	if err != nil {
		return DefinitionPage{}, err
	}
	access, err := service.repository.ResolveDefinitionInventoryAccess(ctx, actor, tenantID)
	if err != nil {
		return DefinitionPage{}, repositoryError(err)
	}
	if !validDefinitionInventoryAccess(actor, access) {
		return DefinitionPage{}, ErrForbidden
	}
	page, err := service.repository.ListDefinitions(ctx, actor, tenantID, input, access)
	if err != nil {
		return DefinitionPage{}, repositoryError(err)
	}
	if len(page.Items) > input.Limit || page.NextCursor != "" && !cursorPattern.MatchString(page.NextCursor) {
		return DefinitionPage{}, ErrUnavailable
	}
	seen := make(map[kernel.EntityID]struct{}, len(page.Items))
	for _, definition := range page.Items {
		archivedProjectionAllowed := input.IncludeArchived && definition.Archived() &&
			actor.Kind == PrincipalHuman && (access.Manage || definition.Visibility().Operator)
		if definition.TenantID().String() != tenantID.String() || definition.ObjectType() != input.ObjectType ||
			!definition.Archived() && !access.Manage && !definition.VisibleTo(access.Audience) ||
			definition.Archived() && !archivedProjectionAllowed {
			return DefinitionPage{}, ErrUnavailable
		}
		if _, duplicate := seen[definition.ID()]; duplicate {
			return DefinitionPage{}, ErrUnavailable
		}
		seen[definition.ID()] = struct{}{}
	}
	page.Items = slices.Clone(page.Items)
	return page, nil
}

func (service *Service) GetDefinition(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	id kernel.EntityID,
) (kernel.Definition, error) {
	if !validActor(actor, tenantID) || objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase {
		return kernel.Definition{}, ErrForbidden
	}
	access, err := service.repository.ResolveDefinitionInventoryAccess(ctx, actor, tenantID)
	if err != nil {
		return kernel.Definition{}, repositoryError(err)
	}
	if !validDefinitionInventoryAccess(actor, access) {
		return kernel.Definition{}, ErrForbidden
	}
	definition, err := service.repository.GetDefinition(ctx, actor, tenantID, objectType, id, access)
	if err != nil {
		return kernel.Definition{}, repositoryError(err)
	}
	if !validDefinitionProjection(definition, tenantID, objectType, id) {
		return kernel.Definition{}, ErrUnavailable
	}
	if !access.Manage && !definition.VisibleTo(access.Audience) {
		return kernel.Definition{}, ErrNotFound
	}
	return definition, nil
}

func (service *Service) CreateDefinition(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input CreateDefinitionInput,
) (DefinitionResult, error) {
	if err := validateMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil {
		return DefinitionResult{}, err
	}
	if err := service.requireManage(ctx, actor, tenantID); err != nil {
		return DefinitionResult{}, err
	}
	definition, err := kernel.NewDefinition(input.Definition)
	if err != nil || definition.TenantID().String() != tenantID.String() ||
		definition.SchemaVersion() != 1 || definition.Archived() {
		return DefinitionResult{}, ErrInvalidInput
	}
	command, err := bindDefinitionCommand(operationDefinitionCreate, input.IdempotencyKey, definition)
	if err != nil {
		return DefinitionResult{}, err
	}
	result, err := service.repository.CreateDefinition(ctx, DefinitionWrite{
		Actor: actor, Definition: definition, ExpectedVersion: 0,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if !sameDefinitionProjection(result.Definition, definition) {
		return DefinitionResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceDefinition(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
	input ReplaceDefinitionInput,
) (DefinitionResult, error) {
	if err := validateMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		input.ExpectedVersion == 0 {
		if err != nil {
			return DefinitionResult{}, err
		}
		return DefinitionResult{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID); err != nil {
		return DefinitionResult{}, err
	}
	manageAccess := Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant, Manage: true}
	current, err := service.repository.GetDefinition(ctx, actor, tenantID, input.Definition.ObjectType, id, manageAccess)
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if !validDefinitionProjection(current, tenantID, input.Definition.ObjectType, id) {
		return DefinitionResult{}, ErrUnavailable
	}
	if current.SchemaVersion() != input.ExpectedVersion {
		return DefinitionResult{}, ErrPreconditionFailed
	}
	state, err := service.repository.InspectDefinitionUpdate(
		ctx, actor, tenantID, current, input.Definition, input.ExpectedVersion,
	)
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if state.ExpectedSchemaVersion != input.ExpectedVersion {
		return DefinitionResult{}, ErrUnavailable
	}
	next, err := kernel.UpdateDefinition(current, input.Definition, state)
	if err != nil {
		if errors.Is(err, kernel.ErrDefinitionConflict) {
			return DefinitionResult{}, ErrPreconditionFailed
		}
		if errors.Is(err, kernel.ErrMigrationRequired) {
			return DefinitionResult{}, ErrConflict
		}
		return DefinitionResult{}, ErrInvalidInput
	}
	command, err := bindDefinitionCommand(operationDefinitionReplace, input.IdempotencyKey, next)
	if err != nil {
		return DefinitionResult{}, err
	}
	result, err := service.repository.ReplaceDefinition(ctx, DefinitionWrite{
		Actor: actor, Definition: next, ExpectedVersion: input.ExpectedVersion,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if !sameDefinitionProjection(result.Definition, next) {
		return DefinitionResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ArchiveDefinition(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	id kernel.EntityID,
	input ArchiveDefinitionInput,
) (DefinitionResult, error) {
	if err := validateMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		input.ExpectedVersion == 0 || !validReason(input.Reason) {
		if err != nil {
			return DefinitionResult{}, err
		}
		return DefinitionResult{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID); err != nil {
		return DefinitionResult{}, err
	}
	access := Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant, Manage: true}
	current, err := service.repository.GetDefinition(ctx, actor, tenantID, objectType, id, access)
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if !validDefinitionProjection(current, tenantID, objectType, id) {
		return DefinitionResult{}, ErrUnavailable
	}
	if current.SchemaVersion() != input.ExpectedVersion {
		return DefinitionResult{}, ErrPreconditionFailed
	}
	archiveInput := definitionInput(current)
	archiveInput.Required = false
	archiveInput.RequiredOnTransitions = nil
	archiveInput.EditPolicy = kernel.EditPolicy{}
	archiveInput.Placement.ShowInCreate = false
	archiveInput.Archived = true
	archiveInput.SchemaVersion++
	archived, err := kernel.UpdateDefinition(current, archiveInput, kernel.DefinitionUpdateState{
		ExpectedSchemaVersion: input.ExpectedVersion,
	})
	if err != nil {
		return DefinitionResult{}, ErrInvalidInput
	}
	command, err := bindDefinitionArchive(input.IdempotencyKey, archived, input.ExpectedVersion, input.Reason)
	if err != nil {
		return DefinitionResult{}, err
	}
	result, err := service.repository.ArchiveDefinition(ctx, DefinitionArchive{
		Actor: actor, Current: current, Archived: archived, ExpectedVersion: input.ExpectedVersion,
		Reason: input.Reason, Command: command, Audit: input.Audit,
	})
	if err != nil {
		return DefinitionResult{}, repositoryError(err)
	}
	if !sameDefinitionProjection(result.Definition, archived) {
		return DefinitionResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ValidateAndCommitObjectFields(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ObjectWriteInput,
) (ObjectWriteResult, error) {
	if err := validateMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		input.ObjectID == uuid.Nil || input.ExpectedVersion == 0 || len(input.Fields) > maximumObjectFieldCount {
		if err != nil {
			return ObjectWriteResult{}, err
		}
		return ObjectWriteResult{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveObjectWriteAccess(
		ctx, actor, tenantID, input.ObjectType, input.ObjectID,
	)
	if err != nil {
		return ObjectWriteResult{}, repositoryError(err)
	}
	if !validWriteAccess(actor, access) {
		return ObjectWriteResult{}, ErrForbidden
	}
	definitions, existingValues, currentVersion, err := service.repository.LoadObjectFields(
		ctx, actor, tenantID, input.ObjectType, input.ObjectID, access,
	)
	if err != nil {
		return ObjectWriteResult{}, repositoryError(err)
	}
	if len(definitions) > maximumObjectFieldCount || len(existingValues) > maximumObjectFieldCount {
		return ObjectWriteResult{}, ErrUnavailable
	}
	if currentVersion != input.ExpectedVersion || currentVersion == 0 {
		return ObjectWriteResult{}, ErrPreconditionFailed
	}
	fields, transition, err := parseFieldInputs(input.Fields, input.Phase, input.TransitionKey)
	if err != nil {
		return ObjectWriteResult{}, err
	}
	kernelTenant, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		return ObjectWriteResult{}, ErrInvalidInput
	}
	validationDefinitions := definitions
	if input.Phase == kernel.PhaseUpdate {
		validationDefinitions = make([]kernel.Definition, 0, len(definitions))
		for _, definition := range definitions {
			if definition.VisibleOn(access.Audience, kernel.SurfaceDetail) {
				validationDefinitions = append(validationDefinitions, definition)
			}
		}
	}
	values, fieldErrors, err := kernel.ValidateSet(validationDefinitions, fields, kernel.ValidationContext{
		TenantID: kernelTenant, ObjectType: input.ObjectType, Audience: access.Audience,
		Phase: input.Phase, TransitionKey: transition,
	})
	if err != nil {
		return ObjectWriteResult{}, ErrInvalidInput
	}
	if len(fieldErrors) != 0 {
		return ObjectWriteResult{}, &FieldValidationError{Fields: slices.Clone(fieldErrors)}
	}
	values, err = preserveNonEditableValues(definitions, existingValues, values, access.Audience, input.Phase)
	if err != nil {
		return ObjectWriteResult{}, ErrUnavailable
	}
	write := ObjectFieldWrite{
		Actor: actor, TenantID: tenantID, ObjectType: input.ObjectType, ObjectID: input.ObjectID,
		ExpectedVersion: input.ExpectedVersion, Values: values,
		Audit: input.Audit,
	}
	write.Command, err = bindObjectValues(input.IdempotencyKey, write)
	if err != nil {
		return ObjectWriteResult{}, err
	}
	result, err := service.repository.CommitObjectFields(ctx, write)
	if err != nil {
		return ObjectWriteResult{}, repositoryError(err)
	}
	if result.Version != input.ExpectedVersion+1 || !sameFieldValueProjection(result.Values, values) {
		return ObjectWriteResult{}, ErrUnavailable
	}
	return result, nil
}

func preserveNonEditableValues(
	definitions []kernel.Definition,
	existing []kernel.FieldValue,
	validated []kernel.FieldValue,
	audience kernel.Audience,
	phase kernel.WritePhase,
) ([]kernel.FieldValue, error) {
	definitionsByID := make(map[kernel.EntityID]kernel.Definition, len(definitions))
	definitionKeys := make(map[kernel.Key]struct{}, len(definitions))
	for _, definition := range definitions {
		if _, duplicate := definitionsByID[definition.ID()]; duplicate {
			return nil, ErrUnavailable
		}
		if _, duplicate := definitionKeys[definition.Key()]; duplicate {
			return nil, ErrUnavailable
		}
		definitionsByID[definition.ID()] = definition
		definitionKeys[definition.Key()] = struct{}{}
	}
	result := slices.Clone(validated)
	validatedIDs := make(map[kernel.EntityID]struct{}, len(validated))
	for _, value := range validated {
		if _, duplicate := validatedIDs[value.DefinitionID()]; duplicate {
			return nil, ErrUnavailable
		}
		validatedIDs[value.DefinitionID()] = struct{}{}
	}
	existingIDs := make(map[kernel.EntityID]struct{}, len(existing))
	for _, value := range existing {
		definition, found := definitionsByID[value.DefinitionID()]
		if !found || definition.TenantID() != value.TenantID() ||
			definition.ObjectType() != value.ObjectType() || definition.Key() != value.Key() ||
			definition.SchemaVersion() != value.SchemaVersion() {
			return nil, ErrUnavailable
		}
		if _, duplicate := existingIDs[value.DefinitionID()]; duplicate {
			return nil, ErrUnavailable
		}
		existingIDs[value.DefinitionID()] = struct{}{}
		if _, replaced := validatedIDs[value.DefinitionID()]; replaced {
			continue
		}
		// PhaseUpdate replaces the caller's authorized detail-edit projection,
		// not every stored value. A definition hidden from that projection can
		// still be update-editable, so omission must not erase its value.
		preserveOutsideDetail := phase == kernel.PhaseUpdate &&
			!definition.VisibleOn(audience, kernel.SurfaceDetail)
		if !definition.CanEdit(audience, phase) || preserveOutsideDetail {
			result = append(result, value)
		}
	}
	slices.SortFunc(result, func(left, right kernel.FieldValue) int {
		if left.Key().String() < right.Key().String() {
			return -1
		}
		if left.Key().String() > right.Key().String() {
			return 1
		}
		return 0
	})
	return result, nil
}

func (service *Service) ProjectObjectFields(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ProjectionInput,
) (Projection, error) {
	if !validActor(actor, tenantID) || input.ObjectID == uuid.Nil {
		return Projection{}, ErrForbidden
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, CapabilityRead)
	if err != nil {
		return Projection{}, repositoryError(err)
	}
	if !validReadAccess(actor, access) || access.Audience == kernel.AudienceSystem {
		return Projection{}, ErrForbidden
	}
	definitions, values, version, err := service.repository.LoadObjectFields(
		ctx, actor, tenantID, input.ObjectType, input.ObjectID, access,
	)
	if err != nil {
		return Projection{}, repositoryError(err)
	}
	kernelTenant, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		return Projection{}, ErrInvalidInput
	}
	projected, err := kernel.ProjectValues(
		definitions, values, kernelTenant, input.ObjectType, access.Audience, input.Surface,
	)
	if err != nil {
		return Projection{}, ErrUnavailable
	}
	visibleDefinitions := make([]kernel.Definition, 0, len(definitions))
	for _, definition := range definitions {
		if definition.VisibleOn(access.Audience, input.Surface) {
			visibleDefinitions = append(visibleDefinitions, definition)
		}
	}
	if version == 0 {
		return Projection{}, ErrUnavailable
	}
	return Projection{Definitions: visibleDefinitions, Values: projected, Version: version}, nil
}

func (service *Service) requireManage(ctx context.Context, actor Actor, tenantID uuid.UUID) error {
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, CapabilityManage)
	if err != nil {
		return repositoryError(err)
	}
	if actor.Kind != PrincipalHuman || access.Audience != kernel.AudienceOperator || access.Scope != ScopeTenant {
		return ErrForbidden
	}
	return nil
}

func validateMutationEnvelope(actor Actor, tenantID uuid.UUID, key string, audit AuditContext) error {
	if !validActor(actor, tenantID) {
		return ErrForbidden
	}
	if !validIdempotencyKey(key) || !validAudit(audit) || actor.Audit != (AuditContext{}) && actor.Audit != audit {
		return ErrInvalidInput
	}
	return nil
}

func validReadAccess(actor Actor, access Access) bool {
	return access.Scope == ScopeTenant &&
		(actor.Kind == PrincipalHuman && access.Audience == kernel.AudienceOperator ||
			actor.Kind == PrincipalCustomer && access.Audience == kernel.AudienceCustomer)
}

func validDefinitionInventoryAccess(actor Actor, access Access) bool {
	return access.DefinitionInventory && validReadAccess(actor, access) &&
		(!access.Manage || actor.Kind == PrincipalHuman && access.Audience == kernel.AudienceOperator)
}

func validWriteAccess(actor Actor, access Access) bool {
	validScope := access.Scope == ScopeAssigned || access.Scope == ScopeOperatorTeam || access.Scope == ScopeTenant
	return access.Write && validScope &&
		(actor.Kind == PrincipalHuman && access.Audience == kernel.AudienceOperator ||
			actor.Kind == PrincipalCustomer && access.Audience == kernel.AudienceCustomer)
}

func validDefinitionProjection(
	definition kernel.Definition,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	id kernel.EntityID,
) bool {
	return definition.TenantID().String() == tenantID.String() &&
		definition.ObjectType() == objectType && definition.ID() == id &&
		definition.SchemaVersion() > 0
}

func sameDefinitionIdentity(left, right kernel.Definition) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() &&
		left.ObjectType() == right.ObjectType() && left.Key() == right.Key()
}

func parseFieldInputs(
	inputs []RawFieldInput,
	phase kernel.WritePhase,
	transitionValue string,
) ([]kernel.FieldInput, kernel.Key, error) {
	var transition kernel.Key
	var err error
	if phase == kernel.PhaseTransition {
		transition, err = kernel.NewKey(transitionValue)
		if err != nil {
			return nil, kernel.Key{}, ErrInvalidInput
		}
	} else if transitionValue != "" {
		return nil, kernel.Key{}, ErrInvalidInput
	}
	result := make([]kernel.FieldInput, len(inputs))
	for index, input := range inputs {
		key, keyErr := kernel.NewKey(input.Key)
		if keyErr != nil || !input.Present && len(input.RawJSON) != 0 ||
			input.Present && (len(input.RawJSON) == 0 || !json.Valid(input.RawJSON)) {
			return nil, kernel.Key{}, ErrInvalidInput
		}
		value := kernel.MissingInputValue()
		if input.Present {
			value = kernel.JSONInputValue(input.RawJSON)
		}
		result[index] = kernel.FieldInput{Key: key, Value: value}
	}
	return result, transition, nil
}

func definitionInput(definition kernel.Definition) kernel.DefinitionInput {
	options := definition.Options()
	optionInputs := make([]kernel.OptionInput, len(options))
	for index, option := range options {
		optionInputs[index] = kernel.OptionInput{
			ID: option.ID(), Key: option.Key(), Label: option.Label(),
			Position: option.Position(), Archived: option.Archived(),
		}
	}
	defaultValue := kernel.MissingInputValue()
	if definition.Default().Presence() != kernel.PresenceMissing {
		defaultValue = kernel.JSONInputValue(definition.Default().CanonicalJSON())
	}
	constraints := definition.Constraints()
	return kernel.DefinitionInput{
		ID: definition.ID(), TenantID: definition.TenantID(), ObjectType: definition.ObjectType(),
		Key: definition.Key(), Label: definition.Label(), Description: definition.Description(),
		DataType: definition.DataType(), Required: definition.Required(), Nullable: definition.Nullable(),
		Default: defaultValue, Constraints: kernel.ConstraintsInput{
			MinimumLength: constraints.MinimumLength(), MaximumLength: constraints.MaximumLength(),
			Minimum: constraints.Minimum(), Maximum: constraints.Maximum(), Pattern: constraints.Pattern(),
		},
		Options: optionInputs, Visibility: definition.Visibility(), EditPolicy: definition.EditPolicy(),
		Placement: definition.Placement(), RequiredOnTransitions: definition.RequiredOnTransitions(),
		Searchable: definition.Searchable(), Filterable: definition.Filterable(), Sortable: definition.Sortable(),
		AllowStructuredJSON: definition.AllowStructuredJSON(), Archived: definition.Archived(),
		SchemaVersion: definition.SchemaVersion(),
	}
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrRepositoryForbidden):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict):
		return ErrConflict
	case errors.Is(err, ErrRepositoryPrecondition):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
