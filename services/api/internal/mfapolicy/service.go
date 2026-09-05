package mfapolicy

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type TenantAuthorityResolver interface {
	GetTenantAuthority(
		context.Context,
		authorization.Actor,
		uuid.UUID,
	) (authorization.TenantAuthority, error)
}

type Service struct {
	repository Repository
	authority  TenantAuthorityResolver
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	now        func() time.Time
}

func NewService(repository Repository, authority TenantAuthorityResolver) (*Service, error) {
	if interfaceIsNil(repository) || interfaceIsNil(authority) {
		return nil, errors.New("MFA policy repository and tenant authority resolver are required")
	}
	return &Service{
		repository: repository,
		authority:  authority,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		now:        time.Now,
	}, nil
}

func (service *Service) ListPlatform(
	ctx context.Context,
	session authentication.Session,
	input ListInput,
) (Page, error) {
	if err := service.requirePlatform(ctx, session, authorization.PermissionPlatformIdentityPolicyRead); err != nil {
		return Page{}, err
	}
	input, err := normalizeListInput(input)
	if err != nil {
		return Page{}, err
	}
	rows, err := service.repository.ListPlatform(ctx, ListParams{
		SessionParams: sessionParams(session), After: cloneCursor(input.After),
		Limit: int32(input.Limit + 1), IncludeRetired: input.IncludeRetired,
	})
	if err != nil {
		return Page{}, mapDependencyError(err)
	}
	return buildPage(rows, uuid.Nil, input)
}

func (service *Service) ListTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input ListInput,
) (Page, error) {
	if err := service.requireTenant(ctx, session, tenantID, authorization.TenantPermissionIdentityPolicyRead); err != nil {
		return Page{}, err
	}
	input, err := normalizeListInput(input)
	if err != nil {
		return Page{}, err
	}
	rows, err := service.repository.ListTenant(ctx, ListParams{
		SessionParams: sessionParams(session), TenantID: tenantID, After: cloneCursor(input.After),
		Limit: int32(input.Limit + 1), IncludeRetired: input.IncludeRetired,
	})
	if err != nil {
		return Page{}, mapDependencyError(err)
	}
	return buildPage(rows, tenantID, input)
}

func (service *Service) GetPlatform(
	ctx context.Context,
	session authentication.Session,
	policyID uuid.UUID,
	revision int64,
) (mfa.PolicyDocument, error) {
	if err := service.requirePlatform(ctx, session, authorization.PermissionPlatformIdentityPolicyRead); err != nil {
		return mfa.PolicyDocument{}, err
	}
	if !validUUIDv7(policyID) || !validRevision(revision) {
		return mfa.PolicyDocument{}, ErrInvalidInput
	}
	document, err := service.repository.GetPlatform(ctx, GetParams{
		SessionParams: sessionParams(session), PolicyID: policyID, Revision: revision,
	})
	return validatedGet(document, err, uuid.Nil, policyID, revision)
}

func (service *Service) GetTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	policyID uuid.UUID,
	revision int64,
) (mfa.PolicyDocument, error) {
	if err := service.requireTenant(ctx, session, tenantID, authorization.TenantPermissionIdentityPolicyRead); err != nil {
		return mfa.PolicyDocument{}, err
	}
	if !validUUIDv7(policyID) || !validRevision(revision) {
		return mfa.PolicyDocument{}, ErrInvalidInput
	}
	document, err := service.repository.GetTenant(ctx, GetParams{
		SessionParams: sessionParams(session), TenantID: tenantID,
		PolicyID: policyID, Revision: revision,
	})
	return validatedGet(document, err, tenantID, policyID, revision)
}

func (service *Service) SimulatePlatform(
	ctx context.Context,
	session authentication.Session,
	input SimulationInput,
) (mfa.PolicySimulation, error) {
	if err := service.requirePlatform(ctx, session, authorization.PermissionPlatformIdentityPolicyRead); err != nil {
		return mfa.PolicySimulation{}, err
	}
	input, err := normalizeSimulationInput(input, uuid.Nil)
	if err != nil {
		return mfa.PolicySimulation{}, err
	}
	if !candidateDeadlineIsFuture(input.Requirement, service.now()) {
		return mfa.PolicySimulation{}, ErrInvalidInput
	}
	result, err := service.repository.SimulatePlatform(ctx, simulationParams(session, uuid.Nil, input))
	if err != nil {
		return mfa.PolicySimulation{}, mapDependencyError(err)
	}
	return validateSimulationResult(result, input, uuid.Nil)
}

func (service *Service) SimulateTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input SimulationInput,
) (mfa.PolicySimulation, error) {
	if err := service.requireTenant(ctx, session, tenantID, authorization.TenantPermissionIdentityPolicyRead); err != nil {
		return mfa.PolicySimulation{}, err
	}
	input, err := normalizeSimulationInput(input, tenantID)
	if err != nil {
		return mfa.PolicySimulation{}, err
	}
	if !candidateDeadlineIsFuture(input.Requirement, service.now()) {
		return mfa.PolicySimulation{}, ErrInvalidInput
	}
	result, err := service.repository.SimulateTenant(ctx, simulationParams(session, tenantID, input))
	if err != nil {
		return mfa.PolicySimulation{}, mapDependencyError(err)
	}
	return validateSimulationResult(result, input, tenantID)
}

func (service *Service) PublishPlatform(
	ctx context.Context,
	session authentication.Session,
	input PublishInput,
) (MutationResult, error) {
	if err := service.requirePlatformMutation(ctx, session); err != nil {
		return MutationResult{}, err
	}
	input, err := normalizePublishInput(input, uuid.Nil)
	if err != nil {
		return MutationResult{}, err
	}
	if !candidateDeadlineIsFuture(&input.Requirement, service.now()) {
		return MutationResult{}, ErrInvalidInput
	}
	eventID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	validate := func(result MutationResult) (MutationResult, error) {
		return validatePublishResult(result, input, uuid.Nil)
	}
	result, err := service.repository.PublishPlatform(ctx, publishParams(session, uuid.Nil, input, eventID, validate))
	if err != nil {
		return MutationResult{}, mapDependencyError(err)
	}
	return validate(result)
}

func (service *Service) PublishTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input PublishInput,
) (MutationResult, error) {
	if err := service.requireTenantMutation(ctx, session, tenantID); err != nil {
		return MutationResult{}, err
	}
	input, err := normalizePublishInput(input, tenantID)
	if err != nil {
		return MutationResult{}, err
	}
	if !candidateDeadlineIsFuture(&input.Requirement, service.now()) {
		return MutationResult{}, ErrInvalidInput
	}
	eventID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	validate := func(result MutationResult) (MutationResult, error) {
		return validatePublishResult(result, input, tenantID)
	}
	result, err := service.repository.PublishTenant(ctx, publishParams(session, tenantID, input, eventID, validate))
	if err != nil {
		return MutationResult{}, mapDependencyError(err)
	}
	return validate(result)
}

func (service *Service) RetirePlatform(
	ctx context.Context,
	session authentication.Session,
	input RetireInput,
) (MutationResult, error) {
	if err := service.requirePlatformMutation(ctx, session); err != nil {
		return MutationResult{}, err
	}
	input, err := normalizeRetireInput(input, uuid.Nil)
	if err != nil {
		return MutationResult{}, err
	}
	eventID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	validate := func(result MutationResult) (MutationResult, error) {
		return validateRetireResult(result, input, uuid.Nil)
	}
	result, err := service.repository.RetirePlatform(ctx, retireParams(session, uuid.Nil, input, eventID, validate))
	if err != nil {
		return MutationResult{}, mapDependencyError(err)
	}
	return validate(result)
}

func (service *Service) RetireTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input RetireInput,
) (MutationResult, error) {
	if err := service.requireTenantMutation(ctx, session, tenantID); err != nil {
		return MutationResult{}, err
	}
	input, err := normalizeRetireInput(input, tenantID)
	if err != nil {
		return MutationResult{}, err
	}
	eventID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	validate := func(result MutationResult) (MutationResult, error) {
		return validateRetireResult(result, input, tenantID)
	}
	result, err := service.repository.RetireTenant(ctx, retireParams(session, tenantID, input, eventID, validate))
	if err != nil {
		return MutationResult{}, mapDependencyError(err)
	}
	return validate(result)
}

func (service *Service) requirePlatformMutation(ctx context.Context, session authentication.Session) error {
	if err := service.requirePlatform(ctx, session, authorization.PermissionPlatformIdentityPolicyManage); err != nil {
		return err
	}
	return service.requirePlatform(ctx, session, authorization.PermissionPlatformIdentityPolicyRead)
}

func (service *Service) requireTenantMutation(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
) error {
	return service.requireTenantAll(
		ctx, session, tenantID,
		authorization.TenantPermissionIdentityPolicyManage,
		authorization.TenantPermissionIdentityPolicyRead,
	)
}

func (service *Service) requirePlatform(
	ctx context.Context,
	session authentication.Session,
	permission authorization.Permission,
) error {
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.authority) ||
		service.newID == nil || service.now == nil || interfaceIsNil(ctx) || !validateSession(session) {
		return ErrUnavailable
	}
	if err := service.evaluator.Require(session.Permissions, permission); err != nil {
		return ErrForbidden
	}
	return nil
}

func (service *Service) requireTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	permission authorization.TenantPermission,
) error {
	return service.requireTenantAll(ctx, session, tenantID, permission)
}

func (service *Service) requireTenantAll(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) error {
	if interfaceIsNil(ctx) {
		return ErrUnavailable
	}
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.authority) ||
		service.newID == nil || service.now == nil || len(permissions) == 0 || !validateSession(session) ||
		!validUUIDv7(tenantID) ||
		session.ActiveTenantID == nil || *session.ActiveTenantID != tenantID {
		return ErrForbidden
	}
	authority, err := service.authority.GetTenantAuthority(ctx, actor(session), tenantID)
	if err != nil {
		return mapDependencyError(err)
	}
	for _, permission := range permissions {
		if err = service.evaluator.RequireTenant(
			authority,
			permission,
			authorization.ResourceContext{TenantID: tenantID},
		); err != nil {
			return ErrForbidden
		}
	}
	return nil
}

func candidateDeadlineIsFuture(requirement *mfa.PolicyRequirement, now time.Time) bool {
	return requirement == nil || requirement.EnrollmentDeadline == nil ||
		requirement.EnrollmentDeadline.After(now.UTC())
}

func (service *Service) nextID() (uuid.UUID, error) {
	value, err := service.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func buildPage(rows []mfa.PolicyDocument, tenantID uuid.UUID, input ListInput) (Page, error) {
	if err := validatePage(rows, tenantID, input); err != nil {
		return Page{}, err
	}
	count := min(len(rows), input.Limit)
	page := Page{Items: make([]mfa.PolicyDocument, count)}
	for index := range page.Items {
		page.Items[index] = mfa.ClonePolicyDocument(rows[index])
	}
	if len(rows) > input.Limit {
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &Cursor{ID: uuid.UUID(last.ID), Revision: last.Revision}
	}
	return page, nil
}

func validatedGet(
	document mfa.PolicyDocument,
	err error,
	tenantID uuid.UUID,
	policyID uuid.UUID,
	revision int64,
) (mfa.PolicyDocument, error) {
	if err != nil {
		return mfa.PolicyDocument{}, mapDependencyError(err)
	}
	if validateDocument(document, tenantID) != nil || uuid.UUID(document.ID) != policyID ||
		document.Revision != revision {
		return mfa.PolicyDocument{}, ErrUnavailable
	}
	return mfa.ClonePolicyDocument(document), nil
}

func simulationParams(
	session authentication.Session,
	tenantID uuid.UUID,
	input SimulationInput,
) SimulationParams {
	return SimulationParams{
		SessionParams: sessionParams(session), TenantID: tenantID,
		Operation: input.Operation, Target: input.Target, ExpectedRevision: input.ExpectedRevision,
		ExpectedPolicyID: cloneUUID(input.ExpectedPolicyID), Requirement: cloneRequirementPointer(input.Requirement),
		Context: cloneSimulationContext(input.Context),
	}
}

func publishParams(
	session authentication.Session,
	tenantID uuid.UUID,
	input PublishInput,
	eventID uuid.UUID,
	validate MutationResultValidator,
) PublishParams {
	return PublishParams{
		SessionParams: sessionParams(session), TenantID: tenantID, CommandID: input.CommandID,
		Target: input.Target, ExpectedRevision: input.ExpectedRevision,
		ExpectedPolicyID: cloneUUID(input.ExpectedPolicyID), Requirement: cloneRequirement(input.Requirement),
		Reason: input.Reason, Audit: CommandAudit{EventID: eventID, Event: input.Event},
		ValidateResult: validate,
	}
}

func retireParams(
	session authentication.Session,
	tenantID uuid.UUID,
	input RetireInput,
	eventID uuid.UUID,
	validate MutationResultValidator,
) RetireParams {
	return RetireParams{
		SessionParams: sessionParams(session), TenantID: tenantID, CommandID: input.CommandID,
		Target: input.Target, ExpectedRevision: input.ExpectedRevision,
		ExpectedPolicyID: input.ExpectedPolicyID, Reason: input.Reason,
		Audit: CommandAudit{EventID: eventID, Event: input.Event}, ValidateResult: validate,
	}
}

func cloneRequirementPointer(value *mfa.PolicyRequirement) *mfa.PolicyRequirement {
	if value == nil {
		return nil
	}
	result := cloneRequirement(*value)
	return &result
}

func sessionParams(session authentication.Session) SessionParams {
	return SessionParams{
		ActorID: session.User.ID, SessionID: session.ID,
		AuthenticationMethod: session.AuthenticationMethod,
	}
}

func actor(session authentication.Session) authorization.Actor {
	activeTenantID := uuid.Nil
	if session.ActiveTenantID != nil {
		activeTenantID = *session.ActiveTenantID
	}
	return authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID, ActiveTenantID: activeTenantID,
		AuthenticationMethod: session.AuthenticationMethod,
	}
}

func cloneCursor(value *Cursor) *Cursor {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func (service *Service) String() string {
	return "mfapolicy.Service{dependencies:[REDACTED]}"
}

func (service *Service) GoString() string { return service.String() }
