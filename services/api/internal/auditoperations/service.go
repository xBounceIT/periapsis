package auditoperations

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Service struct {
	repository Repository
	resolver   TenantAuthorityResolver
	storage    ArtifactStorage
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	now        func() time.Time
}

func NewService(
	repository Repository,
	resolver TenantAuthorityResolver,
	storage ArtifactStorage,
) (*Service, error) {
	if interfaceIsNil(repository) || interfaceIsNil(resolver) || interfaceIsNil(storage) {
		return nil, errors.New("audit operation repository, authority resolver, and storage are required")
	}
	return &Service{
		repository: repository,
		resolver:   resolver,
		storage:    storage,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		now:        time.Now,
	}, nil
}

func (service *Service) CreateTenantExport(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input CreateExportInput,
) (ExportMutationResult, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRead,
		authorization.TenantPermissionAuditExport,
	)
	if err != nil {
		return ExportMutationResult{}, err
	}
	return service.createExport(ctx, StreamTenant, &tenant, nil, input)
}

func (service *Service) CreatePlatformExport(
	ctx context.Context,
	session authentication.Session,
	input CreateExportInput,
) (ExportMutationResult, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRead,
		authorization.PermissionPlatformAuditExport,
	)
	if err != nil {
		return ExportMutationResult{}, err
	}
	return service.createExport(ctx, StreamPlatform, nil, &platform, input)
}

func (service *Service) createExport(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	input CreateExportInput,
) (ExportMutationResult, error) {
	normalizedFilter, err := normalizeFilter(input.Filter, stream)
	if err != nil {
		return ExportMutationResult{}, err
	}
	if input.RetentionSeconds == 0 {
		input.RetentionSeconds = 86400
	}
	reason, err := normalizeMutation(input.IdempotencyKey, input.Reason, input.Event)
	if err != nil || input.RetentionSeconds < 900 || input.RetentionSeconds > 604800 {
		return ExportMutationResult{}, ErrInvalidInput
	}
	filterJSON, err := marshalFilter(normalizedFilter)
	if err != nil {
		return ExportMutationResult{}, ErrInvalidInput
	}
	jobID, err := service.newUUIDv7()
	if err != nil {
		return ExportMutationResult{}, err
	}
	envelope, err := service.envelope(input.IdempotencyKey, input.Event)
	if err != nil {
		return ExportMutationResult{}, err
	}
	params := CreateExportParams{
		TenantSession: tenant, PlatformSession: platform, JobID: jobID,
		FilterJSON: filterJSON, RetentionSeconds: input.RetentionSeconds,
		Reason: reason, Envelope: envelope,
		ValidateResult: func(result ExportMutationResult) (ExportMutationResult, error) {
			if validateExportMutation(result, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC()) != nil ||
				!result.Replayed && result.Job.ID != jobID {
				return ExportMutationResult{}, ErrUnavailable
			}
			return cloneExportMutation(result), nil
		},
	}
	var result ExportMutationResult
	if stream == StreamTenant {
		result, err = service.repository.CreateTenantExport(ctx, params)
	} else {
		result, err = service.repository.CreatePlatformExport(ctx, params)
	}
	clear(envelope.KeyDigest[:])
	if err != nil {
		return ExportMutationResult{}, mapDependencyError(err)
	}
	if validateExportMutation(result, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC()) != nil ||
		!result.Replayed && result.Job.ID != jobID {
		return ExportMutationResult{}, ErrUnavailable
	}
	return cloneExportMutation(result), nil
}

func (service *Service) GetTenantExport(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	exportID uuid.UUID,
	event authentication.EventContext,
) (ExportJob, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRead,
		authorization.TenantPermissionAuditExport,
	)
	if err != nil {
		return ExportJob{}, err
	}
	return service.getExport(ctx, StreamTenant, &tenant, nil, exportID, event)
}

func (service *Service) GetPlatformExport(
	ctx context.Context,
	session authentication.Session,
	exportID uuid.UUID,
	event authentication.EventContext,
) (ExportJob, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRead,
		authorization.PermissionPlatformAuditExport,
	)
	if err != nil {
		return ExportJob{}, err
	}
	return service.getExport(ctx, StreamPlatform, nil, &platform, exportID, event)
}

func (service *Service) getExport(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	exportID uuid.UUID,
	event authentication.EventContext,
) (ExportJob, error) {
	if !validUUIDv7(exportID) || !validEvent(event) {
		return ExportJob{}, ErrInvalidInput
	}
	auditID, err := service.newUUIDv7()
	if err != nil {
		return ExportJob{}, err
	}
	params := ReadExportParams{
		TenantSession: tenant, PlatformSession: platform, ExportID: exportID,
		AuditID: auditID, Event: event,
		ValidateJob: func(job ExportJob) (ExportJob, error) {
			if job.ID != exportID || validateExportJob(job, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC()) != nil {
				return ExportJob{}, ErrUnavailable
			}
			return cloneExportJob(job), nil
		},
	}
	var job ExportJob
	if stream == StreamTenant {
		job, err = service.repository.GetTenantExport(ctx, params)
	} else {
		job, err = service.repository.GetPlatformExport(ctx, params)
	}
	if err != nil {
		return ExportJob{}, mapDependencyError(err)
	}
	if job.ID != exportID || validateExportJob(job, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC()) != nil {
		return ExportJob{}, ErrUnavailable
	}
	return cloneExportJob(job), nil
}

func (service *Service) CancelTenantExport(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input CancelExportInput,
) (ExportMutationResult, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRead,
		authorization.TenantPermissionAuditExport,
	)
	if err != nil {
		return ExportMutationResult{}, err
	}
	return service.cancelExport(ctx, StreamTenant, &tenant, nil, input)
}

func (service *Service) CancelPlatformExport(
	ctx context.Context,
	session authentication.Session,
	input CancelExportInput,
) (ExportMutationResult, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRead,
		authorization.PermissionPlatformAuditExport,
	)
	if err != nil {
		return ExportMutationResult{}, err
	}
	return service.cancelExport(ctx, StreamPlatform, nil, &platform, input)
}

func (service *Service) cancelExport(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	input CancelExportInput,
) (ExportMutationResult, error) {
	reason, err := normalizeMutation(input.IdempotencyKey, input.Reason, input.Event)
	if err != nil || !validUUIDv7(input.ExportID) || !validRevision(input.ExpectedRevision) {
		return ExportMutationResult{}, ErrInvalidInput
	}
	envelope, err := service.envelope(input.IdempotencyKey, input.Event)
	if err != nil {
		return ExportMutationResult{}, err
	}
	params := CancelExportParams{
		TenantSession: tenant, PlatformSession: platform, ExportID: input.ExportID,
		ExpectedRevision: input.ExpectedRevision, Reason: reason, Envelope: envelope,
		ValidateResult: func(result ExportMutationResult) (ExportMutationResult, error) {
			if result.Job.ID != input.ExportID || validateExportMutation(
				result, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC(),
			) != nil || !result.Replayed && result.Job.Revision != input.ExpectedRevision+1 {
				return ExportMutationResult{}, ErrUnavailable
			}
			return cloneExportMutation(result), nil
		},
	}
	var result ExportMutationResult
	if stream == StreamTenant {
		result, err = service.repository.CancelTenantExport(ctx, params)
	} else {
		result, err = service.repository.CancelPlatformExport(ctx, params)
	}
	clear(envelope.KeyDigest[:])
	if err != nil {
		return ExportMutationResult{}, mapDependencyError(err)
	}
	if result.Job.ID != input.ExportID || validateExportMutation(
		result, stream, tenantID(tenant), actorID(tenant, platform), service.now().UTC(),
	) != nil || !result.Replayed && result.Job.Revision != input.ExpectedRevision+1 {
		return ExportMutationResult{}, ErrUnavailable
	}
	return cloneExportMutation(result), nil
}

func (service *Service) DownloadTenantExport(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	exportID uuid.UUID,
	event authentication.EventContext,
) (Download, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRead,
		authorization.TenantPermissionAuditExport,
	)
	if err != nil {
		return Download{}, err
	}
	return service.download(ctx, StreamTenant, &tenant, nil, exportID, event)
}

func (service *Service) DownloadPlatformExport(
	ctx context.Context,
	session authentication.Session,
	exportID uuid.UUID,
	event authentication.EventContext,
) (Download, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRead,
		authorization.PermissionPlatformAuditExport,
	)
	if err != nil {
		return Download{}, err
	}
	return service.download(ctx, StreamPlatform, nil, &platform, exportID, event)
}

func (service *Service) download(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	exportID uuid.UUID,
	event authentication.EventContext,
) (Download, error) {
	if !validUUIDv7(exportID) || !validEvent(event) {
		return Download{}, ErrInvalidInput
	}
	auditID, err := service.newUUIDv7()
	if err != nil {
		return Download{}, err
	}
	params := ReadExportParams{
		TenantSession: tenant, PlatformSession: platform, ExportID: exportID,
		AuditID: auditID, Event: event,
		ValidateLocation: func(location ArtifactLocation) (ArtifactLocation, error) {
			if validateArtifactLocation(location, stream, tenantID(tenant), exportID, service.now().UTC()) != nil {
				return ArtifactLocation{}, ErrUnavailable
			}
			return location, nil
		},
	}
	var location ArtifactLocation
	if stream == StreamTenant {
		location, err = service.repository.AuthorizeTenantDownload(ctx, params)
	} else {
		location, err = service.repository.AuthorizePlatformDownload(ctx, params)
	}
	if err != nil {
		return Download{}, mapDependencyError(err)
	}
	if validateArtifactLocation(location, stream, tenantID(tenant), exportID, service.now().UTC()) != nil {
		return Download{}, ErrUnavailable
	}
	reader, err := service.storage.OpenAuditExport(ctx, location)
	if err != nil || reader.Body == nil || reader.Size != location.Bytes {
		if reader.Body != nil {
			_ = reader.Body.Close()
		}
		return Download{}, ErrUnavailable
	}
	return Download{Reader: reader.Body, Size: reader.Size, Filename: location.Filename}, nil
}

func (service *Service) GetTenantRetention(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	event authentication.EventContext,
) (RetentionState, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRetentionManage,
	)
	if err != nil {
		return RetentionState{}, err
	}
	return service.getRetention(ctx, StreamTenant, &tenant, nil, event)
}

func (service *Service) GetPlatformRetention(
	ctx context.Context,
	session authentication.Session,
	event authentication.EventContext,
) (RetentionState, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRetentionManage,
	)
	if err != nil {
		return RetentionState{}, err
	}
	return service.getRetention(ctx, StreamPlatform, nil, &platform, event)
}

func (service *Service) getRetention(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	event authentication.EventContext,
) (RetentionState, error) {
	if !validEvent(event) {
		return RetentionState{}, ErrInvalidInput
	}
	auditID, err := service.newUUIDv7()
	if err != nil {
		return RetentionState{}, err
	}
	params := ReadRetentionParams{
		TenantSession: tenant, PlatformSession: platform, AuditID: auditID, Event: event,
		ValidateState: func(state RetentionState) (RetentionState, error) {
			if validateRetentionState(state, stream, tenantID(tenant), service.now().UTC()) != nil {
				return RetentionState{}, ErrUnavailable
			}
			return cloneRetentionState(state), nil
		},
	}
	var state RetentionState
	if stream == StreamTenant {
		state, err = service.repository.GetTenantRetention(ctx, params)
	} else {
		state, err = service.repository.GetPlatformRetention(ctx, params)
	}
	if err != nil {
		return RetentionState{}, mapDependencyError(err)
	}
	if validateRetentionState(state, stream, tenantID(tenant), service.now().UTC()) != nil {
		return RetentionState{}, ErrUnavailable
	}
	return cloneRetentionState(state), nil
}

func (service *Service) UpdateTenantRetention(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input UpdateRetentionInput,
) (RetentionMutationResult, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRetentionManage,
	)
	if err != nil {
		return RetentionMutationResult{}, err
	}
	return service.updateRetention(ctx, StreamTenant, &tenant, nil, input)
}

func (service *Service) UpdatePlatformRetention(
	ctx context.Context,
	session authentication.Session,
	input UpdateRetentionInput,
) (RetentionMutationResult, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRetentionManage,
	)
	if err != nil {
		return RetentionMutationResult{}, err
	}
	return service.updateRetention(ctx, StreamPlatform, nil, &platform, input)
}

func (service *Service) updateRetention(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	input UpdateRetentionInput,
) (RetentionMutationResult, error) {
	reason, err := normalizeMutation(input.IdempotencyKey, input.Reason, input.Event)
	if err != nil || !validRevision(input.ExpectedRevision) || input.RetentionDays < 30 || input.RetentionDays > 3650 {
		return RetentionMutationResult{}, ErrInvalidInput
	}
	envelope, err := service.envelope(input.IdempotencyKey, input.Event)
	if err != nil {
		return RetentionMutationResult{}, err
	}
	params := UpdateRetentionParams{
		TenantSession: tenant, PlatformSession: platform,
		ExpectedRevision: input.ExpectedRevision, RetentionDays: input.RetentionDays,
		Reason: reason, Envelope: envelope,
		ValidateResult: func(result RetentionMutationResult) (RetentionMutationResult, error) {
			if validateRetentionState(result.State, stream, tenantID(tenant), service.now().UTC()) != nil ||
				!result.Replayed && result.State.Policy.Revision != input.ExpectedRevision+1 ||
				result.State.Policy.RetentionDays != input.RetentionDays {
				return RetentionMutationResult{}, ErrUnavailable
			}
			return cloneRetentionMutation(result), nil
		},
	}
	var result RetentionMutationResult
	if stream == StreamTenant {
		result, err = service.repository.UpdateTenantRetention(ctx, params)
	} else {
		result, err = service.repository.UpdatePlatformRetention(ctx, params)
	}
	clear(envelope.KeyDigest[:])
	if err != nil {
		return RetentionMutationResult{}, mapDependencyError(err)
	}
	if validateRetentionState(result.State, stream, tenantID(tenant), service.now().UTC()) != nil ||
		!result.Replayed && result.State.Policy.Revision != input.ExpectedRevision+1 ||
		result.State.Policy.RetentionDays != input.RetentionDays {
		return RetentionMutationResult{}, ErrUnavailable
	}
	return cloneRetentionMutation(result), nil
}

func (service *Service) PlaceTenantLegalHold(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input PlaceLegalHoldInput,
) (LegalHoldMutationResult, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRetentionManage,
	)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	return service.placeLegalHold(ctx, StreamTenant, &tenant, nil, input)
}

func (service *Service) PlacePlatformLegalHold(
	ctx context.Context,
	session authentication.Session,
	input PlaceLegalHoldInput,
) (LegalHoldMutationResult, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRetentionManage,
	)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	return service.placeLegalHold(ctx, StreamPlatform, nil, &platform, input)
}

func (service *Service) placeLegalHold(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	input PlaceLegalHoldInput,
) (LegalHoldMutationResult, error) {
	reason, err := normalizeMutation(input.IdempotencyKey, input.Reason, input.Event)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	holdID, err := service.newUUIDv7()
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	envelope, err := service.envelope(input.IdempotencyKey, input.Event)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	params := PlaceLegalHoldParams{
		TenantSession: tenant, PlatformSession: platform, HoldID: holdID,
		Reason: reason, Envelope: envelope,
		ValidateResult: func(result LegalHoldMutationResult) (LegalHoldMutationResult, error) {
			if validateLegalHold(result.Hold, false, service.now().UTC()) != nil ||
				!result.Replayed && result.Hold.ID != holdID {
				return LegalHoldMutationResult{}, ErrUnavailable
			}
			return cloneLegalHoldMutation(result), nil
		},
	}
	var result LegalHoldMutationResult
	if stream == StreamTenant {
		result, err = service.repository.PlaceTenantLegalHold(ctx, params)
	} else {
		result, err = service.repository.PlacePlatformLegalHold(ctx, params)
	}
	clear(envelope.KeyDigest[:])
	if err != nil {
		return LegalHoldMutationResult{}, mapDependencyError(err)
	}
	if validateLegalHold(result.Hold, false, service.now().UTC()) != nil ||
		!result.Replayed && result.Hold.ID != holdID {
		return LegalHoldMutationResult{}, ErrUnavailable
	}
	return cloneLegalHoldMutation(result), nil
}

func (service *Service) ReleaseTenantLegalHold(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input ReleaseLegalHoldInput,
) (LegalHoldMutationResult, error) {
	tenant, err := service.requireTenant(ctx, session, tenantID,
		authorization.TenantPermissionAuditRetentionManage,
	)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	return service.releaseLegalHold(ctx, StreamTenant, &tenant, nil, input)
}

func (service *Service) ReleasePlatformLegalHold(
	ctx context.Context,
	session authentication.Session,
	input ReleaseLegalHoldInput,
) (LegalHoldMutationResult, error) {
	platform, err := service.requirePlatform(session,
		authorization.PermissionPlatformAuditRetentionManage,
	)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	return service.releaseLegalHold(ctx, StreamPlatform, nil, &platform, input)
}

func (service *Service) releaseLegalHold(
	ctx context.Context,
	stream Stream,
	tenant *TenantSessionParams,
	platform *PlatformSessionParams,
	input ReleaseLegalHoldInput,
) (LegalHoldMutationResult, error) {
	reason, err := normalizeMutation(input.IdempotencyKey, input.Reason, input.Event)
	if err != nil || !validUUIDv7(input.HoldID) || input.ExpectedRevision != 1 {
		return LegalHoldMutationResult{}, ErrInvalidInput
	}
	envelope, err := service.envelope(input.IdempotencyKey, input.Event)
	if err != nil {
		return LegalHoldMutationResult{}, err
	}
	params := ReleaseLegalHoldParams{
		TenantSession: tenant, PlatformSession: platform, HoldID: input.HoldID,
		ExpectedRevision: input.ExpectedRevision, Reason: reason, Envelope: envelope,
		ValidateResult: func(result LegalHoldMutationResult) (LegalHoldMutationResult, error) {
			if result.Hold.ID != input.HoldID || validateLegalHold(result.Hold, true, service.now().UTC()) != nil ||
				!result.Replayed && result.Hold.Revision != input.ExpectedRevision+1 {
				return LegalHoldMutationResult{}, ErrUnavailable
			}
			return cloneLegalHoldMutation(result), nil
		},
	}
	var result LegalHoldMutationResult
	if stream == StreamTenant {
		result, err = service.repository.ReleaseTenantLegalHold(ctx, params)
	} else {
		result, err = service.repository.ReleasePlatformLegalHold(ctx, params)
	}
	clear(envelope.KeyDigest[:])
	if err != nil {
		return LegalHoldMutationResult{}, mapDependencyError(err)
	}
	if result.Hold.ID != input.HoldID || validateLegalHold(result.Hold, true, service.now().UTC()) != nil ||
		!result.Replayed && result.Hold.Revision != input.ExpectedRevision+1 {
		return LegalHoldMutationResult{}, ErrUnavailable
	}
	return cloneLegalHoldMutation(result), nil
}

func (service *Service) requireTenant(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) (TenantSessionParams, error) {
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.resolver) ||
		service.newID == nil || service.now == nil || ctx == nil || len(permissions) == 0 ||
		!validTenantSession(session, tenantID, service.now().UTC()) {
		return TenantSessionParams{}, ErrForbidden
	}
	actor := authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID,
		ActiveTenantID: tenantID, AuthenticationMethod: session.AuthenticationMethod,
	}
	authority, err := service.resolver.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return TenantSessionParams{}, mapDependencyError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID {
		return TenantSessionParams{}, ErrForbidden
	}
	for _, permission := range permissions {
		if service.evaluator.RequireTenant(authority, permission, authorization.ResourceContext{TenantID: tenantID}) != nil {
			return TenantSessionParams{}, ErrForbidden
		}
	}
	return TenantSessionParams{Actor: actor, TenantID: tenantID, Session: session}, nil
}

func (service *Service) requirePlatform(
	session authentication.Session,
	permissions ...authorization.Permission,
) (PlatformSessionParams, error) {
	if service == nil || interfaceIsNil(service.repository) || service.newID == nil || service.now == nil ||
		len(permissions) == 0 || !validPlatformSession(session, service.now().UTC()) {
		return PlatformSessionParams{}, ErrForbidden
	}
	for _, permission := range permissions {
		if service.evaluator.Require(session.Permissions, permission) != nil {
			return PlatformSessionParams{}, ErrForbidden
		}
	}
	return PlatformSessionParams{Session: session}, nil
}

func (service *Service) envelope(key string, event authentication.EventContext) (OperationEnvelope, error) {
	auditID, err := service.newUUIDv7()
	if err != nil {
		return OperationEnvelope{}, err
	}
	return OperationEnvelope{KeyDigest: sha256.Sum256([]byte(key)), AuditID: auditID, Event: event}, nil
}

func (service *Service) newUUIDv7() (uuid.UUID, error) {
	identifier, err := service.newID()
	if err != nil || !validUUIDv7(identifier) {
		return uuid.Nil, ErrUnavailable
	}
	return identifier, nil
}

func tenantID(value *TenantSessionParams) *uuid.UUID {
	if value == nil {
		return nil
	}
	identifier := value.TenantID
	return &identifier
}

func actorID(tenant *TenantSessionParams, platform *PlatformSessionParams) uuid.UUID {
	if tenant != nil {
		return tenant.Session.User.ID
	}
	if platform != nil {
		return platform.Session.User.ID
	}
	return uuid.Nil
}

func mapDependencyError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, authentication.ErrInvalidInput), errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrForbidden), errors.Is(err, authentication.ErrForbidden), errors.Is(err, authorization.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrNotFound), errors.Is(err, authentication.ErrNotFound), errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrPrecondition):
		return ErrPrecondition
	case errors.Is(err, ErrConflict), errors.Is(err, authentication.ErrConflict), errors.Is(err, authorization.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
