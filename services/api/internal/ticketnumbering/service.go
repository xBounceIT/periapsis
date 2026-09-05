package ticketnumbering

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Clock func() time.Time

type Service struct {
	repository Repository
	authority  TenantAuthorityResolver
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	clock      Clock
}

func NewService(repository Repository, authority TenantAuthorityResolver) (*Service, error) {
	if nilInterface(repository) || nilInterface(authority) {
		return nil, ErrUnavailable
	}
	return &Service{
		repository: repository,
		authority:  authority,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		clock: func() time.Time {
			return time.Now().UTC().Truncate(time.Microsecond)
		},
	}, nil
}

func (Service) String() string         { return "ticketnumbering.Service{redacted}" }
func (value Service) GoString() string { return value.String() }

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
) (kernel.NumberingPolicy, error) {
	actor, _, err := service.require(
		ctx, session, tenantID, kind, authorization.TenantPermissionSettingsRead,
	)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	policy, err := service.repository.Current(ctx, ReadParams{
		Actor: actor, TenantID: tenantID, Kind: kind,
	})
	if err != nil {
		return kernel.NumberingPolicy{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil || !validStoredPolicy(policy, tenantID, kind, now) {
		return kernel.NumberingPolicy{}, ErrUnavailable
	}
	return policy, nil
}

// Preview renders only the first value of a validated draft at the server's
// current UTC instant. It never reads or advances a durable counter.
func (service *Service) Preview(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	draft PolicyDraft,
) (Preview, error) {
	if _, _, err := service.require(
		ctx, session, tenantID, kind, authorization.TenantPermissionSettingsRead,
	); err != nil {
		return Preview{}, err
	}
	normalized, spec, err := normalizeDraft(draft)
	if err != nil {
		return Preview{}, err
	}
	now, err := service.now()
	if err != nil {
		return Preview{}, err
	}
	period, periodErr := spec.PeriodKey(now)
	example, renderErr := spec.Render(spec.Start(), now)
	if periodErr != nil || renderErr != nil {
		return Preview{}, ErrUnavailable
	}
	preview := Preview{
		TenantID: tenantID, Kind: kind, Prefix: normalized.Prefix,
		Separator: normalized.Separator, Period: normalized.Period,
		Width: normalized.Width, Start: normalized.Start,
		MaximumSequence: spec.MaximumSequence(), At: now,
		PeriodKey: period, Example: example,
	}
	if !validPreview(preview, tenantID, kind, normalized, now) {
		return Preview{}, ErrUnavailable
	}
	return preview, nil
}

func (service *Service) Replace(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ReplaceInput,
) (ReplaceResult, error) {
	actor, publisherID, err := service.require(
		ctx, session, tenantID, kind,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
	)
	if err != nil {
		return ReplaceResult{}, err
	}
	normalized, nextSpec, err := normalizeReplaceInput(input)
	if err != nil {
		return ReplaceResult{}, err
	}
	command, err := bindReplaceCommand(tenantID, kind, normalized)
	if err != nil {
		return ReplaceResult{}, err
	}
	publishedAt, err := service.now()
	if err != nil {
		return ReplaceResult{}, err
	}

	var buildCalls atomic.Uint32
	var validationCalls atomic.Uint32
	var planned kernel.NumberingPolicy
	params := ReplaceParams{
		Actor: actor, TenantID: tenantID, Kind: kind,
		ExpectedVersion: normalized.ExpectedVersion, Command: command,
		Reason: normalized.Reason, Audit: normalized.Event,
	}
	params.BuildPlan = func(current kernel.NumberingPolicy) (kernel.NumberingPolicyPlan, error) {
		if buildCalls.Add(1) != 1 ||
			!validStoredPolicy(current, tenantID, kind, publishedAt) {
			return kernel.NumberingPolicyPlan{}, ErrUnavailable
		}
		nextVersionUUID, idErr := service.newID()
		if idErr != nil {
			return kernel.NumberingPolicyPlan{}, ErrUnavailable
		}
		nextVersionID, ok := entityID(nextVersionUUID)
		if !ok {
			return kernel.NumberingPolicyPlan{}, ErrUnavailable
		}
		plan, planErr := kernel.PlanNumberingPolicyReplacement(
			current, normalized.ExpectedVersion, nextVersionID, nextSpec, publisherID, publishedAt,
		)
		if planErr != nil {
			return kernel.NumberingPolicyPlan{}, applicationError(planErr)
		}
		planned = plan.Next()
		return plan, nil
	}
	params.ValidateResult = func(result ReplaceResult) error {
		if validationCalls.Add(1) != 1 || !validReplaceResult(
			result, tenantID, kind, normalized.ExpectedVersion,
			normalized.Policy, publisherID, publishedAt,
		) {
			return ErrUnavailable
		}
		if result.Replayed {
			if buildCalls.Load() != 0 {
				return ErrUnavailable
			}
			return nil
		}
		if buildCalls.Load() != 1 || !kernel.SameNumberingPolicy(result.Policy, planned) {
			return ErrUnavailable
		}
		return nil
	}

	result, err := service.repository.Replace(ctx, params)
	if err != nil {
		return ReplaceResult{}, repositoryError(err)
	}
	if validationCalls.Load() != 1 || !validReplaceResult(
		result, tenantID, kind, normalized.ExpectedVersion,
		normalized.Policy, publisherID, publishedAt,
	) {
		return ReplaceResult{}, ErrUnavailable
	}
	if result.Replayed {
		if buildCalls.Load() != 0 {
			return ReplaceResult{}, ErrUnavailable
		}
	} else if buildCalls.Load() != 1 || !kernel.SameNumberingPolicy(result.Policy, planned) {
		return ReplaceResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) require(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	permissions ...authorization.TenantPermission,
) (authorization.Actor, kernel.EntityID, error) {
	if service == nil || nilInterface(service.repository) || nilInterface(service.authority) ||
		service.newID == nil || service.clock == nil || ctx == nil || len(permissions) == 0 {
		return authorization.Actor{}, kernel.EntityID{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return authorization.Actor{}, kernel.EntityID{}, err
	}
	now, err := service.now()
	if err != nil {
		return authorization.Actor{}, kernel.EntityID{}, err
	}
	if _, ok := entityID(session.User.ID); !ok || !validAggregateKind(kind) ||
		!validSession(session, tenantID, now) {
		return authorization.Actor{}, kernel.EntityID{}, ErrForbidden
	}
	actor := authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID, ActiveTenantID: tenantID,
		AuthenticationMethod: session.AuthenticationMethod,
	}
	authority, err := service.authority.GetTenantAuthority(ctx, actor, tenantID)
	if err != nil {
		return authorization.Actor{}, kernel.EntityID{}, repositoryError(err)
	}
	if authority.TenantID != tenantID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != session.User.ID {
		return authorization.Actor{}, kernel.EntityID{}, ErrForbidden
	}
	for _, permission := range permissions {
		if service.evaluator.RequireTenant(
			authority, permission, authorization.ResourceContext{TenantID: tenantID},
		) != nil {
			return authorization.Actor{}, kernel.EntityID{}, ErrForbidden
		}
	}
	membershipID, ok := entityID(authority.MembershipID)
	if !ok {
		return authorization.Actor{}, kernel.EntityID{}, ErrForbidden
	}
	return actor, membershipID, nil
}

func (service *Service) now() (time.Time, error) {
	now := service.clock()
	if !validInstant(now) || now.Year() < 2000 || now.Year() > 9999 {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func applicationError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrInvalidNumberingPolicy),
		errors.Is(err, kernel.ErrInvalidNumberingAllocation):
		return ErrInvalidInput
	case errors.Is(err, kernel.ErrNumberingRevisionConflict):
		return ErrPrecondition
	case errors.Is(err, kernel.ErrNumberingReplayConflict):
		return ErrConflict
	case errors.Is(err, kernel.ErrNumberingNoChange):
		return ErrNoChange
	default:
		return ErrUnavailable
	}
}

func repositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrRepositoryInvalidInput), errors.Is(err, ErrInvalidInput),
		errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrRepositoryForbidden), errors.Is(err, ErrForbidden),
		errors.Is(err, authorization.ErrForbidden), errors.Is(err, authorization.ErrDenied):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound), errors.Is(err, ErrNotFound),
		errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryPrecondition), errors.Is(err, ErrPrecondition):
		return ErrPrecondition
	case errors.Is(err, ErrRepositoryConflict), errors.Is(err, ErrConflict),
		errors.Is(err, authorization.ErrConflict),
		errors.Is(err, kernel.ErrNumberingReplayConflict):
		return ErrConflict
	case errors.Is(err, ErrNoChange), errors.Is(err, kernel.ErrNumberingNoChange):
		return ErrNoChange
	default:
		return ErrUnavailable
	}
}

func nilInterface(value any) bool {
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
