package webhookurlpolicy

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

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
			return time.Now().UTC().Truncate(time.Millisecond)
		},
	}, nil
}

func (Service) String() string         { return "webhookurlpolicy.Service{redacted}" }
func (value Service) GoString() string { return value.String() }

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
) (Policy, error) {
	actor, _, err := service.require(ctx, session, tenantID, authorization.TenantPermissionNotificationManage)
	if err != nil {
		return Policy{}, err
	}
	policy, err := service.repository.Current(ctx, ReadParams{Actor: actor, TenantID: tenantID})
	if err != nil {
		return Policy{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil || !validStoredPolicy(policy, tenantID, now) {
		return Policy{}, ErrUnavailable
	}
	return policy, nil
}

func (service *Service) Decide(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	endpointURL string,
) (DecisionEvidence, error) {
	policy, err := service.Get(ctx, session, tenantID)
	if err != nil {
		return DecisionEvidence{}, err
	}
	endpoint, err := CanonicalEndpoint(endpointURL)
	if err != nil {
		return DecisionEvidence{}, ErrInvalidInput
	}
	decision, err := Evaluate(policy, endpoint)
	if err != nil {
		return DecisionEvidence{}, ErrUnavailable
	}
	return decision, nil
}

func (service *Service) Publish(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input PublishInput,
) (PublishResult, error) {
	actor, publisherID, err := service.require(
		ctx, session, tenantID, authorization.TenantPermissionNotificationManage,
	)
	if err != nil {
		return PublishResult{}, err
	}
	normalized, semanticDigest, err := normalizePublishInput(input)
	if err != nil {
		return PublishResult{}, err
	}
	command, err := bindPublishCommand(tenantID, actor.UserID, publisherID, normalized)
	if err != nil {
		return PublishResult{}, err
	}
	publishedAt, err := service.now()
	if err != nil {
		return PublishResult{}, err
	}

	var buildCalls atomic.Uint32
	var validationCalls atomic.Uint32
	var planned atomic.Pointer[Policy]
	params := PublishParams{
		Actor: actor, PublisherMembershipID: publisherID, TenantID: tenantID,
		ExpectedVersion: normalized.ExpectedVersion, Command: command,
		Reason: normalized.Reason, Audit: normalized.Event,
	}
	params.BuildPlan = func(current *Policy) (PolicyPlan, error) {
		if buildCalls.Add(1) != 1 {
			return PolicyPlan{}, ErrUnavailable
		}
		versionID, idErr := service.newID()
		if idErr != nil || !validUUIDv7(versionID) {
			return PolicyPlan{}, ErrUnavailable
		}
		if normalized.ExpectedVersion == 0 {
			if current != nil {
				return PolicyPlan{}, ErrConflict
			}
			policyID, policyIDErr := service.newID()
			if policyIDErr != nil || !validUUIDv7(policyID) || policyID == versionID {
				return PolicyPlan{}, ErrUnavailable
			}
			plan, planErr := PlanPolicyCreation(PolicyInput{
				ID: policyID, VersionID: versionID, TenantID: tenantID, Version: 1,
				Rules: normalized.Policy.Rules, PublishedByMembershipID: publisherID, PublishedAt: publishedAt,
			})
			if planErr != nil {
				return PolicyPlan{}, applicationError(planErr)
			}
			next := plan.Next()
			planned.Store(&next)
			return plan, nil
		}
		if current == nil || !validStoredPolicy(*current, tenantID, publishedAt) {
			return PolicyPlan{}, ErrUnavailable
		}
		plan, planErr := PlanPolicyReplacement(*current, normalized.ExpectedVersion, PolicyInput{
			ID: current.id, VersionID: versionID, TenantID: tenantID, Version: normalized.ExpectedVersion + 1,
			Rules: normalized.Policy.Rules, PublishedByMembershipID: publisherID, PublishedAt: publishedAt,
		})
		if planErr != nil {
			return PolicyPlan{}, applicationError(planErr)
		}
		next := plan.Next()
		planned.Store(&next)
		return plan, nil
	}
	params.ValidateResult = func(result PublishResult) error {
		if validationCalls.Add(1) != 1 || !validPublishResult(
			result, tenantID, normalized.ExpectedVersion, semanticDigest, publisherID, command, publishedAt,
		) {
			return ErrUnavailable
		}
		if result.Replayed {
			if buildCalls.Load() > 1 {
				return ErrUnavailable
			}
			return nil
		}
		plannedPolicy := planned.Load()
		if buildCalls.Load() != 1 || plannedPolicy == nil || !SamePolicy(result.Policy, *plannedPolicy) {
			return ErrUnavailable
		}
		return nil
	}

	result, err := service.repository.Publish(ctx, params)
	if err != nil {
		return PublishResult{}, repositoryError(err)
	}
	if validationCalls.Load() != 1 || !validPublishResult(
		result, tenantID, normalized.ExpectedVersion, semanticDigest, publisherID, command, publishedAt,
	) {
		return PublishResult{}, ErrUnavailable
	}
	if result.Replayed {
		if buildCalls.Load() > 1 {
			return PublishResult{}, ErrUnavailable
		}
	} else {
		plannedPolicy := planned.Load()
		if buildCalls.Load() != 1 || plannedPolicy == nil || !SamePolicy(result.Policy, *plannedPolicy) {
			return PublishResult{}, ErrUnavailable
		}
	}
	return result, nil
}

func (service *Service) require(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) (authorization.Actor, uuid.UUID, error) {
	if service == nil || nilInterface(service.repository) || nilInterface(service.authority) ||
		service.newID == nil || service.clock == nil || ctx == nil || len(permissions) == 0 {
		return authorization.Actor{}, uuid.Nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return authorization.Actor{}, uuid.Nil, err
	}
	now, err := service.now()
	if err != nil {
		return authorization.Actor{}, uuid.Nil, err
	}
	if !validSession(session, tenantID, now) {
		return authorization.Actor{}, uuid.Nil, ErrForbidden
	}
	actor := authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID, ActiveTenantID: tenantID,
		AuthenticationMethod: session.AuthenticationMethod,
	}
	authority, err := service.authority.GetTenantAuthority(ctx, actor, tenantID)
	if err != nil {
		return authorization.Actor{}, uuid.Nil, repositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != session.User.ID || !validUUIDv7(authority.MembershipID) {
		return authorization.Actor{}, uuid.Nil, ErrForbidden
	}
	for _, permission := range permissions {
		if service.evaluator.RequireTenant(
			authority, permission, authorization.ResourceContext{TenantID: tenantID},
		) != nil {
			return authorization.Actor{}, uuid.Nil, ErrForbidden
		}
	}
	return actor, authority.MembershipID, nil
}

func (service *Service) now() (time.Time, error) {
	now := service.clock()
	if !validClockInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func applicationError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrNoChange):
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
	case errors.Is(err, ErrRepositoryInvalidInput), errors.Is(err, ErrInvalidInput), errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrRepositoryForbidden), errors.Is(err, ErrForbidden),
		errors.Is(err, authorization.ErrForbidden), errors.Is(err, authorization.ErrDenied):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound), errors.Is(err, ErrNotFound), errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict), errors.Is(err, ErrConflict), errors.Is(err, authorization.ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrNoChange):
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
