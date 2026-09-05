package notification

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const maximumResourceVersion = int64(2_147_483_647)

type ServiceOptions struct {
	AllowPlainLocal bool
}

// Service is the deny-by-default application boundary for all public
// notification administration. The notifier runtime intentionally does not
// implement or expose this surface.
type Service struct {
	repository      Repository
	keyring         Keyring
	previewer       Previewer
	smtpProber      SMTPProber
	evaluator       authorization.Evaluator
	allowPlainLocal bool
	now             func() time.Time
	newID           func() (uuid.UUID, error)
}

func NewService(repository Repository, keyring Keyring, notifier NotifierClient, options ServiceOptions) (*Service, error) {
	if repository == nil {
		return nil, errors.New("notification repository is required")
	}
	if keyring.ActiveVersion() < 1 || len(keyring.Versions()) == 0 {
		return nil, errors.New("notification keyring is required")
	}
	if notifier == nil {
		return nil, errors.New("notification notifier client is required")
	}
	return &Service{
		repository: repository, keyring: keyring, previewer: notifier, smtpProber: notifier,
		evaluator: authorization.Evaluator{}, allowPlainLocal: options.AllowPlainLocal,
		now: time.Now, newID: uuid.NewV7,
	}, nil
}

func (s *Service) ListRules(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input PageInput,
) (RulePage, error) {
	page, err := normalizePage(input)
	if err != nil {
		return RulePage{}, err
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return RulePage{}, err
	}
	result, err := s.repository.ListRules(ctx, ListRulesParams{
		Human: human, After: page.After, Limit: int32(page.Limit),
	})
	if err != nil {
		return RulePage{}, mapRepositoryError(err)
	}
	if !validRulePage(result, tenantID, page.Limit) {
		return RulePage{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) GetRule(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, ruleID uuid.UUID,
) (Rule, error) {
	if !validUUIDv7(ruleID) {
		return Rule{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Rule{}, err
	}
	result, err := s.repository.GetRule(ctx, GetRuleParams{Human: human, RuleID: ruleID})
	if err != nil {
		return Rule{}, mapRepositoryError(err)
	}
	if result.ID != ruleID || !validRule(result, tenantID) {
		return Rule{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) CreateRule(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input RuleWriteInput,
) (Rule, error) {
	fields, err := normalizeRuleFields(input.Fields)
	if err != nil || input.ExpectedVersion != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Rule{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Rule{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Rule{}, err
	}
	ruleID, err := s.nextID()
	if err != nil {
		return Rule{}, err
	}
	result, err := s.repository.CreateRule(ctx, CreateRuleParams{
		Mutation: mutation, RuleID: ruleID, Fields: fields,
	})
	if err != nil {
		return Rule{}, mapRepositoryError(err)
	}
	if !validRuleMutationResult(result, tenantID, ruleID, 1, actor.UserID) {
		return Rule{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) VersionRule(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, ruleID uuid.UUID,
	input RuleWriteInput,
) (Rule, error) {
	if !validUUIDv7(ruleID) {
		return Rule{}, ErrInvalidInput
	}
	fields, err := normalizeRuleFields(input.Fields)
	if err != nil || input.ExpectedVersion == nil {
		if input.ExpectedVersion == nil && err == nil {
			return Rule{}, ErrPreconditionRequired
		}
		return Rule{}, ErrInvalidInput
	}
	expected := *input.ExpectedVersion
	if expected < 1 || expected >= maximumResourceVersion || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Rule{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Rule{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Rule{}, err
	}
	result, err := s.repository.VersionRule(ctx, VersionRuleParams{
		Mutation: mutation, RuleID: ruleID, ExpectedVersion: expected, Fields: fields,
	})
	if err != nil {
		return Rule{}, mapRepositoryError(err)
	}
	if result.Value.ID != ruleID || !validRuleMutationResult(result, tenantID, ruleID, expected+1, actor.UserID) {
		return Rule{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) requireTenant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (HumanParams, error) {
	if !validUUIDv7(tenantID) {
		return HumanParams{}, ErrInvalidInput
	}
	if !validUUIDv7(actor.UserID) || !validUUIDv7(actor.SessionID) || actor.ActiveTenantID != tenantID ||
		!validText(actor.AuthenticationMethod, 1, 64, false) {
		return HumanParams{}, ErrForbidden
	}
	authority, err := s.repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return HumanParams{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman || !validUUIDv7(authority.MembershipID) {
		return HumanParams{}, ErrUnavailable
	}
	if err := s.evaluator.RequireTenant(
		authority,
		authorization.TenantPermissionNotificationManage,
		authorization.ResourceContext{TenantID: tenantID},
	); err != nil {
		return HumanParams{}, ErrForbidden
	}
	return HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID}, nil
}

func (s *Service) requirePlatform(session authentication.Session) (PlatformActor, error) {
	if !validUUIDv7(session.User.ID) || !validUUIDv7(session.ID) ||
		!validText(session.AuthenticationMethod, 1, 64, false) {
		return PlatformActor{}, ErrForbidden
	}
	if err := s.evaluator.Require(session.Permissions, authorization.PermissionPlatformNotificationManage); err != nil {
		return PlatformActor{}, ErrForbidden
	}
	return PlatformActor{
		UserID: session.User.ID, SessionID: session.ID, AuthenticationMethod: session.AuthenticationMethod,
	}, nil
}

func (s *Service) tenantMutation(human HumanParams, idempotencyKey string, audit authorization.AuditContext) (MutationParams, error) {
	when, err := s.currentTime()
	if err != nil {
		return MutationParams{}, err
	}
	return MutationParams{Human: human, Audit: audit, OccurredAt: when, IdempotencyKey: idempotencyKey}, nil
}

func (s *Service) platformMutation(actor PlatformActor, idempotencyKey string, audit authorization.AuditContext) (PlatformMutationParams, error) {
	when, err := s.currentTime()
	if err != nil {
		return PlatformMutationParams{}, err
	}
	return PlatformMutationParams{Actor: actor, Audit: audit, OccurredAt: when, IdempotencyKey: idempotencyKey}, nil
}

func (s *Service) currentTime() (time.Time, error) {
	value := s.now().UTC().Truncate(time.Microsecond)
	if !validInstant(value) {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) nextID() (uuid.UUID, error) {
	value, err := s.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func validCommonMutation(idempotencyKey string, audit authorization.AuditContext) bool {
	return validIdempotency(idempotencyKey) && validMutationAudit(audit)
}

func validRulePage(page RulePage, tenantID uuid.UUID, limit int) bool {
	if len(page.Items) > limit || !validNextCursor(page.NextCursor, len(page.Items), limit) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	for _, item := range page.Items {
		if !validRule(item, tenantID) {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
	}
	return true
}

func validNextCursor(cursor *string, itemCount, limit int) bool {
	if cursor == nil {
		return itemCount <= limit
	}
	return itemCount == limit && len(*cursor) <= maximumNotificationCursor && cursorPattern.MatchString(*cursor)
}

func validRuleMutationResult(result IdempotentResult[Rule], tenantID, requestedID uuid.UUID, freshVersion int64, actorID uuid.UUID) bool {
	value := result.Value
	if !validRule(value, tenantID) || value.ID != requestedID && !result.Replayed {
		return false
	}
	if result.Replayed {
		return true
	}
	return value.ID == requestedID && value.Version == freshVersion && value.CreatedBy == actorID
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden), errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authorization.ErrInvalidInput), errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, authorization.ErrNotFound), errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authorization.ErrConflict), errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, authorization.ErrPreconditionRequired), errors.Is(err, ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, authorization.ErrPreconditionFailed), errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, ErrRateLimited):
		return ErrRateLimited
	case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
