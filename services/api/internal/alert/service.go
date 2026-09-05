package alert

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type Service struct {
	repository Repository
	keyring    serviceaccount.CredentialKeyring
	evaluator  authorization.Evaluator
}

func NewService(repository Repository, keyring serviceaccount.CredentialKeyring) (*Service, error) {
	if repository == nil {
		return nil, errors.New("Alert repository is required")
	}
	if keyring.ActiveVersion() == 0 {
		return nil, errors.New("API credential keyring is required")
	}
	return &Service{repository: repository, keyring: keyring, evaluator: authorization.Evaluator{}}, nil
}

func (s *Service) CreateAsHuman(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input CreateInput) (Alert, error) {
	if !validHumanActor(actor, tenantID) {
		return Alert{}, ErrForbidden
	}
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		return Alert{}, err
	}
	authority, err := s.repository.ResolveHumanAuthority(ctx, authorization.ResolveAuthorityParams{Actor: actor, TenantID: tenantID})
	if err != nil {
		return Alert{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID || !validUUIDv7(authority.MembershipID) ||
		s.evaluator.RequireTenant(authority, authorization.TenantPermissionAlertCreate, authorization.ResourceContext{TenantID: tenantID}) != nil {
		return Alert{}, ErrForbidden
	}
	result, err := s.repository.CreateAsHuman(ctx, CreateAsHumanParams{
		Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID,
		Payload: createPayload(normalized), Audit: normalized.Audit,
	})
	if err != nil {
		return Alert{}, mapRepositoryError(err)
	}
	if !validStoredAlert(result.Alert, tenantID) ||
		!result.Replayed && !freshAlertMatchesCreateInput(result.Alert, normalized) ||
		result.Alert.CreatedByMembershipID == nil ||
		*result.Alert.CreatedByMembershipID != authority.MembershipID || result.Alert.CreatedByUserID == nil ||
		*result.Alert.CreatedByUserID != actor.UserID {
		return Alert{}, ErrUnavailable
	}
	return result.Alert, nil
}

func (s *Service) CreateAsBearer(ctx context.Context, tenantID uuid.UUID, input BearerCreateInput) (Alert, error) {
	if !validUUIDv7(tenantID) {
		return Alert{}, ErrInvalidInput
	}
	normalized, err := normalizeCreateInput(input.CreateInput)
	if err != nil || input.Token == "" {
		return Alert{}, ErrInvalidInput
	}
	if normalized.AssignedTeamID != nil || normalized.AssigneeUserID != nil {
		return Alert{}, ErrForbidden
	}
	credential, err := s.keyring.ParseAndDigest(input.Token)
	if err != nil {
		return Alert{}, ErrUnauthenticated
	}
	defer clear(credential.Digest[:])
	result, err := s.repository.CreateAsServiceAccount(ctx, CreateAsServiceAccountParams{
		Credential: credential, TenantID: tenantID,
		Payload: createPayload(normalized), Audit: normalized.Audit,
	})
	if err != nil {
		return Alert{}, mapRepositoryError(err)
	}
	if !validStoredAlert(result.Alert, tenantID) ||
		!result.Replayed && !freshAlertMatchesCreateInput(result.Alert, normalized) ||
		result.Alert.CreatedByServiceAccountID == nil {
		return Alert{}, ErrUnavailable
	}
	return result.Alert, nil
}

func freshAlertMatchesCreateInput(value Alert, input CreateInput) bool {
	expectedVersion := int64(1)
	if input.AssignedTeamID != nil {
		expectedVersion = 2
	}
	return value.Status == StatusNew && value.Version == expectedVersion && value.UpdatedAt.Equal(value.CreatedAt) &&
		alertMatchesCreateInput(value, input)
}

func validHumanActor(actor authorization.Actor, tenantID uuid.UUID) bool {
	return validUUIDv7(tenantID) && validUUIDv7(actor.UserID) && validUUIDv7(actor.SessionID) &&
		actor.ActiveTenantID == tenantID && validText(actor.AuthenticationMethod, 1, 64)
}

func mapRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, serviceaccount.ErrInvalidCredential):
		return ErrUnauthenticated
	case errors.Is(err, ErrForbidden), errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrInvalidInput), errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrConflict), errors.Is(err, authorization.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
