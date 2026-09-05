package platform

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	ErrInvalidPlatformTenantAccess            = errors.New("invalid platform tenant access command")
	ErrPlatformTenantAccessConflict           = errors.New("platform tenant access conflict")
	ErrPlatformTenantAccessPreconditionFailed = errors.New("platform tenant access precondition failed")
	platformTenantAccessKeyPattern            = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

// PlatformTenantAccessCommand is an explicit, optimistic request to create one
// ordinary tenant-admin membership for the current platform super administrator.
// It never represents an RLS bypass or implicit tenant authority.
type PlatformTenantAccessCommand struct {
	tenantID        uuid.UUID
	expectedVersion int32
	reason          string
	idempotencyKey  string
}

func NewPlatformTenantAccessCommand(
	tenantID uuid.UUID,
	expectedVersion int32,
	reason string,
	idempotencyKey string,
) (PlatformTenantAccessCommand, error) {
	if !validPlatformTenantID(tenantID) || expectedVersion <= 0 || expectedVersion >= math.MaxInt32 ||
		!validTenantLifecycleReason(reason) || !platformTenantAccessKeyPattern.MatchString(idempotencyKey) {
		return PlatformTenantAccessCommand{}, ErrInvalidPlatformTenantAccess
	}
	return PlatformTenantAccessCommand{
		tenantID: tenantID, expectedVersion: expectedVersion,
		reason: reason, idempotencyKey: idempotencyKey,
	}, nil
}

func (command PlatformTenantAccessCommand) TenantID() uuid.UUID    { return command.tenantID }
func (command PlatformTenantAccessCommand) ExpectedVersion() int32 { return command.expectedVersion }
func (command PlatformTenantAccessCommand) Reason() string         { return command.reason }
func (command PlatformTenantAccessCommand) IdempotencyKey() string { return command.idempotencyKey }
func (command PlatformTenantAccessCommand) String() string {
	return fmt.Sprintf(
		"PlatformTenantAccessCommand{expected_version:%d,metadata:[REDACTED]}",
		command.expectedVersion,
	)
}
func (command PlatformTenantAccessCommand) GoString() string { return command.String() }

func ValidatePlatformTenantAccessCommand(command PlatformTenantAccessCommand) error {
	rebuilt, err := NewPlatformTenantAccessCommand(
		command.tenantID, command.expectedVersion, command.reason, command.idempotencyKey,
	)
	if err != nil || rebuilt != command {
		return ErrInvalidPlatformTenantAccess
	}
	return nil
}

type PlatformTenantAccessReceiptInput struct {
	TenantID              uuid.UUID
	MembershipID          uuid.UUID
	UserID                uuid.UUID
	TenantVersion         int32
	MembershipRevision    int32
	AuthorizationRevision int64
	AuthorizedAt          time.Time
	Replayed              bool
}

type PlatformTenantAccessReceipt struct {
	tenantID              uuid.UUID
	membershipID          uuid.UUID
	userID                uuid.UUID
	tenantVersion         int32
	membershipRevision    int32
	authorizationRevision int64
	authorizedAt          time.Time
	replayed              bool
}

func RestorePlatformTenantAccessReceipt(
	input PlatformTenantAccessReceiptInput,
) (PlatformTenantAccessReceipt, error) {
	if !validPlatformTenantID(input.TenantID) || !validPlatformTenantID(input.MembershipID) ||
		!validPlatformTenantID(input.UserID) || input.TenantVersion <= 0 ||
		input.TenantVersion >= math.MaxInt32 || input.MembershipRevision <= 0 ||
		input.MembershipRevision >= math.MaxInt32 || input.AuthorizationRevision <= 0 ||
		!validTenantLifecycleInstant(input.AuthorizedAt) {
		return PlatformTenantAccessReceipt{}, ErrInvalidPlatformTenantAccess
	}
	return PlatformTenantAccessReceipt{
		tenantID: input.TenantID, membershipID: input.MembershipID, userID: input.UserID,
		tenantVersion: input.TenantVersion, membershipRevision: input.MembershipRevision,
		authorizationRevision: input.AuthorizationRevision,
		authorizedAt:          input.AuthorizedAt, replayed: input.Replayed,
	}, nil
}

func (receipt PlatformTenantAccessReceipt) TenantID() uuid.UUID     { return receipt.tenantID }
func (receipt PlatformTenantAccessReceipt) MembershipID() uuid.UUID { return receipt.membershipID }
func (receipt PlatformTenantAccessReceipt) UserID() uuid.UUID       { return receipt.userID }
func (receipt PlatformTenantAccessReceipt) TenantVersion() int32    { return receipt.tenantVersion }
func (receipt PlatformTenantAccessReceipt) MembershipRevision() int32 {
	return receipt.membershipRevision
}
func (receipt PlatformTenantAccessReceipt) AuthorizationRevision() int64 {
	return receipt.authorizationRevision
}
func (receipt PlatformTenantAccessReceipt) AuthorizedAt() time.Time { return receipt.authorizedAt }
func (receipt PlatformTenantAccessReceipt) Replayed() bool          { return receipt.replayed }
func (receipt PlatformTenantAccessReceipt) String() string {
	return fmt.Sprintf(
		"PlatformTenantAccessReceipt{tenant_version:%d,membership_revision:%d,authorization_revision:%d,replayed:%t,metadata:[REDACTED]}",
		receipt.tenantVersion, receipt.membershipRevision, receipt.authorizationRevision, receipt.replayed,
	)
}
func (receipt PlatformTenantAccessReceipt) GoString() string { return receipt.String() }

func ValidatePlatformTenantAccessReceipt(receipt PlatformTenantAccessReceipt) error {
	rebuilt, err := RestorePlatformTenantAccessReceipt(PlatformTenantAccessReceiptInput{
		TenantID: receipt.tenantID, MembershipID: receipt.membershipID, UserID: receipt.userID,
		TenantVersion: receipt.tenantVersion, MembershipRevision: receipt.membershipRevision,
		AuthorizationRevision: receipt.authorizationRevision,
		AuthorizedAt:          receipt.authorizedAt, Replayed: receipt.replayed,
	})
	if err != nil || rebuilt != receipt {
		return ErrInvalidPlatformTenantAccess
	}
	return nil
}

type PlatformTenantAccessRepository interface {
	AuthorizePlatformTenantAccess(
		context.Context,
		AuthorizePlatformTenantAccessParams,
	) (PlatformTenantAccessReceipt, error)
}

type AuthorizePlatformTenantAccessParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
	Command              PlatformTenantAccessCommand
	Event                authentication.EventContext
}

func (params AuthorizePlatformTenantAccessParams) String() string {
	return fmt.Sprintf(
		"AuthorizePlatformTenantAccessParams{command:%s,actor:[REDACTED],authentication:[REDACTED],event:[REDACTED]}",
		params.Command,
	)
}
func (params AuthorizePlatformTenantAccessParams) GoString() string { return params.String() }

type PlatformTenantAccessService struct {
	repository PlatformTenantAccessRepository
	evaluator  authorization.Evaluator
}

func NewPlatformTenantAccessService(
	repository PlatformTenantAccessRepository,
) (*PlatformTenantAccessService, error) {
	if tenantLifecycleInterfaceIsNil(repository) {
		return nil, errors.New("platform tenant access repository is required")
	}
	return &PlatformTenantAccessService{repository: repository}, nil
}

func (service *PlatformTenantAccessService) Authorize(
	ctx context.Context,
	session authentication.Session,
	command PlatformTenantAccessCommand,
	event authentication.EventContext,
) (PlatformTenantAccessReceipt, error) {
	if service == nil || tenantLifecycleInterfaceIsNil(service.repository) ||
		tenantLifecycleInterfaceIsNil(ctx) {
		return PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(
		session.Permissions, authorization.PermissionPlatformTenantAccess,
	); err != nil {
		return PlatformTenantAccessReceipt{}, authentication.ErrForbidden
	}
	if ValidatePlatformTenantAccessCommand(command) != nil {
		return PlatformTenantAccessReceipt{}, authentication.ErrInvalidInput
	}
	if !validPlatformTenantID(session.User.ID) || !validPlatformTenantID(session.ID) ||
		!validPlatformTenantAccessAuthenticationMethod(session.AuthenticationMethod) ||
		!validTenantLifecycleEvent(event) || event.UserAgent == "" {
		return PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
	}

	receipt, err := service.repository.AuthorizePlatformTenantAccess(
		ctx,
		AuthorizePlatformTenantAccessParams{
			ActorID: session.User.ID, SessionID: session.ID,
			AuthenticationMethod: session.AuthenticationMethod,
			Command:              command, Event: event,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, authentication.ErrForbidden):
			return PlatformTenantAccessReceipt{}, authentication.ErrForbidden
		case errors.Is(err, authentication.ErrNotFound):
			return PlatformTenantAccessReceipt{}, authentication.ErrNotFound
		case errors.Is(err, authentication.ErrConflict),
			errors.Is(err, ErrPlatformTenantAccessConflict):
			return PlatformTenantAccessReceipt{}, authentication.ErrConflict
		case errors.Is(err, ErrPlatformTenantAccessPreconditionFailed):
			return PlatformTenantAccessReceipt{}, ErrPlatformTenantAccessPreconditionFailed
		case errors.Is(err, authentication.ErrInvalidInput),
			errors.Is(err, ErrInvalidPlatformTenantAccess):
			return PlatformTenantAccessReceipt{}, authentication.ErrInvalidInput
		default:
			return PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
		}
	}
	if ValidatePlatformTenantAccessReceipt(receipt) != nil ||
		receipt.TenantID() != command.TenantID() ||
		receipt.UserID() != session.User.ID ||
		receipt.TenantVersion() != command.ExpectedVersion() {
		return PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (*PlatformTenantAccessService) String() string {
	return "platform.PlatformTenantAccessService{dependencies:[REDACTED]}"
}
func (service *PlatformTenantAccessService) GoString() string { return service.String() }

func validPlatformTenantAccessAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "ldap", "oidc", "passkey", "saml", "totp":
		return true
	default:
		return false
	}
}
