package platform

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type TenantLifecycleRepository interface {
	ChangeTenantLifecycle(context.Context, ChangeTenantLifecycleParams) (TenantLifecycleReceipt, error)
}

type ChangeTenantLifecycleParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
	Command              TenantLifecycleCommand
	Event                authentication.EventContext
}

func (params ChangeTenantLifecycleParams) String() string {
	return fmt.Sprintf(
		"ChangeTenantLifecycleParams{command:%s,actor:[REDACTED],authentication:[REDACTED],event:[REDACTED]}",
		params.Command,
	)
}

func (params ChangeTenantLifecycleParams) GoString() string { return params.String() }

type TenantLifecycleReceiptInput struct {
	TenantID  uuid.UUID
	Previous  TenantLifecycleStatus
	Current   TenantLifecycleStatus
	Version   int32
	UpdatedAt time.Time
	Replayed  bool
}

type TenantLifecycleReceipt struct {
	tenantID  uuid.UUID
	previous  TenantLifecycleStatus
	current   TenantLifecycleStatus
	version   int32
	updatedAt time.Time
	replayed  bool
}

func RestoreTenantLifecycleReceipt(
	input TenantLifecycleReceiptInput,
) (TenantLifecycleReceipt, error) {
	if !validPlatformTenantID(input.TenantID) || !validTenantLifecycleStatus(input.Previous) ||
		!validTenantLifecycleStatus(input.Current) || input.Previous == input.Current ||
		input.Version < 2 || !validTenantLifecycleInstant(input.UpdatedAt) {
		return TenantLifecycleReceipt{}, ErrInvalidTenantLifecycle
	}
	if input.Previous == TenantLifecycleActive && input.Current != TenantLifecycleSuspended ||
		input.Previous == TenantLifecycleSuspended && input.Current != TenantLifecycleActive {
		return TenantLifecycleReceipt{}, ErrInvalidTenantLifecycle
	}
	return TenantLifecycleReceipt{
		tenantID: input.TenantID, previous: input.Previous, current: input.Current,
		version: input.Version, updatedAt: input.UpdatedAt, replayed: input.Replayed,
	}, nil
}

func (receipt TenantLifecycleReceipt) TenantID() uuid.UUID             { return receipt.tenantID }
func (receipt TenantLifecycleReceipt) Previous() TenantLifecycleStatus { return receipt.previous }
func (receipt TenantLifecycleReceipt) Current() TenantLifecycleStatus  { return receipt.current }
func (receipt TenantLifecycleReceipt) Version() int32                  { return receipt.version }
func (receipt TenantLifecycleReceipt) UpdatedAt() time.Time            { return receipt.updatedAt }
func (receipt TenantLifecycleReceipt) Replayed() bool                  { return receipt.replayed }
func (receipt TenantLifecycleReceipt) Action() TenantLifecycleAction {
	if receipt.previous == TenantLifecycleSuspended && receipt.current == TenantLifecycleActive {
		return TenantLifecycleReactivate
	}
	return TenantLifecycleSuspend
}
func (receipt TenantLifecycleReceipt) String() string {
	return fmt.Sprintf(
		"TenantLifecycleReceipt{action:%s,version:%d,replayed:%t,metadata:[REDACTED]}",
		receipt.Action(), receipt.version, receipt.replayed,
	)
}
func (receipt TenantLifecycleReceipt) GoString() string { return receipt.String() }

func ValidateTenantLifecycleReceipt(receipt TenantLifecycleReceipt) error {
	rebuilt, err := RestoreTenantLifecycleReceipt(TenantLifecycleReceiptInput{
		TenantID: receipt.tenantID, Previous: receipt.previous, Current: receipt.current,
		Version: receipt.version, UpdatedAt: receipt.updatedAt, Replayed: receipt.replayed,
	})
	if err != nil || rebuilt != receipt {
		return ErrInvalidTenantLifecycle
	}
	return nil
}

type TenantLifecycleService struct {
	repository TenantLifecycleRepository
	evaluator  authorization.Evaluator
}

func NewTenantLifecycleService(
	repository TenantLifecycleRepository,
) (*TenantLifecycleService, error) {
	if tenantLifecycleInterfaceIsNil(repository) {
		return nil, errors.New("tenant lifecycle repository is required")
	}
	return &TenantLifecycleService{repository: repository, evaluator: authorization.Evaluator{}}, nil
}

func (service *TenantLifecycleService) Change(
	ctx context.Context,
	session authentication.Session,
	command TenantLifecycleCommand,
	event authentication.EventContext,
) (TenantLifecycleReceipt, error) {
	if service == nil || tenantLifecycleInterfaceIsNil(service.repository) ||
		tenantLifecycleInterfaceIsNil(ctx) {
		return TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(
		session.Permissions, authorization.PermissionPlatformTenantManage,
	); err != nil {
		return TenantLifecycleReceipt{}, authentication.ErrForbidden
	}
	if ValidateTenantLifecycleCommand(command) != nil {
		return TenantLifecycleReceipt{}, authentication.ErrInvalidInput
	}
	if !validPlatformTenantID(session.User.ID) || !validPlatformTenantID(session.ID) ||
		!validTenantLifecycleAuthenticationMethod(session.AuthenticationMethod) ||
		!validTenantLifecycleEvent(event) {
		return TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}
	receipt, err := service.repository.ChangeTenantLifecycle(ctx, ChangeTenantLifecycleParams{
		ActorID: session.User.ID, SessionID: session.ID,
		AuthenticationMethod: session.AuthenticationMethod,
		Command:              command, Event: event,
	})
	if err != nil {
		switch {
		case errors.Is(err, authentication.ErrForbidden):
			return TenantLifecycleReceipt{}, authentication.ErrForbidden
		case errors.Is(err, authentication.ErrNotFound):
			return TenantLifecycleReceipt{}, authentication.ErrNotFound
		case errors.Is(err, authentication.ErrConflict),
			errors.Is(err, ErrTenantLifecycleConflict),
			errors.Is(err, ErrTenantLifecycleNoChange):
			return TenantLifecycleReceipt{}, authentication.ErrConflict
		case errors.Is(err, authentication.ErrInvalidInput),
			errors.Is(err, ErrInvalidTenantLifecycle):
			return TenantLifecycleReceipt{}, authentication.ErrInvalidInput
		default:
			return TenantLifecycleReceipt{}, authentication.ErrUnavailable
		}
	}
	if ValidateTenantLifecycleReceipt(receipt) != nil || receipt.tenantID != command.tenantID ||
		receipt.current != command.target || receipt.version != command.expectedVersion+1 {
		return TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (*TenantLifecycleService) String() string {
	return "platform.TenantLifecycleService{dependencies:[REDACTED]}"
}

func (service *TenantLifecycleService) GoString() string { return service.String() }

func validTenantLifecycleInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func validTenantLifecycleAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validTenantLifecycleEvent(value authentication.EventContext) bool {
	if value.RequestID == uuid.Nil || value.CorrelationID == uuid.Nil ||
		!value.RemoteAddress.IsValid() || value.RemoteAddress.Zone() != "" ||
		len(value.UserAgent) > 512 || !utf8.ValidString(value.UserAgent) {
		return false
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func tenantLifecycleInterfaceIsNil(value any) bool {
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
