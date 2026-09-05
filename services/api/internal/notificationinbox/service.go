package notificationinbox

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Clock func() time.Time

type Service struct {
	repository Repository
	clock      Clock
}

func NewService(repository Repository, clock Clock) (*Service, error) {
	if nilInterface(repository) || clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (Service) String() string   { return "notificationinbox.Service{redacted}" }
func (Service) GoString() string { return "notificationinbox.Service{redacted}" }

func (service *Service) List(ctx context.Context, actor Actor, tenantID uuid.UUID, input ListInput) (Page, error) {
	if err := service.validateRequest(ctx, actor, tenantID); err != nil {
		return Page{}, err
	}
	normalized, err := normalizeListInput(input)
	if err != nil {
		return Page{}, err
	}
	access, err := service.resolveAccess(ctx, actor, tenantID)
	if err != nil {
		return Page{}, err
	}
	params := ListParams{
		Actor: actor, Access: access, TenantID: tenantID, UserID: actor.UserID,
		After: normalized.After, FetchLimit: normalized.Limit + 1, UnreadOnly: normalized.UnreadOnly,
	}
	validationParams := params
	if params.After != nil {
		cursor := *params.After
		validationParams.After = &cursor
	}
	snapshot, err := service.repository.List(ctx, params)
	if err != nil {
		return Page{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil || !validListSnapshot(snapshot, validationParams, now) {
		return Page{}, ErrUnavailable
	}
	itemCount := len(snapshot.Items)
	hasNext := itemCount > normalized.Limit
	if hasNext {
		itemCount = normalized.Limit
	}
	items := cloneItems(snapshot.Items[:itemCount])
	page := Page{
		TenantID: tenantID, UserID: actor.UserID, Items: items,
		InboxRevision: snapshot.InboxRevision,
	}
	if hasNext {
		cursor := items[len(items)-1].ID
		page.NextCursor = &cursor
	}
	return page, nil
}

func (service *Service) CountUnread(ctx context.Context, actor Actor, tenantID uuid.UUID) (UnreadState, error) {
	if err := service.validateRequest(ctx, actor, tenantID); err != nil {
		return UnreadState{}, err
	}
	access, err := service.resolveAccess(ctx, actor, tenantID)
	if err != nil {
		return UnreadState{}, err
	}
	state, err := service.repository.CountUnread(ctx, CountUnreadParams{
		Actor: actor, Access: access, TenantID: tenantID, UserID: actor.UserID,
	})
	if err != nil {
		return UnreadState{}, repositoryError(err)
	}
	if !validUnreadState(state, tenantID, actor.UserID) {
		return UnreadState{}, ErrUnavailable
	}
	return state, nil
}

// SetReadState applies item-level CAS. ExpectedRevision is the current item
// revision; changed results advance it exactly once, while no-ops retain it.
func (service *Service) SetReadState(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input SetReadStateInput,
) (ReadStateResult, error) {
	if err := service.validateRequest(ctx, actor, tenantID); err != nil {
		return ReadStateResult{}, err
	}
	if !validUUIDv7(input.ItemID) || !validCASRevision(input.ExpectedRevision, false) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return ReadStateResult{}, ErrInvalidInput
	}
	access, err := service.resolveAccess(ctx, actor, tenantID)
	if err != nil {
		return ReadStateResult{}, err
	}
	command, err := bindSetReadStateCommand(tenantID, actor.UserID, input.ItemID, input)
	if err != nil {
		return ReadStateResult{}, err
	}
	var validationCalls atomic.Uint32
	params := SetReadStateParams{
		Actor: actor, Access: access, TenantID: tenantID, UserID: actor.UserID,
		ItemID: input.ItemID, Read: input.Read, ExpectedRevision: input.ExpectedRevision,
		Command: command, Audit: actor.Audit,
	}
	params.ValidateResult = func(result ReadStateResult) error {
		call := validationCalls.Add(1)
		now, clockErr := service.now()
		if call != 1 || clockErr != nil || !validReadStateResult(result, params, now) {
			return ErrUnavailable
		}
		return nil
	}
	result, err := service.repository.SetReadState(ctx, params)
	if err != nil {
		return ReadStateResult{}, repositoryError(err)
	}
	now, clockErr := service.now()
	if validationCalls.Load() != 1 || clockErr != nil || !validReadStateResult(result, params, now) {
		return ReadStateResult{}, ErrUnavailable
	}
	return ReadStateResult{
		Item: cloneItem(result.Item), InboxRevision: result.InboxRevision,
		Changed: result.Changed, Replayed: result.Replayed,
	}, nil
}

// MarkAllRead applies CAS to the personal inbox revision. A changed result
// advances it exactly once; an empty/no-op result retains the expected value.
func (service *Service) MarkAllRead(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input MarkAllReadInput,
) (MarkAllReadResult, error) {
	if err := service.validateRequest(ctx, actor, tenantID); err != nil {
		return MarkAllReadResult{}, err
	}
	if !validCASRevision(input.ExpectedRevision, true) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return MarkAllReadResult{}, ErrInvalidInput
	}
	access, err := service.resolveAccess(ctx, actor, tenantID)
	if err != nil {
		return MarkAllReadResult{}, err
	}
	command, err := bindMarkAllReadCommand(tenantID, actor.UserID, input)
	if err != nil {
		return MarkAllReadResult{}, err
	}
	var validationCalls atomic.Uint32
	params := MarkAllReadParams{
		Actor: actor, Access: access, TenantID: tenantID, UserID: actor.UserID,
		ExpectedRevision: input.ExpectedRevision, Command: command, Audit: actor.Audit,
	}
	params.ValidateResult = func(result MarkAllReadResult) error {
		if validationCalls.Add(1) != 1 || !validMarkAllReadResult(result, params) {
			return ErrUnavailable
		}
		return nil
	}
	result, err := service.repository.MarkAllRead(ctx, params)
	if err != nil {
		return MarkAllReadResult{}, repositoryError(err)
	}
	if validationCalls.Load() != 1 || !validMarkAllReadResult(result, params) {
		return MarkAllReadResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) validateRequest(ctx context.Context, actor Actor, tenantID uuid.UUID) error {
	if service == nil || nilInterface(service.repository) || service.clock == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if !validActorCoordinate(actor, tenantID) {
		return ErrForbidden
	}
	if !validAudit(actor.Audit) {
		return ErrInvalidInput
	}
	if _, err := service.now(); err != nil {
		return err
	}
	return nil
}

func (service *Service) resolveAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
) (AccessEvidence, error) {
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID)
	if err != nil {
		return AccessEvidence{}, repositoryError(err)
	}
	now, clockErr := service.now()
	if clockErr != nil {
		return AccessEvidence{}, clockErr
	}
	if !validAccessEvidence(actor, tenantID, access, now) {
		return AccessEvidence{}, ErrForbidden
	}
	return access, nil
}

func (service *Service) now() (time.Time, error) {
	now := service.clock()
	if !validInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrRepositoryInvalidInput):
		return ErrInvalidInput
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
