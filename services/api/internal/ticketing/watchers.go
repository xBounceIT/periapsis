package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const maximumTicketWatchers = 1_000

// TicketWatcher is the bounded operator identity projected by watcher
// management. Membership identifiers and authorization material deliberately
// remain inside PostgreSQL: a watcher is addressed by its tenant user ID.
type TicketWatcher struct {
	UserID      uuid.UUID
	DisplayName string
	AddedAt     time.Time
}

// TicketWatcherProjection is both the list representation and the immutable
// command result retained by the idempotency ledger. A command replay can
// therefore return the exact historical result even after a later ticket
// mutation advances the aggregate version.
type TicketWatcherProjection struct {
	TenantID  uuid.UUID
	TicketID  uuid.UUID
	Kind      kernel.AggregateKind
	Items     []TicketWatcher
	Version   uint64
	UpdatedAt time.Time
}

type WatcherMutationAction string

const (
	WatcherAdd    WatcherMutationAction = "add"
	WatcherRemove WatcherMutationAction = "remove"
)

type WatcherMutationInput struct {
	ExpectedVersion uint64
	IdempotencyKey  string
}

type WatcherMutationResult struct {
	Projection TicketWatcherProjection
	Replayed   bool
}

type WatcherListQuery struct {
	Actor    Actor
	TenantID uuid.UUID
	Kind     kernel.AggregateKind
	TicketID uuid.UUID
}

type WatcherMutationWrite struct {
	Actor           Actor
	TenantID        uuid.UUID
	Kind            kernel.AggregateKind
	TicketID        uuid.UUID
	TargetUserID    uuid.UUID
	Action          WatcherMutationAction
	ExpectedVersion uint64
	KeyHash         [sha256.Size]byte
	Fingerprint     [sha256.Size]byte
	Audit           AuditContext
}

func (service *Service) ListAlertWatchers(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (TicketWatcherProjection, error) {
	return service.listWatchers(ctx, actor, tenantID, kernel.AggregateAlert, alertID)
}

func (service *Service) ListCaseWatchers(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID uuid.UUID,
) (TicketWatcherProjection, error) {
	return service.listWatchers(ctx, actor, tenantID, kernel.AggregateCase, caseID)
}

func (service *Service) listWatchers(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) (TicketWatcherProjection, error) {
	if ctx == nil || ctx.Err() != nil {
		return TicketWatcherProjection{}, ErrUnavailable
	}
	if _, err := entityID(ticketID); err != nil {
		return TicketWatcherProjection{}, ErrInvalidInput
	}
	access, err := service.access(ctx, actor, tenantID, readCapability(kind))
	if err != nil {
		return TicketWatcherProjection{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return TicketWatcherProjection{}, ErrForbidden
	}
	view, err := service.getAuthorized(ctx, tenantID, kind, ticketID, access)
	if err != nil {
		return TicketWatcherProjection{}, err
	}
	if view.Projection != ProjectionOperator || ctx.Err() != nil {
		if ctx.Err() != nil {
			return TicketWatcherProjection{}, ErrUnavailable
		}
		return TicketWatcherProjection{}, ErrForbidden
	}
	projection, err := service.repository.ListWatchers(ctx, WatcherListQuery{
		Actor: actor, TenantID: tenantID, Kind: kind, TicketID: ticketID,
	})
	if err != nil {
		return TicketWatcherProjection{}, repositoryError(err)
	}
	projection.Items = slices.Clone(projection.Items)
	currentVersion := view.Record.Snapshot.Version()
	if !validWatcherProjection(projection, tenantID, kind, ticketID) ||
		projection.Version < currentVersion ||
		projection.Version == currentVersion && !projection.UpdatedAt.Equal(view.Record.UpdatedAt) ||
		projection.Version > currentVersion && projection.UpdatedAt.Before(view.Record.UpdatedAt) {
		return TicketWatcherProjection{}, ErrUnavailable
	}
	return projection, nil
}

func (service *Service) AddAlertWatcher(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	targetUserID uuid.UUID,
	input WatcherMutationInput,
) (WatcherMutationResult, error) {
	return service.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateAlert, alertID, targetUserID, WatcherAdd, input,
	)
}

func (service *Service) AddCaseWatcher(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	targetUserID uuid.UUID,
	input WatcherMutationInput,
) (WatcherMutationResult, error) {
	return service.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateCase, caseID, targetUserID, WatcherAdd, input,
	)
}

func (service *Service) RemoveAlertWatcher(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	targetUserID uuid.UUID,
	input WatcherMutationInput,
) (WatcherMutationResult, error) {
	return service.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateAlert, alertID, targetUserID, WatcherRemove, input,
	)
}

func (service *Service) RemoveCaseWatcher(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	targetUserID uuid.UUID,
	input WatcherMutationInput,
) (WatcherMutationResult, error) {
	return service.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateCase, caseID, targetUserID, WatcherRemove, input,
	)
}

func (service *Service) mutateWatcher(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	targetUserID uuid.UUID,
	action WatcherMutationAction,
	input WatcherMutationInput,
) (WatcherMutationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return WatcherMutationResult{}, ErrUnavailable
	}
	if !validMutationActor(actor, tenantID) {
		return WatcherMutationResult{}, ErrForbidden
	}
	if _, err := entityID(ticketID); err != nil {
		return WatcherMutationResult{}, ErrInvalidInput
	}
	if _, err := entityID(targetUserID); err != nil ||
		!validWatcherMutationAction(action) || input.ExpectedVersion == 0 ||
		input.ExpectedVersion >= maxResourceVersion || !validIdempotencyKey(input.IdempotencyKey) {
		return WatcherMutationResult{}, ErrInvalidInput
	}
	fingerprint, err := watcherMutationFingerprint(
		tenantID, actor.UserID, ticketID, targetUserID, kind, action, input.ExpectedVersion,
	)
	if err != nil {
		return WatcherMutationResult{}, err
	}
	capability := CapabilityCaseUpdate
	if kind == kernel.AggregateAlert {
		capability = CapabilityAlertUpdate
	}
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return WatcherMutationResult{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return WatcherMutationResult{}, ErrForbidden
	}
	view, err := service.getAuthorized(ctx, tenantID, kind, ticketID, access)
	if err != nil {
		return WatcherMutationResult{}, err
	}
	if view.Projection != ProjectionOperator {
		return WatcherMutationResult{}, ErrForbidden
	}
	if ctx.Err() != nil {
		return WatcherMutationResult{}, ErrUnavailable
	}
	result, err := service.repository.MutateWatcher(ctx, WatcherMutationWrite{
		Actor: actor, TenantID: tenantID, Kind: kind, TicketID: ticketID,
		TargetUserID: targetUserID, Action: action, ExpectedVersion: input.ExpectedVersion,
		KeyHash: sha256.Sum256([]byte(input.IdempotencyKey)), Fingerprint: fingerprint,
		Audit: actor.Audit,
	})
	if err != nil {
		return WatcherMutationResult{}, repositoryError(err)
	}
	result.Projection.Items = slices.Clone(result.Projection.Items)
	if !validWatcherMutationResult(
		result, tenantID, kind, ticketID, targetUserID, action, input.ExpectedVersion,
	) {
		return WatcherMutationResult{}, ErrUnavailable
	}
	currentVersion := view.Record.Snapshot.Version()
	if !result.Replayed {
		if currentVersion != input.ExpectedVersion {
			return WatcherMutationResult{}, ErrUnavailable
		}
		switch result.Projection.Version {
		case input.ExpectedVersion:
			if !result.Projection.UpdatedAt.Equal(view.Record.UpdatedAt) {
				return WatcherMutationResult{}, ErrUnavailable
			}
		case input.ExpectedVersion + 1:
			if result.Projection.UpdatedAt.Before(view.Record.UpdatedAt) {
				return WatcherMutationResult{}, ErrUnavailable
			}
		default:
			return WatcherMutationResult{}, ErrUnavailable
		}
	}
	return result, nil
}

func validWatcherMutationAction(action WatcherMutationAction) bool {
	return action == WatcherAdd || action == WatcherRemove
}

func watcherMutationFingerprint(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	ticketID uuid.UUID,
	targetUserID uuid.UUID,
	kind kernel.AggregateKind,
	action WatcherMutationAction,
	expectedVersion uint64,
) ([sha256.Size]byte, error) {
	document := struct {
		SchemaVersion   int       `json:"schemaVersion"`
		TenantID        uuid.UUID `json:"tenantId"`
		ActorID         uuid.UUID `json:"actorId"`
		TicketID        uuid.UUID `json:"ticketId"`
		TargetUserID    uuid.UUID `json:"targetUserId"`
		AggregateKind   string    `json:"aggregateKind"`
		Action          string    `json:"action"`
		ExpectedVersion uint64    `json:"expectedVersion"`
	}{
		SchemaVersion: 1, TenantID: tenantID, ActorID: actorID, TicketID: ticketID,
		TargetUserID: targetUserID, AggregateKind: kind.String(), Action: string(action),
		ExpectedVersion: expectedVersion,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 4*1024 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validWatcherProjection(
	projection TicketWatcherProjection,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) bool {
	if projection.TenantID != tenantID || projection.TicketID != ticketID || projection.Kind != kind ||
		projection.Version == 0 || projection.Version > maxResourceVersion ||
		!validStoredInstant(projection.UpdatedAt) || projection.Items == nil ||
		len(projection.Items) > maximumTicketWatchers {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(projection.Items))
	for index, watcher := range projection.Items {
		if _, err := entityID(watcher.UserID); err != nil ||
			!validWatcherDisplayName(watcher.DisplayName) || !validStoredInstant(watcher.AddedAt) ||
			watcher.AddedAt.After(projection.UpdatedAt) {
			return false
		}
		if _, duplicate := seen[watcher.UserID]; duplicate {
			return false
		}
		if index > 0 && compareTicketWatchers(projection.Items[index-1], watcher) >= 0 {
			return false
		}
		seen[watcher.UserID] = struct{}{}
	}
	return true
}

func compareTicketWatchers(left, right TicketWatcher) int {
	if displayOrder := strings.Compare(left.DisplayName, right.DisplayName); displayOrder != 0 {
		return displayOrder
	}
	return strings.Compare(left.UserID.String(), right.UserID.String())
}

func validWatcherMutationResult(
	result WatcherMutationResult,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	targetUserID uuid.UUID,
	action WatcherMutationAction,
	expectedVersion uint64,
) bool {
	projection := result.Projection
	if !validWatcherProjection(projection, tenantID, kind, ticketID) ||
		projection.Version != expectedVersion && projection.Version != expectedVersion+1 {
		return false
	}
	targetPresent := false
	for _, watcher := range projection.Items {
		if watcher.UserID == targetUserID {
			targetPresent = true
			break
		}
	}
	return action == WatcherAdd && targetPresent || action == WatcherRemove && !targetPresent
}

func validWatcherDisplayName(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > 160 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
