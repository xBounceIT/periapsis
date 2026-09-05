package httpserver

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const idempotentReplayHeader = "X-Idempotent-Replay"

func (h *Handler) GetTenantAlertWatchers(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
) {
	h.listTicketWatchers(
		w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID),
	)
}

func (h *Handler) GetTenantCaseWatchers(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
) {
	h.listTicketWatchers(
		w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID),
	)
}

func (h *Handler) listTicketWatchers(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	var projection applicationticketing.TicketWatcherProjection
	var err error
	if kind == kernel.AggregateAlert {
		projection, err = h.ticketing.ListAlertWatchers(r.Context(), actor, tenantID, ticketID)
	} else {
		projection, err = h.ticketing.ListCaseWatchers(r.Context(), actor, tenantID, ticketID)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketWatcherPage(projection, tenantID, kind, ticketID, nil)
	if err != nil || !setVersionETag(w, int64(projection.Version)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) AddTenantAlertWatcher(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	userID contract.UserId,
	params contract.AddTenantAlertWatcherParams,
) {
	h.mutateTicketWatcher(
		w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), uuid.UUID(userID),
		applicationticketing.WatcherAdd, params.IfMatch, params.IdempotencyKey,
	)
}

func (h *Handler) RemoveTenantAlertWatcher(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	userID contract.UserId,
	params contract.RemoveTenantAlertWatcherParams,
) {
	h.mutateTicketWatcher(
		w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), uuid.UUID(userID),
		applicationticketing.WatcherRemove, params.IfMatch, params.IdempotencyKey,
	)
}

func (h *Handler) AddTenantCaseWatcher(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	userID contract.UserId,
	params contract.AddTenantCaseWatcherParams,
) {
	h.mutateTicketWatcher(
		w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), uuid.UUID(userID),
		applicationticketing.WatcherAdd, params.IfMatch, params.IdempotencyKey,
	)
}

func (h *Handler) RemoveTenantCaseWatcher(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	userID contract.UserId,
	params contract.RemoveTenantCaseWatcherParams,
) {
	h.mutateTicketWatcher(
		w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), uuid.UUID(userID),
		applicationticketing.WatcherRemove, params.IfMatch, params.IdempotencyKey,
	)
}

func (h *Handler) mutateTicketWatcher(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	targetUserID uuid.UUID,
	action applicationticketing.WatcherMutationAction,
	ifMatch contract.TicketWatcherIfMatch,
	parameterKey contract.IdempotencyKey,
) {
	actor, expectedVersion, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	if expectedVersion >= 2_147_483_647 {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(parameterKey) != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	if err := requireEmptyTicketWatcherMutationBody(r); err != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input := applicationticketing.WatcherMutationInput{
		ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey,
	}
	var result applicationticketing.WatcherMutationResult
	if kind == kernel.AggregateAlert && action == applicationticketing.WatcherAdd {
		result, err = h.ticketing.AddAlertWatcher(
			r.Context(), actor, tenantID, ticketID, targetUserID, input,
		)
	} else if kind == kernel.AggregateAlert {
		result, err = h.ticketing.RemoveAlertWatcher(
			r.Context(), actor, tenantID, ticketID, targetUserID, input,
		)
	} else if action == applicationticketing.WatcherAdd {
		result, err = h.ticketing.AddCaseWatcher(
			r.Context(), actor, tenantID, ticketID, targetUserID, input,
		)
	} else {
		result, err = h.ticketing.RemoveCaseWatcher(
			r.Context(), actor, tenantID, ticketID, targetUserID, input,
		)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketWatcherPage(
		result.Projection, tenantID, kind, ticketID, &expectedVersion,
	)
	if err != nil || !setVersionETag(w, int64(result.Projection.Version)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func requireEmptyTicketWatcherMutationBody(r *http.Request) error {
	if r == nil {
		return errors.New("watcher mutation request is missing")
	}
	if r.Body == nil {
		return nil
	}
	body := r.Body
	var firstByte [1]byte
	count, readErr := body.Read(firstByte[:])
	closeErr := body.Close()
	if count != 0 || !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.New("watcher mutation request body must be empty")
	}
	return nil
}

func mapTicketWatcherPage(
	value applicationticketing.TicketWatcherProjection,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	expectedVersion *uint64,
) (contract.TicketWatcherPage, error) {
	if value.TenantID != tenantID || value.TicketID != ticketID || value.Kind != kind ||
		value.Version == 0 || value.Version > 2_147_483_647 || value.Items == nil ||
		len(value.Items) > 1_000 || !validTicketWatcherTransportTime(value.UpdatedAt) {
		return contract.TicketWatcherPage{}, errors.New("invalid ticket watcher projection")
	}
	if expectedVersion != nil && value.Version != *expectedVersion && value.Version != *expectedVersion+1 {
		return contract.TicketWatcherPage{}, errors.New("invalid ticket watcher mutation version")
	}
	items := make([]contract.TicketWatcher, 0, len(value.Items))
	seen := make(map[uuid.UUID]struct{}, len(value.Items))
	for index, watcher := range value.Items {
		if !validTicketWatcherTransportUUID(watcher.UserID) ||
			!validBoundedText(watcher.DisplayName, 1, 160) ||
			strings.TrimSpace(watcher.DisplayName) != watcher.DisplayName ||
			!validTicketWatcherTransportTime(watcher.AddedAt) || watcher.AddedAt.After(value.UpdatedAt) {
			return contract.TicketWatcherPage{}, errors.New("invalid ticket watcher")
		}
		if _, duplicate := seen[watcher.UserID]; duplicate {
			return contract.TicketWatcherPage{}, errors.New("duplicate ticket watcher")
		}
		if index > 0 && compareTicketWatcherTransportItems(value.Items[index-1], watcher) >= 0 {
			return contract.TicketWatcherPage{}, errors.New("non-canonical ticket watcher order")
		}
		seen[watcher.UserID] = struct{}{}
		items = append(items, contract.TicketWatcher{
			UserId: watcher.UserID, DisplayName: watcher.DisplayName, AddedAt: watcher.AddedAt.UTC(),
		})
	}
	return contract.TicketWatcherPage{
		Items: items, UpdatedAt: value.UpdatedAt.UTC(), Version: int64(value.Version),
	}, nil
}

func compareTicketWatcherTransportItems(left, right applicationticketing.TicketWatcher) int {
	if displayOrder := strings.Compare(left.DisplayName, right.DisplayName); displayOrder != 0 {
		return displayOrder
	}
	return strings.Compare(left.UserID.String(), right.UserID.String())
}

func validTicketWatcherTransportUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validTicketWatcherTransportTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Nanosecond()%int(time.Microsecond) == 0
}
