package httpserver

import (
	"context"
	"errors"
	"math"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
)

type unavailableTenantLifecycleService struct{}

func tenantLifecycleServiceIsNil(service TenantLifecycleService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (unavailableTenantLifecycleService) Change(
	context.Context,
	authentication.Session,
	platform.TenantLifecycleCommand,
	authentication.EventContext,
) (platform.TenantLifecycleReceipt, error) {
	return platform.TenantLifecycleReceipt{}, authentication.ErrUnavailable
}

func (h *Handler) SuspendPlatformTenant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.SuspendPlatformTenantParams,
) {
	h.changePlatformTenantLifecycle(
		w, r, uuid.UUID(tenantID), params.IfMatch, platform.TenantLifecycleSuspended,
	)
}

func (h *Handler) ReactivatePlatformTenant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ReactivatePlatformTenantParams,
) {
	h.changePlatformTenantLifecycle(
		w, r, uuid.UUID(tenantID), params.IfMatch, platform.TenantLifecycleActive,
	)
}

func (h *Handler) changePlatformTenantLifecycle(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	ifMatch contract.IfMatch,
	target platform.TenantLifecycleStatus,
) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	if err := h.authentication.ValidateCSRF(session, csrf); err != nil {
		writeDomainError(w, r, err)
		return
	}

	var body contract.TenantLifecycleChangeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeTenantLifecycleError(w, r, authentication.ErrInvalidInput)
		return
	}
	expectedVersion, ok := tenantLifecyclePrecondition(
		w, r, ifMatch, int64(body.ExpectedVersion),
	)
	if !ok {
		return
	}
	command, err := platform.NewTenantLifecycleCommand(
		tenantID, target, expectedVersion, body.Reason,
	)
	if err != nil {
		h.writeTenantLifecycleError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeTenantLifecycleError(w, r, authentication.ErrInvalidInput)
		return
	}
	receipt, err := h.tenantLifecycle.Change(r.Context(), session, command, event)
	if err != nil {
		h.writeTenantLifecycleError(w, r, err)
		return
	}
	mapped, err := mapTenantLifecycleReceipt(receipt)
	if err != nil || !setVersionETag(w, int64(receipt.Version())) {
		h.writeTenantLifecycleError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func tenantLifecyclePrecondition(
	w http.ResponseWriter,
	r *http.Request,
	ifMatch contract.IfMatch,
	bodyVersion int64,
) (int32, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required",
			"Precondition required", "A current strong If-Match entity tag is required.",
		)
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || strings.TrimSpace(string(ifMatch)) != canonical ||
		bodyVersion != version || version < 1 || version >= math.MaxInt32 {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return 0, false
	}
	return int32(version), true
}

func mapTenantLifecycleReceipt(
	receipt platform.TenantLifecycleReceipt,
) (contract.TenantLifecycleReceipt, error) {
	if platform.ValidateTenantLifecycleReceipt(receipt) != nil {
		return contract.TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}
	previous := contract.TenantLifecycleReceiptPreviousStatus(receipt.Previous())
	current := contract.TenantLifecycleReceiptStatus(receipt.Current())
	if !previous.Valid() || !current.Valid() ||
		previous == contract.TenantLifecycleReceiptPreviousStatusActive &&
			current != contract.TenantLifecycleReceiptStatusSuspended ||
		previous == contract.TenantLifecycleReceiptPreviousStatusSuspended &&
			current != contract.TenantLifecycleReceiptStatusActive {
		return contract.TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}
	return contract.TenantLifecycleReceipt{
		TenantId: receipt.TenantID(), PreviousStatus: previous, Status: current,
		Version: int64(receipt.Version()), UpdatedAt: receipt.UpdatedAt(), Replayed: receipt.Replayed(),
	}, nil
}

func (h *Handler) writeTenantLifecycleError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	if errors.Is(err, authentication.ErrConflict) ||
		errors.Is(err, platform.ErrTenantLifecycleConflict) ||
		errors.Is(err, platform.ErrTenantLifecycleNoChange) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The tenant lifecycle state changed after the supplied version was issued.",
		)
		return
	}
	if errors.Is(err, authentication.ErrNotFound) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusNotFound, "not_found", "Resource not found",
			"The requested resource does not exist.",
		)
		return
	}
	writeDomainError(w, r, err)
}

var _ TenantLifecycleService = unavailableTenantLifecycleService{}
