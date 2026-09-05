package httpserver

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
)

type unavailablePlatformTenantAccessService struct{}

func platformTenantAccessServiceIsNil(service PlatformTenantAccessService) bool {
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

func (unavailablePlatformTenantAccessService) Authorize(
	context.Context,
	authentication.Session,
	platform.PlatformTenantAccessCommand,
	authentication.EventContext,
) (platform.PlatformTenantAccessReceipt, error) {
	return platform.PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
}

func (h *Handler) AuthorizePlatformTenantAccess(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.AuthorizePlatformTenantAccessParams,
) {
	// Every response from this high-impact command is session-specific, including
	// validation failures emitted before the domain-specific error mapper runs.
	w.Header().Set("Cache-Control", "no-store")
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
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}

	var body contract.PlatformTenantAccessRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writePlatformTenantAccessError(w, r, authentication.ErrInvalidInput)
		return
	}
	expectedVersion, ok := tenantLifecyclePrecondition(
		w, r, params.IfMatch, int64(body.ExpectedVersion),
	)
	if !ok {
		return
	}
	command, err := platform.NewPlatformTenantAccessCommand(
		uuid.UUID(tenantID), expectedVersion, body.Reason, idempotencyKey,
	)
	if err != nil {
		h.writePlatformTenantAccessError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil || event.UserAgent == "" {
		h.writePlatformTenantAccessError(w, r, authentication.ErrInvalidInput)
		return
	}
	receipt, err := h.platformTenantAccess.Authorize(r.Context(), session, command, event)
	if err != nil {
		h.writePlatformTenantAccessError(w, r, err)
		return
	}
	mapped, err := mapPlatformTenantAccessReceipt(receipt)
	if err != nil || !setVersionETag(w, int64(receipt.TenantVersion())) {
		h.writePlatformTenantAccessError(w, r, authentication.ErrUnavailable)
		return
	}
	status := http.StatusCreated
	if receipt.Replayed() {
		status = http.StatusOK
	}
	writeSensitiveJSON(w, status, mapped)
}

func mapPlatformTenantAccessReceipt(
	receipt platform.PlatformTenantAccessReceipt,
) (contract.PlatformTenantAccessReceipt, error) {
	if platform.ValidatePlatformTenantAccessReceipt(receipt) != nil {
		return contract.PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
	}
	return contract.PlatformTenantAccessReceipt{
		TenantId: receipt.TenantID(), MembershipId: receipt.MembershipID(),
		UserId: receipt.UserID(), TenantVersion: int64(receipt.TenantVersion()),
		MembershipRevision:    int64(receipt.MembershipRevision()),
		AuthorizationRevision: strconv.FormatInt(receipt.AuthorizationRevision(), 10),
		AuthorizedAt:          receipt.AuthorizedAt(), Replayed: receipt.Replayed(),
	}, nil
}

func (h *Handler) writePlatformTenantAccessError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	w.Header().Set("Cache-Control", "no-store")
	if errors.Is(err, platform.ErrPlatformTenantAccessPreconditionFailed) {
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The tenant or explicit access state changed after the supplied version was issued.",
		)
		return
	}
	if errors.Is(err, authentication.ErrNotFound) {
		writeProblem(
			w, r, http.StatusNotFound, "not_found", "Resource not found",
			"The requested resource does not exist.",
		)
		return
	}
	writeDomainError(w, r, err)
}

var _ PlatformTenantAccessService = unavailablePlatformTenantAccessService{}
