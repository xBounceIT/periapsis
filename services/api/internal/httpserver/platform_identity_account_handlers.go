package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
)

type unavailablePlatformIdentityAccountService struct{}

func platformIdentityAccountServiceIsNil(service PlatformIdentityAccountService) bool {
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

func (unavailablePlatformIdentityAccountService) List(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityaccount.ListInput,
) (platformidentityaccount.AccountPage, error) {
	return platformidentityaccount.AccountPage{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityAccountService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
) (platformidentityaccount.Account, error) {
	return platformidentityaccount.Account{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityAccountService) Prelink(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityaccount.PrelinkInput,
) (platformidentityaccount.PrelinkResult, error) {
	return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityAccountService) Retire(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
	platformidentityaccount.RetireInput,
) (platformidentityaccount.RetireResult, error) {
	return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
}

func (h *Handler) ListPlatformAuthProviderAccounts(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ListPlatformAuthProviderAccountsParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	input := platformidentityaccount.ListInput{
		IncludeRetired: params.IncludeRetired != nil && *params.IncludeRetired,
	}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.platformIdentityAccounts.List(
		r.Context(), session, uuid.UUID(providerID), input,
	)
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, err)
		return
	}
	mapped, err := mapPlatformIdentityAccountPage(uuid.UUID(providerID), page)
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) PrelinkPlatformAuthProviderAccount(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.PrelinkPlatformAuthProviderAccountParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderAccountPrelinkRequest
	if err := decodePlatformIdentityAccountPrelinkBody(r, &body); err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	issuer, subject := *body.Issuer, *body.Subject
	body.Issuer = nil
	body.Subject = nil
	result, err := h.platformIdentityAccounts.Prelink(
		r.Context(), session, uuid.UUID(providerID), platformidentityaccount.PrelinkInput{
			UserID: uuid.UUID(body.UserId), Issuer: issuer, Subject: subject,
			Reason: reason, IdempotencyKey: idempotencyKey, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, err)
		return
	}
	account := result.Account()
	if result.AccountID() != account.ID || account.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityAccount(account)
	if err != nil || !setPlatformIdentityAccountETag(w, account.Version, account.User.Version) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Location", platformIdentityAccountLocation(account.ProviderID, account.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetPlatformAuthProviderAccount(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	accountID contract.PlatformAuthProviderAccountId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	account, err := h.platformIdentityAccounts.Get(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(accountID),
	)
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, err)
		return
	}
	if account.ID != uuid.UUID(accountID) || account.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityAccount(account)
	if err != nil || !setPlatformIdentityAccountETag(w, account.Version, account.User.Version) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) RetirePlatformAuthProviderAccount(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	accountID contract.PlatformAuthProviderAccountId,
	params contract.RetirePlatformAuthProviderAccountParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderAccountRetireRequest
	if err := decodePlatformIdentityAccountRetireBody(r, &body); err != nil {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityAccountPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityAccounts.Retire(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(accountID),
		platformidentityaccount.RetireInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityAccountError(w, r, err)
		return
	}
	account := result.Account()
	if result.AccountID() != uuid.UUID(accountID) || account.ID != uuid.UUID(accountID) ||
		account.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityAccount(account)
	if err != nil || !setPlatformIdentityAccountETag(w, account.Version, account.User.Version) {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) platformIdentityAccountPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue string,
	bodyVersion int64,
) (*string, bool) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required",
			"A current strong platform identity-account If-Match entity tag is required.",
		)
		return nil, false
	}
	if len(values) != 1 {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return nil, false
	}
	value := values[0]
	version, userVersion, err := platformidentityaccount.ParseEntityTag(value)
	canonical, canonicalErr := platformidentityaccount.EntityTag(version, userVersion)
	if err != nil || canonicalErr != nil || value != contractValue || canonical != value ||
		bodyVersion != version || version > maximumIncrementableResourceVersion {
		h.writePlatformIdentityAccountError(w, r, authentication.ErrInvalidInput)
		return nil, false
	}
	return &canonical, true
}

func setPlatformIdentityAccountETag(w http.ResponseWriter, version, userVersion int64) bool {
	value, err := platformidentityaccount.EntityTag(version, userVersion)
	if err != nil {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}

func (h *Handler) writePlatformIdentityAccountError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	if errors.Is(err, context.Canceled) {
		if errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		err = authentication.ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = authentication.ErrUnavailable
	}
	if errors.Is(err, authentication.ErrNotFound) {
		writeProblem(
			w, r, http.StatusNotFound, "not_found", "Resource not found",
			"The requested platform identity resource does not exist.",
		)
		return
	}
	if errors.Is(err, platformidentityaccount.ErrPreconditionFailed) {
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The platform identity account or embedded user representation changed after the supplied validator was issued.",
		)
		return
	}
	writeDomainError(w, r, err)
}

func platformIdentityAccountLocation(providerID, accountID uuid.UUID) string {
	return fmt.Sprintf(
		"/api/v1/platform/auth-providers/%s/accounts/%s", providerID, accountID,
	)
}

var _ PlatformIdentityAccountService = unavailablePlatformIdentityAccountService{}
