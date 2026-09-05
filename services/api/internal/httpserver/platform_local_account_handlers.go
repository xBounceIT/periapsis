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
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
)

type unavailablePlatformLocalAccountService struct{}

func platformLocalAccountServiceIsNil(service PlatformLocalAccountService) bool {
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

func (unavailablePlatformLocalAccountService) List(
	context.Context,
	authentication.Session,
	platformlocalaccount.ListInput,
) (platformlocalaccount.Page, error) {
	return platformlocalaccount.Page{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
) (platformlocalaccount.Account, error) {
	return platformlocalaccount.Account{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Invite(
	context.Context,
	authentication.Session,
	platformlocalaccount.InviteInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Activate(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.ActivationInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Disable(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Enable(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) Recover(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformLocalAccountService) RotatePassword(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.PasswordTransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return platformlocalaccount.MutationResult{}, authentication.ErrUnavailable
}

func (h *Handler) ListPlatformLocalAccounts(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformLocalAccountsParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if requireTenantLDAPBodyAbsent(r) != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	input := platformlocalaccount.ListInput{
		IncludeDisabled: params.IncludeDisabled != nil && *params.IncludeDisabled,
	}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.platformLocalAccounts.List(r.Context(), session, input)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	mapped, err := mapPlatformLocalAccountPage(page)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) InvitePlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	params contract.InvitePlatformLocalAccountParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, reason, ok := h.platformLocalAccountMutationHeaders(
		w, r, string(params.IdempotencyKey), string(params.XAuditReason),
	)
	if !ok {
		return
	}
	var body contract.PlatformLocalAccountInviteRequest
	if decodePlatformLocalAccountInviteBody(r, &body) != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := h.platformLocalAccounts.Invite(
		r.Context(),
		session,
		platformlocalaccount.InviteInput{
			DisplayName: body.DisplayName, LoginIdentifier: string(body.LoginIdentifier),
			ProtectedRecoveryPrincipal: body.ProtectedRecoveryPrincipal,
			Reason:                     reason, IdempotencyKey: idempotencyKey, Event: event,
		},
	)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	defer result.Destroy()
	h.writePlatformLocalAccountMutation(w, r, http.StatusCreated, &result, true)
}

func (h *Handler) GetPlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if requireTenantLDAPBodyAbsent(r) != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	account, err := h.platformLocalAccounts.Get(r.Context(), session, uuid.UUID(localAccountID))
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	if account.ID != uuid.UUID(localAccountID) {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformLocalAccount(account)
	if err != nil || !setPlatformLocalAccountETag(w, account.Revision) {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ActivatePlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
	params contract.ActivatePlatformLocalAccountParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	body, err := decodePlatformLocalAccountActivationBody(r)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	defer body.clear()
	entityTag, idempotencyKey, reason, ok := h.platformLocalAccountCASHeaders(
		w, r, string(params.IfMatch), string(params.IdempotencyKey), string(params.XAuditReason), body.ExpectedRevision,
	)
	if !ok {
		return
	}
	result, err := h.platformLocalAccounts.Activate(
		r.Context(), session, uuid.UUID(localAccountID), platformlocalaccount.ActivationInput{
			Reason: reason, IdempotencyKey: idempotencyKey, ExpectedEntityTag: entityTag,
			CeremonyToken: body.CeremonyToken, NewPassword: body.NewPassword, FactorProof: body.FactorProof,
			Event: event,
		},
	)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	defer result.Destroy()
	h.writePlatformLocalAccountMutation(w, r, http.StatusOK, &result, false)
}

func (h *Handler) DisablePlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
	params contract.DisablePlatformLocalAccountParams,
) {
	h.platformLocalAccountTransition(w, r, uuid.UUID(localAccountID), string(params.IfMatch), string(params.IdempotencyKey), string(params.XAuditReason), false, h.platformLocalAccounts.Disable)
}

func (h *Handler) EnablePlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
	params contract.EnablePlatformLocalAccountParams,
) {
	h.platformLocalAccountTransition(w, r, uuid.UUID(localAccountID), string(params.IfMatch), string(params.IdempotencyKey), string(params.XAuditReason), false, h.platformLocalAccounts.Enable)
}

func (h *Handler) RecoverPlatformLocalAccount(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
	params contract.RecoverPlatformLocalAccountParams,
) {
	h.platformLocalAccountTransition(w, r, uuid.UUID(localAccountID), string(params.IfMatch), string(params.IdempotencyKey), string(params.XAuditReason), true, h.platformLocalAccounts.Recover)
}

func (h *Handler) RotatePlatformLocalAccountPassword(
	w http.ResponseWriter,
	r *http.Request,
	localAccountID contract.PlatformLocalAccountId,
	params contract.RotatePlatformLocalAccountPasswordParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	body, err := decodePlatformLocalAccountPasswordBody(r)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	defer body.clear()
	entityTag, idempotencyKey, reason, ok := h.platformLocalAccountCASHeaders(
		w, r, string(params.IfMatch), string(params.IdempotencyKey), string(params.XAuditReason), body.ExpectedRevision,
	)
	if !ok {
		return
	}
	result, err := h.platformLocalAccounts.RotatePassword(
		r.Context(), session, uuid.UUID(localAccountID), platformlocalaccount.PasswordTransitionInput{
			Reason: reason, IdempotencyKey: idempotencyKey, ExpectedEntityTag: entityTag,
			NewPassword: body.NewPassword, Event: event,
		},
	)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	defer result.Destroy()
	h.writePlatformLocalAccountMutation(w, r, http.StatusOK, &result, false)
}

type platformLocalAccountTransitionMethod func(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error)

func (h *Handler) platformLocalAccountTransition(
	w http.ResponseWriter,
	r *http.Request,
	accountID uuid.UUID,
	contractETag string,
	contractIdempotencyKey string,
	contractReason string,
	allowArtifact bool,
	transition platformLocalAccountTransitionMethod,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	var body contract.PlatformLocalAccountTransitionRequest
	if decodePlatformLocalAccountTransitionBody(r, &body) != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, idempotencyKey, reason, ok := h.platformLocalAccountCASHeaders(
		w, r, contractETag, contractIdempotencyKey, contractReason, body.ExpectedRevision,
	)
	if !ok {
		return
	}
	result, err := transition(
		r.Context(), session, accountID, platformlocalaccount.TransitionInput{
			Reason: reason, IdempotencyKey: idempotencyKey, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, err)
		return
	}
	defer result.Destroy()
	h.writePlatformLocalAccountMutation(w, r, http.StatusOK, &result, allowArtifact)
}

func (h *Handler) platformLocalAccountMutationHeaders(
	w http.ResponseWriter,
	r *http.Request,
	contractIdempotencyKey string,
	contractReason string,
) (string, string, bool) {
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != contractIdempotencyKey {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return "", "", false
	}
	reason, err := platformLocalAccountAuditReason(r, contractReason)
	if err != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return "", "", false
	}
	return idempotencyKey, reason, true
}

func (h *Handler) platformLocalAccountCASHeaders(
	w http.ResponseWriter,
	r *http.Request,
	contractETag string,
	contractIdempotencyKey string,
	contractReason string,
	bodyRevision int64,
) (*string, string, string, bool) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required",
			"A current strong platform local-account If-Match entity tag is required.",
		)
		return nil, "", "", false
	}
	if len(values) != 1 || bodyRevision < 1 {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return nil, "", "", false
	}
	revision, err := platformlocalaccount.ParseEntityTag(values[0])
	canonical, canonicalErr := platformlocalaccount.EntityTag(revision)
	if err != nil || canonicalErr != nil || canonical != values[0] || values[0] != contractETag ||
		revision >= maximumPlatformLocalAccountRevision || uint64(bodyRevision) != revision {
		h.writePlatformLocalAccountError(w, r, authentication.ErrInvalidInput)
		return nil, "", "", false
	}
	idempotencyKey, reason, ok := h.platformLocalAccountMutationHeaders(
		w, r, contractIdempotencyKey, contractReason,
	)
	if !ok {
		return nil, "", "", false
	}
	return &canonical, idempotencyKey, reason, true
}

func platformLocalAccountAuditReason(r *http.Request, contractValue string) (string, error) {
	reason, err := singleHeader(r, "X-Audit-Reason", 500)
	if err != nil || reason != contractValue || !platformIdentityProviderAuditReasonIsHTTPValue(reason) {
		return "", authentication.ErrInvalidInput
	}
	return reason, nil
}

func (h *Handler) writePlatformLocalAccountMutation(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	result *platformlocalaccount.MutationResult,
	allowArtifact bool,
) {
	if result == nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	account, err := mapPlatformLocalAccount(result.Account)
	entityTag, entityTagErr := platformlocalaccount.EntityTag(result.Account.Revision)
	if err != nil || entityTagErr != nil {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	material, present := result.Artifact.Consume()
	defer material.Destroy()
	if present != (allowArtifact && !result.Replayed) {
		h.writePlatformLocalAccountError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", entityTag)
	response := contract.PlatformLocalAccountMutationResult{Account: account, Replayed: result.Replayed}
	if present {
		token := string(material.CeremonyToken)
		secret := string(material.TOTPSecret)
		provisioningURI := string(material.ProvisioningURI)
		response.CeremonyToken = &token
		response.TotpEnrollment = &contract.PlatformLocalAccountTOTPEnrollment{
			ProvisioningUri: provisioningURI,
			Secret:          secret,
		}
	}
	if status == http.StatusCreated {
		w.Header().Set("Location", platformLocalAccountLocation(result.Account.ID))
	}
	writeSensitiveJSON(w, status, response)
}

func (h *Handler) writePlatformLocalAccountError(
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
	if errors.Is(err, platformlocalaccount.ErrPreconditionFailed) {
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The platform local-account representation changed after the supplied validator was issued.",
		)
		return
	}
	if errors.Is(err, platformlocalaccount.ErrTransitionConflict) ||
		errors.Is(err, platformlocalaccount.ErrPasswordReused) ||
		errors.Is(err, platformlocalaccount.ErrEnrollmentProofRejected) {
		writeProblem(
			w, r, http.StatusConflict, "conflict", "Conflict",
			"The requested local-account transition cannot be completed in the current state.",
		)
		return
	}
	writeDomainError(w, r, err)
}

func platformLocalAccountLocation(accountID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/platform/local-accounts/%s", accountID)
}

var _ PlatformLocalAccountService = unavailablePlatformLocalAccountService{}
