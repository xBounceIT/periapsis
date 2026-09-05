package platformidentityaccount

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Service struct {
	repository Repository
	protector  SubjectProtector
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository, protector SubjectProtector) (*Service, error) {
	if interfaceIsNil(repository) {
		return nil, errors.New("platform identity account repository is required")
	}
	if interfaceIsNil(protector) || protector.ActiveVersion() < 1 {
		return nil, errors.New("platform identity account subject protector is required")
	}
	return &Service{
		repository: repository, protector: protector,
		evaluator: authorization.Evaluator{}, newID: uuid.NewV7,
	}, nil
}

func (service *Service) List(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ListInput,
) (AccountPage, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return AccountPage{}, err
	}
	if !validSession(session) {
		return AccountPage{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return AccountPage{}, err
	}
	normalized, err := normalizeList(providerID, input)
	if err != nil {
		return AccountPage{}, err
	}
	rows, err := service.repository.List(ctx, ListParams{
		SessionParams: sessionParams(session), ProviderID: providerID, After: normalized.After,
		Limit: int32(normalized.Limit + 1), IncludeRetired: normalized.IncludeRetired,
	})
	if err != nil {
		return AccountPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 {
		return AccountPage{}, authentication.ErrUnavailable
	}
	for index := range rows {
		if !validAccount(rows[index]) || rows[index].ProviderID != providerID ||
			!normalized.IncludeRetired && rows[index].State == AccountStateRetired ||
			index > 0 && bytes.Compare(rows[index-1].ID[:], rows[index].ID[:]) >= 0 ||
			normalized.After != nil && bytes.Compare(rows[index].ID[:], normalized.After[:]) <= 0 {
			return AccountPage{}, authentication.ErrUnavailable
		}
	}
	page := AccountPage{Items: make([]Account, min(len(rows), normalized.Limit))}
	for index := range page.Items {
		page.Items[index] = cloneAccount(rows[index])
	}
	if len(rows) > normalized.Limit {
		next := page.Items[len(page.Items)-1].ID
		page.NextCursor = &next
	}
	return page, nil
}

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	providerID, accountID uuid.UUID,
) (Account, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return Account{}, err
	}
	if !validSession(session) {
		return Account{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return Account{}, err
	}
	if !validUUIDv7(providerID) || !validUUIDv7(accountID) {
		return Account{}, authentication.ErrInvalidInput
	}
	account, err := service.repository.Get(ctx, GetParams{
		SessionParams: sessionParams(session), ProviderID: providerID, AccountID: accountID,
	})
	if err != nil {
		return Account{}, mapRepositoryError(err)
	}
	if account.ID != accountID || account.ProviderID != providerID || !validAccount(account) {
		return Account{}, authentication.ErrUnavailable
	}
	return cloneAccount(account), nil
}

func (service *Service) Prelink(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input PrelinkInput,
) (PrelinkResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountManage); err != nil {
		return PrelinkResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return PrelinkResult{}, err
	}
	if !validSession(session) {
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return PrelinkResult{}, err
	}
	normalized, subject, requestDigest, err := normalizePrelink(providerID, input)
	if err != nil {
		return PrelinkResult{}, err
	}
	defer subject.Clear()
	defer clear(requestDigest[:])
	commandID, err := service.nextID()
	if err != nil {
		return PrelinkResult{}, err
	}
	accountID, err := service.nextID()
	if err != nil {
		return PrelinkResult{}, err
	}
	providerContext := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
	}
	activeKeyVersion := service.protector.ActiveVersion()
	if activeKeyVersion < 1 {
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	aliases, err := service.protector.SubjectAliases(providerContext, subject)
	if err != nil {
		clearSubjectAliases(aliases)
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	envelope, err := service.protector.EncryptExternalSubject(identity.ExternalSubjectContext{
		Provider: providerContext, ExternalIdentityID: identity.EntityID(accountID),
	}, subject)
	if err != nil {
		clearSubjectAliases(aliases)
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	protected := ProtectedSubject{Aliases: aliases, Envelope: envelope}
	defer clearProtectedSubject(&protected)
	// A mutable or incorrectly implemented protector must not let an envelope
	// and alias vector cross key epochs inside one command. identity.Keyring is
	// immutable, but this check keeps the narrower dependency contract closed.
	if service.protector.ActiveVersion() != activeKeyVersion ||
		protected.Envelope.KeyVersion != activeKeyVersion || !validProtectedSubject(protected) {
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	keyDigest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(keyDigest[:])
	validateResult := func(result PrelinkResult) (PrelinkResult, error) {
		validated, validationErr := validatePrelinkResult(result)
		account := validated.Account()
		if validationErr != nil || account.ProviderID != providerID || account.User.ID != normalized.UserID ||
			!validated.Replayed() && (validated.AccountID() != accountID || !initialAccountProjection(account)) {
			return PrelinkResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Prelink(ctx, PrelinkParams{
		SessionParams: sessionParams(session), CommandID: commandID, AccountID: accountID,
		ProviderID: providerID, UserID: normalized.UserID, Issuer: normalized.Issuer,
		Subject: protected, KeyDigest: keyDigest, PublicRequestDigest: requestDigest,
		Reason: normalized.Reason, Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return PrelinkResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Retire(
	ctx context.Context,
	session authentication.Session,
	providerID, accountID uuid.UUID,
	input RetireInput,
) (RetireResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountManage); err != nil {
		return RetireResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return RetireResult{}, err
	}
	if !validSession(session) {
		return RetireResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return RetireResult{}, err
	}
	normalized, expectedVersion, expectedUserVersion, err := normalizeRetire(providerID, accountID, input)
	if err != nil {
		return RetireResult{}, err
	}
	validateResult := func(previous Account, result RetireResult) (RetireResult, error) {
		validated, validationErr := validateRetireResult(result)
		account := validated.Account()
		if validationErr != nil || previous.ID != accountID || previous.ProviderID != providerID ||
			previous.Version != expectedVersion || previous.User.Version != expectedUserVersion ||
			validated.AccountID() != accountID ||
			validated.Version() != expectedVersion+1 || account.ProviderID != providerID ||
			account.User.Version != expectedUserVersion || !validRetirementTransition(previous, account) {
			return RetireResult{}, authentication.ErrUnavailable
		}
		previousCopy := cloneAccount(previous)
		validated.previous = &previousCopy
		return validated, nil
	}
	result, err := service.repository.Retire(ctx, RetireParams{
		SessionParams: sessionParams(session), ProviderID: providerID, AccountID: accountID,
		ExpectedVersion: expectedVersion, ExpectedUserVersion: expectedUserVersion,
		Reason: normalized.Reason, Event: normalized.Event,
		ValidateResult: validateResult,
	})
	if err != nil {
		return RetireResult{}, mapRepositoryError(err)
	}
	if result.previous == nil {
		return RetireResult{}, authentication.ErrUnavailable
	}
	return validateResult(*result.previous, result)
}

func (service *Service) require(session authentication.Session, permission authorization.Permission) error {
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.protector) ||
		service.protector.ActiveVersion() < 1 || service.newID == nil {
		return authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(session.Permissions, permission); err != nil {
		return authentication.ErrForbidden
	}
	return nil
}

func (service *Service) nextID() (uuid.UUID, error) {
	value, err := service.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, authentication.ErrUnavailable
	}
	return value, nil
}

func sessionParams(session authentication.Session) SessionParams {
	return SessionParams{
		ActorID: session.User.ID, SessionID: session.ID, AuthenticationMethod: session.AuthenticationMethod,
	}
}

func validatePrelinkResult(result PrelinkResult) (PrelinkResult, error) {
	restored, err := RestorePrelinkResult(PrelinkResultInput{
		AccountID: result.receipt.accountID, Version: result.receipt.version,
		Replayed: result.receipt.replayed, Account: result.account,
	})
	if err != nil {
		return PrelinkResult{}, authentication.ErrInvalidInput
	}
	return restored, nil
}

func validateRetireResult(result RetireResult) (RetireResult, error) {
	restored, err := RestoreRetireResult(RetireResultInput{
		AccountID: result.receipt.accountID, Version: result.receipt.version, Account: result.account,
	})
	if err != nil {
		return RetireResult{}, authentication.ErrInvalidInput
	}
	if result.previous != nil {
		previous := cloneAccount(*result.previous)
		restored.previous = &previous
	}
	return restored, nil
}

func clearSubjectAliases(values []identity.SubjectAlias) {
	for index := range values {
		clear(values[index].Digest[:])
	}
	clear(values)
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, authentication.ErrForbidden):
		return authentication.ErrForbidden
	case errors.Is(err, authentication.ErrNotFound):
		return authentication.ErrNotFound
	case errors.Is(err, authentication.ErrConflict):
		return authentication.ErrConflict
	case errors.Is(err, authentication.ErrInvalidInput):
		return authentication.ErrInvalidInput
	case errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	default:
		return authentication.ErrUnavailable
	}
}

func serviceContextError(ctx context.Context) error {
	if interfaceIsNil(ctx) {
		return authentication.ErrUnavailable
	}
	return ctx.Err()
}

func interfaceIsNil(value any) bool {
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

func (service *Service) String() string {
	return "platformidentityaccount.Service{dependencies:[REDACTED]}"
}

func (service *Service) GoString() string { return service.String() }
