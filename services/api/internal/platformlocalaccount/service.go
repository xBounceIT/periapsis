package platformlocalaccount

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Options struct {
	Repository       Repository
	PasswordHasher   PasswordHasher
	TOTPEnrollment   TOTPEnrollmentSecurity
	CommandDigestKey []byte
	Random           io.Reader
	Now              func() time.Time
	NewID            func() (uuid.UUID, error)
}

func (Options) String() string           { return "platformlocalaccount.Options{dependencies:[REDACTED]}" }
func (options Options) GoString() string { return options.String() }

type Service struct {
	repository Repository
	passwords  PasswordHasher
	enrollment TOTPEnrollmentSecurity
	secrets    secretGenerator
	evaluator  authorization.Evaluator
	now        func() time.Time
	newID      func() (uuid.UUID, error)
}

func NewService(options Options) (*Service, error) {
	if interfaceIsNil(options.Repository) || interfaceIsNil(options.PasswordHasher) ||
		interfaceIsNil(options.TOTPEnrollment) {
		return nil, errors.New("platform local account repository, password hasher, and TOTP enrollment security are required")
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = io.Reader(nil)
	}
	var generator secretGenerator
	var err error
	if randomSource == nil {
		generator, err = defaultSecretGenerator(options.CommandDigestKey)
	} else {
		generator, err = newSecretGenerator(randomSource, options.CommandDigestKey)
	}
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = uuid.NewV7
	}
	return &Service{
		repository: options.Repository, passwords: options.PasswordHasher, enrollment: options.TOTPEnrollment, secrets: generator,
		evaluator: authorization.Evaluator{}, now: options.Now, newID: options.NewID,
	}, nil
}

func (service *Service) List(ctx context.Context, session authentication.Session, input ListInput) (Page, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return Page{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return Page{}, err
	}
	normalized, err := normalizeList(input)
	if err != nil {
		return Page{}, err
	}
	rows, err := service.repository.List(ctx, ListParams{
		SessionParams: sessionParams(session), After: normalized.After,
		Limit: int32(normalized.Limit + 1), IncludeDisabled: normalized.IncludeDisabled,
	})
	if err != nil {
		return Page{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 {
		return Page{}, authentication.ErrUnavailable
	}
	for index := range rows {
		if !validAccount(rows[index]) || !normalized.IncludeDisabled && rows[index].Status == StatusDisabled ||
			index > 0 && bytes.Compare(rows[index-1].ID[:], rows[index].ID[:]) >= 0 ||
			normalized.After != nil && bytes.Compare(rows[index].ID[:], normalized.After[:]) <= 0 {
			return Page{}, authentication.ErrUnavailable
		}
	}
	page := Page{Items: make([]Account, min(len(rows), normalized.Limit))}
	for index := range page.Items {
		page.Items[index] = cloneAccount(rows[index])
	}
	if len(rows) > normalized.Limit {
		next := page.Items[len(page.Items)-1].ID
		page.NextCursor = &next
	}
	return page, nil
}

func (service *Service) Get(ctx context.Context, session authentication.Session, accountID uuid.UUID) (Account, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountRead); err != nil {
		return Account{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return Account{}, err
	}
	if !validUUIDv7(accountID) {
		return Account{}, authentication.ErrInvalidInput
	}
	account, err := service.repository.Get(ctx, GetParams{SessionParams: sessionParams(session), AccountID: accountID})
	if err != nil {
		return Account{}, mapRepositoryError(err)
	}
	if account.ID != accountID || !validAccount(account) {
		return Account{}, authentication.ErrUnavailable
	}
	return cloneAccount(account), nil
}

func (service *Service) Invite(ctx context.Context, session authentication.Session, input InviteInput) (MutationResult, error) {
	if err := service.requireMutation(session); err != nil {
		return MutationResult{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationResult{}, err
	}
	normalized, err := normalizeInvite(input)
	if err != nil {
		return MutationResult{}, err
	}
	now := service.currentTime()
	commandID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	accountID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	userID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	factorID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	token, tokenDigest, err := service.secrets.issue("ceremony-token")
	if err != nil {
		return MutationResult{}, authentication.ErrUnavailable
	}
	defer clear(token)
	expiresAt := now.Add(ceremonyLifetime)
	enrollmentRequest := NewTOTPEnrollmentRequest{
		AccountID: accountID, UserID: userID, FactorID: factorID,
		Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
		CeremonyTokenDigest: tokenDigest,
	}
	enrollment, err := service.enrollment.New(ctx, enrollmentRequest)
	if err != nil || ctx.Err() != nil || !validTOTPEnrollmentMaterial(enrollment, enrollmentRequest) {
		enrollment.Destroy()
		return MutationResult{}, authentication.ErrUnavailable
	}
	defer enrollment.Destroy()
	pending := &PendingTOTPEnrollment{
		AccountID: accountID, UserID: userID, FactorID: factorID,
		Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
		FactorRevision: initialTOTPFactorRevision, CeremonyTokenDigest: tokenDigest,
		ProtectedSecret: cloneEncryptedTOTPSecret(enrollment.ProtectedSecret), ExpiresAt: expiresAt,
	}
	defer pending.Destroy()
	requestDigest, err := publicRequestDigest(service.secrets, struct {
		Action                     string `json:"action"`
		DisplayName                string `json:"displayName"`
		LoginIdentifier            string `json:"loginIdentifier"`
		ProtectedRecoveryPrincipal bool   `json:"protectedRecoveryPrincipal"`
		Reason                     string `json:"reason"`
	}{"invite", normalized.DisplayName, normalized.LoginIdentifier, normalized.ProtectedRecoveryPrincipal, normalized.Reason}, nil)
	if err != nil {
		return MutationResult{}, err
	}
	defer clear(requestDigest[:])
	result, err := service.apply(ctx, session, applyCommand{
		action: localaccount.ActionInvite, commandID: commandID, newAccountID: accountID, newUserID: userID,
		now: now, displayName: normalized.DisplayName, loginIdentifier: normalized.LoginIdentifier,
		protectedRecoveryPrincipal: normalized.ProtectedRecoveryPrincipal, reason: normalized.Reason,
		idempotencyKey: normalized.IdempotencyKey, requestDigest: requestDigest,
		issueTokenDigest: tokenDigest, issueTokenExpiresAt: expiresAt,
		pendingTOTPEnrollment: pending, event: normalized.Event,
	})
	if err != nil {
		return MutationResult{}, err
	}
	if result.ArtifactIssued {
		return MutationResult{
			Account: cloneAccount(result.Account), Replayed: result.Replayed,
			Artifact: newOneTimeArtifact(
				append([]byte(nil), token...), append([]byte(nil), enrollment.DisplaySecret...),
				append([]byte(nil), enrollment.ProvisioningURI...),
			),
		}, nil
	}
	return MutationResult{Account: cloneAccount(result.Account), Replayed: result.Replayed}, nil
}

func (service *Service) Activate(ctx context.Context, session authentication.Session, accountID uuid.UUID, input ActivationInput) (MutationResult, error) {
	defer clear(input.CeremonyToken)
	defer clear(input.NewPassword)
	defer clear(input.FactorProof)
	if err := service.requireMutation(session); err != nil {
		return MutationResult{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationResult{}, err
	}
	normalized, expected, err := normalizeActivation(accountID, input)
	if err != nil {
		return MutationResult{}, err
	}
	phc, err := service.passwords.Hash(normalized.NewPassword)
	if err != nil || !validGeneratedPasswordPHC(phc) {
		clear(phc)
		return MutationResult{}, authentication.ErrUnavailable
	}
	defer clear(phc)
	requestMaterial := make([]byte, 0, len(normalized.CeremonyToken)+len(normalized.NewPassword)+len(normalized.FactorProof)+2)
	requestMaterial = append(requestMaterial, normalized.CeremonyToken...)
	requestMaterial = append(requestMaterial, 0)
	requestMaterial = append(requestMaterial, normalized.NewPassword...)
	requestMaterial = append(requestMaterial, 0)
	requestMaterial = append(requestMaterial, normalized.FactorProof...)
	defer clear(requestMaterial)
	requestDigest, err := publicRequestDigest(service.secrets, struct {
		Action   string    `json:"action"`
		Account  uuid.UUID `json:"accountId"`
		Expected uint64    `json:"expectedRevision"`
		Reason   string    `json:"reason"`
	}{"activate", accountID, expected, normalized.Reason}, requestMaterial)
	if err != nil {
		return MutationResult{}, err
	}
	defer clear(requestDigest[:])
	commandID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.apply(ctx, session, applyCommand{
		action: localaccount.ActionActivate, commandID: commandID, accountID: accountID,
		expectedRevision: expected, now: service.currentTime(), reason: normalized.Reason,
		idempotencyKey: normalized.IdempotencyKey, requestDigest: requestDigest,
		ceremonyTokenDigest: service.secrets.digest("ceremony-token", normalized.CeremonyToken),
		ceremonyFactorProof: normalized.FactorProof, passwordPHC: phc,
		validatePasswordHistory: service.passwordHistoryValidator(normalized.NewPassword), event: normalized.Event,
	})
	if err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Account: cloneAccount(result.Account), Replayed: result.Replayed}, nil
}

func (service *Service) Disable(ctx context.Context, session authentication.Session, accountID uuid.UUID, input TransitionInput) (MutationResult, error) {
	return service.transition(ctx, session, accountID, localaccount.ActionDisable, input)
}

func (service *Service) Enable(ctx context.Context, session authentication.Session, accountID uuid.UUID, input TransitionInput) (MutationResult, error) {
	return service.transition(ctx, session, accountID, localaccount.ActionEnable, input)
}

func (service *Service) Recover(ctx context.Context, session authentication.Session, accountID uuid.UUID, input TransitionInput) (MutationResult, error) {
	return service.transition(ctx, session, accountID, localaccount.ActionRecover, input)
}

func (service *Service) RotatePassword(ctx context.Context, session authentication.Session, accountID uuid.UUID, input PasswordTransitionInput) (MutationResult, error) {
	defer clear(input.NewPassword)
	if err := service.requireMutation(session); err != nil {
		return MutationResult{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationResult{}, err
	}
	normalized, expected, err := normalizePasswordTransition(accountID, input)
	if err != nil {
		return MutationResult{}, err
	}
	phc, err := service.passwords.Hash(normalized.NewPassword)
	if err != nil || !validGeneratedPasswordPHC(phc) {
		clear(phc)
		return MutationResult{}, authentication.ErrUnavailable
	}
	defer clear(phc)
	requestDigest, err := publicRequestDigest(service.secrets, struct {
		Action   string    `json:"action"`
		Account  uuid.UUID `json:"accountId"`
		Expected uint64    `json:"expectedRevision"`
		Reason   string    `json:"reason"`
	}{"rotate_password", accountID, expected, normalized.Reason}, normalized.NewPassword)
	if err != nil {
		return MutationResult{}, err
	}
	defer clear(requestDigest[:])
	validateHistory := service.passwordHistoryValidator(normalized.NewPassword)
	commandID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.apply(ctx, session, applyCommand{
		action: localaccount.ActionRotatePassword, commandID: commandID, accountID: accountID,
		expectedRevision: expected, now: service.currentTime(), reason: normalized.Reason,
		idempotencyKey: normalized.IdempotencyKey, requestDigest: requestDigest,
		passwordPHC: phc, validatePasswordHistory: validateHistory, event: normalized.Event,
	})
	if err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Account: cloneAccount(result.Account), Replayed: result.Replayed}, nil
}

type applyCommand struct {
	action                     localaccount.Action
	commandID                  uuid.UUID
	accountID                  uuid.UUID
	newAccountID               uuid.UUID
	newUserID                  uuid.UUID
	expectedRevision           uint64
	now                        time.Time
	displayName                string
	loginIdentifier            string
	protectedRecoveryPrincipal bool
	reason                     string
	idempotencyKey             string
	requestDigest              [sha256.Size]byte
	ceremonyTokenDigest        [sha256.Size]byte
	ceremonyFactorProof        []byte
	passwordPHC                []byte
	issueTokenDigest           [sha256.Size]byte
	issueTokenExpiresAt        time.Time
	pendingTOTPEnrollment      *PendingTOTPEnrollment
	event                      authentication.EventContext
	validatePasswordHistory    PasswordHistoryValidator
}

func (service *Service) transition(ctx context.Context, session authentication.Session, accountID uuid.UUID, action localaccount.Action, input TransitionInput) (MutationResult, error) {
	if err := service.requireMutation(session); err != nil {
		return MutationResult{}, err
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationResult{}, err
	}
	normalized, expected, err := normalizeTransition(accountID, action, input)
	if err != nil {
		return MutationResult{}, err
	}
	actionName := map[localaccount.Action]string{
		localaccount.ActionDisable: "disable", localaccount.ActionEnable: "enable", localaccount.ActionRecover: "recover",
	}[action]
	requestDigest, err := publicRequestDigest(service.secrets, struct {
		Action   string    `json:"action"`
		Account  uuid.UUID `json:"accountId"`
		Expected uint64    `json:"expectedRevision"`
		Reason   string    `json:"reason"`
	}{actionName, accountID, expected, normalized.Reason}, nil)
	if err != nil {
		return MutationResult{}, err
	}
	defer clear(requestDigest[:])
	var token []byte
	var issueDigest [sha256.Size]byte
	var issueExpires time.Time
	var enrollment TOTPEnrollmentMaterial
	var pending *PendingTOTPEnrollment
	now := service.currentTime()
	if action == localaccount.ActionRecover {
		account, getErr := service.repository.Get(ctx, GetParams{
			SessionParams: sessionParams(session), AccountID: accountID,
		})
		if getErr != nil {
			return MutationResult{}, mapRepositoryError(getErr)
		}
		if account.ID != accountID || !validAccount(account) {
			return MutationResult{}, authentication.ErrUnavailable
		}
		token, issueDigest, err = service.secrets.issue("ceremony-token")
		if err != nil {
			return MutationResult{}, authentication.ErrUnavailable
		}
		defer clear(token)
		issueExpires = now.Add(ceremonyLifetime)
		factorID, factorErr := service.nextID()
		if factorErr != nil {
			return MutationResult{}, factorErr
		}
		enrollmentRequest := NewTOTPEnrollmentRequest{
			AccountID: account.ID, UserID: account.UserID, FactorID: factorID,
			Purpose: TOTPEnrollmentRecover, Version: initialTOTPEnrollmentVersion,
			CeremonyTokenDigest: issueDigest,
		}
		enrollment, err = service.enrollment.New(ctx, enrollmentRequest)
		if err != nil || ctx.Err() != nil || !validTOTPEnrollmentMaterial(enrollment, enrollmentRequest) {
			enrollment.Destroy()
			return MutationResult{}, authentication.ErrUnavailable
		}
		defer enrollment.Destroy()
		pending = &PendingTOTPEnrollment{
			AccountID: account.ID, UserID: account.UserID, FactorID: factorID,
			Purpose: TOTPEnrollmentRecover, Version: initialTOTPEnrollmentVersion,
			FactorRevision: initialTOTPFactorRevision, CeremonyTokenDigest: issueDigest,
			ProtectedSecret: cloneEncryptedTOTPSecret(enrollment.ProtectedSecret), ExpiresAt: issueExpires,
		}
		defer pending.Destroy()
	}
	commandID, err := service.nextID()
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.apply(ctx, session, applyCommand{
		action: action, commandID: commandID, accountID: accountID, expectedRevision: expected,
		now: now, reason: normalized.Reason, idempotencyKey: normalized.IdempotencyKey,
		requestDigest:    requestDigest,
		issueTokenDigest: issueDigest, issueTokenExpiresAt: issueExpires,
		pendingTOTPEnrollment: pending, event: normalized.Event,
	})
	if err != nil {
		return MutationResult{}, err
	}
	if result.ArtifactIssued {
		return MutationResult{
			Account: cloneAccount(result.Account), Replayed: result.Replayed,
			Artifact: newOneTimeArtifact(
				append([]byte(nil), token...), append([]byte(nil), enrollment.DisplaySecret...),
				append([]byte(nil), enrollment.ProvisioningURI...),
			),
		}, nil
	}
	return MutationResult{Account: cloneAccount(result.Account), Replayed: result.Replayed}, nil
}

func (service *Service) apply(ctx context.Context, session authentication.Session, command applyCommand) (ApplyResult, error) {
	if err := serviceContextError(ctx); err != nil {
		return ApplyResult{}, err
	}
	expectsPendingEnrollment := command.action == localaccount.ActionInvite || command.action == localaccount.ActionRecover
	if expectsPendingEnrollment != (command.pendingTOTPEnrollment != nil) {
		return ApplyResult{}, authentication.ErrUnavailable
	}
	if command.pendingTOTPEnrollment != nil {
		pending := command.pendingTOTPEnrollment
		expectedPurpose := TOTPEnrollmentInvite
		expectedAccountID, expectedUserID := command.newAccountID, command.newUserID
		if command.action == localaccount.ActionRecover {
			expectedPurpose = TOTPEnrollmentRecover
			expectedAccountID = command.accountID
			expectedUserID = pending.UserID
		}
		if !validPendingTOTPEnrollment(*pending) || pending.Purpose != expectedPurpose ||
			pending.AccountID != expectedAccountID || pending.UserID != expectedUserID ||
			pending.CeremonyTokenDigest != command.issueTokenDigest ||
			!pending.ExpiresAt.Equal(command.issueTokenExpiresAt) {
			return ApplyResult{}, authentication.ErrUnavailable
		}
	}
	keyDigest := service.secrets.digest("idempotency-key", []byte(command.idempotencyKey))
	defer clear(keyDigest[:])
	var planned *localaccount.Plan
	planCalled := false
	historyCalled := false
	historyValidated := command.validatePasswordHistory == nil
	factorCalled := false
	factorConfirmed := command.action != localaccount.ActionActivate
	var confirmedTOTPUserID uuid.UUID
	planTransition := func(state PlanningState) (localaccount.Plan, error) {
		if planCalled {
			return localaccount.Plan{}, authentication.ErrUnavailable
		}
		planCalled = true
		if command.action == localaccount.ActionInvite {
			if state.Snapshot != (localaccount.Snapshot{}) || state.RecoveryFleet != (localaccount.RecoveryFleet{}) {
				return localaccount.Plan{}, authentication.ErrUnavailable
			}
		} else if state.Snapshot.AccountID != plannerID(command.accountID) || state.Snapshot.Revision != command.expectedRevision {
			if state.Snapshot.AccountID == plannerID(command.accountID) && state.Snapshot.Revision != command.expectedRevision {
				return localaccount.Plan{}, ErrPreconditionFailed
			}
			return localaccount.Plan{}, authentication.ErrUnavailable
		}
		switch command.action {
		case localaccount.ActionActivate:
			if confirmedTOTPUserID == uuid.Nil || state.Snapshot.UserID != plannerID(confirmedTOTPUserID) {
				return localaccount.Plan{}, authentication.ErrUnavailable
			}
		case localaccount.ActionRecover:
			if command.pendingTOTPEnrollment == nil ||
				state.Snapshot.UserID != plannerID(command.pendingTOTPEnrollment.UserID) {
				return localaccount.Plan{}, authentication.ErrUnavailable
			}
		}
		if !historyValidated || !factorConfirmed {
			return localaccount.Plan{}, authentication.ErrUnavailable
		}
		plan, err := localaccount.BuildPlan(state.Snapshot, state.RecoveryFleet, localaccount.Command{
			Action: command.action, ExpectedRevision: command.expectedRevision,
			ActorID: plannerID(session.User.ID), At: command.now, Reason: command.reason,
			FreshLocalMFA: state.FreshLocalMFA, ProtectedWorkflow: state.ProtectedWorkflow,
			NewAccountID: plannerID(command.newAccountID), NewUserID: plannerID(command.newUserID),
		})
		if err != nil {
			return localaccount.Plan{}, ErrTransitionConflict
		}
		planned = &plan
		return plan, nil
	}
	validatePasswordHistory := command.validatePasswordHistory
	if validatePasswordHistory != nil {
		validatePasswordHistory = func(history [][]byte) error {
			if historyCalled {
				clearHistory(history)
				return authentication.ErrUnavailable
			}
			historyCalled = true
			err := command.validatePasswordHistory(history)
			if err == nil {
				historyValidated = true
			}
			return err
		}
	}
	var confirmTOTPEnrollment TOTPEnrollmentConfirmer
	if command.action == localaccount.ActionActivate {
		confirmTOTPEnrollment = func(
			pending PendingTOTPEnrollment,
			lastAcceptedCounter *int64,
		) (ConfirmedTOTPFactor, error) {
			if factorCalled {
				pending.Destroy()
				return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
			}
			factorCalled = true
			if pending.AccountID != command.accountID || pending.CeremonyTokenDigest != command.ceremonyTokenDigest {
				pending.Destroy()
				return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
			}
			confirmed, err := service.enrollment.Confirm(ctx, ConfirmTOTPEnrollmentRequest{
				Pending: pending, Code: append([]byte(nil), command.ceremonyFactorProof...),
				At: command.now, LastAcceptedCounter: lastAcceptedCounter,
			})
			if err != nil {
				return ConfirmedTOTPFactor{}, err
			}
			if !validConfirmedTOTPFactor(confirmed, pending) {
				confirmed.Destroy()
				return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
			}
			confirmedTOTPUserID = pending.UserID
			factorConfirmed = true
			return confirmed, nil
		}
	}
	validateResult := func(result ApplyResult) (ApplyResult, error) {
		expectedStatus := statusForAction(command.action)
		if !validAccount(result.Account) || expectedStatus == "" || result.Account.Status != expectedStatus ||
			result.Replayed && result.ArtifactIssued ||
			command.action != localaccount.ActionInvite && result.Account.ID != command.accountID ||
			command.action == localaccount.ActionInvite &&
				(result.Account.DisplayName != command.displayName ||
					result.Account.LoginIdentifier != command.loginIdentifier ||
					result.Account.ProtectedRecoveryPrincipal != command.protectedRecoveryPrincipal) {
			return ApplyResult{}, authentication.ErrUnavailable
		}
		if command.action == localaccount.ActionInvite {
			if result.Account.Revision != 1 || result.Account.IdentityEpoch != 1 {
				return ApplyResult{}, authentication.ErrUnavailable
			}
		} else if result.Account.Revision != command.expectedRevision+1 {
			return ApplyResult{}, authentication.ErrUnavailable
		}
		if result.Replayed {
			if planCalled || historyCalled || factorCalled {
				return ApplyResult{}, authentication.ErrUnavailable
			}
			return result, nil
		}
		if planned == nil || !historyValidated || !factorConfirmed ||
			result.Account.ID != uuid.UUID(planned.AccountID) || result.Account.UserID != uuid.UUID(planned.UserID) ||
			result.Account.Revision != planned.NextRevision || result.Account.IdentityEpoch != planned.NextIdentityEpoch ||
			result.Account.Status != statusFromPlan(planned.To) {
			return ApplyResult{}, authentication.ErrUnavailable
		}
		if command.action == localaccount.ActionInvite {
			if result.Account.ID != command.newAccountID || result.Account.UserID != command.newUserID ||
				result.Account.Status != StatusInvited || result.Account.Revision != 1 || result.Account.IdentityEpoch != 1 ||
				!result.ArtifactIssued {
				return ApplyResult{}, authentication.ErrUnavailable
			}
			return result, nil
		}
		if result.Account.ID != command.accountID {
			return ApplyResult{}, authentication.ErrUnavailable
		}
		// The repository must validate the exact prior projection against the
		// plan before mutation. Result shape checks here close the output port.
		if result.ArtifactIssued != (command.action == localaccount.ActionRecover) {
			return ApplyResult{}, authentication.ErrUnavailable
		}
		return result, nil
	}
	params := ApplyParams{
		SessionParams: sessionParams(session), CommandID: command.commandID, Action: command.action,
		AccountID: command.accountID, NewAccountID: command.newAccountID, NewUserID: command.newUserID,
		ExpectedRevision: command.expectedRevision, At: command.now, DisplayName: command.displayName,
		CanonicalLoginIdentifier: command.loginIdentifier, ProtectedRecoveryPrincipal: command.protectedRecoveryPrincipal,
		Reason: command.reason, IdempotencyKeyDigest: keyDigest, PublicRequestDigest: command.requestDigest,
		CeremonyTokenDigest:      command.ceremonyTokenDigest,
		ReplacementPasswordPHC:   command.passwordPHC,
		IssueCeremonyTokenDigest: command.issueTokenDigest, IssueCeremonyTokenExpiresAt: command.issueTokenExpiresAt,
		Event: command.event, Plan: planTransition, ValidatePasswordHistory: validatePasswordHistory,
		ConfirmTOTPEnrollment: confirmTOTPEnrollment, ValidateResult: validateResult,
	}
	if command.pendingTOTPEnrollment != nil {
		params.PendingTOTPEnrollment = clonePendingTOTPEnrollment(command.pendingTOTPEnrollment)
		defer params.PendingTOTPEnrollment.Destroy()
	}
	result, err := service.repository.Apply(ctx, params)
	if err != nil {
		return ApplyResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) requireMutation(session authentication.Session) error {
	if err := service.require(session, authorization.PermissionPlatformIdentityAccountManage); err != nil {
		return err
	}
	return service.require(session, authorization.PermissionPlatformIdentityAccountRead)
}

func (service *Service) require(session authentication.Session, permission authorization.Permission) error {
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.passwords) ||
		interfaceIsNil(service.enrollment) || service.now == nil || service.newID == nil {
		return authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(session.Permissions, permission); err != nil {
		return authentication.ErrForbidden
	}
	if session.ActiveTenantID != nil {
		return authentication.ErrForbidden
	}
	if !validSession(session) {
		return authentication.ErrUnavailable
	}
	return nil
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC().Truncate(time.Millisecond)
}

func (service *Service) nextID() (uuid.UUID, error) {
	value, err := service.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, authentication.ErrUnavailable
	}
	return value, nil
}

func sessionParams(session authentication.Session) SessionParams {
	return SessionParams{ActorID: session.User.ID, SessionID: session.ID, AuthenticationMethod: session.AuthenticationMethod}
}

func clearHistory(history [][]byte) {
	for index := range history {
		clear(history[index])
	}
	clear(history)
}

func (service *Service) passwordHistoryValidator(password []byte) PasswordHistoryValidator {
	return func(history [][]byte) error {
		defer clearHistory(history)
		if len(history) > 25 {
			return authentication.ErrUnavailable
		}
		for _, encoded := range history {
			if len(encoded) < 32 || len(encoded) > 1024 {
				return authentication.ErrUnavailable
			}
			if service.passwords.Verify(password, encoded) {
				return ErrPasswordReused
			}
		}
		return nil
	}
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
	case errors.Is(err, ErrTransitionConflict):
		return ErrTransitionConflict
	case errors.Is(err, ErrPasswordReused):
		return ErrPasswordReused
	case errors.Is(err, ErrEnrollmentProofRejected):
		return ErrEnrollmentProofRejected
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
	return "platformlocalaccount.Service{dependencies:[REDACTED]}"
}
func (service *Service) GoString() string { return service.String() }

func statusFromPlan(value localaccount.Status) Status {
	switch value {
	case localaccount.StatusInvited:
		return StatusInvited
	case localaccount.StatusActive:
		return StatusActive
	case localaccount.StatusDisabled:
		return StatusDisabled
	case localaccount.StatusRecoveryRestricted:
		return StatusRecoveryRestricted
	default:
		return ""
	}
}

func statusForAction(value localaccount.Action) Status {
	switch value {
	case localaccount.ActionInvite:
		return StatusInvited
	case localaccount.ActionActivate, localaccount.ActionEnable, localaccount.ActionRotatePassword:
		return StatusActive
	case localaccount.ActionDisable:
		return StatusDisabled
	case localaccount.ActionRecover:
		return StatusRecoveryRestricted
	default:
		return ""
	}
}
