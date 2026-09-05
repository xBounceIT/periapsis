package federatedauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const (
	maximumRefreshTokenBytes        = 256 * 1024
	oidcProtectedTokenOverheadBytes = 12 + 16 // GCM nonce plus authentication tag.
	minimumProtectedTokenBytes      = 1 + oidcProtectedTokenOverheadBytes
	maximumProtectedTokenBytes      = maximumRefreshTokenBytes + oidcProtectedTokenOverheadBytes
	maximumOIDCClientIDBytes        = 512
	maximumPersistentOIDCCounter    = uint64(9_000_000_000_000_000)
)

// RotateOIDCRefresh claims one exact generation, performs the pinned upstream
// exchange outside a transaction, and atomically installs a mandatory rotated
// successor. Every ambiguous outcome revokes the local session family.
func (service *Service) RotateOIDCRefresh(ctx context.Context, command RefreshCommand) error {
	if service == nil || !validRefreshCommand(command) {
		return ErrInvalidInput
	}
	if service.refreshes == nil || service.tokenProtector == nil ||
		service.clientSecrets == nil || service.oidcRefresh == nil {
		return ErrRefreshRejected
	}
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	now := service.currentTime()
	if !validInstant(now) {
		return ErrRefreshRejected
	}
	snapshot, err := service.refreshes.ClaimRefreshRotation(operation, command, now)
	if err != nil {
		service.revokeFamily(ctx, command.SessionFamilyID, RevokeRefreshFailure, now)
		return ErrRefreshRejected
	}
	defer clear(snapshot.Token.Ciphertext)
	if snapshot.Category == RefreshReuse {
		service.revokeFamily(ctx, command.SessionFamilyID, RevokeRefreshReuse, now)
		return ErrRefreshRejected
	}
	if snapshot.Category == RefreshBusy {
		return ErrRefreshRejected
	}
	if snapshot.Category != RefreshClaimed {
		return ErrRefreshRejected
	}
	return service.executeClaimedOIDCRefresh(operation, ctx, command, snapshot, now)
}

// ExecuteClaimedOIDCRefresh consumes the exact credential-bearing snapshot
// returned by the worker dispatcher. It deliberately does not claim again:
// claiming an already-leased generation would conflate delivery duplication
// with cryptographic refresh-token reuse.
func (service *Service) ExecuteClaimedOIDCRefresh(
	ctx context.Context,
	command RefreshCommand,
	snapshot RefreshSnapshot,
) error {
	defer clear(snapshot.Token.Ciphertext)
	if service == nil || !validRefreshCommand(command) {
		return ErrInvalidInput
	}
	if service.refreshes == nil || service.tokenProtector == nil ||
		service.clientSecrets == nil || service.oidcRefresh == nil {
		return ErrRefreshRejected
	}
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	now := service.currentTime()
	if !validInstant(now) || snapshot.Category != RefreshClaimed {
		return ErrRefreshRejected
	}
	return service.executeClaimedOIDCRefresh(operation, ctx, command, snapshot, now)
}

func (service *Service) executeClaimedOIDCRefresh(
	operation context.Context,
	cleanupContext context.Context,
	command RefreshCommand,
	snapshot RefreshSnapshot,
	now time.Time,
) error {
	if !validRefreshSnapshot(snapshot, command, now) {
		service.revokeFamily(cleanupContext, command.SessionFamilyID, RevokeRefreshFailure, now)
		return ErrRefreshRejected
	}
	currentContext := RefreshTokenContext{
		TenantID: snapshot.TenantID, MaterialID: snapshot.MaterialID,
		SessionFamilyID: snapshot.SessionFamilyID, Provider: snapshot.Provider,
		BindingID: snapshot.BindingID, Generation: snapshot.Generation,
	}
	refreshToken, err := service.tokenProtector.OpenRefreshToken(operation, currentContext, snapshot.Token)
	if err != nil || !validRefreshToken(refreshToken) {
		clear(refreshToken)
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshRejected, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshKeyFailure, now)
		return ErrRefreshRejected
	}
	defer clear(refreshToken)
	refreshDigest := sha256.Sum256(refreshToken)
	if subtle.ConstantTimeCompare(refreshDigest[:], snapshot.TokenDigest[:]) != 1 {
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshRejected, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshKeyFailure, now)
		return ErrRefreshRejected
	}
	clientBindingID := snapshot.BindingID
	clientAdmission := snapshot.Admission
	if snapshot.Provider.Scope == identity.TenantProviderScope {
		clientAdmission = identity.TenantAdmissionContext{}
	}
	if snapshot.Provider.Scope == identity.PlatformProviderScope {
		clientBindingID = identity.EntityID{}
	}
	secret, err := service.clientSecrets.OpenOIDCClientSecret(operation, ClientSecretContext{
		Provider: snapshot.Provider, Admission: clientAdmission,
		BindingID: clientBindingID, Revision: snapshot.ClientSecretRevision,
		Maintenance: OIDCMaintenanceSecretProof{
			Kind: OIDCMaintenanceSecretRefresh, MaterialID: snapshot.MaterialID,
			SessionFamilyID: snapshot.SessionFamilyID, ClaimVersion: snapshot.Version,
			RefreshGeneration: snapshot.Generation,
		},
	})
	if err != nil || len(secret) == 0 {
		clear(secret)
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshRejected, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshKeyFailure, now)
		return ErrRefreshRejected
	}
	defer clear(secret)
	rotation, err := service.oidcRefresh.ExchangeOIDCRefresh(operation, federatedoidc.StoredRefreshExchangeRequest{
		EndpointURL: snapshot.Endpoint, ClientAuthentication: snapshot.ClientAuthentication,
		ClientID: snapshot.ClientID, ClientSecret: append([]byte(nil), secret...),
		RefreshToken: append([]byte(nil), refreshToken...),
	}, now)
	if err != nil || rotation == nil {
		outcome := RefreshAmbiguous
		if errors.Is(err, federatedoidc.ErrRefreshSafeToRetry) {
			outcome = RefreshSafeToRetry
		}
		service.completeRefreshOutcome(cleanupContext, snapshot, outcome, now)
		if outcome != RefreshSafeToRetry {
			service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshFailure, now)
		}
		return ErrRefreshRejected
	}
	defer rotation.Destroy()
	successor := rotation.RefreshToken()
	defer clear(successor)
	accessExpiry := rotation.AccessExpiresAt()
	if !validRefreshToken(successor) || bytes.Equal(successor, refreshToken) ||
		!validInstant(accessExpiry) || !accessExpiry.After(now) ||
		snapshot.Generation >= maximumPersistentOIDCCounter {
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshAmbiguous, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshFailure, now)
		return ErrRefreshRejected
	}
	successorGeneration := snapshot.Generation + 1
	protected, err := service.tokenProtector.SealRefreshToken(operation, RefreshTokenContext{
		TenantID: snapshot.TenantID, MaterialID: snapshot.MaterialID,
		SessionFamilyID: snapshot.SessionFamilyID, Provider: snapshot.Provider,
		BindingID: snapshot.BindingID, Generation: successorGeneration,
	}, successor)
	if err != nil || protected.KeyVersion == 0 || len(protected.Ciphertext) < minimumProtectedTokenBytes {
		clear(protected.Ciphertext)
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshAmbiguous, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshKeyFailure, now)
		return ErrRefreshRejected
	}
	defer clear(protected.Ciphertext)
	if accessExpiry.After(snapshot.MaterialExpiresAt) {
		accessExpiry = snapshot.MaterialExpiresAt
	}
	completion := RefreshCompletion{
		TenantID: snapshot.TenantID, EffectiveTenantID: snapshot.EffectiveTenantID,
		MaterialID:      snapshot.MaterialID,
		SessionFamilyID: snapshot.SessionFamilyID, ExpectedVersion: snapshot.Version,
		ExpectedGeneration: snapshot.Generation, Outcome: RefreshRotated, SuccessorGeneration: successorGeneration,
		SuccessorDigest: sha256.Sum256(successor),
		SuccessorToken:  ProtectedToken{KeyVersion: protected.KeyVersion, Ciphertext: append([]byte(nil), protected.Ciphertext...)},
		AccessExpiresAt: accessExpiry, CompletedAt: now,
	}
	if !validRefreshCompletion(completion, snapshot, now) {
		clear(completion.SuccessorToken.Ciphertext)
		service.completeRefreshOutcome(cleanupContext, snapshot, RefreshAmbiguous, now)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshFailure, now)
		return ErrRefreshRejected
	}
	if err := service.refreshes.CompleteRefreshRotation(operation, completion); err != nil {
		clear(completion.SuccessorToken.Ciphertext)
		service.revokeFamily(cleanupContext, snapshot.SessionFamilyID, RevokeRefreshFailure, now)
		return ErrRefreshRejected
	}
	clear(completion.SuccessorToken.Ciphertext)
	return nil
}

func validRefreshCommand(command RefreshCommand) bool {
	return command.SessionFamilyID != (identity.EntityID{}) &&
		command.ExpectedGeneration > 0 && command.ExpectedGeneration < maximumPersistentOIDCCounter &&
		command.ExpectedDigest != ([sha256.Size]byte{})
}

func validRefreshSnapshot(snapshot RefreshSnapshot, command RefreshCommand, now time.Time) bool {
	return validApplyUUIDv7(snapshot.MaterialID) && validRefreshSnapshotScope(snapshot) &&
		snapshot.SessionFamilyID == command.SessionFamilyID && snapshot.Generation == command.ExpectedGeneration &&
		snapshot.Generation > 0 && snapshot.Generation < maximumPersistentOIDCCounter &&
		snapshot.Version > 0 && snapshot.Version < maximumPersistentOIDCCounter &&
		validProviderContext(snapshot.Provider) && snapshot.ClientSecretRevision > 0 &&
		snapshot.Endpoint != "" && validOIDCClientID(snapshot.ClientID) && validClientAuthentication(snapshot.ClientAuthentication) &&
		snapshot.Token.KeyVersion > 0 && len(snapshot.Token.Ciphertext) >= minimumProtectedTokenBytes &&
		len(snapshot.Token.Ciphertext) <= maximumProtectedTokenBytes &&
		snapshot.TokenDigest != ([sha256.Size]byte{}) &&
		subtle.ConstantTimeCompare(snapshot.TokenDigest[:], command.ExpectedDigest[:]) == 1 &&
		validInstant(snapshot.ObservedAt) && !snapshot.ObservedAt.After(now.Add(5*time.Minute)) &&
		!snapshot.ObservedAt.Before(now.Add(-5*time.Minute)) &&
		validInstant(snapshot.LeaseExpiresAt) && snapshot.LeaseExpiresAt.After(snapshot.ObservedAt) &&
		validInstant(snapshot.MaterialExpiresAt) && snapshot.MaterialExpiresAt.After(snapshot.ObservedAt) &&
		!snapshot.LeaseExpiresAt.After(snapshot.MaterialExpiresAt) &&
		validInstant(snapshot.AbsoluteSessionExpiry) && snapshot.AbsoluteSessionExpiry.After(snapshot.ObservedAt) &&
		!snapshot.MaterialExpiresAt.After(snapshot.AbsoluteSessionExpiry)
}

func validRefreshSnapshotScope(snapshot RefreshSnapshot) bool {
	zero := identity.EntityID{}
	if snapshot.EffectiveTenantID != zero && !validApplyUUIDv7(snapshot.EffectiveTenantID) {
		return false
	}
	switch snapshot.Provider.Scope {
	case identity.TenantProviderScope:
		return snapshot.TenantID != zero && snapshot.BindingID != zero &&
			snapshot.EffectiveTenantID == snapshot.TenantID &&
			snapshot.Provider.TenantID == snapshot.TenantID &&
			snapshot.Admission.TenantID == snapshot.TenantID &&
			snapshot.Admission.BindingID == snapshot.BindingID
	case identity.PlatformProviderScope:
		if snapshot.Provider.TenantID != zero {
			return false
		}
		if snapshot.TenantID == zero {
			return snapshot.BindingID == zero && snapshot.Admission == (identity.TenantAdmissionContext{})
		}
		return snapshot.EffectiveTenantID == snapshot.TenantID && snapshot.BindingID != zero &&
			snapshot.Admission.TenantID == snapshot.TenantID &&
			snapshot.Admission.BindingID == snapshot.BindingID
	default:
		return false
	}
}

func validRefreshCompletion(completion RefreshCompletion, snapshot RefreshSnapshot, now time.Time) bool {
	if completion.TenantID != snapshot.TenantID || completion.EffectiveTenantID != snapshot.EffectiveTenantID ||
		completion.MaterialID != snapshot.MaterialID ||
		completion.SessionFamilyID != snapshot.SessionFamilyID ||
		completion.ExpectedVersion != snapshot.Version || completion.ExpectedVersion == 0 ||
		completion.ExpectedVersion >= maximumPersistentOIDCCounter ||
		completion.ExpectedGeneration != snapshot.Generation || completion.ExpectedGeneration == 0 ||
		completion.ExpectedGeneration >= maximumPersistentOIDCCounter || !completion.CompletedAt.Equal(now) ||
		!completion.CompletedAt.Before(snapshot.LeaseExpiresAt) {
		return false
	}
	if completion.Outcome != RefreshRotated {
		return (completion.Outcome == RefreshSafeToRetry || completion.Outcome == RefreshAmbiguous ||
			completion.Outcome == RefreshRejected) && completion.SuccessorGeneration == 0 &&
			completion.SuccessorDigest == ([sha256.Size]byte{}) && completion.SuccessorToken.KeyVersion == 0 &&
			len(completion.SuccessorToken.Ciphertext) == 0 && completion.AccessExpiresAt.IsZero()
	}
	return completion.SuccessorGeneration == completion.ExpectedGeneration+1 &&
		completion.SuccessorGeneration < maximumPersistentOIDCCounter &&
		completion.SuccessorDigest != ([sha256.Size]byte{}) && completion.SuccessorToken.KeyVersion > 0 &&
		len(completion.SuccessorToken.Ciphertext) >= minimumProtectedTokenBytes &&
		len(completion.SuccessorToken.Ciphertext) <= maximumProtectedTokenBytes &&
		validInstant(completion.AccessExpiresAt) && completion.AccessExpiresAt.After(now) &&
		!completion.AccessExpiresAt.After(snapshot.MaterialExpiresAt) &&
		!completion.AccessExpiresAt.After(snapshot.AbsoluteSessionExpiry)
}

func (service *Service) completeRefreshOutcome(
	ctx context.Context,
	snapshot RefreshSnapshot,
	outcome RefreshCompletionOutcome,
	now time.Time,
) {
	if service == nil || service.refreshes == nil || ctx == nil {
		return
	}
	completion := RefreshCompletion{
		TenantID: snapshot.TenantID, EffectiveTenantID: snapshot.EffectiveTenantID,
		MaterialID:      snapshot.MaterialID,
		SessionFamilyID: snapshot.SessionFamilyID, ExpectedVersion: snapshot.Version,
		ExpectedGeneration: snapshot.Generation, Outcome: outcome, CompletedAt: now,
	}
	if !validRefreshCompletion(completion, snapshot, now) {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.operationTimeout)
	defer cancel()
	_ = service.refreshes.CompleteRefreshRotation(cleanup, completion)
}

func validClientAuthentication(mode federatedoidc.ClientAuthenticationMode) bool {
	return mode == federatedoidc.ClientSecretBasic || mode == federatedoidc.ClientSecretPost
}

func validOIDCClientID(value string) bool {
	if len(value) == 0 || len(value) > maximumOIDCClientIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validRefreshToken(value []byte) bool {
	if len(value) == 0 || len(value) > maximumRefreshTokenBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (service *Service) revokeFamily(
	ctx context.Context,
	familyID identity.EntityID,
	reason RevocationReason,
	now time.Time,
) {
	if service == nil || service.refreshes == nil || ctx == nil {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.operationTimeout)
	defer cancel()
	_ = service.refreshes.RevokeSessionFamily(cleanup, familyID, reason, now)
}

// RunLogoutRetry claims and executes one due best-effort upstream logout job.
// Local revocation has already committed before such a job may exist.
func (service *Service) RunLogoutRetry(ctx context.Context, jobID identity.EntityID) error {
	if service == nil || jobID == (identity.EntityID{}) {
		return ErrInvalidInput
	}
	if service.logoutRetries == nil || service.logoutExecutor == nil {
		return ErrUpstreamLogoutRetry
	}
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	now := service.currentTime()
	if !validInstant(now) {
		return ErrUpstreamLogoutRetry
	}
	job, err := service.logoutRetries.ClaimLogoutRetry(operation, jobID, now)
	if err != nil || !validLogoutJob(job, jobID, now) {
		return ErrUpstreamLogoutRetry
	}
	defer clear(job.OpaqueReference.Ciphertext)
	executionErr := service.logoutExecutor.ExecuteUpstreamLogoutRetry(operation, job)
	completedAt := service.currentTime()
	if !validInstant(completedAt) || completedAt.Before(now) {
		completedAt = now
	}
	update := LogoutRetryUpdate{
		JobID: job.JobID, Attempt: job.Attempt, ExpectedVersion: job.ClaimVersion, ObservedAt: completedAt,
	}
	if executionErr == nil {
		update.Disposition = LogoutRetryComplete
	} else if errors.Is(executionErr, federatedoidc.ErrRevocationSafeToRetry) &&
		job.Attempt < job.MaximumAttempts {
		update.Disposition = LogoutRetryReschedule
		update.NextTryAt = completedAt.Add(logoutBackoff(job.Attempt))
	} else if errors.Is(executionErr, federatedoidc.ErrRevocationAmbiguous) {
		update.Disposition = LogoutRetryAmbiguous
	} else {
		update.Disposition = LogoutRetryRejected
	}
	cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), service.operationTimeout)
	defer cleanupCancel()
	if err := service.logoutRetries.CompleteLogoutRetry(cleanup, update); err != nil {
		return ErrUpstreamLogoutRetry
	}
	if executionErr != nil {
		return ErrUpstreamLogoutRetry
	}
	return nil
}

func validLogoutJob(job LogoutRetryJob, expected identity.EntityID, now time.Time) bool {
	return validLogoutJobShape(job, expected) && validInstant(job.NotBefore) && !job.NotBefore.After(now) &&
		validInstant(job.LeaseExpiresAt) && job.LeaseExpiresAt.After(now) &&
		validInstant(job.MaterialExpiresAt) && job.MaterialExpiresAt.After(now) &&
		!job.LeaseExpiresAt.After(job.MaterialExpiresAt)
}

func validLogoutJobShape(job LogoutRetryJob, expected identity.EntityID) bool {
	return expected != (identity.EntityID{}) && job.JobID == expected &&
		job.MaterialID != (identity.EntityID{}) && job.SessionFamilyID != (identity.EntityID{}) &&
		job.Attempt >= 1 &&
		job.MaximumAttempts >= 1 && job.MaximumAttempts <= 16 && job.Attempt <= job.MaximumAttempts &&
		job.ClaimVersion > 0 && job.ClaimVersion < maximumPersistentOIDCCounter &&
		validLogoutJobScope(job) && job.ClientSecretRevision > 0 &&
		validClientAuthentication(job.ClientAuthentication) && validOIDCClientID(job.ClientID) &&
		job.Endpoint != "" && job.RefreshGeneration > 0 &&
		job.RefreshGeneration < maximumPersistentOIDCCounter && job.TokenDigest != ([sha256.Size]byte{}) &&
		job.OpaqueReference.KeyVersion > 0 && len(job.OpaqueReference.Ciphertext) >= minimumProtectedTokenBytes &&
		len(job.OpaqueReference.Ciphertext) <= maximumProtectedTokenBytes
}

func validLogoutJobScope(job LogoutRetryJob) bool {
	zero := identity.EntityID{}
	switch job.Provider.Scope {
	case identity.TenantProviderScope:
		return job.TenantID != zero && job.Provider.TenantID == job.TenantID && job.BindingID != zero &&
			job.Admission == (identity.TenantAdmissionContext{TenantID: job.TenantID, BindingID: job.BindingID})
	case identity.PlatformProviderScope:
		if job.Provider.TenantID != zero {
			return false
		}
		if job.TenantID == zero {
			return job.BindingID == zero && job.Admission == (identity.TenantAdmissionContext{})
		}
		return job.BindingID != zero &&
			job.Admission == (identity.TenantAdmissionContext{TenantID: job.TenantID, BindingID: job.BindingID})
	default:
		return false
	}
}

func logoutBackoff(attempt int) time.Duration {
	delay := time.Second << min(attempt-1, 9)
	return min(delay, 15*time.Minute)
}
