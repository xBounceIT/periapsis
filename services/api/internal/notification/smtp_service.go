package notification

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) GetTenantSMTP(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (SMTPConfiguration, error) {
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	result, err := s.repository.GetTenantSMTP(ctx, GetTenantSMTPParams{Human: human})
	if err != nil {
		return SMTPConfiguration{}, mapRepositoryError(err)
	}
	if !validSMTP(result, &tenantID) {
		return SMTPConfiguration{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) VersionTenantSMTP(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input SMTPWriteInput,
) (SMTPConfiguration, error) {
	normalized, err := normalizeSMTPWrite(input, s.allowPlainLocal)
	if err != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	creating := normalized.ExpectedVersion == nil
	if normalized.ExpectedVersion != nil && (*normalized.ExpectedVersion < 1 || *normalized.ExpectedVersion >= maximumResourceVersion) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	if creating && (normalized.ClearPassword || normalized.ClearDKIM) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	write, err := s.protectSMTPWrite(&tenantID, normalized, creating)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	defer clearSMTPPersistedWrite(&write)
	mutation, err := s.tenantMutation(human, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	candidateID, err := s.nextID()
	if err != nil {
		return SMTPConfiguration{}, err
	}
	result, err := s.repository.VersionTenantSMTP(ctx, VersionTenantSMTPParams{
		Mutation: mutation, ConfigurationID: candidateID,
		ExpectedVersion: cloneInt64(normalized.ExpectedVersion), Write: write,
	})
	if err != nil {
		return SMTPConfiguration{}, mapRepositoryError(err)
	}
	if !validSMTPMutationResult(result, &tenantID, candidateID, normalized.ExpectedVersion, actor.UserID) {
		return SMTPConfiguration{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) TestTenantSMTP(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input SMTPTestInput,
) (SMTPHealth, error) {
	normalized, err := normalizeSMTPTest(input)
	if err != nil {
		return SMTPHealth{}, err
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return SMTPHealth{}, err
	}
	mutation, err := s.tenantMutation(human, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return SMTPHealth{}, err
	}
	deliveryID, err := s.optionalDeliveryID(normalized.Recipient)
	if err != nil {
		return SMTPHealth{}, err
	}
	probeID, fenceToken, err := s.smtpProbeIdentity()
	if err != nil {
		return SMTPHealth{}, err
	}
	result, err := s.repository.TestTenantSMTP(ctx, TestTenantSMTPParams{
		Mutation: mutation, ConfigurationVersion: normalized.ConfigurationVersion,
		DeliveryID: deliveryID, Recipient: cloneString(normalized.Recipient), Reason: normalized.Reason,
	})
	if err != nil {
		return SMTPHealth{}, mapRepositoryError(err)
	}
	if !validSMTPProbePreflight(result, normalized.ConfigurationVersion, normalized.Recipient != nil, deliveryID, false) {
		return SMTPHealth{}, ErrUnavailable
	}
	probe, err := s.smtpProber.ProbeSMTP(ctx, SMTPProbeRequest{
		ProbeID: probeID, FenceToken: fenceToken, TenantID: &tenantID,
		ConfigurationScope: result.Value.ConfigurationScope,
		ConfigurationID:    result.Value.ConfigurationID, ConfigurationVersion: result.Value.ConfigurationVersion,
	})
	if err != nil {
		return SMTPHealth{}, mapRepositoryError(err)
	}
	return smtpHealthFromProbe(probe, result.Value, tenantID, probeID, fenceToken)
}

func (s *Service) GetPlatformSMTP(
	ctx context.Context,
	session authentication.Session,
) (SMTPConfiguration, error) {
	actor, err := s.requirePlatform(session)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	result, err := s.repository.GetPlatformSMTP(ctx, GetPlatformSMTPParams{Actor: actor})
	if err != nil {
		return SMTPConfiguration{}, mapRepositoryError(err)
	}
	if !validSMTP(result, nil) {
		return SMTPConfiguration{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) VersionPlatformSMTP(
	ctx context.Context,
	session authentication.Session,
	input SMTPWriteInput,
) (SMTPConfiguration, error) {
	normalized, err := normalizeSMTPWrite(input, s.allowPlainLocal)
	if err != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	creating := normalized.ExpectedVersion == nil
	if normalized.ExpectedVersion != nil && (*normalized.ExpectedVersion < 1 || *normalized.ExpectedVersion >= maximumResourceVersion) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	if creating && (normalized.ClearPassword || normalized.ClearDKIM) {
		return SMTPConfiguration{}, ErrInvalidInput
	}
	actor, err := s.requirePlatform(session)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	write, err := s.protectSMTPWrite(nil, normalized, creating)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	defer clearSMTPPersistedWrite(&write)
	mutation, err := s.platformMutation(actor, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return SMTPConfiguration{}, err
	}
	candidateID, err := s.nextID()
	if err != nil {
		return SMTPConfiguration{}, err
	}
	result, err := s.repository.VersionPlatformSMTP(ctx, VersionPlatformSMTPParams{
		Mutation: mutation, ConfigurationID: candidateID,
		ExpectedVersion: cloneInt64(normalized.ExpectedVersion), Write: write,
	})
	if err != nil {
		return SMTPConfiguration{}, mapRepositoryError(err)
	}
	if !validSMTPMutationResult(result, nil, candidateID, normalized.ExpectedVersion, session.User.ID) {
		return SMTPConfiguration{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) TestPlatformSMTP(
	ctx context.Context,
	session authentication.Session,
	input SMTPTestInput,
) (SMTPHealth, error) {
	normalized, err := normalizeSMTPTest(input)
	if err != nil {
		return SMTPHealth{}, err
	}
	// Platform SMTP tests are health-only. A recipient would create a
	// tenant-owned delivery without a tenant authorization context, so the
	// platform surface rejects it instead of inventing a tenant or ledger.
	if normalized.Recipient != nil {
		return SMTPHealth{}, ErrInvalidInput
	}
	actor, err := s.requirePlatform(session)
	if err != nil {
		return SMTPHealth{}, err
	}
	mutation, err := s.platformMutation(actor, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return SMTPHealth{}, err
	}
	probeID, fenceToken, err := s.smtpProbeIdentity()
	if err != nil {
		return SMTPHealth{}, err
	}
	result, err := s.repository.TestPlatformSMTP(ctx, TestPlatformSMTPParams{
		Mutation: mutation, ConfigurationVersion: normalized.ConfigurationVersion,
		DeliveryID: nil, Recipient: nil, Reason: normalized.Reason,
	})
	if err != nil {
		return SMTPHealth{}, mapRepositoryError(err)
	}
	if !validSMTPProbePreflight(result, normalized.ConfigurationVersion, false, nil, true) {
		return SMTPHealth{}, ErrUnavailable
	}
	probe, err := s.smtpProber.ProbeSMTP(ctx, SMTPProbeRequest{
		ProbeID: probeID, FenceToken: fenceToken,
		ConfigurationScope: result.Value.ConfigurationScope,
		ConfigurationID:    result.Value.ConfigurationID, ConfigurationVersion: result.Value.ConfigurationVersion,
	})
	if err != nil {
		return SMTPHealth{}, mapRepositoryError(err)
	}
	return smtpHealthFromProbe(probe, result.Value, uuid.Nil, probeID, fenceToken)
}

func (s *Service) protectSMTPWrite(scope *uuid.UUID, input SMTPWriteInput, creating bool) (SMTPPersistedWrite, error) {
	write := SMTPPersistedWrite{
		Name: input.Name, Host: input.Host, Port: input.Port, Security: input.Security,
		Username: cloneString(input.Username), FromName: input.FromName, FromEmail: input.FromEmail,
		ReplyToEmail: cloneString(input.ReplyToEmail), TimeoutMS: input.TimeoutMS,
		MaximumConnections: input.MaximumConnections, MaximumMessagesPerConnection: input.MaximumMessagesPerConnection,
		RateLimitPerSecond: input.RateLimitPerSecond, Enabled: input.Enabled,
	}
	if input.Password != nil {
		secret, err := s.protectSecret(scope, SecretKindSMTPPassword, *input.Password)
		if err != nil {
			return SMTPPersistedWrite{}, err
		}
		write.Password = &secret
	} else if input.ClearPassword {
		write.RemovePassword = true
	} else if !creating {
		write.RetainPassword = true
	}
	if creating && input.Username != nil && input.Password == nil {
		clearSMTPPersistedWrite(&write)
		return SMTPPersistedWrite{}, ErrInvalidInput
	}

	switch {
	case input.DKIM != nil:
		write.DKIMDomainName = pointer(input.DKIM.DomainName)
		write.DKIMSelector = pointer(input.DKIM.Selector)
		if input.DKIM.PrivateKey != nil {
			secret, err := s.protectSecret(scope, SecretKindSMTPDKIMPrivateKey, *input.DKIM.PrivateKey)
			if err != nil {
				clearSMTPPersistedWrite(&write)
				return SMTPPersistedWrite{}, err
			}
			write.DKIMPrivateKey = &secret
		} else if creating {
			clearSMTPPersistedWrite(&write)
			return SMTPPersistedWrite{}, ErrInvalidInput
		} else {
			write.RetainDKIMPrivateKey = true
		}
	case input.ClearDKIM:
		write.RemoveDKIM = true
	case !creating:
		write.RetainDKIMPrivateKey = true
	}
	return write, nil
}

func (s *Service) protectSecret(scope *uuid.UUID, kind SecretKind, value string) (ProtectedSecret, error) {
	secretID, err := s.nextID()
	if err != nil {
		return ProtectedSecret{}, err
	}
	var tenantID *uuid.UUID
	if scope != nil {
		copy := *scope
		tenantID = &copy
	}
	plaintext := []byte(value)
	defer clear(plaintext)
	envelope, err := s.keyring.Protect(SecretContext{
		TenantID: tenantID, SecretID: secretID, SecretVersion: 1, Kind: kind,
	}, plaintext)
	if err != nil {
		return ProtectedSecret{}, ErrUnavailable
	}
	return ProtectedSecret{ID: secretID, Version: 1, Kind: kind, Envelope: envelope}, nil
}

func normalizeSMTPTest(input SMTPTestInput) (SMTPTestInput, error) {
	if input.ConfigurationVersion < 1 || input.ConfigurationVersion > maximumResourceVersion ||
		!validCommonMutation(input.IdempotencyKey, input.Audit) {
		return SMTPTestInput{}, ErrInvalidInput
	}
	recipient, err := normalizeOptionalEmail(input.Recipient)
	if err != nil {
		return SMTPTestInput{}, err
	}
	reason, ok := normalizedText(input.Reason, 1, 1_000, false)
	if !ok {
		return SMTPTestInput{}, ErrInvalidInput
	}
	return SMTPTestInput{
		ConfigurationVersion: input.ConfigurationVersion, Recipient: recipient, Reason: reason,
		IdempotencyKey: input.IdempotencyKey, Audit: input.Audit,
	}, nil
}

func (s *Service) optionalDeliveryID(recipient *string) (*uuid.UUID, error) {
	if recipient == nil {
		return nil, nil
	}
	value, err := s.nextID()
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Service) smtpProbeIdentity() (uuid.UUID, uuid.UUID, error) {
	probeID, err := s.nextID()
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	fenceToken, err := s.nextID()
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return probeID, fenceToken, nil
}

func validSMTPMutationResult(
	result IdempotentResult[SMTPConfiguration],
	tenantID *uuid.UUID,
	candidateID uuid.UUID,
	expectedVersion *int64,
	actorID uuid.UUID,
) bool {
	value := result.Value
	if !validSMTP(value, tenantID) || value.InheritedFromGlobal {
		return false
	}
	if result.Replayed {
		return true
	}
	if value.CreatedBy != actorID {
		return false
	}
	if expectedVersion == nil {
		return value.ID == candidateID && value.Version == 1
	}
	return value.Version == *expectedVersion+1
}

func validSMTPProbePreflight(
	result IdempotentResult[SMTPProbePreflight],
	configurationVersion int64,
	expectsDelivery bool,
	candidateDeliveryID *uuid.UUID,
	platformOnly bool,
) bool {
	value := result.Value
	if !validUUIDv7(value.ConfigurationID) || value.ConfigurationVersion != configurationVersion ||
		value.ConfigurationScope != SMTPConfigurationTenant && value.ConfigurationScope != SMTPConfigurationPlatform ||
		platformOnly && value.ConfigurationScope != SMTPConfigurationPlatform ||
		(value.QueuedDeliveryID != nil) != expectsDelivery ||
		value.QueuedDeliveryID != nil && !validUUIDv7(*value.QueuedDeliveryID) {
		return false
	}
	return result.Replayed || !expectsDelivery ||
		candidateDeliveryID != nil && *value.QueuedDeliveryID == *candidateDeliveryID
}

func smtpHealthFromProbe(
	probe SMTPProbeResult,
	preflight SMTPProbePreflight,
	tenantID uuid.UUID,
	probeID uuid.UUID,
	fenceToken uuid.UUID,
) (SMTPHealth, error) {
	expectsTenant := tenantID != uuid.Nil
	if probe.ProbeID != probeID || probe.FenceToken != fenceToken ||
		probe.ConfigurationID != preflight.ConfigurationID ||
		probe.ConfigurationVersion != preflight.ConfigurationVersion ||
		probe.ConfigurationScope != preflight.ConfigurationScope ||
		(expectsTenant && (probe.TenantID == nil || *probe.TenantID != tenantID)) ||
		(!expectsTenant && probe.TenantID != nil) {
		return SMTPHealth{}, ErrUnavailable
	}
	health := SMTPHealth{
		ConfigurationID: probe.ConfigurationID, ConfigurationVersion: probe.ConfigurationVersion,
		Healthy: probe.Healthy, CheckedAt: probe.CheckedAt,
		Checks:           append([]SMTPHealthCheck(nil), probe.Checks...),
		QueuedDeliveryID: cloneUUIDPointer(preflight.QueuedDeliveryID),
	}
	if !validSMTPHealthResult(
		IdempotentResult[SMTPHealth]{Value: health},
		preflight.ConfigurationVersion,
		preflight.QueuedDeliveryID != nil,
		preflight.QueuedDeliveryID,
	) {
		return SMTPHealth{}, ErrUnavailable
	}
	return health, nil
}

func validSMTPHealthResult(
	result IdempotentResult[SMTPHealth],
	configurationVersion int64,
	expectsDelivery bool,
	candidateDeliveryID *uuid.UUID,
) bool {
	value := result.Value
	if !validUUIDv7(value.ConfigurationID) || value.ConfigurationVersion != configurationVersion || !validInstant(value.CheckedAt) ||
		len(value.Checks) < 1 || len(value.Checks) > 4 || (value.QueuedDeliveryID != nil) != expectsDelivery {
		return false
	}
	if !result.Replayed && expectsDelivery && (candidateDeliveryID == nil || *value.QueuedDeliveryID != *candidateDeliveryID) {
		return false
	}
	seen := make(map[string]struct{}, len(value.Checks))
	allHealthy := true
	for _, check := range value.Checks {
		if check.Kind != "dns" && check.Kind != "connect" && check.Kind != "tls" && check.Kind != "authentication" ||
			check.Outcome != "passed" && check.Outcome != "failed" && check.Outcome != "skipped" ||
			check.Outcome == "failed" != (check.ErrorClass != nil) {
			return false
		}
		if check.ErrorClass != nil && !validHealthErrorClass(*check.ErrorClass) {
			return false
		}
		if _, duplicate := seen[check.Kind]; duplicate {
			return false
		}
		seen[check.Kind] = struct{}{}
		if check.Outcome == "failed" {
			allHealthy = false
		}
	}
	if value.Healthy != allHealthy {
		return false
	}
	if !value.Healthy {
		return len(value.Checks) == 1 && value.Checks[0].Outcome == "failed"
	}
	if len(value.Checks) < 2 || value.Checks[0] != (SMTPHealthCheck{Kind: "dns", Outcome: "passed"}) ||
		value.Checks[1] != (SMTPHealthCheck{Kind: "connect", Outcome: "passed"}) {
		return false
	}
	next := 2
	if next < len(value.Checks) && value.Checks[next] == (SMTPHealthCheck{Kind: "tls", Outcome: "passed"}) {
		next++
	}
	if next < len(value.Checks) && value.Checks[next] == (SMTPHealthCheck{Kind: "authentication", Outcome: "passed"}) {
		next++
	}
	return next == len(value.Checks)
}

func validHealthErrorClass(value string) bool {
	return value == "authentication" || value == "connectivity" || value == "tls" || value == "timeout" ||
		value == "security" || value == "unknown"
}

func clearSMTPPersistedWrite(write *SMTPPersistedWrite) {
	if write == nil {
		return
	}
	clearProtectedSecret(write.Password)
	clearProtectedSecret(write.DKIMPrivateKey)
}

func clearProtectedSecret(secret *ProtectedSecret) {
	if secret == nil {
		return
	}
	clear(secret.Envelope.Nonce)
	clear(secret.Envelope.Ciphertext)
}
