package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	beginPlatformOIDCDirectTOTPSQL         = `select app.begin_platform_post_primary_totp_v2($1::jsonb)`
	loadPlatformOIDCDirectTOTPSQL          = `select app.load_platform_post_primary_totp_v1($1::jsonb)`
	recordPlatformOIDCDirectTOTPFailureSQL = `select app.record_platform_post_primary_totp_failure_v1($1::jsonb)`
	applyPlatformOIDCDirectTOTPSQL         = `select app.apply_platform_post_primary_totp_v1($1::jsonb)`
	abandonPlatformOIDCDirectTOTPSQL       = `select app.abandon_platform_post_primary_totp_v1($1::jsonb)`
)

var _ platformoidcauth.DirectTOTPStore = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) BeginDirectTOTP(
	ctx context.Context,
	request platformoidcauth.DirectTOTPBeginRequest,
) (platformoidcauth.DirectTOTPChallenge, error) {
	eventID, err := repository.newPlatformOIDCDirectAuditEventID()
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	wire, err := platformOIDCDirectTOTPBeginToWire(request, eventID)
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	defer clearPlatformOIDCDirectTOTPBeginWire(&wire)
	var response platformOIDCDirectTOTPChallengeWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, beginPlatformOIDCDirectTOTPSQL, wire, &response,
		maximumPlatformOIDCDirectTOTPWireBytes,
	); err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	challenge, err := platformOIDCDirectTOTPChallengeFromWire(response)
	if err != nil || challenge.ChallengeID != request.ChallengeID ||
		challenge.ContinuationID != request.ContinuationID || challenge.FailureCount != 0 ||
		challenge.State != platformoidcauth.DirectTOTPChallengePending || challenge.Version != 1 ||
		!challenge.ExpiresAt.Equal(request.ExpiresAt) {
		return platformoidcauth.DirectTOTPChallenge{}, errFederatedAuthPersistence
	}
	return challenge, nil
}

func (repository *FederatedAuthRepository) LoadDirectTOTP(
	ctx context.Context,
	lookup platformoidcauth.DirectTOTPLookup,
) (platformoidcauth.DirectTOTPVerificationSnapshot, error) {
	wire, err := platformOIDCDirectTOTPLookupToWire(lookup)
	if err != nil {
		return platformoidcauth.DirectTOTPVerificationSnapshot{}, err
	}
	defer clearPlatformOIDCDirectTOTPLookupWire(&wire)
	var response platformOIDCDirectTOTPVerificationWire
	defer clearPlatformOIDCDirectTOTPVerificationWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, loadPlatformOIDCDirectTOTPSQL, wire, &response,
		maximumPlatformOIDCDirectTOTPWireBytes,
	); err != nil {
		return platformoidcauth.DirectTOTPVerificationSnapshot{}, err
	}
	snapshot, err := platformOIDCDirectTOTPVerificationFromWire(response)
	if err != nil || snapshot.ChallengeID != lookup.ChallengeID ||
		snapshot.ContinuationID != lookup.ContinuationID || snapshot.Authority != lookup.Authority ||
		snapshot.ReceiptDigest != lookup.ReceiptDigest || !snapshot.ExpiresAt.After(lookup.ObservedAt) {
		snapshot.Destroy()
		return platformoidcauth.DirectTOTPVerificationSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func (repository *FederatedAuthRepository) RecordDirectTOTPFailure(
	ctx context.Context,
	request platformoidcauth.DirectTOTPFailureRequest,
) (platformoidcauth.DirectTOTPChallenge, error) {
	eventID, err := repository.newPlatformOIDCDirectAuditEventID()
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	wire, err := platformOIDCDirectTOTPFailureToWire(request, eventID)
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	defer clearPlatformOIDCDirectTOTPFailureWire(&wire)
	var response platformOIDCDirectTOTPChallengeWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, recordPlatformOIDCDirectTOTPFailureSQL, wire, &response,
		maximumPlatformOIDCDirectTOTPWireBytes,
	); err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	challenge, err := platformOIDCDirectTOTPChallengeFromWire(response)
	if err != nil || challenge.ChallengeID != request.ChallengeID ||
		challenge.ContinuationID != request.ContinuationID {
		return platformoidcauth.DirectTOTPChallenge{}, errFederatedAuthPersistence
	}
	return challenge, nil
}

func (repository *FederatedAuthRepository) ApplyDirectTOTP(
	ctx context.Context,
	request platformoidcauth.DirectTOTPApplyRequest,
) (platformoidcauth.DirectTOTPApplyResult, error) {
	eventID, err := repository.newPlatformOIDCDirectAuditEventID()
	if err != nil {
		return platformoidcauth.DirectTOTPApplyResult{}, err
	}
	wire, err := platformOIDCDirectTOTPApplyToWire(request, eventID)
	if err != nil {
		return platformoidcauth.DirectTOTPApplyResult{}, err
	}
	defer clearPlatformOIDCDirectTOTPApplyWire(&wire)
	var response platformOIDCDirectTOTPApplyResultWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, applyPlatformOIDCDirectTOTPSQL, wire, &response,
		maximumPlatformOIDCDirectTOTPWireBytes,
	); err != nil {
		return platformoidcauth.DirectTOTPApplyResult{}, err
	}
	result, err := platformOIDCDirectTOTPApplyResultFromWire(response)
	if err != nil {
		return platformoidcauth.DirectTOTPApplyResult{}, err
	}
	if result.Category == platformoidcauth.DirectTOTPApplySuccess &&
		(result.SessionID != request.Session.SessionID() || result.AcceptedCounter != request.AcceptedCounter) {
		return platformoidcauth.DirectTOTPApplyResult{}, errFederatedAuthPersistence
	}
	return result, nil
}

func (repository *FederatedAuthRepository) AbandonDirectTOTP(
	ctx context.Context,
	request platformoidcauth.DirectTOTPAbandonRequest,
) (platformoidcauth.DirectTOTPChallenge, error) {
	eventID, err := repository.newPlatformOIDCDirectAuditEventID()
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	wire, err := platformOIDCDirectTOTPAbandonToWire(request, eventID)
	if err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	defer clearPlatformOIDCDirectTOTPAbandonWire(&wire)
	var response platformOIDCDirectTOTPChallengeWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, abandonPlatformOIDCDirectTOTPSQL, wire, &response,
		maximumPlatformOIDCDirectTOTPWireBytes,
	); err != nil {
		return platformoidcauth.DirectTOTPChallenge{}, err
	}
	challenge, err := platformOIDCDirectTOTPChallengeFromWire(response)
	if err != nil || challenge.ChallengeID != request.ChallengeID ||
		challenge.ContinuationID != request.ContinuationID {
		return platformoidcauth.DirectTOTPChallenge{}, errFederatedAuthPersistence
	}
	return challenge, nil
}

func (repository *FederatedAuthRepository) newPlatformOIDCDirectAuditEventID() (uuid.UUID, error) {
	if repository == nil || repository.newDirectAuditID == nil {
		return uuid.Nil, errFederatedAuthPersistence
	}
	identifier, err := repository.newDirectAuditID()
	if err != nil || !platformOIDCDirectUUIDv7(identifier) {
		return uuid.Nil, errFederatedAuthPersistence
	}
	return identifier, nil
}
