package httpserver

import (
	"context"
	"fmt"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

type directSAMLTOTPApplication interface {
	Start(context.Context, platformsamlauth.StartDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPStartArtifact, error)
	Complete(context.Context, platformsamlauth.CompleteDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPCompletionOutcome, error)
}

type RuntimePlatformSAMLContinuationOptions struct {
	TOTP      directSAMLTOTPApplication
	Readiness PlatformSAMLReadiness
}

// RuntimePlatformSAMLContinuation is the only bridge between the generic MFA
// HTTP routes and the purpose-specific direct-platform-SAML continuation. It
// cannot accept or relabel a tenant or OIDC continuation authority.
type RuntimePlatformSAMLContinuation struct {
	totp      directSAMLTOTPApplication
	readiness PlatformSAMLReadiness
}

func NewRuntimePlatformSAMLContinuation(
	options RuntimePlatformSAMLContinuationOptions,
) (*RuntimePlatformSAMLContinuation, error) {
	if interfaceIsNil(options.TOTP) || interfaceIsNil(options.Readiness) {
		return nil, errFederatedTransportUnavailable
	}
	return &RuntimePlatformSAMLContinuation{totp: options.TOTP, readiness: options.Readiness}, nil
}

func (service *RuntimePlatformSAMLContinuation) String() string {
	return fmt.Sprintf(
		"httpserver.RuntimePlatformSAMLContinuation{configured:%t,authority:direct_platform_saml}",
		service != nil && !interfaceIsNil(service.totp) && !interfaceIsNil(service.readiness),
	)
}

func (service *RuntimePlatformSAMLContinuation) GoString() string { return service.String() }

func (service *RuntimePlatformSAMLContinuation) Ready(ctx context.Context) error {
	if service == nil || interfaceIsNil(service.totp) || interfaceIsNil(service.readiness) ||
		ctx == nil || ctx.Err() != nil {
		return errFederatedTransportUnavailable
	}
	if err := service.readiness.ReadyDirectPlatformSAML(ctx); err != nil {
		return errFederatedTransportUnavailable
	}
	return nil
}

func (service *RuntimePlatformSAMLContinuation) StartTOTP(
	ctx context.Context,
	command PlatformSAMLStartTOTPCommand,
) (PlatformSAMLTOTPStart, error) {
	if err := service.Ready(ctx); err != nil {
		return PlatformSAMLTOTPStart{}, err
	}
	artifact, err := service.totp.Start(ctx, platformsamlauth.StartDirectSAMLTOTPCommand{
		ContinuationID: command.ContinuationID, ReceiptDigest: command.ReceiptDigest, Audit: command.Audit,
	})
	if err != nil {
		artifact.Destroy()
		return PlatformSAMLTOTPStart{}, err
	}
	defer artifact.Destroy()
	browserHandle, consumed := artifact.ConsumeBrowserHandle()
	if !consumed || artifact.ChallengeID() == (mfa.ChallengeID{}) ||
		!validFederatedEntityID(artifact.FactorID()) || artifact.ExpiresAt().IsZero() {
		clear(browserHandle)
		return PlatformSAMLTOTPStart{}, platformsamlauth.ErrAuthenticationUnavailable
	}
	return PlatformSAMLTOTPStart{
		ChallengeID: artifact.ChallengeID(), BrowserHandle: browserHandle,
		FactorID: artifact.FactorID(), ExpiresAt: artifact.ExpiresAt(),
	}, nil
}

func (service *RuntimePlatformSAMLContinuation) CompleteTOTP(
	ctx context.Context,
	command PlatformSAMLCompleteTOTPCommand,
) (PlatformSAMLTOTPOutcome, error) {
	if err := service.Ready(ctx); err != nil {
		return PlatformSAMLTOTPOutcome{}, err
	}
	browserHandle := append([]byte(nil), command.BrowserHandle...)
	code := append([]byte(nil), command.Code...)
	defer clear(browserHandle)
	defer clear(code)
	outcome, err := service.totp.Complete(ctx, platformsamlauth.CompleteDirectSAMLTOTPCommand{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		ReceiptDigest: command.ReceiptDigest, BrowserHandle: browserHandle,
		FactorID: command.FactorID, Code: code, Audit: command.Audit,
	})
	mapped := PlatformSAMLTOTPOutcome{
		UserID: outcome.UserID, SessionID: outcome.SessionID, FactorID: outcome.FactorID,
	}
	if outcome.Credential != nil {
		mapped.Credential = outcome.Credential
		outcome.Credential = nil
	}
	if outcome.Delivery != nil {
		mapped.Delivery = outcome.Delivery
		outcome.Delivery = nil
	}
	outcome.Destroy()
	if err != nil {
		if interfaceIsNil(mapped.Delivery) {
			mapped.Destroy()
			return PlatformSAMLTOTPOutcome{}, err
		}
		return mapped, err
	}
	if interfaceIsNil(mapped.Credential) || interfaceIsNil(mapped.Delivery) ||
		!validFederatedEntityID(mapped.UserID) || !validFederatedEntityID(mapped.SessionID) ||
		!validFederatedEntityID(mapped.FactorID) || mapped.SessionID == mapped.UserID ||
		mapped.SessionID == mapped.FactorID || mapped.UserID == mapped.FactorID {
		return mapped, platformsamlauth.ErrAuthenticationUnavailable
	}
	return mapped, nil
}

var _ PlatformSAMLContinuationService = (*RuntimePlatformSAMLContinuation)(nil)
var _ PlatformSAMLSessionCredential = (*platformsamlauth.BrowserCredential)(nil)
var _ PlatformSAMLTOTPDeliveryFinalizer = (*platformsamlauth.DirectSAMLTOTPDeliveryFinalizer)(nil)
