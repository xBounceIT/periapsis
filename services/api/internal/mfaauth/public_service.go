package mfaauth

import (
	"context"
	"net/netip"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type PublicServiceOptions struct {
	Cryptography *RuntimeCryptography
	Completions  *CompletionTicketIssuer
	Enrollment   *FactorEnrollment
	LocalStepUp  *LocalStepUp
	Passkey      *Passkey
	Devices      *DeviceManager
}

// PublicService is the small composition boundary consumed by HTTP. Passkey
// may be disabled outside production; local MFA remains fully available.
type PublicService struct {
	cryptography *RuntimeCryptography
	completions  *CompletionTicketIssuer
	enrollment   *FactorEnrollment
	localStepUp  *LocalStepUp
	passkey      *Passkey
	devices      *DeviceManager
}

func NewPublicService(options PublicServiceOptions) (*PublicService, error) {
	if options.Cryptography == nil || options.Completions == nil || options.Enrollment == nil || options.LocalStepUp == nil {
		return nil, ErrInvalidInput
	}
	return &PublicService{
		cryptography: options.Cryptography, completions: options.Completions, enrollment: options.Enrollment,
		localStepUp: options.LocalStepUp, passkey: options.Passkey, devices: options.Devices,
	}, nil
}

// PrepareCompletion performs the one admission and the receipt-aware,
// action-specific live resolution required before any browser credential is
// reserved or one-use artifact is claimed.
func (service *PublicService) PrepareCompletion(
	ctx context.Context,
	request CompletionTicketRequest,
) (CompletionTicket, error) {
	if service == nil || service.completions == nil {
		return CompletionTicket{}, ErrUnavailable
	}
	return service.completions.Prepare(ctx, request)
}

func (service *PublicService) ListDevices(
	ctx context.Context,
	authority DeviceAuthority,
	input DeviceListInput,
) (DevicePage, error) {
	if service == nil || service.devices == nil {
		return DevicePage{}, ErrUnavailable
	}
	return service.devices.List(ctx, authority, input)
}

func (service *PublicService) RenamePasskey(
	ctx context.Context,
	authority DeviceAuthority,
	deviceID identity.EntityID,
	displayName string,
	expectedVersion uint64,
) (DeviceMutationResult, error) {
	if service == nil || service.devices == nil {
		return DeviceMutationResult{}, ErrUnavailable
	}
	return service.devices.RenamePasskey(ctx, authority, deviceID, displayName, expectedVersion)
}

func (service *PublicService) RevokeDevice(
	ctx context.Context,
	authority DeviceAuthority,
	deviceID identity.EntityID,
	kind DeviceKind,
	expectedVersion uint64,
) (DeviceMutationResult, error) {
	if service == nil || service.devices == nil {
		return DeviceMutationResult{}, ErrUnavailable
	}
	return service.devices.Revoke(ctx, authority, deviceID, kind, expectedVersion)
}

func (service *PublicService) String() string {
	return "mfaauth.PublicService{material:[REDACTED]}"
}
func (service *PublicService) GoString() string { return service.String() }

func (service *PublicService) Admission(
	network netip.Addr,
	principal identity.EntityID,
	resource string,
) (AdmissionContext, error) {
	if service == nil || service.cryptography == nil {
		return AdmissionContext{}, ErrUnavailable
	}
	return service.cryptography.Admission(network, principal, resource)
}

func (service *PublicService) StartLocalStepUp(
	ctx context.Context,
	command StartLocalStepUpCommand,
) (LocalStepUpStartArtifact, error) {
	if service == nil || service.localStepUp == nil {
		return LocalStepUpStartArtifact{}, ErrUnavailable
	}
	return service.localStepUp.Start(ctx, command)
}

func (service *PublicService) CompleteTOTP(
	ctx context.Context,
	command CompleteTOTPCommand,
) (mfa.StepUpArtifact, error) {
	if service == nil || service.localStepUp == nil {
		return mfa.StepUpArtifact{}, ErrUnavailable
	}
	return service.localStepUp.CompleteTOTP(ctx, command)
}

func (service *PublicService) CompleteRecovery(
	ctx context.Context,
	command CompleteRecoveryCommand,
) (mfa.StepUpArtifact, error) {
	if service == nil || service.localStepUp == nil {
		return mfa.StepUpArtifact{}, ErrUnavailable
	}
	return service.localStepUp.CompleteRecovery(ctx, command)
}

func (service *PublicService) StartTOTP(
	ctx context.Context,
	lookup AuthorityLookup,
) (TOTPEnrollmentStartArtifact, error) {
	if service == nil || service.enrollment == nil {
		return TOTPEnrollmentStartArtifact{}, ErrUnavailable
	}
	return service.enrollment.StartTOTP(ctx, lookup)
}

func (service *PublicService) FinishTOTP(
	ctx context.Context,
	command FinishTOTPEnrollmentCommand,
) (TOTPEnrollmentApplyResult, error) {
	if service == nil || service.enrollment == nil {
		return TOTPEnrollmentApplyResult{}, ErrUnavailable
	}
	return service.enrollment.FinishTOTP(ctx, command)
}

func (service *PublicService) RegenerateRecoveryCodes(
	ctx context.Context,
	command RegenerateRecoveryCodesCommand,
) (RecoveryCodesArtifact, error) {
	if service == nil || service.enrollment == nil {
		return RecoveryCodesArtifact{}, ErrUnavailable
	}
	return service.enrollment.RegenerateRecoveryCodes(ctx, command)
}

func (service *PublicService) StartPasskeyRegistration(
	ctx context.Context,
	lookup PasskeyLookup,
) (webauthn.StartArtifact, error) {
	if service == nil || service.passkey == nil {
		return webauthn.StartArtifact{}, ErrUnavailable
	}
	return service.passkey.StartRegistration(ctx, lookup)
}

func (service *PublicService) StartPasskeyAuthentication(
	ctx context.Context,
	lookup PasskeyLookup,
) (webauthn.StartArtifact, error) {
	if service == nil || service.passkey == nil {
		return webauthn.StartArtifact{}, ErrUnavailable
	}
	return service.passkey.StartAuthentication(ctx, lookup)
}

func (service *PublicService) FinishPasskeyRegistration(
	ctx context.Context,
	command FinishPasskeyRegistrationCommand,
) (PasskeyRegistrationResult, error) {
	if service == nil || service.passkey == nil {
		return PasskeyRegistrationResult{}, ErrUnavailable
	}
	return service.passkey.FinishRegistration(ctx, command)
}

func (service *PublicService) FinishPasskeyAuthentication(
	ctx context.Context,
	command FinishPasskeyAuthenticationCommand,
) (PasskeyAuthenticationResult, error) {
	if service == nil || service.passkey == nil {
		return PasskeyAuthenticationResult{}, ErrUnavailable
	}
	return service.passkey.FinishAuthentication(ctx, command)
}
