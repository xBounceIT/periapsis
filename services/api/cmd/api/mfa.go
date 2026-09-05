package main

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/config"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
)

func newMFAApplication(pool *pgxpool.Pool, cfg config.Config) (*mfaauth.PublicService, error) {
	cryptography, err := mfaauth.NewDefaultRuntimeCryptography(cfg.IdentityKeyring, cfg.MasterKey)
	if err != nil {
		return nil, errors.New("initialize MFA cryptography")
	}
	admissions := postgres.NewMFAAdmissionRepository(pool)
	stepUpStore := postgres.NewMFAStepUpRepository(pool)
	enrollmentStore := postgres.NewMFAEnrollmentRepository(pool)
	deviceRepository := postgres.NewMFADeviceRepository(pool)

	registrationPolicy := webauthn.CeremonyPolicy{}
	primaryPolicy := webauthn.CeremonyPolicy{}
	stepUpPolicy := webauthn.CeremonyPolicy{}
	var relyingParty webauthn.RelyingParty
	if cfg.WebAuthnEnabled {
		relyingParty, err = webauthn.CompileRelyingParty(cfg.WebAuthnRPID, []string{cfg.PublicOrigin}, 1)
		if err != nil {
			return nil, errors.New("compile WebAuthn relying-party pins")
		}
		registrationPolicy = webauthn.CeremonyPolicy{
			RequireUserPresence: true, UserVerification: webauthn.UserVerificationRequired,
			ResidentKey: webauthn.ResidentKeyRequired, Attestation: webauthn.AttestationNone,
		}
		primaryPolicy = registrationPolicy
		stepUpPolicy = webauthn.CeremonyPolicy{
			RequireUserPresence: true, UserVerification: webauthn.UserVerificationRequired,
			ResidentKey: webauthn.ResidentKeyPreferred, Attestation: webauthn.AttestationNone,
		}
	}
	plans, err := postgres.NewMFAPlanRepository(postgres.MFAPlanRepositoryOptions{
		Pool: pool, PasskeyEnabled: cfg.WebAuthnEnabled, RelyingParty: relyingParty,
		RegistrationPolicy: registrationPolicy, PrimaryPolicy: primaryPolicy, StepUpPolicy: stepUpPolicy,
	})
	if err != nil {
		return nil, errors.New("initialize MFA live-authority plans")
	}
	completions, err := mfaauth.NewCompletionTicketIssuer(mfaauth.CompletionTicketOptions{
		Source: plans, Admissions: admissions, OperationTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, errors.New("initialize atomic MFA completion boundary")
	}
	stepUpKernel, err := mfa.NewStepUp(mfa.StepUpOptions{
		Challenges: stepUpStore, Factors: stepUpStore, TOTP: cryptography,
		Recovery: cryptography, Consumer: stepUpStore, ChallengeTTL: cfg.MFAChallengeTimeout,
		OperationTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, errors.New("initialize local MFA step-up kernel")
	}
	localStepUp, err := mfaauth.NewLocalStepUp(mfaauth.LocalStepUpOptions{
		Source: plans, Admissions: admissions, Kernel: stepUpKernel, OperationTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, errors.New("initialize local MFA step-up application")
	}
	enrollment, err := mfaauth.NewFactorEnrollment(mfaauth.FactorEnrollmentOptions{
		Source: plans, Admissions: admissions, TOTP: cryptography, TOTPVerifier: cryptography,
		TOTPStore: enrollmentStore, Recovery: cryptography, RecoveryStore: enrollmentStore,
		EnrollmentTTL: cfg.MFAChallengeTimeout, RecoveryCodeCount: 10, OperationTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, errors.New("initialize MFA enrollment application")
	}

	var passkey *mfaauth.Passkey
	if cfg.WebAuthnEnabled {
		webauthnStore := postgres.NewWebAuthnRepository(pool)
		verifier, verifierErr := webauthn.NewLibraryVerifier(webauthn.LibraryVerifierOptions{})
		if verifierErr != nil {
			return nil, errors.New("initialize WebAuthn verifier")
		}
		kernel, kernelErr := webauthn.NewKernel(webauthn.KernelOptions{
			Ceremonies: webauthnStore, Credentials: webauthnStore, Verifier: verifier,
			CeremonyTTL: cfg.MFAChallengeTimeout, OperationTimeout: cfg.RequestTimeout,
			Limits: webauthn.DefaultLimits(),
		})
		if kernelErr != nil {
			return nil, errors.New("initialize WebAuthn ceremony kernel")
		}
		passkey, err = mfaauth.NewPasskey(mfaauth.PasskeyOptions{
			Plans: plans, Admissions: admissions, Kernel: kernel, Transactions: webauthnStore,
			OperationTimeout: cfg.RequestTimeout,
		})
		if err != nil {
			return nil, errors.New("initialize passkey application")
		}
	}
	devices, err := mfaauth.NewDeviceManager(deviceRepository, time.Now)
	if err != nil {
		return nil, errors.New("initialize MFA device inventory")
	}
	service, err := mfaauth.NewPublicService(mfaauth.PublicServiceOptions{
		Cryptography: cryptography, Enrollment: enrollment, LocalStepUp: localStepUp,
		Passkey: passkey, Devices: devices, Completions: completions,
	})
	if err != nil {
		return nil, errors.New("initialize public MFA application")
	}
	return service, nil
}
