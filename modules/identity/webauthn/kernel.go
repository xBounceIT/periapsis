package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type Kernel struct {
	ceremonies       CeremonyRepository
	credentials      CredentialLookupRepository
	verifier         Verifier
	random           io.Reader
	now              func() time.Time
	ceremonyTTL      time.Duration
	operationTimeout time.Duration
	limits           Limits
}

func NewKernel(options KernelOptions) (*Kernel, error) {
	if options.Ceremonies == nil || options.Credentials == nil || options.Verifier == nil ||
		options.CeremonyTTL < minimumCeremonyTTL || options.CeremonyTTL > maximumCeremonyTTL ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		!validLimits(options.Limits) {
		return nil, ErrInvalidOptions
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &Kernel{
		ceremonies: options.Ceremonies, credentials: options.Credentials, verifier: options.Verifier,
		random: options.Random, now: options.Now, ceremonyTTL: options.CeremonyTTL,
		operationTimeout: options.OperationTimeout, limits: options.Limits,
	}, nil
}

func (kernel *Kernel) StartRegistration(ctx context.Context, request RegistrationStartRequest) (StartArtifact, error) {
	if kernel == nil || !validUserHandle(request.UserHandle) || !validRP(request.RP) ||
		!validBinding(kernel.safeNow(), request.Binding, 0) || request.Binding.Purpose != PurposeRegistration ||
		!validPolicy(request.Policy, request.Binding.Purpose, request.Binding.Requirement) {
		return StartArtifact{}, ErrCeremonyRejected
	}
	credentials, ok := normalizeCredentialIDs(request.ExcludeCredentialIDs, kernel.limits, true)
	if !ok {
		return StartArtifact{}, ErrCeremonyRejected
	}
	return kernel.start(ctx, request.RP, request.Binding, request.Policy, 0, request.UserHandle, credentials)
}

func (kernel *Kernel) StartAuthentication(ctx context.Context, request AuthenticationStartRequest) (StartArtifact, error) {
	now := kernel.safeNow()
	if kernel == nil || !validRP(request.RP) || !validBinding(now, request.Binding, request.Mode) ||
		request.Binding.Purpose == PurposeRegistration ||
		request.Policy.Attestation != AttestationNone || request.Policy.MetadataRevision != 0 ||
		!validPolicy(request.Policy, request.Binding.Purpose, request.Binding.Requirement) {
		return StartArtifact{}, ErrCeremonyRejected
	}
	if request.Mode == AuthenticationDiscoverable {
		if len(request.UserHandle) != 0 || len(request.AllowedCredentialIDs) != 0 ||
			request.Policy.UserVerification != UserVerificationRequired ||
			request.Policy.ResidentKey != ResidentKeyRequired {
			return StartArtifact{}, ErrCeremonyRejected
		}
		return kernel.start(ctx, request.RP, request.Binding, request.Policy, request.Mode, nil, nil)
	}
	if !validUserHandle(request.UserHandle) {
		return StartArtifact{}, ErrCeremonyRejected
	}
	credentials, ok := normalizeCredentialIDs(request.AllowedCredentialIDs, kernel.limits, false)
	if !ok {
		return StartArtifact{}, ErrCeremonyRejected
	}
	return kernel.start(ctx, request.RP, request.Binding, request.Policy, request.Mode, request.UserHandle, credentials)
}

func (kernel *Kernel) start(ctx context.Context, rp RelyingParty, binding CeremonyBinding, policy CeremonyPolicy,
	mode AuthenticationMode, userHandle []byte, credentialIDs [][]byte,
) (StartArtifact, error) {
	operation, cancel, ok := kernel.operationContext(ctx)
	if !ok {
		return StartArtifact{}, ErrCeremonyRejected
	}
	defer cancel()
	now := kernel.safeNow()
	if !validInstant(now) {
		return StartArtifact{}, ErrCeremonyRejected
	}
	idBytes, challenge, browser, ok := kernel.randomArtifacts()
	if !ok {
		return StartArtifact{}, ErrCeremonyRejected
	}
	defer clear(idBytes)
	defer clear(browser)
	var id CeremonyID
	copy(id[:], idBytes)
	expiresAt := now.Add(kernel.ceremonyTTL).Truncate(time.Millisecond)
	if !binding.AnchorExpiresAt.IsZero() && binding.AnchorExpiresAt.Before(expiresAt) {
		expiresAt = binding.AnchorExpiresAt
	}
	pending := PendingCeremony{
		ID: id, ChallengeDigest: sha256.Sum256(challenge), BrowserDigest: sha256.Sum256(browser),
		RP: cloneRP(rp), Binding: cloneBinding(binding), Policy: policy, Mode: mode,
		AllowedCredentialIDs: cloneBytes2D(credentialIDs), CreatedAt: now,
		ExpiresAt: expiresAt, State: CeremonyPending, Version: 1,
	}
	if len(userHandle) != 0 {
		pending.UserHandleDigest = sha256.Sum256(userHandle)
	}
	if err := kernel.ceremonies.Create(operation, pending); err != nil {
		clear(challenge)
		return StartArtifact{}, ErrCeremonyPersistence
	}
	return StartArtifact{
		id: id, challenge: challenge, browserHandle: append([]byte(nil), browser...), expiresAt: pending.ExpiresAt,
		rp: cloneRP(rp), binding: cloneBinding(binding), policy: policy, mode: mode,
		userHandle: append([]byte(nil), userHandle...), credentialIDs: cloneBytes2D(credentialIDs),
	}, nil
}

// FinishRegistrationWithConsumer preserves the kernel's verification and
// one-time semantics while allowing an application transaction to couple the
// credential mutation to session rotation and audit.
func (kernel *Kernel) FinishRegistrationWithConsumer(
	ctx context.Context,
	response RegistrationResponse,
	consumer RegistrationConsumer,
) (RegistrationArtifact, error) {
	if kernel == nil || !kernel.validRegistrationResponse(response) {
		return RegistrationArtifact{}, ErrCeremonyRejected
	}
	if consumer == nil {
		return RegistrationArtifact{}, ErrCeremonyRejected
	}
	response.Transports, _ = normalizeTransports(response.Transports)
	claimed, claimedAt, operation, cancel, err := kernel.claim(
		ctx, response.CeremonyID, response.BrowserHandle, response.ContinuationReceiptDigest,
	)
	if err != nil {
		return RegistrationArtifact{}, err
	}
	defer cancel()
	if claimed.Binding.Purpose != PurposeRegistration || claimed.Mode != 0 ||
		!validClaimed(claimed, claimedAt, laterCeremonyTime(claimed.ClaimedAt, kernel.safeNow()), kernel.limits) {
		kernel.fail(operation, claimed, FailureMalformed)
		return RegistrationArtifact{}, ErrCeremonyRejected
	}
	proof, verifyErr := kernel.verifier.VerifyRegistration(operation, RegistrationVerificationRequest{
		ChallengeDigest: claimed.ChallengeDigest, RPID: claimed.RP.id,
		AllowedOrigins: append([]string(nil), claimed.RP.origins...), Policy: claimed.Policy,
		CredentialID:           append([]byte(nil), response.CredentialID...),
		ClientDataJSON:         append([]byte(nil), response.ClientDataJSON...),
		AttestationObject:      append([]byte(nil), response.AttestationObject...),
		ClientExtensionResults: append([]byte(nil), response.ClientExtensionResults...),
		Transports:             append([]CredentialTransport(nil), response.Transports...),
	})
	if verifyErr != nil || !kernel.validRegistrationProof(claimed, response, proof) {
		kernel.fail(operation, claimed, FailureVerification)
		return RegistrationArtifact{}, ErrVerificationRejected
	}
	credential := Credential{
		ID: append([]byte(nil), proof.CredentialID...), PublicKey: append([]byte(nil), proof.PublicKey...),
		TenantID: claimed.Binding.TenantID, UserID: claimed.Binding.UserID,
		IdentityEpoch:    claimed.Binding.IdentityEpoch,
		UserHandleDigest: claimed.UserHandleDigest, RPID: claimed.RP.id, RPRevision: claimed.RP.revision,
		Version: 1, SecurityRevision: 1, Status: CredentialActive, SignCount: proof.SignCount,
		Discoverable: proof.Discoverable, UserVerification: proof.UserVerified,
		BackupEligible: proof.BackupEligible, BackedUp: proof.BackedUp,
		Transports: append([]CredentialTransport(nil), proof.Transports...),
	}
	completedAt := laterCeremonyTime(claimed.ClaimedAt, kernel.safeNow())
	if !completedAt.Before(claimed.ExpiresAt) || !validBinding(completedAt, claimed.Binding, claimed.Mode) {
		kernel.fail(operation, claimed, FailureExpired)
		return RegistrationArtifact{}, ErrCeremonyRejected
	}
	expectedCredential := cloneCredential(credential)
	completion := RegistrationCompletion{
		CeremonyID: claimed.ID, ExpectedCeremonyVersion: claimed.Version, CompletedAt: completedAt,
		Binding:    cloneBinding(claimed.Binding),
		Credential: cloneCredential(credential), AAGUID: proof.AAGUID, AttestationFormat: proof.AttestationFormat,
		AttestationType: proof.AttestationType, AttestationTrusted: proof.AttestationTrusted,
		MetadataRevision: proof.MetadataRevision,
	}
	stored, storeErr := consumer.CompleteRegistration(operation, cloneRegistrationCompletion(completion))
	if storeErr != nil || !sameRegisteredCredential(expectedCredential, stored) {
		return RegistrationArtifact{}, ErrCredentialRejected
	}
	return RegistrationArtifact{
		TenantID: stored.TenantID, UserID: stored.UserID, IdentityEpoch: stored.IdentityEpoch,
		CredentialVersion: stored.Version,
		Discoverable:      stored.Discoverable, BackupEligible: stored.BackupEligible,
		BackedUp: stored.BackedUp, Transports: append([]CredentialTransport(nil), stored.Transports...),
	}, nil
}

// FinishAuthenticationWithConsumer lets the protected writer advance or
// revoke the credential, complete the ceremony, rotate/create the session,
// and append audit atomically. The kernel still validates the returned
// credential projection before exposing assurance.
func (kernel *Kernel) FinishAuthenticationWithConsumer(
	ctx context.Context,
	response AuthenticationResponse,
	consumer AuthenticationConsumer,
) (AuthenticationArtifact, error) {
	if kernel == nil || !kernel.validAuthenticationResponse(response) {
		return AuthenticationArtifact{}, ErrCeremonyRejected
	}
	if consumer == nil {
		return AuthenticationArtifact{}, ErrCeremonyRejected
	}
	claimed, claimedAt, operation, cancel, err := kernel.claim(
		ctx, response.CeremonyID, response.BrowserHandle, response.ContinuationReceiptDigest,
	)
	if err != nil {
		return AuthenticationArtifact{}, err
	}
	defer cancel()
	if claimed.Binding.Purpose == PurposeRegistration ||
		!validClaimed(claimed, claimedAt, laterCeremonyTime(claimed.ClaimedAt, kernel.safeNow()), kernel.limits) {
		kernel.fail(operation, claimed, FailureMalformed)
		return AuthenticationArtifact{}, ErrCeremonyRejected
	}
	credential, loadErr := kernel.credentials.LoadForAuthentication(operation, CredentialLookup{
		TenantID: claimed.Binding.TenantID, CredentialID: append([]byte(nil), response.CredentialID...),
		UserHandle:   append([]byte(nil), response.UserHandle...),
		Discoverable: claimed.Mode == AuthenticationDiscoverable,
	})
	if loadErr != nil || !validCredentialProjection(credential, claimed, response, kernel.limits) {
		kernel.fail(operation, claimed, FailureCredential)
		return AuthenticationArtifact{}, ErrCredentialRejected
	}
	proof, verifyErr := kernel.verifier.VerifyAuthentication(operation, AuthenticationVerificationRequest{
		ChallengeDigest: claimed.ChallengeDigest, RPID: claimed.RP.id,
		AllowedOrigins: append([]string(nil), claimed.RP.origins...), Policy: claimed.Policy,
		Credential: cloneCredential(credential), CredentialID: append([]byte(nil), response.CredentialID...),
		ClientDataJSON:    append([]byte(nil), response.ClientDataJSON...),
		AuthenticatorData: append([]byte(nil), response.AuthenticatorData...),
		Signature:         append([]byte(nil), response.Signature...), UserHandle: append([]byte(nil), response.UserHandle...),
	})
	if verifyErr != nil || !validAuthenticationProof(claimed, response, proof) {
		kernel.fail(operation, claimed, FailureVerification)
		return AuthenticationArtifact{}, ErrVerificationRejected
	}
	if !validVersionAsInt64(credential.Version + 1) {
		kernel.fail(operation, claimed, FailureCredential)
		return AuthenticationArtifact{}, ErrCredentialRejected
	}
	disposition := EvaluateSignCount(credential.SignCount, proof.SignCount)
	backupStateChanged := credential.BackupEligible != proof.BackupEligible || credential.BackedUp != proof.BackedUp
	nextSecurityRevision := credential.SecurityRevision
	if disposition == CounterCloneSuspected || backupStateChanged {
		if !validVersionAsInt64(nextSecurityRevision + 1) {
			kernel.fail(operation, claimed, FailureCredential)
			return AuthenticationArtifact{}, ErrCredentialRejected
		}
		nextSecurityRevision++
	}
	completedAt := laterCeremonyTime(claimed.ClaimedAt, kernel.safeNow())
	if !completedAt.Before(claimed.ExpiresAt) || !validBinding(completedAt, claimed.Binding, claimed.Mode) {
		kernel.fail(operation, claimed, FailureExpired)
		return AuthenticationArtifact{}, ErrCeremonyRejected
	}
	factorRevision := int64(nextSecurityRevision)
	level := identity.AssuranceMFA
	if claimed.Binding.Purpose == PurposePrimaryAuthentication {
		level = identity.AssurancePrimary
	}
	if proof.UserVerified {
		level = identity.AssurancePhishingResistant
	}
	evidence := identity.AssuranceEvidence{
		Level: level, Kind: identity.AssuranceEvidenceFactor, Source: identity.AssuranceSource{Local: true},
		AuthenticatedAt: completedAt, FactorRevision: &factorRevision,
	}
	if disposition != CounterCloneSuspected {
		combined := append(cloneAssuranceEvidence(claimed.Binding.BaselineEvidence), evidence)
		if identity.EvaluateAssurance(completedAt, claimed.Binding.Requirement, combined, false) != identity.AssuranceSatisfied {
			kernel.fail(operation, claimed, FailureVerification)
			return AuthenticationArtifact{}, ErrVerificationRejected
		}
	}
	completion := AuthenticationCompletion{
		CeremonyID: claimed.ID, ExpectedCeremonyVersion: claimed.Version,
		Binding: cloneBinding(claimed.Binding), ResolvedUserID: credential.UserID,
		ExpectedIdentityEpoch: credential.IdentityEpoch,
		CredentialID:          append([]byte(nil), credential.ID...), ExpectedCredentialVersion: credential.Version,
		ExpectedSecurityRevision: credential.SecurityRevision,
		CompletedAt:              completedAt, ExpectedSignCount: credential.SignCount,
		ObservedSignCount: proof.SignCount, ExpectedBackupEligible: credential.BackupEligible,
		ExpectedBackedUp:   credential.BackedUp,
		CounterDisposition: disposition,
		UserVerified:       proof.UserVerified,
		BackupEligible:     proof.BackupEligible, BackedUp: proof.BackedUp,
	}
	expectedCompletion := cloneAuthenticationCompletion(completion)
	result, applyErr := consumer.CompleteAuthentication(operation, cloneAuthenticationCompletion(completion))
	if applyErr != nil || !validCounterResult(expectedCompletion, result) {
		return AuthenticationArtifact{}, ErrCredentialRejected
	}
	if disposition == CounterCloneSuspected {
		return AuthenticationArtifact{}, ErrCredentialCloneSuspected
	}
	return AuthenticationArtifact{
		TenantID: credential.TenantID, UserID: credential.UserID, IdentityEpoch: credential.IdentityEpoch,
		CredentialVersion: result.CredentialVersion, CredentialDigest: sha256.Sum256(credential.ID),
		Evidence:           evidence,
		CounterUnsupported: disposition == CounterUnsupported,
		BackupStateChanged: backupStateChanged,
	}, nil
}

func (kernel *Kernel) claim(
	ctx context.Context,
	id CeremonyID,
	browser []byte,
	receiptDigest [sha256.Size]byte,
) (ClaimedCeremony, time.Time, context.Context, context.CancelFunc, error) {
	if id == (CeremonyID{}) || !validOpaqueArtifact(browser) {
		return ClaimedCeremony{}, time.Time{}, nil, nil, ErrCeremonyRejected
	}
	operation, cancel, ok := kernel.operationContext(ctx)
	if !ok {
		return ClaimedCeremony{}, time.Time{}, nil, nil, ErrCeremonyRejected
	}
	requestedAt := kernel.safeNow()
	claimed, err := kernel.ceremonies.Claim(operation, CeremonyClaim{
		ID: id, BrowserDigest: sha256.Sum256(browser), ClaimedAt: requestedAt,
		ContinuationReceiptDigest: receiptDigest,
	})
	if err != nil || claimed.ID != id || claimed.BrowserDigest != sha256.Sum256(browser) ||
		claimed.ClaimedAt.Before(requestedAt) ||
		claimed.ClaimedAt.After(requestedAt.Add(5*time.Minute+kernel.operationTimeout)) ||
		!validInstant(claimed.ClaimedAt) {
		cancel()
		return ClaimedCeremony{}, time.Time{}, nil, nil, ErrCeremonyRejected
	}
	return claimed, claimed.ClaimedAt, operation, cancel, nil
}

func (kernel *Kernel) fail(ctx context.Context, claimed ClaimedCeremony, reason CeremonyFailureReason) {
	state := CeremonyFailed
	if reason == FailureExpired {
		state = CeremonyExpired
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), kernel.operationTimeout)
	defer cancel()
	_ = kernel.ceremonies.Fail(cleanup, CeremonyFailure{
		ID: claimed.ID, ExpectedVersion: claimed.Version,
		FailedAt: laterCeremonyTime(claimed.ClaimedAt, kernel.safeNow()), State: state, Reason: reason,
	})
}

func laterCeremonyTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func (kernel *Kernel) validRegistrationResponse(value RegistrationResponse) bool {
	_, ok := normalizeTransports(value.Transports)
	return value.CeremonyID != (CeremonyID{}) && validOpaqueArtifact(value.BrowserHandle) && ok &&
		len(value.CredentialID) >= minimumCredentialIDBytes &&
		len(value.CredentialID) <= kernel.limits.MaxCredentialIDBytes && len(value.ClientDataJSON) > 0 &&
		len(value.AttestationObject) > 0 && totalWithin(kernel.limits.MaxResponseBytes,
		value.CredentialID, value.ClientDataJSON, value.AttestationObject, value.ClientExtensionResults)
}

func (kernel *Kernel) validAuthenticationResponse(value AuthenticationResponse) bool {
	return value.CeremonyID != (CeremonyID{}) && validOpaqueArtifact(value.BrowserHandle) &&
		len(value.CredentialID) >= minimumCredentialIDBytes && len(value.CredentialID) <= kernel.limits.MaxCredentialIDBytes &&
		len(value.ClientDataJSON) > 0 && len(value.AuthenticatorData) > 0 && len(value.Signature) > 0 &&
		(len(value.UserHandle) == 0 || validUserHandle(value.UserHandle)) &&
		totalWithin(kernel.limits.MaxResponseBytes, value.CredentialID, value.ClientDataJSON,
			value.AuthenticatorData, value.Signature, value.UserHandle)
}

func (kernel *Kernel) validRegistrationProof(claimed ClaimedCeremony, response RegistrationResponse, proof RegistrationProof) bool {
	transports, transportsOK := normalizeTransports(proof.Transports)
	if !transportsOK || !slices.Equal(transports, proof.Transports) ||
		proof.ChallengeDigest != claimed.ChallengeDigest ||
		!validProofCommon(proof.ChallengeDigest, proof.Origin, claimed.RP, proof.RPIDHash,
			proof.UserPresent, proof.UserVerified, proof.CrossOrigin, claimed.Policy) ||
		!bytes.Equal(proof.CredentialID, response.CredentialID) ||
		len(proof.PublicKey) < minimumPublicKeyBytes || len(proof.PublicKey) > kernel.limits.MaxPublicKeyBytes ||
		proof.BackedUp && !proof.BackupEligible || !validAttestationFormat(proof.AttestationFormat) ||
		!slices.Equal(proof.Transports, response.Transports) {
		return false
	}
	if claimed.Policy.ResidentKey == ResidentKeyRequired && !proof.Discoverable {
		return false
	}
	switch claimed.Policy.Attestation {
	case AttestationNone:
		return proof.AttestationType == AttestationTypeNone && !proof.AttestationTrusted && proof.MetadataRevision == 0
	case AttestationDirect:
		return proof.AttestationType == AttestationTypeBasic &&
			proof.AttestationTrusted && proof.MetadataRevision == claimed.Policy.MetadataRevision
	case AttestationEnterprise:
		return proof.AttestationType == AttestationTypeEnterprise && proof.AttestationTrusted &&
			proof.MetadataRevision == claimed.Policy.MetadataRevision
	default:
		return false
	}
}

func validAuthenticationProof(claimed ClaimedCeremony, response AuthenticationResponse, proof AuthenticationProof) bool {
	return proof.ChallengeDigest == claimed.ChallengeDigest &&
		validProofCommon(proof.ChallengeDigest, proof.Origin, claimed.RP, proof.RPIDHash,
			proof.UserPresent, proof.UserVerified, proof.CrossOrigin, claimed.Policy) &&
		bytes.Equal(proof.CredentialID, response.CredentialID) && bytes.Equal(proof.UserHandle, response.UserHandle) &&
		(!proof.BackedUp || proof.BackupEligible)
}

func validClaimed(value ClaimedCeremony, expectedClaimedAt, now time.Time, limits Limits) bool {
	credentials, credentialsOK := normalizeCredentialIDs(
		value.AllowedCredentialIDs,
		limits,
		value.Binding.Purpose == PurposeRegistration || value.Mode == AuthenticationDiscoverable,
	)
	if !credentialsOK || !slices.EqualFunc(credentials, value.AllowedCredentialIDs, bytes.Equal) ||
		value.ChallengeDigest == ([sha256.Size]byte{}) || value.BrowserDigest == ([sha256.Size]byte{}) {
		return false
	}
	if value.Binding.Purpose == PurposeRegistration || value.Mode == AuthenticationKnownUser {
		if value.UserHandleDigest == ([sha256.Size]byte{}) {
			return false
		}
	} else if value.UserHandleDigest != ([sha256.Size]byte{}) {
		return false
	}
	return value.ID != (CeremonyID{}) && value.State == CeremonyClaimed && value.Version >= 2 &&
		validVersionAsInt64(value.Version) &&
		validInstant(value.CreatedAt) && validDeadline(value.ExpiresAt) && validInstant(value.ClaimedAt) &&
		value.ExpiresAt.After(value.CreatedAt) && value.ClaimedAt.Equal(expectedClaimedAt) &&
		!value.ClaimedAt.Before(value.CreatedAt) && !value.ClaimedAt.After(now) && now.Before(value.ExpiresAt) &&
		validRP(value.RP) && validBinding(now, value.Binding, value.Mode) &&
		validPolicy(value.Policy, value.Binding.Purpose, value.Binding.Requirement)
}

func sameRegisteredCredential(expected, actual Credential) bool {
	return actual.Version == expected.Version && actual.SecurityRevision == expected.SecurityRevision &&
		actual.SecurityRevision == 1 && actual.Status == CredentialActive &&
		bytes.Equal(expected.ID, actual.ID) && bytes.Equal(expected.PublicKey, actual.PublicKey) &&
		expected.TenantID == actual.TenantID && expected.UserID == actual.UserID &&
		expected.IdentityEpoch == actual.IdentityEpoch &&
		expected.UserHandleDigest == actual.UserHandleDigest && expected.RPID == actual.RPID &&
		expected.RPRevision == actual.RPRevision && expected.SignCount == actual.SignCount &&
		expected.Discoverable == actual.Discoverable && expected.UserVerification == actual.UserVerification &&
		expected.BackupEligible == actual.BackupEligible && expected.BackedUp == actual.BackedUp &&
		slices.Equal(expected.Transports, actual.Transports)
}

func cloneCredential(value Credential) Credential {
	value.ID = append([]byte(nil), value.ID...)
	value.PublicKey = append([]byte(nil), value.PublicKey...)
	value.Transports = append([]CredentialTransport(nil), value.Transports...)
	return value
}

func cloneRegistrationCompletion(value RegistrationCompletion) RegistrationCompletion {
	value.Binding = cloneBinding(value.Binding)
	value.Credential = cloneCredential(value.Credential)
	return value
}

func cloneAuthenticationCompletion(value AuthenticationCompletion) AuthenticationCompletion {
	value.Binding = cloneBinding(value.Binding)
	value.CredentialID = append([]byte(nil), value.CredentialID...)
	return value
}

func (kernel *Kernel) operationContext(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	if kernel == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, false
	}
	bounded, cancel := context.WithTimeout(ctx, kernel.operationTimeout)
	return bounded, cancel, true
}

func (kernel *Kernel) safeNow() time.Time {
	if kernel == nil || kernel.now == nil {
		return time.Time{}
	}
	return kernel.now().UTC().Truncate(time.Microsecond)
}

func (kernel *Kernel) randomArtifacts() ([]byte, []byte, []byte, bool) {
	id := make([]byte, artifactEntropyBytes)
	challenge := make([]byte, artifactEntropyBytes)
	browserRaw := make([]byte, artifactEntropyBytes)
	if _, err := io.ReadFull(kernel.random, id); err != nil {
		clear(id)
		clear(challenge)
		clear(browserRaw)
		return nil, nil, nil, false
	}
	if _, err := io.ReadFull(kernel.random, challenge); err != nil {
		clear(id)
		clear(challenge)
		clear(browserRaw)
		return nil, nil, nil, false
	}
	if _, err := io.ReadFull(kernel.random, browserRaw); err != nil {
		clear(id)
		clear(challenge)
		clear(browserRaw)
		return nil, nil, nil, false
	}
	if allZeroBytes(id) || allZeroBytes(challenge) || allZeroBytes(browserRaw) {
		clear(id)
		clear(challenge)
		clear(browserRaw)
		return nil, nil, nil, false
	}
	browser := make([]byte, base64.RawURLEncoding.EncodedLen(len(browserRaw)))
	base64.RawURLEncoding.Encode(browser, browserRaw)
	clear(browserRaw)
	return id, challenge, browser, true
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
