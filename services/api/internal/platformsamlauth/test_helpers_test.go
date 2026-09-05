package platformsamlauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type transactionRepository struct {
	request federatedsaml.CreateTransactionRequest
}

func (repository *transactionRepository) CreateReplacing(
	_ context.Context,
	request federatedsaml.CreateTransactionRequest,
) error {
	repository.request = request
	return nil
}

func (repository *transactionRepository) Lookup(
	context.Context,
	federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	return repository.request.Current, nil
}

type redirectSigner struct{}

func (redirectSigner) SignRedirect(context.Context, federatedsaml.RedirectSignRequest) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

type signatureVerifier struct{}

func (signatureVerifier) VerifyXMLSignature(
	context.Context,
	federatedsaml.SignatureVerificationRequest,
) (federatedsaml.SignatureVerificationResult, error) {
	return federatedsaml.SignatureVerificationResult{}, errors.New("unused")
}

type assertionDecrypter struct{}

func (assertionDecrypter) DecryptAssertion(
	context.Context,
	federatedsaml.DecryptionRequest,
) (federatedsaml.DecryptionResult, error) {
	return federatedsaml.DecryptionResult{}, errors.New("unused")
}

type sessionProtector struct{}

func (sessionProtector) OpenSAMLSession(
	context.Context,
	federatedsaml.SessionMaterialContext,
	federatedsaml.ProtectedSessionMaterial,
) (federatedsaml.SessionMaterial, error) {
	return federatedsaml.SessionMaterial{}, errors.New("unused")
}

type startSourceFunc func(context.Context, StartAuthority) (StartGrant, error)

func (function startSourceFunc) BeginDirectSAMLLogin(ctx context.Context, authority StartAuthority) (StartGrant, error) {
	return function(ctx, authority)
}

type planningSourceFunc func(context.Context, PlanningLookup) (PlanningState, error)

func (function planningSourceFunc) LoadDirectSAMLPlanningState(ctx context.Context, lookup PlanningLookup) (PlanningState, error) {
	return function(ctx, lookup)
}

type credentialIssuerFunc func(CredentialRequest) (*CredentialReservation, error)

func (function credentialIssuerFunc) ReserveDirectSAMLCredential(request CredentialRequest) (*CredentialReservation, error) {
	return function(request)
}

type fakeConfigurations struct {
	start       StartConfigurationSnapshot
	callback    CallbackConfigurationSnapshot
	startErr    error
	callbackErr error
}

func (source *fakeConfigurations) LoadDirectSAMLStartConfiguration(
	context.Context,
	StartGrant,
) (StartConfigurationSnapshot, error) {
	return source.start, source.startErr
}

func (source *fakeConfigurations) ResolveDirectSAMLCallbackConfiguration(
	_ context.Context,
	lookup CallbackConfigurationLookup,
) (CallbackConfigurationSnapshot, error) {
	result := source.callback
	result.Lookup = lookup
	return result, source.callbackErr
}

type fakeProtocol struct {
	guard              sync.Mutex
	start              AuthorizationStart
	validated          *ValidatedCallback
	consumption        Consumption
	startRequest       StartProtocolRequest
	validateCalls      int
	consumeCalls       int
	abortCalls         int
	startErr           error
	validateErr        error
	consumeErr         error
	afterConsumeErr    error
	consumeTwice       bool
	resolveTwice       bool
	nilConsumerContext bool
	capturedCredential *BrowserCredential
}

func (protocol *fakeProtocol) StartDirectSAML(
	_ context.Context,
	request StartProtocolRequest,
) (AuthorizationStart, error) {
	protocol.guard.Lock()
	defer protocol.guard.Unlock()
	protocol.startRequest = request
	return cloneAuthorizationStart(protocol.start), protocol.startErr
}

func (protocol *fakeProtocol) ValidateDirectSAMLCallbackResolved(
	ctx context.Context,
	_ CallbackRequest,
	resolver federatedsaml.CallbackConfigurationResolver,
) (*ValidatedCallback, error) {
	protocol.guard.Lock()
	protocol.validateCalls++
	consumption := cloneConsumption(protocol.consumption)
	validated, wantedErr := protocol.validated, protocol.validateErr
	protocol.guard.Unlock()
	if wantedErr != nil {
		return validated, wantedErr
	}
	lookup := federatedsaml.CallbackConfigurationLookup{
		TransactionID: consumption.TransactionID, ExpectedVersion: consumption.ExpectedVersion, Pins: consumption.Pins,
	}
	_, err := resolver.ResolveSAMLCallbackConfiguration(ctx, lookup)
	if err != nil {
		return nil, err
	}
	protocol.guard.Lock()
	resolveTwice := protocol.resolveTwice
	protocol.guard.Unlock()
	if resolveTwice {
		_, _ = resolver.ResolveSAMLCallbackConfiguration(ctx, lookup)
	}
	return validated, nil
}

func (protocol *fakeProtocol) ConsumeDirectSAML(
	ctx context.Context,
	_ *ValidatedCallback,
	consumer Consumer,
) (federatedsaml.ConsumptionResult, error) {
	protocol.guard.Lock()
	protocol.consumeCalls++
	consumption := cloneConsumption(protocol.consumption)
	wantedErr := protocol.consumeErr
	protocol.guard.Unlock()
	if wantedErr != nil {
		return federatedsaml.ConsumptionResult{}, wantedErr
	}
	consumerContext := ctx
	protocol.guard.Lock()
	if protocol.nilConsumerContext {
		consumerContext = nil
	}
	protocol.guard.Unlock()
	result, err := consumer.ConsumeDirectSAML(consumerContext, consumption)
	if concrete, ok := consumer.(*applicationConsumer); ok {
		concrete.guard.Lock()
		protocol.guard.Lock()
		protocol.capturedCredential = concrete.outcome.Credential
		consumeTwice := protocol.consumeTwice
		afterErr := protocol.afterConsumeErr
		protocol.guard.Unlock()
		concrete.guard.Unlock()
		if consumeTwice {
			_, _ = consumer.ConsumeDirectSAML(ctx, consumption)
			return result, err
		}
		if afterErr != nil {
			return result, afterErr
		}
	}
	return result, err
}

func (protocol *fakeProtocol) AbortDirectSAMLCallback(
	context.Context,
	*ValidatedCallback,
	AuditContext,
) error {
	protocol.guard.Lock()
	defer protocol.guard.Unlock()
	protocol.abortCalls++
	return nil
}

type fakeApply struct {
	guard          sync.Mutex
	request        ApplyRequest
	applyCalls     int
	recoveryCalls  int
	rejectCalls    int
	cleanupCalls   int
	active         bool
	applyCategory  ApplyCategory
	applyErr       error
	recovery       RecoveryResult
	recoveryErr    error
	rejectReason   RejectReason
	cleanupReason  CleanupReason
	cleanupErr     error
	resultMutate   func(*ApplyResult)
	recoveryCtxErr error
	onApply        func()
	onRecover      func(context.Context)
}

func (store *fakeApply) ApplyDirectSAML(_ context.Context, request ApplyRequest) (ApplyResult, error) {
	store.guard.Lock()
	store.applyCalls++
	store.request = cloneApplyRequest(request)
	onApply := store.onApply
	applyErr := store.applyErr
	category := store.applyCategory
	store.guard.Unlock()
	if onApply != nil {
		onApply()
	}
	if applyErr != nil {
		return ApplyResult{}, applyErr
	}
	if category == "" {
		category = ApplySuccess
	}
	result := applyResultForRequest(request, category)
	store.guard.Lock()
	if category == ApplySuccess || category == ApplyAlreadyApplied {
		store.active = true
	}
	resultMutate := store.resultMutate
	store.guard.Unlock()
	if resultMutate != nil {
		resultMutate(&result)
	}
	return result, nil
}

func (store *fakeApply) RecoverDirectSAML(ctx context.Context, lookup RecoveryLookup) (RecoveryResult, error) {
	store.guard.Lock()
	store.recoveryCalls++
	store.recoveryCtxErr = ctx.Err()
	onRecover := store.onRecover
	recoveryErr := store.recoveryErr
	recovery := store.recovery
	store.guard.Unlock()
	if onRecover != nil {
		onRecover(ctx)
	}
	if recoveryErr != nil {
		return RecoveryResult{}, recoveryErr
	}
	if recovery.Matched && recovery.Result == (ApplyResult{}) {
		return RecoveryResult{Matched: true, Result: applyResultForRequest(lookup.Request, ApplyAlreadyApplied)}, nil
	}
	return recovery, nil
}

func (store *fakeApply) RejectDirectSAML(_ context.Context, request RejectRequest) error {
	store.guard.Lock()
	defer store.guard.Unlock()
	store.rejectCalls++
	store.rejectReason = request.Reason
	return nil
}

func (store *fakeApply) CleanupDirectSAML(_ context.Context, request CleanupRequest) error {
	store.guard.Lock()
	defer store.guard.Unlock()
	store.cleanupCalls++
	store.cleanupReason = request.Reason
	if store.cleanupErr == nil && validCleanupRequest(request) {
		store.active = false
	}
	return store.cleanupErr
}

type testHarness struct {
	now            time.Time
	configuration  federatedsaml.Configuration
	pins           DirectSAMLPins
	start          AuthorizationStart
	proof          AuthenticationProof
	consumption    Consumption
	protocol       *fakeProtocol
	configurations *fakeConfigurations
	planning       *mutablePlanningSource
	apply          *fakeApply
	application    *Application
	request        CompleteRequest
	audit          AuditContext
	keyring        identity.Keyring
}

type mutablePlanningSource struct {
	guard  sync.Mutex
	mutate func(*PlanningState, PlanningLookup)
	state  PlanningState
}

func (source *mutablePlanningSource) LoadDirectSAMLPlanningState(
	_ context.Context,
	lookup PlanningLookup,
) (PlanningState, error) {
	source.guard.Lock()
	defer source.guard.Unlock()
	state := clonePlanningState(source.state)
	state.Matches[0].Alias = lookup.SubjectAliases[0]
	if source.mutate != nil {
		source.mutate(&state, lookup)
	}
	return state, nil
}

func newTestHarness(t *testing.T, floorLevel identity.AssuranceLevel, localRequired bool) testHarness {
	t.Helper()
	configuration, protocolPins, start, now := directTestConfigurationAndPins(t)
	floorID := testID(30)
	pins := DirectSAMLPins{
		Protocol: protocolPins, PlatformFloorPolicyID: floorID, PlatformFloorPolicyRevision: 31,
	}
	proof := AuthenticationProof{
		Issuer: configuration.Metadata.EntityID(), SubjectSource: federatedsaml.SubjectPersistentNameID,
		SubjectName: "NameID", SubjectFormat: federatedsaml.PersistentNameIDFormat,
		SubjectValue: "subject-secret-value", AuthnContext: "urn:test:mfa",
		AuthenticatedAt: now.Add(-5 * time.Minute), ValidUntil: now.Add(time.Hour),
		SessionMaterial: federatedsaml.SessionMaterial{
			NameID: "logout-secret-value", NameIDFormat: federatedsaml.PersistentNameIDFormat,
			SessionIndex: "logout-session-secret",
		},
	}
	var sessionDigest [sha256.Size]byte
	sessionDigest[0] = 1
	consumption := Consumption{
		TransactionID: protocolPinsToTransactionID(protocolPins), MaterialID: testID(40), ExpectedVersion: 1,
		Pins: protocolPins, ResponseID: "_response", AssertionID: "_assertion",
		SessionIndexDigest: sessionDigest, HasSessionIndex: true, ConsumedAt: now,
		ReturnPath: "/incidents?view=mine", Authentication: proof,
	}
	validated := &ValidatedCallback{
		kernel: &federatedsaml.ValidatedAuthentication{},
		transaction: CallbackConfigurationLookup{Transaction: federatedsaml.CallbackConfigurationLookup{
			TransactionID: consumption.TransactionID, ExpectedVersion: consumption.ExpectedVersion, Pins: consumption.Pins,
		}},
		proof: cloneProof(proof),
	}
	protocol := &fakeProtocol{start: start, validated: validated, consumption: consumption}
	snapshot := ConfigurationSnapshot{Pins: pins, ProviderKind: ProviderKindSAML, Authentication: configuration}
	configurations := &fakeConfigurations{
		callback: CallbackConfigurationSnapshot{Configuration: snapshot},
	}
	confirmedAt := now.Add(-24 * time.Hour)
	planning := &mutablePlanningSource{state: PlanningState{
		Pins: pins, ProviderKind: ProviderKindSAML, ProviderEnabled: true, PlatformLoginLive: true,
		ConfigurationLive: true, AssurancePolicyLive: true,
		Matches: []IdentityMatch{{
			ProviderID: protocolPins.Provider.ProviderID, ExternalIdentityID: testID(41), UserID: testID(42),
			IdentityRevision: 43, UserAuthenticationRevision: 44,
			PlatformAuthorityID: testID(45), PlatformAuthorityRevision: 46,
			IdentityLive: true, AliasLive: true, UserActive: true, ProtectedPlatformAuthorityLive: true,
		}},
		TrustRules: []TrustRule{{
			RuleID: testID(47), Revision: 12, Enabled: true, ClassRef: "urn:test:mfa",
			Level: identity.AssuranceMFA, MaximumAuthenticationAge: time.Hour,
		}},
		PlatformFloor: identity.EffectiveAssuranceRequirement{
			Level: floorLevel, LocalRequired: localRequired,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: floorID, Revision: 31}},
		},
		LiveConfirmedTOTPFactors: []TOTPFactor{{
			FactorID: testID(48), UserID: testID(42), Revision: 49, Active: true, ConfirmedAt: &confirmedAt,
		}},
	}}
	keyring := testKeyring(t)
	planner, err := NewPlanner(PlannerOptions{Source: planning, Keyring: keyring})
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	apply := &fakeApply{}
	issuer := credentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		if request.Disposition == ImmediateSession {
			token := opaqueCredential(50)
			csrf := opaqueCredential(51)
			issuedAt := request.IssuedAt.Truncate(time.Millisecond)
			reservation, reservationErr := mfa.NewSessionReservation(mfa.SessionMaterial{
				SessionID: testID(52), FamilyID: testID(53), TokenDigest: sha256.Sum256(token),
				CSRFDigest: sha256.Sum256(csrf), AuthenticationMethod: mfa.SessionAuthenticationSAML,
				IdleExpiresAt: issuedAt.Add(30 * time.Minute), AbsoluteExpiresAt: issuedAt.Add(8 * time.Hour),
			}, issuedAt)
			if reservationErr != nil {
				return nil, reservationErr
			}
			return NewSessionCredentialReservation(reservation, token, csrf)
		}
		receipt := opaqueCredential(54)
		continuationID := testID(55)
		digest, digestErr := ContinuationReceiptDigest(continuationID, receipt)
		if digestErr != nil {
			return nil, digestErr
		}
		reservation, reservationErr := NewContinuationReservation(ContinuationMaterial{
			ContinuationID: continuationID, FactorID: request.TOTP.FactorID,
			FactorRevision: request.TOTP.Revision, ReceiptDigest: digest,
			ExpiresAt: request.IssuedAt.Add(5 * time.Minute),
		}, request.IssuedAt)
		if reservationErr != nil {
			return nil, reservationErr
		}
		return NewContinuationCredentialReservation(reservation, receipt)
	})
	application, err := NewApplication(ApplicationOptions{
		Protocol: protocol, Starts: startSourceFunc(func(_ context.Context, authority StartAuthority) (StartGrant, error) {
			return StartGrant{Authority: authority, Pins: pins}, nil
		}),
		Configurations: configurations, Planner: planner, Credentials: issuer, Apply: apply,
		Keyring: keyring, Now: func() time.Time { return now }, OperationTimeout: time.Second,
		RecoveryTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewApplication() error = %v", err)
	}
	if !validDirectSAMLPins(pins) {
		t.Fatal("test fixture direct pins are invalid")
	}
	if !validConfigurationSnapshot(snapshot, now) {
		t.Fatal("test fixture configuration snapshot is invalid")
	}
	if !validProofForConfiguration(proof, configuration) {
		t.Fatal("test fixture proof is invalid")
	}
	if !validConsumptionForConfiguration(consumption, pins, configuration, now) {
		t.Fatal("test fixture consumption is invalid")
	}
	audit := AuditContext{
		RequestID: testID(60), CorrelationID: testID(61), RemoteAddress: netip.MustParseAddr("192.0.2.10"),
		UserAgent: "test-browser/1",
	}
	return testHarness{
		now: now, configuration: configuration, pins: pins, start: start, proof: proof,
		consumption: consumption, protocol: protocol, configurations: configurations,
		planning: planning, apply: apply, application: application, audit: audit, keyring: keyring,
		request: CompleteRequest{
			MediaType: "application/x-www-form-urlencoded", RawForm: []byte("SAMLResponse=opaque&RelayState=opaque"),
			BrowserHandle: opaqueCredential(62), Audit: audit,
		},
	}
}

func directTestConfigurationAndPins(
	t *testing.T,
) (federatedsaml.Configuration, federatedsaml.TransactionPins, AuthorizationStart, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	certificate := testCertificate(t, now)
	entityID := "https://idp.example.test/entity"
	document := []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		entityID, now.Add(24*time.Hour).Format(time.RFC3339), base64.StdEncoding.EncodeToString(certificate),
	))
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document, ExpectedEntityID: entityID, Revision: 10,
		RetrievedAt: now.Add(-time.Minute), MaximumValidUntil: now.Add(48 * time.Hour),
	}, federatedsaml.DefaultLimits())
	if err != nil {
		t.Fatalf("CompileMetadata() error = %v", err)
	}
	configuration := federatedsaml.Configuration{
		Authority:        federatedsaml.DirectPlatformCeremonyAuthority,
		Provider:         identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testID(1)},
		ProviderRevision: 2, PlatformLoginRevision: 3, ConfigurationRevision: 4,
		SecurityRevision: 5, PlanRevision: 6, AssurancePolicyRevision: 7,
		SPEntityID: "https://sp.example.test/api/v1/auth/platform/saml/provider-a/metadata",
		ACSURL:     "https://sp.example.test" + DirectSAMLACSURL, Metadata: metadata, SPKeyRevision: 8,
		RedirectSignatureAlgorithm: federatedsaml.RedirectECDSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
		RequestedAuthnContexts: []string{"urn:test:mfa"},
		Subject:                federatedsaml.SubjectPolicy{Source: federatedsaml.SubjectPersistentNameID},
		Mapping:                federatedsaml.AttributeMappingPolicy{},
		TrustRules: []federatedsaml.AuthnContextTrustRule{{
			ClassRef: "urn:test:mfa", Level: identity.AssuranceMFA, Revision: 12, MaxAge: time.Hour,
		}},
		ClockSkew: time.Minute, MaxAuthenticationAge: 8 * time.Hour,
	}
	repository := &transactionRepository{}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Authority:    federatedsaml.DirectPlatformCeremonyAuthority,
		Transactions: repository, RedirectSigner: redirectSigner{}, SignatureVerifier: signatureVerifier{},
		AssertionDecrypter: assertionDecrypter{}, SessionProtector: sessionProtector{},
		Limits: federatedsaml.DefaultLimits(), TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("federatedsaml.New() error = %v", err)
	}
	kernelStart, err := kernel.StartAuthentication(context.Background(), federatedsaml.StartRequest{
		Begin: testBegin(20), Configuration: configuration, ReturnPath: "/incidents?view=mine",
	})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	start, err := NewAuthorizationStart(kernelStart)
	if err != nil {
		t.Fatalf("NewAuthorizationStart() error = %v", err)
	}
	return configuration, repository.request.Current.Pins, start, repository.request.Current.CreatedAt.Add(time.Second)
}

func testCertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-idp"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testBegin(seed byte) federatedsaml.AuthenticationBegin {
	var receipt, network, account, provider [sha256.Size]byte
	receipt[0], network[0], account[0], provider[0] = seed, seed+1, seed+2, seed+3
	return federatedsaml.AuthenticationBegin{
		OperationRunID: testID(seed), ReceiptDigest: federatedsaml.StartReceiptDigest(receipt),
		NetworkDigest:  federatedsaml.NetworkThrottleDigest(network),
		AccountDigest:  federatedsaml.AccountThrottleDigest(account),
		ProviderDigest: federatedsaml.ProviderThrottleDigest(provider),
	}
}

func testID(seed byte) identity.EntityID {
	result := identity.EntityID{0, 0, 0, 0, 0, seed, 0x70, seed, 0x80, seed}
	result[15] = seed
	return result
}

func protocolPinsToTransactionID(pins federatedsaml.TransactionPins) federatedsaml.TransactionID {
	var result federatedsaml.TransactionID
	copy(result[:16], pins.Provider.ProviderID[:])
	copy(result[16:], pins.ConfigurationDigest[:16])
	return result
}

func opaqueCredential(seed byte) []byte {
	value := bytes.Repeat([]byte{seed}, sha256.Size)
	return []byte(base64.RawURLEncoding.EncodeToString(value))
}

func testKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}
