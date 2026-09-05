package platformsamladapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	testSAMLProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	testSAMLAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	testXMLSignatureNamespace  = "http://www.w3.org/2000/09/xmldsig#"
	testSAMLSuccessStatus      = "urn:oasis:names:tc:SAML:2.0:status:Success"
	testSAMLBearerConfirmation = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	testDigestSHA256           = "http://www.w3.org/2001/04/xmlenc#sha256"
	testExclusiveC14N          = "http://www.w3.org/2001/10/xml-exc-c14n#"
	testEnvelopedTransform     = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

func testInstant() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func testEntity(seed byte) identity.EntityID {
	var value identity.EntityID
	value[6] = 0x70
	value[8] = 0x80
	value[15] = seed
	if seed == 0 {
		value[14] = 1
	}
	return value
}

func testDigest(seed byte) [sha256.Size]byte {
	var value [sha256.Size]byte
	value[0] = seed
	value[sha256.Size-1] = seed ^ 0xff
	return value
}

func testBegin(seed byte) federatedsaml.AuthenticationBegin {
	return federatedsaml.AuthenticationBegin{
		OperationRunID: testEntity(seed),
		ReceiptDigest:  federatedsaml.StartReceiptDigest(testDigest(seed)),
		NetworkDigest:  federatedsaml.NetworkThrottleDigest(testDigest(seed + 1)),
		AccountDigest:  federatedsaml.AccountThrottleDigest(testDigest(seed + 2)),
		ProviderDigest: federatedsaml.ProviderThrottleDigest(testDigest(seed + 3)),
	}
}

func testAudit(seed byte) platformsamlauth.AuditContext {
	return platformsamlauth.AuditContext{
		RequestID: testEntity(seed), CorrelationID: testEntity(seed + 1),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "direct-saml-adapter-test",
	}
}

var sharedCertificate = struct {
	sync.Once
	key *rsa.PrivateKey
	der []byte
	err error
}{}

func testRSAKeyAndCertificate(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	sharedCertificate.Do(func() {
		sharedCertificate.key, sharedCertificate.err = rsa.GenerateKey(rand.Reader, 2048)
		if sharedCertificate.err != nil {
			return
		}
		now := time.Now().UTC()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "platform-saml-test"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		sharedCertificate.der, sharedCertificate.err = x509.CreateCertificate(
			rand.Reader, template, template, &sharedCertificate.key.PublicKey, sharedCertificate.key,
		)
	})
	if sharedCertificate.err != nil {
		t.Fatalf("generate test certificate: %v", sharedCertificate.err)
	}
	return sharedCertificate.key, append([]byte(nil), sharedCertificate.der...)
}

func testMetadataSnapshot(t *testing.T, now time.Time) federatedsaml.MetadataSnapshot {
	t.Helper()
	_, certificate := testRSAKeyAndCertificate(t)
	entityID := "https://idp.example.test/entity"
	document := []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="%s" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="%s" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		testXMLSignatureNamespace, entityID, now.Add(24*time.Hour).Format(time.RFC3339),
		"urn:oasis:names:tc:SAML:2.0:protocol", base64.StdEncoding.EncodeToString(certificate),
	))
	snapshot, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document, ExpectedEntityID: entityID, Revision: 9,
		RetrievedAt: now, MaximumValidUntil: now.Add(48 * time.Hour),
	}, federatedsaml.DefaultLimits())
	clear(document)
	if err != nil {
		t.Fatalf("CompileMetadata() error = %v", err)
	}
	return snapshot
}

func testDirectConfiguration(t *testing.T, encryption federatedsaml.EncryptionPolicy, decryption []uint64) federatedsaml.Configuration {
	t.Helper()
	now := testInstant()
	return federatedsaml.Configuration{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority,
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: testEntity(10),
		},
		ProviderRevision: 2, PlatformLoginRevision: 3, ConfigurationRevision: 4,
		SecurityRevision: 5, PlanRevision: 6, AssurancePolicyRevision: 7,
		SPEntityID: "https://sp.example.test" + DirectSAMLMetadataPathPrefix + "primary" + DirectSAMLMetadataPathSuffix,
		ACSURL:     "https://sp.example.test" + platformsamlauth.DirectSAMLACSURL,
		Metadata:   testMetadataSnapshot(t, now), SPKeyRevision: 8,
		RedirectSignatureAlgorithm:           federatedsaml.RedirectRSASHA256,
		SignaturePolicy:                      federatedsaml.SignedBoth,
		EncryptionPolicy:                     encryption,
		DirectPlatformDecryptionKeyRevisions: append([]uint64(nil), decryption...),
		RequestedAuthnContexts:               []string{"urn:test:mfa"},
		Subject:                              federatedsaml.SubjectPolicy{Source: federatedsaml.SubjectPersistentNameID},
		TrustRules: []federatedsaml.AuthnContextTrustRule{{
			ClassRef: "urn:test:mfa", Level: identity.AssuranceMFA, Revision: 11, MaxAge: time.Hour,
		}},
		ClockSkew: time.Minute, MaxAuthenticationAge: 8 * time.Hour,
	}
}

type pinCaptureRepository struct {
	create federatedsaml.CreateTransactionRequest
}

func (repository *pinCaptureRepository) CreateReplacing(_ context.Context, request federatedsaml.CreateTransactionRequest) error {
	repository.create = request
	return nil
}
func (*pinCaptureRepository) Lookup(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error) {
	return federatedsaml.PendingTransaction{}, errors.New("unused")
}

type testRedirectSigner struct{}

func (testRedirectSigner) SignRedirect(_ context.Context, request federatedsaml.RedirectSignRequest) ([]byte, error) {
	if request.Authority != federatedsaml.DirectPlatformCeremonyAuthority || request.BindingID != (identity.EntityID{}) {
		return nil, errors.New("wrong authority")
	}
	return []byte("test-signature"), nil
}

type testSignatureVerifier struct{}

func (testSignatureVerifier) VerifyXMLSignature(
	_ context.Context,
	request federatedsaml.SignatureVerificationRequest,
) (federatedsaml.SignatureVerificationResult, error) {
	certificates := request.Metadata.Certificates()
	if len(certificates) != 1 {
		return federatedsaml.SignatureVerificationResult{}, errors.New("missing certificate")
	}
	return federatedsaml.SignatureVerificationResult{
		Authority: request.Authority, Provider: request.Provider, BindingID: request.BindingID,
		PlatformLoginRevision: request.PlatformLoginRevision, ObjectKind: request.ObjectKind,
		ObjectID: request.ObjectID, ReferenceURI: "#" + request.ObjectID,
		CertificateFingerprintSHA256: certificates[0].FingerprintSHA256,
		SignatureAlgorithm:           string(federatedsaml.RedirectRSASHA256),
		DigestAlgorithm:              testDigestSHA256,
		CanonicalizationAlgorithm:    testExclusiveC14N,
		Transforms:                   []string{testEnvelopedTransform, testExclusiveC14N},
		DocumentDigest:               sha256.Sum256(request.Document),
		ReferenceCount:               1, KeyInfoCertificateCount: 1, MatchingCertificateCount: 1,
	}, nil
}

type testAssertionDecrypter struct{}

func (testAssertionDecrypter) DecryptAssertion(context.Context, federatedsaml.DecryptionRequest) (federatedsaml.DecryptionResult, error) {
	return federatedsaml.DecryptionResult{}, errors.New("unexpected encrypted assertion")
}

type testSessionProtector struct{}

func (testSessionProtector) OpenSAMLSession(context.Context, federatedsaml.SessionMaterialContext, federatedsaml.ProtectedSessionMaterial) (federatedsaml.SessionMaterial, error) {
	return federatedsaml.SessionMaterial{}, errors.New("unused")
}

func testProtocolPins(t *testing.T, configuration federatedsaml.Configuration) federatedsaml.TransactionPins {
	t.Helper()
	repository := &pinCaptureRepository{}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority, Transactions: repository,
		RedirectSigner: testRedirectSigner{}, SignatureVerifier: testSignatureVerifier{},
		AssertionDecrypter: testAssertionDecrypter{}, SessionProtector: testSessionProtector{},
		Limits: federatedsaml.DefaultLimits(), TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("federatedsaml.New() error = %v", err)
	}
	started, err := kernel.StartAuthentication(context.Background(), federatedsaml.StartRequest{
		Begin: testBegin(31), Configuration: configuration, ReturnPath: "/incidents?view=mine",
	})
	handle := started.BrowserHandle()
	clear(handle)
	if err != nil {
		t.Fatalf("derive transaction pins: %v", err)
	}
	return repository.create.Current.Pins
}

func testDirectPins(t *testing.T, configuration federatedsaml.Configuration) platformsamlauth.DirectSAMLPins {
	t.Helper()
	return platformsamlauth.DirectSAMLPins{
		Protocol: testProtocolPins(t, configuration), PlatformFloorPolicyID: testEntity(20),
		PlatformFloorPolicyRevision: 21,
	}
}

type fakeTransactionPersistence struct {
	guard sync.Mutex

	createCalls  int
	recoverCalls int
	lookupCalls  int
	abortCalls   int

	createRequest DirectSAMLCreateTransactionRequest
	snapshot      DirectSAMLTransactionSnapshot

	createErr            error
	cancelOnCreate       context.CancelFunc
	recoverErr           error
	recoverBlock         bool
	recoverContextErr    error
	lookupErr            error
	lookupMutateAt       int
	abortFirstWait       bool
	abortReceiptMutation func(*DirectSAMLAbortReceipt)
}

func (persistence *fakeTransactionPersistence) CreateDirectPlatformSAMLTransaction(
	_ context.Context,
	request DirectSAMLCreateTransactionRequest,
) (DirectSAMLCreateReceipt, error) {
	persistence.guard.Lock()
	defer persistence.guard.Unlock()
	persistence.createCalls++
	persistence.createRequest = request
	persistence.snapshot = DirectSAMLTransactionSnapshot{Pending: request.Protocol.Current, Pins: request.Grant.Pins}
	if persistence.cancelOnCreate != nil {
		persistence.cancelOnCreate()
	}
	receipt := DirectSAMLCreateReceipt{
		TransactionID: request.Protocol.Current.ID, OperationRunID: request.Protocol.Begin.OperationRunID,
		Version: request.Protocol.Current.Version, State: request.Protocol.Current.State, Pins: request.Grant.Pins,
	}
	return receipt, persistence.createErr
}

func (persistence *fakeTransactionPersistence) RecoverDirectPlatformSAMLCreate(
	ctx context.Context,
	lookup DirectSAMLCreateRecoveryLookup,
) (DirectSAMLCreateReceipt, error) {
	persistence.guard.Lock()
	persistence.recoverCalls++
	persistence.recoverContextErr = ctx.Err()
	block := persistence.recoverBlock
	err := persistence.recoverErr
	request := persistence.createRequest
	persistence.guard.Unlock()
	if block {
		<-ctx.Done()
		return DirectSAMLCreateReceipt{}, ctx.Err()
	}
	if err != nil || !reflect.DeepEqual(lookup.Create, request) {
		if err == nil {
			err = errors.New("recovery proof mismatch")
		}
		return DirectSAMLCreateReceipt{}, err
	}
	return DirectSAMLCreateReceipt{
		TransactionID: request.Protocol.Current.ID, OperationRunID: request.Protocol.Begin.OperationRunID,
		Version: request.Protocol.Current.Version, State: request.Protocol.Current.State, Pins: request.Grant.Pins,
	}, nil
}

func (persistence *fakeTransactionPersistence) LookupDirectPlatformSAMLTransaction(
	_ context.Context,
	_ federatedsaml.LookupTransactionRequest,
) (DirectSAMLTransactionSnapshot, error) {
	persistence.guard.Lock()
	defer persistence.guard.Unlock()
	persistence.lookupCalls++
	if persistence.lookupErr != nil {
		return DirectSAMLTransactionSnapshot{}, persistence.lookupErr
	}
	snapshot := persistence.snapshot
	if persistence.lookupMutateAt == persistence.lookupCalls {
		snapshot.Pins.Protocol.SecurityRevision++
	}
	return snapshot, nil
}

func (persistence *fakeTransactionPersistence) AbortDirectPlatformSAMLTransaction(
	ctx context.Context,
	request DirectSAMLAbortRequest,
) (DirectSAMLAbortReceipt, error) {
	persistence.guard.Lock()
	persistence.abortCalls++
	call := persistence.abortCalls
	wait := persistence.abortFirstWait && call == 1
	mutate := persistence.abortReceiptMutation
	persistence.guard.Unlock()
	if wait {
		<-ctx.Done()
		return DirectSAMLAbortReceipt{}, ctx.Err()
	}
	receipt := DirectSAMLAbortReceipt{
		Disposition: AbortTerminalized, TransactionID: request.Transaction.TransactionID,
		OperationRunID: request.OperationRunID, Version: request.Transaction.ExpectedVersion + 1,
		State: federatedsaml.TransactionFailed, Pins: request.Pins,
	}
	if mutate != nil {
		mutate(&receipt)
	}
	return receipt, nil
}

func (persistence *fakeTransactionPersistence) counts() (int, int, int, int) {
	persistence.guard.Lock()
	defer persistence.guard.Unlock()
	return persistence.createCalls, persistence.recoverCalls, persistence.lookupCalls, persistence.abortCalls
}

type protocolFixture struct {
	adapter       *ProtocolAdapter
	persistence   *fakeTransactionPersistence
	configuration federatedsaml.Configuration
	pins          platformsamlauth.DirectSAMLPins
	request       platformsamlauth.StartProtocolRequest
}

func newProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	configuration := testDirectConfiguration(t, federatedsaml.EncryptionDisabled, nil)
	pins := testDirectPins(t, configuration)
	persistence := &fakeTransactionPersistence{}
	authority := platformsamlauth.StartAuthority{
		Lookup:     platformsamlauth.StartLookup{Begin: testBegin(40), LoginKey: "primary"},
		ReturnPath: "/incidents?view=mine", Audit: testAudit(50),
	}
	request := platformsamlauth.StartProtocolRequest{
		Protocol: federatedsaml.StartRequest{
			Begin: authority.Lookup.Begin, Configuration: configuration, ReturnPath: authority.ReturnPath,
		},
		Grant: platformsamlauth.StartGrant{Authority: authority, Pins: pins},
	}
	adapter, err := newProtocolAdapter(ProtocolAdapterOptions{
		Persistence: persistence, SessionProtector: testSessionProtector{},
		Limits: federatedsaml.DefaultLimits(), TransactionTTL: 5 * time.Minute,
		OperationTimeout: time.Second, RecoveryTimeout: 20 * time.Millisecond,
		AbortTimeout: 20 * time.Millisecond, Now: testInstant,
	}, protocolCrypto{signer: testRedirectSigner{}, verifier: testSignatureVerifier{}, decrypter: testAssertionDecrypter{}})
	if err != nil {
		t.Fatalf("newProtocolAdapter() error = %v", err)
	}
	return protocolFixture{adapter: adapter, persistence: persistence, configuration: configuration, pins: pins, request: request}
}

func (fixture protocolFixture) start(t *testing.T, ctx context.Context) platformsamlauth.AuthorizationStart {
	t.Helper()
	started, err := fixture.adapter.StartDirectSAML(ctx, fixture.request)
	if err != nil {
		t.Fatalf("StartDirectSAML() error = %v", err)
	}
	return started
}

func testCallbackRequest(t *testing.T, fixture protocolFixture, started platformsamlauth.AuthorizationStart) platformsamlauth.CallbackRequest {
	t.Helper()
	fixture.persistence.guard.Lock()
	pending := fixture.persistence.snapshot.Pending
	fixture.persistence.guard.Unlock()
	parsed, err := url.Parse(started.RedirectURL())
	if err != nil {
		t.Fatalf("parse start redirect: %v", err)
	}
	relay := parsed.Query().Get("RelayState")
	assertion := fmt.Sprintf(
		`<saml:Assertion xmlns:saml="%s" xmlns:ds="%s" ID="_assertion" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature/><saml:Subject><saml:NameID Format="%s">secret-subject</saml:NameID><saml:SubjectConfirmation Method="%s"><saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="%s" SessionIndex="secret-session-index" SessionNotOnOrAfter="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:test:mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`,
		testSAMLAssertionNamespace, testXMLSignatureNamespace, pending.CreatedAt.Format(time.RFC3339Nano),
		fixture.configuration.Metadata.EntityID(), federatedsaml.PersistentNameIDFormat, testSAMLBearerConfirmation,
		fixture.configuration.ACSURL, pending.RequestID, pending.CreatedAt.Add(5*time.Minute).Format(time.RFC3339Nano),
		pending.CreatedAt.Add(-time.Minute).Format(time.RFC3339Nano), pending.CreatedAt.Add(10*time.Minute).Format(time.RFC3339Nano),
		fixture.configuration.SPEntityID, pending.CreatedAt.Add(-time.Minute).Format(time.RFC3339Nano),
		pending.CreatedAt.Add(8*time.Minute).Format(time.RFC3339Nano),
	)
	response := fmt.Sprintf(
		`<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" xmlns:ds="%s" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature/><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>`,
		testSAMLProtocolNamespace, testSAMLAssertionNamespace, testXMLSignatureNamespace,
		pending.CreatedAt.Format(time.RFC3339Nano), fixture.configuration.ACSURL, pending.RequestID,
		fixture.configuration.Metadata.EntityID(), testSAMLSuccessStatus, assertion,
	)
	form := url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(response))},
		"RelayState":   {relay},
	}
	return platformsamlauth.CallbackRequest{
		Protocol: federatedsaml.ResolvedCallbackRequest{
			MediaType: "application/x-www-form-urlencoded; charset=UTF-8",
			RawForm:   []byte(form.Encode()), BrowserHandle: started.BrowserHandle(),
		},
		Audit: testAudit(60),
	}
}

type testConfigurationResolver struct {
	configuration federatedsaml.Configuration
	calls         atomic.Int32
}

func (resolver *testConfigurationResolver) ResolveSAMLCallbackConfiguration(
	_ context.Context,
	_ federatedsaml.CallbackConfigurationLookup,
) (federatedsaml.Configuration, error) {
	resolver.calls.Add(1)
	return cloneConfiguration(resolver.configuration), nil
}

type testApplicationConsumer struct {
	calls atomic.Int32
}

func (consumer *testApplicationConsumer) ConsumeDirectSAML(
	_ context.Context,
	_ platformsamlauth.Consumption,
) (federatedsaml.ConsumptionResult, error) {
	consumer.calls.Add(1)
	return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerSuccess}, nil
}
