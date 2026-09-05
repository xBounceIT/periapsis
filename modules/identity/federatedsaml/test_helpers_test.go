package federatedsaml

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
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var fixtureTime = time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)

var testCertificateCache = struct {
	sync.Mutex
	der map[int64][]byte
}{der: make(map[int64][]byte)}

type memoryTransactions struct {
	mu         sync.Mutex
	pending    PendingTransaction
	lastCreate CreateTransactionRequest
	creates    int
	lookups    int
	createErr  error
	lookupErr  error
}

func (repository *memoryTransactions) CreateReplacing(_ context.Context, request CreateTransactionRequest) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.createErr != nil {
		return repository.createErr
	}
	repository.pending = request.Current
	repository.lastCreate = request
	repository.creates++
	return nil
}

func (repository *memoryTransactions) Lookup(_ context.Context, _ LookupTransactionRequest) (PendingTransaction, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.lookups++
	if repository.lookupErr != nil {
		return PendingTransaction{}, repository.lookupErr
	}
	return repository.pending, nil
}

func (repository *memoryTransactions) current() PendingTransaction {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.pending
}

func (repository *memoryTransactions) createRequest() CreateTransactionRequest {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.lastCreate
}

type recordingSigner struct {
	mu       sync.Mutex
	requests []RedirectSignRequest
	err      error
}

func (signer *recordingSigner) SignRedirect(_ context.Context, request RedirectSignRequest) ([]byte, error) {
	signer.mu.Lock()
	defer signer.mu.Unlock()
	request.Payload = append([]byte(nil), request.Payload...)
	signer.requests = append(signer.requests, request)
	if signer.err != nil {
		return nil, signer.err
	}
	return []byte("fixed-signature"), nil
}

type proofVerifier struct {
	mu          sync.Mutex
	calls       []SignatureVerificationRequest
	rawDocument []byte
	mutate      func(*SignatureVerificationResult)
	err         error
}

func (verifier *proofVerifier) VerifyXMLSignature(_ context.Context, request SignatureVerificationRequest) (SignatureVerificationResult, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.rawDocument = request.Document
	request.Document = append([]byte(nil), request.Document...)
	verifier.calls = append(verifier.calls, request)
	if verifier.err != nil {
		return SignatureVerificationResult{}, verifier.err
	}
	certificates := request.Metadata.Certificates()
	proof := SignatureVerificationResult{
		Authority: request.Authority, Provider: request.Provider, BindingID: request.BindingID,
		PlatformLoginRevision: request.PlatformLoginRevision,
		ObjectKind:            request.ObjectKind, ObjectID: request.ObjectID, ReferenceURI: "#" + request.ObjectID,
		CertificateFingerprintSHA256: certificates[0].FingerprintSHA256,
		SignatureAlgorithm:           string(RedirectECDSASHA256), DigestAlgorithm: digestSHA256,
		CanonicalizationAlgorithm: exclusiveCanonicalization,
		Transforms:                []string{envelopedSignatureTransform, exclusiveCanonicalization},
		DocumentDigest:            sha256.Sum256(request.Document), ReferenceCount: 1,
		KeyInfoCertificateCount: 1, MatchingCertificateCount: 1,
	}
	if verifier.mutate != nil {
		verifier.mutate(&proof)
	}
	return proof, nil
}

type fixedDecrypter struct {
	mu        sync.Mutex
	assertion []byte
	mutate    func(*DecryptionResult)
	last      DecryptionRequest
	raw       []byte
	calls     int
	err       error
}

func (decrypter *fixedDecrypter) DecryptAssertion(_ context.Context, request DecryptionRequest) (DecryptionResult, error) {
	decrypter.mu.Lock()
	defer decrypter.mu.Unlock()
	decrypter.calls++
	decrypter.raw = request.Response
	request.Response = nil
	request.AllowedKeyVersions = append([]uint32(nil), request.AllowedKeyVersions...)
	request.DirectPlatformKeyRevisions = append([]uint64(nil), request.DirectPlatformKeyRevisions...)
	decrypter.last = request
	if decrypter.err != nil {
		return DecryptionResult{}, decrypter.err
	}
	result := DecryptionResult{
		Authority: request.Authority, Provider: request.Provider, BindingID: request.BindingID,
		PlatformLoginRevision:      request.PlatformLoginRevision,
		Assertion:                  append([]byte(nil), decrypter.assertion...),
		ContentEncryptionAlgorithm: aes128GCM, KeyTransportAlgorithm: rsaOAEP11,
		KeyDigestAlgorithm: digestSHA256, MaskGenerationAlgorithm: mgf1SHA256,
		EncryptedObjectID: request.EncryptedObjectID,
	}
	if request.Authority == DirectPlatformCeremonyAuthority {
		if len(request.DirectPlatformKeyRevisions) == 0 {
			return DecryptionResult{}, ErrEncryptionRejected
		}
		result.DirectPlatformKeyRevision = request.DirectPlatformKeyRevisions[0]
	} else {
		if len(request.AllowedKeyVersions) == 0 {
			return DecryptionResult{}, ErrEncryptionRejected
		}
		result.KeyVersion = request.AllowedKeyVersions[0]
	}
	if decrypter.mutate != nil {
		decrypter.mutate(&result)
	}
	return result, nil
}

type fixedProtector struct {
	material  SessionMaterial
	calls     int
	context   SessionMaterialContext
	protected ProtectedSessionMaterial
	err       error
}

func (protector *fixedProtector) OpenSAMLSession(_ context.Context, sessionContext SessionMaterialContext, protected ProtectedSessionMaterial) (SessionMaterial, error) {
	protector.calls++
	protector.context = sessionContext
	protector.protected = protected
	if protector.err != nil {
		return SessionMaterial{}, protector.err
	}
	return protector.material, nil
}

type testFixture struct {
	kernel    *Kernel
	config    Configuration
	repo      *memoryTransactions
	signer    *recordingSigner
	verifier  *proofVerifier
	decrypter *fixedDecrypter
	protector *fixedProtector
	start     AuthorizationStart
	relay     string
}

func newTestFixture(t *testing.T) testFixture {
	return newTestFixtureForAuthority(t, TenantCeremonyAuthority)
}

func newTestFixtureForAuthority(t *testing.T, authority CeremonyAuthority) testFixture {
	t.Helper()
	metadata := compileTestMetadata(t, 1, "https://idp.example.test/entity", "https://idp.example.test/sso", "https://idp.example.test/slo", testCertificate(t, 1))
	configuration := testConfiguration(metadata)
	if authority == DirectPlatformCeremonyAuthority {
		configuration.Authority = DirectPlatformCeremonyAuthority
		configuration.Provider = identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: testID(2),
		}
		configuration.BindingID = identity.EntityID{}
		configuration.BindingRevision = 0
		configuration.PlatformLoginRevision = 13
		configuration.PlanRevision = 14
		configuration.MappingRevision = 0
		configuration.AuthorizationRevision = 0
		configuration.ACSURL = "https://sp.example.test" + directPlatformSAMLACSPath
		configuration.Mapping = AttributeMappingPolicy{}
	}
	repository := &memoryTransactions{}
	signer := &recordingSigner{}
	verifier := &proofVerifier{}
	decrypter := &fixedDecrypter{}
	protector := &fixedProtector{material: SessionMaterial{NameID: "logout-secret-subject", NameIDFormat: samlPersistentNameID, SessionIndex: "logout-secret-session"}}
	randomBytes := make([]byte, 1024)
	for index := range randomBytes {
		randomBytes[index] = byte(index%251 + 1)
	}
	kernel, err := newKernel(Options{
		Authority:    authority,
		Transactions: repository, RedirectSigner: signer, SignatureVerifier: verifier,
		AssertionDecrypter: decrypter, SessionProtector: protector,
		Limits: DefaultLimits(), TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	}, bytes.NewReader(randomBytes), func() time.Time { return fixtureTime })
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	start, err := kernel.StartAuthentication(context.Background(), StartRequest{Begin: testAuthenticationBegin(1), Configuration: configuration, ReturnPath: "/incidents?view=mine"})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	parsed, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	relay := parsed.Query().Get("RelayState")
	if relay == "" {
		t.Fatal("redirect has no RelayState")
	}
	return testFixture{kernel: kernel, config: configuration, repo: repository, signer: signer, verifier: verifier, decrypter: decrypter, protector: protector, start: start, relay: relay}
}

func testConfiguration(metadata MetadataSnapshot) Configuration {
	groups := &GroupAttributeRule{Name: "groups", NameFormat: "urn:test:attribute", Required: true}
	return Configuration{
		Provider:  identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: testID(1), ProviderID: testID(2)},
		BindingID: testID(3), ProviderRevision: 4, BindingRevision: 5, ConfigurationRevision: 6,
		SecurityRevision: 7, MappingRevision: 8, AuthorizationRevision: 9, AssurancePolicyRevision: 10,
		SPEntityID: "https://sp.example.test/saml/metadata",
		ACSURL:     "https://sp.example.test" + samlACSPath,
		Metadata:   metadata, SPKeyRevision: 11, RedirectSignatureAlgorithm: RedirectECDSASHA256,
		SignaturePolicy: SignedBoth, EncryptionPolicy: EncryptionDisabled,
		RequestedAuthnContexts: []string{"urn:test:mfa"}, Subject: SubjectPolicy{Source: SubjectPersistentNameID},
		Mapping: AttributeMappingPolicy{
			Scalars:  []ScalarAttributeRule{{Name: "department", NameFormat: "urn:test:attribute", Required: true}},
			Profiles: []ProfileAttributeRule{{Name: "email", NameFormat: "urn:test:attribute", Field: ProfileEmail, Required: true}},
			Groups:   groups,
		},
		TrustRules: []AuthnContextTrustRule{{ClassRef: "urn:test:mfa", Level: identity.AssuranceMFA, Revision: 12, MaxAge: time.Hour}},
		ClockSkew:  2 * time.Minute, MaxAuthenticationAge: 8 * time.Hour,
	}
}

func testAuthenticationBegin(seed byte) AuthenticationBegin {
	operationID := testID(seed)
	operationID[6] = 0x70
	operationID[8] = 0x80
	var receipt, network, account, provider [sha256.Size]byte
	receipt[0], network[0], account[0], provider[0] = seed, seed+1, seed+2, seed+3
	return AuthenticationBegin{
		OperationRunID: operationID,
		ReceiptDigest:  StartReceiptDigest(receipt),
		NetworkDigest:  NetworkThrottleDigest(network),
		AccountDigest:  AccountThrottleDigest(account),
		ProviderDigest: ProviderThrottleDigest(provider),
	}
}

func testID(value byte) identity.EntityID {
	var result identity.EntityID
	result[15] = value
	return result
}

func testCertificate(t *testing.T, serial int64) []byte {
	t.Helper()
	testCertificateCache.Lock()
	defer testCertificateCache.Unlock()
	if cached := testCertificateCache.der[serial]; cached != nil {
		return append([]byte(nil), cached...)
	}
	der := makeTestCertificate(t, serial, fixtureTime.Add(-time.Hour), fixtureTime.Add(365*24*time.Hour))
	testCertificateCache.der[serial] = append([]byte(nil), der...)
	return append([]byte(nil), der...)
}

func makeTestCertificate(t *testing.T, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("idp-%d", serial)},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func compileTestMetadata(t *testing.T, revision uint64, entityID, sso, slo string, certificates ...[]byte) MetadataSnapshot {
	t.Helper()
	document := testMetadataDocument(entityID, sso, slo, certificates...)
	snapshot, err := CompileMetadata(MetadataCompilationRequest{
		Document: document, ExpectedEntityID: entityID, Revision: revision,
		RetrievedAt: fixtureTime, MaximumValidUntil: fixtureTime.Add(48 * time.Hour),
	}, DefaultLimits())
	if err != nil {
		t.Fatalf("CompileMetadata() error = %v", err)
	}
	return snapshot
}

func testMetadataDocument(entityID, sso, slo string, certificates ...[]byte) []byte {
	var keys strings.Builder
	for _, certificate := range certificates {
		fmt.Fprintf(&keys, `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`, base64.StdEncoding.EncodeToString(certificate))
	}
	sloElement := ""
	if slo != "" {
		sloElement = `<md:SingleLogoutService Binding="` + samlHTTPRedirectBinding + `" Location="` + slo + `"/>`
	}
	return []byte(fmt.Sprintf(`<md:EntityDescriptor xmlns:md="%s" xmlns:ds="%s" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="%s" WantAuthnRequestsSigned="true">%s%s<md:SingleSignOnService Binding="%s" Location="%s"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		samlMetadataNamespace, xmlSignatureNamespace, entityID, fixtureTime.Add(24*time.Hour).Format(time.RFC3339),
		samlProtocolEnumeration, keys.String(), sloElement, samlHTTPRedirectBinding, sso))
}

func validResponseDocument(fixture testFixture) []byte {
	return responseDocument(fixture, true, validAssertionDocument(fixture, true))
}

func responseDocument(fixture testFixture, responseSigned bool, assertion []byte) []byte {
	pending := fixture.repo.current()
	signature := ""
	if responseSigned {
		signature = `<ds:Signature/>`
	}
	return []byte(fmt.Sprintf(`<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" xmlns:ds="%s" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer>%s<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>`,
		samlProtocolNamespace, samlAssertionNamespace, xmlSignatureNamespace, fixtureTime.Format(time.RFC3339),
		fixture.config.ACSURL, pending.RequestID, fixture.config.Metadata.EntityID(), signature, samlSuccessStatus, assertion))
}

func validAssertionDocument(fixture testFixture, signed bool) []byte {
	pending := fixture.repo.current()
	signature := ""
	if signed {
		signature = `<ds:Signature/>`
	}
	return []byte(fmt.Sprintf(`<saml:Assertion xmlns:saml="%s" xmlns:ds="%s" ID="_assertion" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer>%s<saml:Subject><saml:NameID Format="%s">subject-secret-value</saml:NameID><saml:SubjectConfirmation Method="%s"><saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="%s" SessionIndex="session-secret-index" SessionNotOnOrAfter="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:test:mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="department" NameFormat="urn:test:attribute"><saml:AttributeValue>department-secret</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email" NameFormat="urn:test:attribute"><saml:AttributeValue>email-secret@example.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups" NameFormat="urn:test:attribute"><saml:AttributeValue>zeta-secret-group</saml:AttributeValue><saml:AttributeValue>alpha-secret-group</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`,
		samlAssertionNamespace, xmlSignatureNamespace, fixtureTime.Format(time.RFC3339), fixture.config.Metadata.EntityID(), signature,
		samlPersistentNameID, samlBearerConfirmation, fixture.config.ACSURL, pending.RequestID,
		fixtureTime.Add(5*time.Minute).Format(time.RFC3339), fixtureTime.Add(-time.Minute).Format(time.RFC3339),
		fixtureTime.Add(10*time.Minute).Format(time.RFC3339), fixture.config.SPEntityID, fixtureTime.Add(-time.Minute).Format(time.RFC3339),
		fixtureTime.Add(8*time.Minute).Format(time.RFC3339)))
}

func callbackRequest(fixture testFixture, document []byte) CallbackRequest {
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(document)}, "RelayState": {fixture.relay}}
	return CallbackRequest{Configuration: fixture.config, MediaType: "application/x-www-form-urlencoded; charset=UTF-8", RawForm: []byte(form.Encode()), BrowserHandle: fixture.start.BrowserHandle()}
}

type atomicConsumer struct {
	mu      sync.Mutex
	calls   int
	request ConsumptionRequest
}

func (consumer *atomicConsumer) ConsumeSAML(_ context.Context, request ConsumptionRequest) (ConsumptionResult, error) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.calls++
	consumer.request = request
	return ConsumptionResult{Category: ConsumerSuccess}, nil
}
