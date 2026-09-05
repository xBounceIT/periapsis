package federatedauth

import (
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
	"net/url"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	testSAMLProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	testSAMLAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	testSAMLMetadataNamespace  = "urn:oasis:names:tc:SAML:2.0:metadata"
	testXMLSignatureNamespace  = "http://www.w3.org/2000/09/xmldsig#"
	testSAMLRedirectBinding    = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	testSAMLBearer             = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	testSAMLPersistentNameID   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	testSAMLSuccess            = "urn:oasis:names:tc:SAML:2.0:status:Success"
	testExclusiveC14N          = "http://www.w3.org/2001/10/xml-exc-c14n#"
	testEnvelopedTransform     = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	testDigestSHA256           = "http://www.w3.org/2001/04/xmlenc#sha256"
)

type samlTestTransactions struct {
	mu      sync.Mutex
	pending federatedsaml.PendingTransaction
}

func (repository *samlTestTransactions) CreateReplacing(
	_ context.Context,
	request federatedsaml.CreateTransactionRequest,
) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.pending = request.Current
	return nil
}

func (repository *samlTestTransactions) Lookup(
	_ context.Context,
	request federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.pending.RelayStateDigest != request.RelayStateDigest ||
		repository.pending.BrowserDigest != request.BrowserDigest {
		return federatedsaml.PendingTransaction{}, errors.New("not found")
	}
	return repository.pending, nil
}

type samlTestSigner struct{}

func (samlTestSigner) SignRedirect(context.Context, federatedsaml.RedirectSignRequest) ([]byte, error) {
	return []byte("test-signature"), nil
}

type samlTestVerifier struct{}

func (samlTestVerifier) VerifyXMLSignature(
	_ context.Context,
	request federatedsaml.SignatureVerificationRequest,
) (federatedsaml.SignatureVerificationResult, error) {
	certificates := request.Metadata.Certificates()
	if len(certificates) != 1 {
		return federatedsaml.SignatureVerificationResult{}, errors.New("certificate mismatch")
	}
	return federatedsaml.SignatureVerificationResult{
		ObjectKind: request.ObjectKind, ObjectID: request.ObjectID, ReferenceURI: "#" + request.ObjectID,
		CertificateFingerprintSHA256: certificates[0].FingerprintSHA256,
		SignatureAlgorithm:           string(federatedsaml.RedirectECDSASHA256), DigestAlgorithm: testDigestSHA256,
		CanonicalizationAlgorithm: testExclusiveC14N,
		Transforms:                []string{testEnvelopedTransform, testExclusiveC14N},
		DocumentDigest:            sha256.Sum256(request.Document), ReferenceCount: 1,
		KeyInfoCertificateCount: 1, MatchingCertificateCount: 1,
	}, nil
}

type samlTestDecrypter struct{}

func (samlTestDecrypter) DecryptAssertion(context.Context, federatedsaml.DecryptionRequest) (federatedsaml.DecryptionResult, error) {
	return federatedsaml.DecryptionResult{}, errors.New("encryption disabled")
}

type samlTestSessionProtector struct{}

func (samlTestSessionProtector) OpenSAMLSession(
	context.Context,
	federatedsaml.SessionMaterialContext,
	federatedsaml.ProtectedSessionMaterial,
) (federatedsaml.SessionMaterial, error) {
	return federatedsaml.SessionMaterial{}, errors.New("not used")
}

type samlKernelFixture struct {
	kernel        *federatedsaml.Kernel
	configuration TenantSAMLConfiguration
	validated     *federatedsaml.ValidatedAuthentication
	now           time.Time
}

func newSAMLKernelFixture(t *testing.T, withSLO bool) samlKernelFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	configuration := samlConfigurationFixture(t, now, withSLO)
	repository := &samlTestTransactions{}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Transactions: repository, RedirectSigner: samlTestSigner{}, SignatureVerifier: samlTestVerifier{},
		AssertionDecrypter: samlTestDecrypter{}, SessionProtector: samlTestSessionProtector{},
		TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New SAML kernel: %v", err)
	}
	start, err := kernel.StartAuthentication(context.Background(), federatedsaml.StartRequest{
		Begin: samlAuthenticationBeginFixture(1), Configuration: configuration.Authentication, ReturnPath: "/cases",
	})
	if err != nil {
		t.Fatalf("StartAuthentication(): %v", err)
	}
	pending := repository.pending
	document := samlResponseDocument(configuration.Authentication, pending.RequestID, now)
	form := url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString(document)},
		"RelayState":   {relayStateFromStart(t, start.RedirectURL())},
	}
	validated, err := kernel.ValidateCallback(context.Background(), federatedsaml.CallbackRequest{
		Configuration: configuration.Authentication,
		MediaType:     "application/x-www-form-urlencoded; charset=UTF-8",
		RawForm:       []byte(form.Encode()),
		BrowserHandle: start.BrowserHandle(),
	})
	if err != nil {
		t.Fatalf("ValidateCallback(): %v", err)
	}
	return samlKernelFixture{kernel: kernel, configuration: configuration, validated: validated, now: now}
}

func samlConfigurationFixture(t *testing.T, now time.Time, withSLO bool) TenantSAMLConfiguration {
	t.Helper()
	entityID := "https://idp.example.test/entity"
	slo := ""
	if withSLO {
		slo = "https://idp.example.test/slo"
	}
	certificate := samlCertificateFixture(t, now)
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: samlMetadataDocument(
			entityID, "https://idp.example.test/sso", slo, now.Add(24*time.Hour), certificate,
		),
		ExpectedEntityID: entityID, Revision: 6, RetrievedAt: now.Add(-time.Minute),
		MaximumValidUntil: now.Add(48 * time.Hour),
	}, federatedsaml.DefaultLimits())
	if err != nil {
		t.Fatalf("CompileMetadata(): %v", err)
	}
	tenantID := serviceID(41)
	groups := &federatedsaml.GroupAttributeRule{Name: "groups", NameFormat: "urn:test:attribute", Required: true}
	return TenantSAMLConfiguration{Authentication: federatedsaml.Configuration{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(42),
		},
		BindingID: serviceID(43), ProviderRevision: 2, BindingRevision: 7,
		ConfigurationRevision: 3, SecurityRevision: 3, MappingRevision: 4,
		AuthorizationRevision: 5, AssurancePolicyRevision: 1,
		SPEntityID: "https://sp.example.test/saml/metadata",
		ACSURL:     "https://sp.example.test/api/v1/auth/federated/saml/acs",
		Metadata:   metadata, SPKeyRevision: 8,
		RedirectSignatureAlgorithm: federatedsaml.RedirectECDSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
		RequestedAuthnContexts: []string{"urn:test:mfa"},
		Subject:                federatedsaml.SubjectPolicy{Source: federatedsaml.SubjectPersistentNameID},
		Mapping: federatedsaml.AttributeMappingPolicy{
			Scalars: []federatedsaml.ScalarAttributeRule{{Name: "department", NameFormat: "urn:test:attribute", Required: true}},
			Profiles: []federatedsaml.ProfileAttributeRule{{
				Name: "email", NameFormat: "urn:test:attribute", Field: federatedsaml.ProfileEmail, Required: true,
			}},
			Groups: groups,
		},
		TrustRules: []federatedsaml.AuthnContextTrustRule{{
			ClassRef: "urn:test:mfa", Level: identity.AssuranceMFA, Revision: 9, MaxAge: time.Hour,
		}},
		ClockSkew: time.Minute, MaxAuthenticationAge: 8 * time.Hour,
	}}
}

func samlCertificateFixture(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-idp"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func samlMetadataDocument(entityID, sso, slo string, validUntil time.Time, certificate []byte) []byte {
	sloElement := ""
	if slo != "" {
		sloElement = `<md:SingleLogoutService Binding="` + testSAMLRedirectBinding + `" Location="` + slo + `"/>`
	}
	return []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="%s" xmlns:ds="%s" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="%s" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>%s<md:SingleSignOnService Binding="%s" Location="%s"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		testSAMLMetadataNamespace, testXMLSignatureNamespace, entityID, validUntil.UTC().Format(time.RFC3339),
		testSAMLProtocolNamespace, base64.StdEncoding.EncodeToString(certificate), sloElement, testSAMLRedirectBinding, sso,
	))
}

func samlResponseDocument(configuration federatedsaml.Configuration, requestID string, now time.Time) []byte {
	return []byte(fmt.Sprintf(
		`<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" xmlns:ds="%s" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature/><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status><saml:Assertion ID="_assertion" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature/><saml:Subject><saml:NameID Format="%s">subject-secret</saml:NameID><saml:SubjectConfirmation Method="%s"><saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="%s" SessionIndex="session-secret" SessionNotOnOrAfter="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:test:mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="department" NameFormat="urn:test:attribute"><saml:AttributeValue>DFIR</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email" NameFormat="urn:test:attribute"><saml:AttributeValue>private@example.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups" NameFormat="urn:test:attribute"><saml:AttributeValue>incident-command</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`,
		testSAMLProtocolNamespace, testSAMLAssertionNamespace, testXMLSignatureNamespace,
		now.Format(time.RFC3339), configuration.ACSURL, requestID, configuration.Metadata.EntityID(), testSAMLSuccess,
		now.Format(time.RFC3339), configuration.Metadata.EntityID(), testSAMLPersistentNameID, testSAMLBearer,
		configuration.ACSURL, requestID, now.Add(5*time.Minute).Format(time.RFC3339),
		now.Add(-time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		configuration.SPEntityID, now.Add(-time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
	))
}

func relayStateFromStart(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Query().Get("RelayState") == "" {
		t.Fatalf("parse SAML start: %v", err)
	}
	return parsed.Query().Get("RelayState")
}

func samlAuthenticationBeginFixture(seed byte) federatedsaml.AuthenticationBegin {
	operationID := serviceID(seed)
	operationID[6], operationID[8] = 0x70, 0x80
	var receipt, network, account, provider [sha256.Size]byte
	receipt[0], network[0], account[0], provider[0] = seed, seed+1, seed+2, seed+3
	return federatedsaml.AuthenticationBegin{
		OperationRunID: operationID,
		ReceiptDigest:  federatedsaml.StartReceiptDigest(receipt),
		NetworkDigest:  federatedsaml.NetworkThrottleDigest(network),
		AccountDigest:  federatedsaml.AccountThrottleDigest(account),
		ProviderDigest: federatedsaml.ProviderThrottleDigest(provider),
	}
}

func validSAMLStartLookupFixture() SAMLStartLookup {
	begin := samlAuthenticationBeginFixture(21)
	return SAMLStartLookup{
		OperationRunID: begin.OperationRunID, ReceiptDigest: begin.ReceiptDigest,
		TenantSlug: "acme", LoginKey: "acme_saml", NetworkDigest: begin.NetworkDigest,
		AccountDigest: begin.AccountDigest, ProviderDigest: begin.ProviderDigest,
	}
}

func validSAMLBrowserHandleFixture(seed byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index%17)
	}
	return []byte(base64.RawURLEncoding.EncodeToString(value))
}
