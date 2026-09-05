// Package federatedsaml implements the bounded, deny-by-default SAML 2.0
// Web Browser SSO domain kernel. XML signature, XML encryption, key access,
// transaction persistence, and JIT/session application remain behind narrow
// deployment-owned ports. It creates local-first outbound SLO artifacts but
// intentionally rejects IdP-initiated SSO by requiring an exact pending
// transaction. The package performs no network I/O.
package federatedsaml

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	samlProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlMetadataNamespace  = "urn:oasis:names:tc:SAML:2.0:metadata"
	xmlSignatureNamespace  = "http://www.w3.org/2000/09/xmldsig#"
	xmlEncryptionNamespace = "http://www.w3.org/2001/04/xmlenc#"
	xmlEncryption11NS      = "http://www.w3.org/2009/xmlenc11#"
	xmlSchemaInstanceNS    = "http://www.w3.org/2001/XMLSchema-instance"
	xmlSchemaNamespace     = "http://www.w3.org/2001/XMLSchema"
	xmlNamespace           = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespace         = "xmlns"

	samlVersion                   = "2.0"
	samlHTTPRedirectBinding       = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	samlHTTPPOSTBinding           = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	samlBearerConfirmation        = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	samlSuccessStatus             = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlPersistentNameID          = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	samlProtocolEnumeration       = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlExactAuthnContextCompare  = "exact"
	samlACSPath                   = "/api/v1/auth/federated/saml/acs"
	directPlatformSAMLACSPath     = "/api/v1/auth/platform/saml/acs"
	minimumOpaqueBytes            = 32
	maximumRelayStateBytes        = 80
	canonicalRelayStateBytes      = 43
	maximumIdentifierBytes        = 1024
	maximumEntityIDBytes          = 2048
	maximumEndpointBytes          = 4096
	maximumAttributeNameBytes     = 512
	maximumAttributeValueBytes    = 16 * 1024
	maximumSessionIndexBytes      = 2048
	maximumAuthnContextBytes      = 2048
	maximumCertificateBytes       = 64 * 1024
	maximumRedirectBytes          = 64 * 1024
	maximumSignedPayloadBytes     = 32 * 1024
	maximumSignatureBytes         = 16 * 1024
	maximumProtectedMaterialBytes = 64 * 1024
)

// PersistentNameIDFormat is the only NameID format admitted for immutable
// subject identity and optional outbound SLO provenance.
const PersistentNameIDFormat = samlPersistentNameID

var (
	ErrInvalidOptions           = errors.New("invalid SAML kernel options")
	ErrInvalidMetadata          = errors.New("SAML metadata rejected")
	ErrMetadataRolloverRejected = errors.New("SAML metadata rollover rejected")
	ErrInvalidConfiguration     = errors.New("SAML configuration rejected")
	ErrAuthenticationStart      = errors.New("SAML authentication start rejected")
	ErrTransactionPersistence   = errors.New("SAML transaction persistence failed")
	ErrCallbackRejected         = errors.New("SAML callback rejected")
	ErrSignatureRejected        = errors.New("SAML signature rejected")
	ErrEncryptionRejected       = errors.New("SAML encrypted assertion rejected")
	ErrAssertionRejected        = errors.New("SAML assertion rejected")
	ErrAttributeMappingRejected = errors.New("SAML attribute mapping rejected")
	ErrConsumptionRejected      = errors.New("SAML authentication consumption rejected")
	ErrLogoutArtifactRejected   = errors.New("SAML logout artifact rejected")
)

// Limits are deployment-owned parser and cardinality ceilings.
type Limits struct {
	MaxMetadataBytes           int
	MaxEncodedResponseBytes    int
	MaxDecodedResponseBytes    int
	MaxDecryptedAssertionBytes int
	MaxXMLDepth                int
	MaxXMLNodes                int
	MaxXMLAttributes           int
	MaxXMLTextBytes            int
	MaxCertificates            int
	MaxAttributes              int
	MaxValuesPerAttribute      int
	MaxMappedScalars           int
	MaxMappedProfiles          int
	MaxGroups                  int
}

func DefaultLimits() Limits {
	return Limits{
		MaxMetadataBytes: 512 * 1024, MaxEncodedResponseBytes: 1024 * 1024,
		MaxDecodedResponseBytes: 768 * 1024, MaxDecryptedAssertionBytes: 512 * 1024,
		MaxXMLDepth: 32, MaxXMLNodes: 8192, MaxXMLAttributes: 16 * 1024,
		MaxXMLTextBytes: 1024 * 1024, MaxCertificates: 32, MaxAttributes: 256,
		MaxValuesPerAttribute: 256, MaxMappedScalars: 32, MaxMappedProfiles: 16,
		MaxGroups: 2048,
	}
}

type SignaturePolicy string

const (
	SignedAssertion SignaturePolicy = "signed_assertion"
	SignedResponse  SignaturePolicy = "signed_response"
	SignedBoth      SignaturePolicy = "both"
)

type EncryptionPolicy string

const (
	EncryptionDisabled EncryptionPolicy = "disabled"
	EncryptionOptional EncryptionPolicy = "optional"
	EncryptionRequired EncryptionPolicy = "required"
)

type SubjectSource string

const (
	SubjectPersistentNameID   SubjectSource = "persistent_nameid"
	SubjectImmutableAttribute SubjectSource = "immutable_attribute"
)

type ProfileField string

const (
	ProfileUsername    ProfileField = "username"
	ProfileEmail       ProfileField = "email"
	ProfileDisplayName ProfileField = "display_name"
)

type RedirectSignatureAlgorithm string

const (
	RedirectRSASHA256   RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	RedirectRSASHA384   RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	RedirectRSASHA512   RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	RedirectECDSASHA256 RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	RedirectECDSASHA384 RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	RedirectECDSASHA512 RedirectSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

type SignedObjectKind string

const (
	SignedObjectResponse  SignedObjectKind = "response"
	SignedObjectAssertion SignedObjectKind = "assertion"
)

// CeremonyAuthority identifies the authority family that owns one SAML
// browser ceremony. TenantCeremonyAuthority remains the zero value solely so
// existing tenant projections preserve their wire shape; direct platform
// authentication must opt in explicitly.
type CeremonyAuthority uint8

const (
	TenantCeremonyAuthority CeremonyAuthority = iota
	DirectPlatformCeremonyAuthority
)

type ScalarAttributeRule struct {
	Name       string
	NameFormat string
	Required   bool
}

type ProfileAttributeRule struct {
	Name       string
	NameFormat string
	Field      ProfileField
	Required   bool
}

type GroupAttributeRule struct {
	Name       string
	NameFormat string
	Required   bool
}

type SubjectPolicy struct {
	Source              SubjectSource
	AttributeName       string
	AttributeNameFormat string
}

type AttributeMappingPolicy struct {
	Scalars  []ScalarAttributeRule
	Profiles []ProfileAttributeRule
	Groups   *GroupAttributeRule
}

// AuthnContextTrustRule can raise normalized assurance only for one exact,
// case-sensitive class reference and exact immutable rule revision.
type AuthnContextTrustRule struct {
	ClassRef string
	Level    identity.AssuranceLevel
	Revision int64
	MaxAge   time.Duration
}

type CertificateSummary struct {
	FingerprintSHA256  [sha256.Size]byte
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Bits               int
}

type MetadataSnapshot struct {
	revision             uint64
	digest               [sha256.Size]byte
	retrievedAt          time.Time
	validUntil           time.Time
	entityID             string
	ssoRedirectURL       string
	sloRedirectURL       string
	certificateSummaries []CertificateSummary
	certificateDER       [][]byte
	valid                bool
}

func (snapshot MetadataSnapshot) Revision() uint64          { return snapshot.revision }
func (snapshot MetadataSnapshot) Digest() [sha256.Size]byte { return snapshot.digest }
func (snapshot MetadataSnapshot) RetrievedAt() time.Time    { return snapshot.retrievedAt }
func (snapshot MetadataSnapshot) ValidUntil() time.Time     { return snapshot.validUntil }
func (snapshot MetadataSnapshot) EntityID() string          { return snapshot.entityID }
func (snapshot MetadataSnapshot) SSORedirectURL() string    { return snapshot.ssoRedirectURL }
func (snapshot MetadataSnapshot) SLORedirectURL() string    { return snapshot.sloRedirectURL }
func (snapshot MetadataSnapshot) Certificates() []CertificateSummary {
	return append([]CertificateSummary(nil), snapshot.certificateSummaries...)
}
func (snapshot MetadataSnapshot) CertificateDER() [][]byte {
	result := make([][]byte, len(snapshot.certificateDER))
	for index := range snapshot.certificateDER {
		result[index] = append([]byte(nil), snapshot.certificateDER[index]...)
	}
	return result
}

type MetadataCompilationRequest struct {
	Document          []byte `json:"-"`
	ExpectedEntityID  string
	Revision          uint64
	RetrievedAt       time.Time
	MaximumValidUntil time.Time
}

type MetadataLoadRequest struct {
	Provider          identity.ProviderContext
	BindingID         identity.EntityID
	ExpectedEntityID  string
	Revision          uint64
	MaximumValidUntil time.Time
}

type MetadataDocument struct {
	Document    []byte `json:"-"`
	RetrievedAt time.Time
}

// MetadataSource owns provider-bound retrieval and must apply the deployment's
// DNS, address, redirect, TLS, and proxy policy. It must enforce maximumBytes
// while streaming and must not select a location from response content.
type MetadataSource interface {
	LoadSAMLMetadata(context.Context, MetadataLoadRequest, int) (MetadataDocument, error)
}

type RolloverDecision string

const (
	RolloverAutomatic         RolloverDecision = "automatic_overlap"
	RolloverProtectedApproval RolloverDecision = "protected_approval_required"
)

type RolloverAssessment struct {
	Decision                RolloverDecision
	OverlappingFingerprints int
	AddedFingerprints       int
	RemovedFingerprints     int
}

// Configuration is one immutable authority/provider projection. SPEntityID
// and ACSURL are server-derived, never tenant or browser input.
type Configuration struct {
	Authority                            CeremonyAuthority
	Provider                             identity.ProviderContext
	BindingID                            identity.EntityID
	ProviderRevision                     uint64
	BindingRevision                      uint64
	PlatformLoginRevision                uint64
	ConfigurationRevision                uint64
	SecurityRevision                     uint64
	PlanRevision                         uint64
	MappingRevision                      uint64
	AuthorizationRevision                uint64
	AssurancePolicyRevision              uint64
	SPEntityID                           string
	ACSURL                               string
	Metadata                             MetadataSnapshot
	SPKeyRevision                        uint64
	RedirectSignatureAlgorithm           RedirectSignatureAlgorithm
	SignaturePolicy                      SignaturePolicy
	EncryptionPolicy                     EncryptionPolicy
	DecryptionKeyVersions                []uint32
	DirectPlatformDecryptionKeyRevisions []uint64
	RequestedAuthnContexts               []string
	Subject                              SubjectPolicy
	Mapping                              AttributeMappingPolicy
	TrustRules                           []AuthnContextTrustRule
	ClockSkew                            time.Duration
	MaxAuthenticationAge                 time.Duration
}

type TransactionPins struct {
	Authority               CeremonyAuthority
	Provider                identity.ProviderContext
	BindingID               identity.EntityID
	ProviderRevision        uint64
	BindingRevision         uint64
	PlatformLoginRevision   uint64
	ConfigurationRevision   uint64
	SecurityRevision        uint64
	PlanRevision            uint64
	MappingRevision         uint64
	AuthorizationRevision   uint64
	AssurancePolicyRevision uint64
	MetadataRevision        uint64
	MetadataDigest          [sha256.Size]byte
	SPKeyRevision           uint64
	ConfigurationDigest     [sha256.Size]byte
}

// DirectPlatformLogin returns the pinned direct-login authority revision only
// for a complete, structurally direct transaction projection.
func (pins TransactionPins) DirectPlatformLogin() (uint64, bool) {
	if !validTransactionPins(pins) || pins.Authority != DirectPlatformCeremonyAuthority {
		return 0, false
	}
	return pins.PlatformLoginRevision, true
}

type TransactionID [minimumOpaqueBytes]byte

// Purpose-specific start digests bind one metered public locator resolution
// to one transaction creation without persisting the raw locator inputs.
type StartReceiptDigest [sha256.Size]byte
type NetworkThrottleDigest [sha256.Size]byte
type AccountThrottleDigest [sha256.Size]byte
type ProviderThrottleDigest [sha256.Size]byte

type AuthenticationBegin struct {
	OperationRunID identity.EntityID
	ReceiptDigest  StartReceiptDigest
	NetworkDigest  NetworkThrottleDigest
	AccountDigest  AccountThrottleDigest
	ProviderDigest ProviderThrottleDigest
}

type TransactionState string

const (
	TransactionPending   TransactionState = "pending"
	TransactionCompleted TransactionState = "completed"
	TransactionExpired   TransactionState = "expired"
	TransactionFailed    TransactionState = "failed"
)

type PendingTransaction struct {
	ID               TransactionID
	MaterialID       identity.EntityID
	RequestID        string
	RelayStateDigest [sha256.Size]byte
	BrowserDigest    [sha256.Size]byte
	Pins             TransactionPins
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ReturnPath       string
	State            TransactionState
	Version          uint64
}

type CreateTransactionRequest struct {
	Begin                     AuthenticationBegin
	Current                   PendingTransaction
	PreviousBrowserDigest     [sha256.Size]byte
	HasPreviousBrowserBinding bool
}

type LookupTransactionRequest struct {
	RelayStateDigest [sha256.Size]byte
	BrowserDigest    [sha256.Size]byte
	ObservedAt       time.Time
}

// TransactionRepository provides a bounded lookup without consuming the row.
// CreateReplacing is atomic and Lookup returns only one live exact projection.
type TransactionRepository interface {
	CreateReplacing(context.Context, CreateTransactionRequest) error
	Lookup(context.Context, LookupTransactionRequest) (PendingTransaction, error)
}

type RedirectSignRequest struct {
	Authority             CeremonyAuthority
	Provider              identity.ProviderContext
	BindingID             identity.EntityID
	PlatformLoginRevision uint64
	KeyRevision           uint64
	// LogoutMaterialID is non-zero only for a stored logout ceremony. It lets
	// the private-key boundary authorize an otherwise retired historical key
	// against the exact session material without weakening interactive loads.
	LogoutMaterialID identity.EntityID
	Algorithm        RedirectSignatureAlgorithm
	Payload          []byte `json:"-"`
}

// RedirectSigner owns SP private-key access. It must bind the exact authority,
// provider, binding when applicable, revisions, and algorithm and must not
// retain Payload.
type RedirectSigner interface {
	SignRedirect(context.Context, RedirectSignRequest) ([]byte, error)
}

type SignatureVerificationRequest struct {
	Authority             CeremonyAuthority
	Provider              identity.ProviderContext
	BindingID             identity.EntityID
	PlatformLoginRevision uint64
	Document              []byte `json:"-"`
	ObjectKind            SignedObjectKind
	ObjectID              string
	Metadata              MetadataSnapshot
}

type SignatureVerificationResult struct {
	Authority                      CeremonyAuthority
	Provider                       identity.ProviderContext
	BindingID                      identity.EntityID
	PlatformLoginRevision          uint64
	ObjectKind                     SignedObjectKind
	ObjectID                       string
	ReferenceURI                   string
	CertificateFingerprintSHA256   [sha256.Size]byte
	SignatureAlgorithm             string
	DigestAlgorithm                string
	CanonicalizationAlgorithm      string
	Transforms                     []string
	DocumentDigest                 [sha256.Size]byte
	ReferenceCount                 int
	KeyInfoCertificateCount        int
	MatchingCertificateCount       int
	CanonicalizationParameterCount int
	TransformParameterCount        int
	ExternalDereferenceCount       int
}

// XMLSignatureVerifier must cryptographically verify exactly ObjectID in the
// supplied bounded document, with exactly one matching pinned metadata
// certificate and no external dereference. KeyInfo may contain zero or one
// certificate. The kernel independently validates the returned safe proof.
type XMLSignatureVerifier interface {
	VerifyXMLSignature(context.Context, SignatureVerificationRequest) (SignatureVerificationResult, error)
}

type DecryptionRequest struct {
	Authority                  CeremonyAuthority
	Response                   []byte `json:"-"`
	ResponseID                 string
	EncryptedObjectID          string
	Provider                   identity.ProviderContext
	BindingID                  identity.EntityID
	PlatformLoginRevision      uint64
	AllowedKeyVersions         []uint32
	DirectPlatformKeyRevisions []uint64
}

type DecryptionResult struct {
	Authority                  CeremonyAuthority
	Provider                   identity.ProviderContext
	BindingID                  identity.EntityID
	PlatformLoginRevision      uint64
	Assertion                  []byte `json:"-"`
	KeyVersion                 uint32
	DirectPlatformKeyRevision  uint64
	ContentEncryptionAlgorithm string
	KeyTransportAlgorithm      string
	KeyDigestAlgorithm         string
	MaskGenerationAlgorithm    string
	EncryptedObjectID          string
	ExternalDereferenceCount   int
}

// AssertionDecrypter owns authority/provider-scoped SP private keys. It must
// never try a key outside the authority-specific pinned revision list, use
// KeyName to cross provider boundaries, or dereference any external URI.
type AssertionDecrypter interface {
	DecryptAssertion(context.Context, DecryptionRequest) (DecryptionResult, error)
}

type ProtectedSessionMaterial struct {
	KeyVersion uint32
	Ciphertext []byte `json:"-"`
}

type SessionMaterialContext struct {
	Authority             CeremonyAuthority
	Provider              identity.ProviderContext
	BindingID             identity.EntityID
	MaterialID            identity.EntityID
	PlatformLoginRevision uint64
}

// TenantProtectionContext converts only a structurally tenant-owned session
// anchor into the established identity keyring context.
func (context SessionMaterialContext) TenantProtectionContext() (identity.SAMLSessionMaterialContext, bool) {
	if !validCeremonyContext(
		context.Authority, context.Provider, context.BindingID, context.PlatformLoginRevision,
	) || context.Authority != TenantCeremonyAuthority || !validEntityID(context.MaterialID) {
		return identity.SAMLSessionMaterialContext{}, false
	}
	return identity.SAMLSessionMaterialContext{
		Provider: context.Provider, BindingID: context.BindingID, MaterialID: context.MaterialID,
	}, true
}

// DirectPlatformProtectionContext converts only an exact direct-platform
// anchor. No tenant or binding value can enter the resulting AAD context.
func (context SessionMaterialContext) DirectPlatformProtectionContext() (identity.DirectPlatformSAMLSessionMaterialContext, bool) {
	if !validCeremonyContext(
		context.Authority, context.Provider, context.BindingID, context.PlatformLoginRevision,
	) || context.Authority != DirectPlatformCeremonyAuthority || !validEntityID(context.MaterialID) {
		return identity.DirectPlatformSAMLSessionMaterialContext{}, false
	}
	return identity.DirectPlatformSAMLSessionMaterialContext{
		Provider: context.Provider, MaterialID: context.MaterialID,
		PlatformLoginRevision: context.PlatformLoginRevision,
	}, true
}

type SessionMaterial struct {
	NameID       string `json:"-"`
	NameIDFormat string
	SessionIndex string `json:"-"`
}

type SessionMaterialProtector interface {
	OpenSAMLSession(context.Context, SessionMaterialContext, ProtectedSessionMaterial) (SessionMaterial, error)
}

type Options struct {
	Authority          CeremonyAuthority
	Transactions       TransactionRepository
	RedirectSigner     RedirectSigner
	SignatureVerifier  XMLSignatureVerifier
	AssertionDecrypter AssertionDecrypter
	SessionProtector   SessionMaterialProtector
	Limits             Limits
	TransactionTTL     time.Duration
	OperationTimeout   time.Duration
}

type Kernel struct {
	authority          CeremonyAuthority
	transactions       TransactionRepository
	redirectSigner     RedirectSigner
	signatureVerifier  XMLSignatureVerifier
	assertionDecrypter AssertionDecrypter
	sessionProtector   SessionMaterialProtector
	limits             Limits
	transactionTTL     time.Duration
	operationTimeout   time.Duration
	random             io.Reader
	now                func() time.Time
}

type StartRequest struct {
	Begin                 AuthenticationBegin
	Configuration         Configuration
	ReturnPath            string
	PreviousBrowserHandle []byte `json:"-"`
	HasLiveSession        bool
}

type AuthorizationStart struct {
	transactionID TransactionID
	redirectURL   string
	browserHandle []byte
	expiresAt     time.Time
	valid         bool
}

func (start AuthorizationStart) TransactionID() TransactionID { return start.transactionID }
func (start AuthorizationStart) RedirectURL() string          { return start.redirectURL }

// BrowserHandle must be set unchanged in the dedicated host-only Secure,
// HttpOnly, SameSite=None transaction cookie and never reused as a session.
func (start AuthorizationStart) BrowserHandle() []byte {
	return append([]byte(nil), start.browserHandle...)
}
func (start AuthorizationStart) ExpiresAt() time.Time { return start.expiresAt }

type CallbackRequest struct {
	Configuration Configuration
	MediaType     string
	RawForm       []byte `json:"-"`
	BrowserHandle []byte `json:"-"`
}

type AuthenticationConsumerCategory string

const (
	ConsumerSuccess     AuthenticationConsumerCategory = "success"
	ConsumerReplay      AuthenticationConsumerCategory = "replay"
	ConsumerStale       AuthenticationConsumerCategory = "stale"
	ConsumerCollision   AuthenticationConsumerCategory = "identity_collision"
	ConsumerDenied      AuthenticationConsumerCategory = "denied"
	ConsumerUnavailable AuthenticationConsumerCategory = "unavailable"
)

type ConsumptionResult struct {
	Category AuthenticationConsumerCategory
}

// AuthenticationConsumer must atomically recheck transaction/pins, consume
// it, insert provider-qualified response/assertion/session replay keys, and
// apply the authority-specific identity admission plus session or
// continuation. A rollback leaves none of those effects visible.
type AuthenticationConsumer interface {
	ConsumeSAML(context.Context, ConsumptionRequest) (ConsumptionResult, error)
}

type ConsumptionRequest struct {
	TransactionID      TransactionID
	MaterialID         identity.EntityID
	ExpectedVersion    uint64
	Pins               TransactionPins
	ResponseID         string
	AssertionID        string
	SessionIndexDigest [sha256.Size]byte
	HasSessionIndex    bool
	ConsumedAt         time.Time
	ReturnPath         string
	Authentication     JITAuthentication
}

// SessionProtectionContext derives the only admissible session-material AAD
// anchor from the immutable transaction pins. Callers must still select the
// tenant or direct-platform identity keyring method through the authority-
// specific conversion methods on the returned context.
func (request ConsumptionRequest) SessionProtectionContext() (SessionMaterialContext, bool) {
	if !validTransactionPins(request.Pins) || !validUUIDv7(request.MaterialID) {
		return SessionMaterialContext{}, false
	}
	return SessionMaterialContext{
		Authority: request.Pins.Authority, Provider: request.Pins.Provider,
		BindingID: request.Pins.BindingID, MaterialID: request.MaterialID,
		PlatformLoginRevision: request.Pins.PlatformLoginRevision,
	}, true
}

type NamedScalar struct {
	Name  string
	Value string `json:"-"`
}

type ProfileValue struct {
	Field ProfileField
	Value string `json:"-"`
}

type JITAuthentication struct {
	issuer           string
	subjectSource    SubjectSource
	subjectName      string
	subjectFormat    string
	subjectValue     string
	scalars          []NamedScalar
	profiles         []ProfileValue
	groups           []string
	authnContext     string
	authenticatedAt  time.Time
	validUntil       time.Time
	assurance        *identity.AssuranceEvidence
	protectedSession SessionMaterial
}

func (authentication JITAuthentication) Issuer() string { return authentication.issuer }
func (authentication JITAuthentication) SubjectSource() SubjectSource {
	return authentication.subjectSource
}
func (authentication JITAuthentication) SubjectName() string   { return authentication.subjectName }
func (authentication JITAuthentication) SubjectFormat() string { return authentication.subjectFormat }
func (authentication JITAuthentication) SubjectValue() string  { return authentication.subjectValue }
func (authentication JITAuthentication) Scalars() []NamedScalar {
	return append([]NamedScalar(nil), authentication.scalars...)
}
func (authentication JITAuthentication) Profiles() []ProfileValue {
	return append([]ProfileValue(nil), authentication.profiles...)
}
func (authentication JITAuthentication) Groups() []string {
	return append([]string(nil), authentication.groups...)
}
func (authentication JITAuthentication) AuthnContextClassRef() string {
	return authentication.authnContext
}
func (authentication JITAuthentication) AuthenticatedAt() time.Time {
	return authentication.authenticatedAt
}
func (authentication JITAuthentication) ValidUntil() time.Time { return authentication.validUntil }
func (authentication JITAuthentication) AssuranceEvidence() *identity.AssuranceEvidence {
	if authentication.assurance == nil {
		return nil
	}
	copyValue := *authentication.assurance
	if authentication.assurance.ExpiresAt != nil {
		expires := *authentication.assurance.ExpiresAt
		copyValue.ExpiresAt = &expires
	}
	if authentication.assurance.TrustRuleRevision != nil {
		revision := *authentication.assurance.TrustRuleRevision
		copyValue.TrustRuleRevision = &revision
	}
	return &copyValue
}
func (authentication JITAuthentication) SessionMaterial() SessionMaterial {
	return authentication.protectedSession
}

const (
	validatedReady uint32 = iota + 1
	validatedConsuming
	validatedConsumed
	validatedFailed
)

type ValidatedAuthentication struct {
	consumption ConsumptionRequest
	stage       atomic.Uint32
}

func (authentication *ValidatedAuthentication) JIT() JITAuthentication {
	if authentication == nil {
		return JITAuthentication{}
	}
	return cloneJITAuthentication(authentication.consumption.Authentication)
}

type LocalLogoutConfirmation interface {
	SAMLProvider() identity.ProviderContext
	SAMLBindingID() identity.EntityID
	LocalSessionID() identity.EntityID
	LocalSessionRevokedAt() time.Time
}

type LogoutRequest struct {
	redirectURL string
	requestID   string
	issuedAt    time.Time
	valid       bool
}

func (request LogoutRequest) RedirectURL() string { return request.redirectURL }
func (request LogoutRequest) RequestID() string   { return request.requestID }
func (request LogoutRequest) IssuedAt() time.Time { return request.issuedAt }

type LogoutBuildRequest struct {
	Configuration     Configuration
	SessionID         identity.EntityID
	MaterialID        identity.EntityID
	ProtectedMaterial ProtectedSessionMaterial
	Confirmation      LocalLogoutConfirmation
}

// StoredLogoutConfiguration is the bounded, provenance-addressed projection
// needed after local revocation. It deliberately excludes live metadata and
// provider readiness: a session may outlive either, while its pinned SLO
// endpoint and signing revision remain valid historical logout provenance.
type StoredLogoutConfiguration struct {
	Authority                  CeremonyAuthority
	Provider                   identity.ProviderContext
	MaterialBindingID          identity.EntityID
	PlatformLoginRevision      uint64
	SPEntityID                 string
	SLORedirectURL             string
	SPKeyRevision              uint64
	RedirectSignatureAlgorithm RedirectSignatureAlgorithm
}

type StoredLogoutBuildRequest struct {
	Configuration     StoredLogoutConfiguration
	SessionID         identity.EntityID
	MaterialID        identity.EntityID
	ProtectedMaterial ProtectedSessionMaterial
	Confirmation      LocalLogoutConfirmation
}
