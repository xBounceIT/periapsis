package federatedauth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const maximumPostPrimaryContinuationLifetime = 15 * time.Minute

// ContinuationAuthority identifies the only application flow allowed to
// redeem a post-primary continuation. The zero value deliberately preserves
// the deployed tenant-scoped v1 continuation ABI.
type ContinuationAuthority string

const (
	ContinuationAuthorityTenant             ContinuationAuthority = ""
	ContinuationAuthorityDirectPlatformOIDC ContinuationAuthority = "direct_platform_oidc"
	ContinuationAuthorityDirectPlatformSAML ContinuationAuthority = "direct_platform_saml"

	directPlatformOIDCContinuationDigestDomain = "periapsis/federated-continuation/direct-platform-oidc/v2"
	directPlatformSAMLContinuationDigestDomain = "periapsis/platform-saml/continuation-receipt/v1"
)

// ContinuationReceiptDigest binds direct-platform continuation receipts to
// their wire authority and identifier. Tenant v1 keeps its deployed
// receipt-only digest so existing in-flight tenant ceremonies remain valid.
func ContinuationReceiptDigest(
	authority ContinuationAuthority,
	continuationID identity.EntityID,
	receipt []byte,
) ([sha256.Size]byte, error) {
	if !validContinuationAuthority(authority) || !validApplyUUIDv7(continuationID) ||
		!validCanonicalOpaqueCredential(receipt) {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	if authority == ContinuationAuthorityTenant {
		return sha256.Sum256(receipt), nil
	}
	domain := directPlatformOIDCContinuationDigestDomain
	if authority == ContinuationAuthorityDirectPlatformSAML {
		domain = directPlatformSAMLContinuationDigestDomain
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(continuationID[:])
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(receipt)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

// PostPrimaryContinuationMaterial contains only a caller-reserved identifier
// and the digest of the one-use browser receipt. Plaintext receipt material
// must never cross the transactional persistence boundary.
type PostPrimaryContinuationMaterial struct {
	ContinuationID identity.EntityID
	Authority      ContinuationAuthority
	ReceiptDigest  [sha256.Size]byte
	ExpiresAt      time.Time
}

// PostPrimaryContinuationReservation is constructor-only material for one
// atomic federated-authentication apply.
type PostPrimaryContinuationReservation struct {
	continuationID identity.EntityID
	authority      ContinuationAuthority
	receiptDigest  [sha256.Size]byte
	expiresAt      time.Time
}

func NewPostPrimaryContinuationReservation(
	material PostPrimaryContinuationMaterial,
	issuedAt time.Time,
) (PostPrimaryContinuationReservation, error) {
	if !validApplyUUIDv7(material.ContinuationID) || !validContinuationAuthority(material.Authority) ||
		material.ReceiptDigest == ([sha256.Size]byte{}) || !validApplyInstant(issuedAt) ||
		!validApplyInstant(material.ExpiresAt) || !material.ExpiresAt.After(issuedAt) ||
		material.ExpiresAt.After(issuedAt.Add(maximumPostPrimaryContinuationLifetime)) {
		return PostPrimaryContinuationReservation{}, ErrInvalidInput
	}
	return PostPrimaryContinuationReservation{
		continuationID: material.ContinuationID,
		authority:      material.Authority,
		receiptDigest:  material.ReceiptDigest,
		expiresAt:      material.ExpiresAt,
	}, nil
}

func (reservation PostPrimaryContinuationReservation) ContinuationID() identity.EntityID {
	return reservation.continuationID
}

func (reservation PostPrimaryContinuationReservation) ReceiptDigest() [sha256.Size]byte {
	return reservation.receiptDigest
}

func (reservation PostPrimaryContinuationReservation) Authority() ContinuationAuthority {
	return reservation.authority
}

func (reservation PostPrimaryContinuationReservation) ExpiresAt() time.Time {
	return reservation.expiresAt
}

func (reservation PostPrimaryContinuationReservation) IsZero() bool {
	return reservation == PostPrimaryContinuationReservation{}
}

func (reservation PostPrimaryContinuationReservation) ValidAt(issuedAt time.Time) bool {
	if reservation.IsZero() {
		return false
	}
	rebuilt, err := NewPostPrimaryContinuationReservation(PostPrimaryContinuationMaterial{
		ContinuationID: reservation.continuationID,
		Authority:      reservation.authority,
		ReceiptDigest:  reservation.receiptDigest,
		ExpiresAt:      reservation.expiresAt,
	}, issuedAt)
	return err == nil && rebuilt == reservation
}

func (reservation PostPrimaryContinuationReservation) String() string {
	return "federatedauth.PostPrimaryContinuationReservation{material:[REDACTED]}"
}

func (reservation PostPrimaryContinuationReservation) GoString() string { return reservation.String() }

type BrowserCredentialKind string

const (
	BrowserCredentialSession      BrowserCredentialKind = "session"
	BrowserCredentialContinuation BrowserCredentialKind = "continuation"
)

// BrowserCredentialMaterial transfers ownership of one plaintext credential
// to the HTTP boundary. The receiver must call Destroy after constructing the
// response cookies. A material value is never safe to log or serialize.
type BrowserCredentialMaterial struct {
	Kind           BrowserCredentialKind
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	Authority      ContinuationAuthority
	ExpiresAt      time.Time
	SessionToken   []byte `json:"-"`
	CSRFToken      []byte `json:"-"`
	Receipt        []byte `json:"-"`
}

func (material *BrowserCredentialMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.SessionToken)
	clear(material.CSRFToken)
	clear(material.Receipt)
	*material = BrowserCredentialMaterial{}
}

func (material BrowserCredentialMaterial) String() string {
	return fmt.Sprintf("federatedauth.BrowserCredentialMaterial{kind:%q,material:[REDACTED]}", material.Kind)
}

func (material BrowserCredentialMaterial) GoString() string { return material.String() }

// BrowserCredential owns plaintext browser material until exactly one caller
// consumes it. Copies of the pointer share the same one-use state.
type BrowserCredential struct {
	guard          sync.Mutex
	kind           BrowserCredentialKind
	sessionID      identity.EntityID
	continuationID identity.EntityID
	authority      ContinuationAuthority
	expiresAt      time.Time
	sessionToken   []byte
	csrfToken      []byte
	receipt        []byte
	consumed       bool
}

func (credential *BrowserCredential) Consume() (BrowserCredentialMaterial, bool) {
	if credential == nil {
		return BrowserCredentialMaterial{}, false
	}
	credential.guard.Lock()
	defer credential.guard.Unlock()
	if credential.consumed || !credential.validLocked() {
		credential.destroyLocked()
		return BrowserCredentialMaterial{}, false
	}
	material := BrowserCredentialMaterial{
		Kind: credential.kind, SessionID: credential.sessionID,
		ContinuationID: credential.continuationID,
		Authority:      credential.authority,
		ExpiresAt:      credential.expiresAt,
		SessionToken:   credential.sessionToken, CSRFToken: credential.csrfToken,
		Receipt: credential.receipt,
	}
	credential.sessionToken = nil
	credential.csrfToken = nil
	credential.receipt = nil
	credential.consumed = true
	return material, true
}

func (credential *BrowserCredential) Destroy() {
	if credential == nil {
		return
	}
	credential.guard.Lock()
	defer credential.guard.Unlock()
	credential.destroyLocked()
}

func (credential *BrowserCredential) String() string {
	return "federatedauth.BrowserCredential{material:[REDACTED]}"
}

func (credential *BrowserCredential) GoString() string { return credential.String() }

func (credential *BrowserCredential) validForResult(sessionID, continuationID identity.EntityID) bool {
	if credential == nil {
		return false
	}
	credential.guard.Lock()
	defer credential.guard.Unlock()
	if credential.consumed || !credential.validLocked() {
		return false
	}
	switch credential.kind {
	case BrowserCredentialSession:
		return credential.sessionID == sessionID && continuationID == (identity.EntityID{})
	case BrowserCredentialContinuation:
		return sessionID == (identity.EntityID{}) && credential.continuationID == continuationID
	default:
		return false
	}
}

func (credential *BrowserCredential) validLocked() bool {
	switch credential.kind {
	case BrowserCredentialSession:
		return validApplyUUIDv7(credential.sessionID) && credential.continuationID == (identity.EntityID{}) &&
			credential.authority == ContinuationAuthorityTenant &&
			credential.expiresAt.IsZero() &&
			validCanonicalOpaqueCredential(credential.sessionToken) &&
			validCanonicalOpaqueCredential(credential.csrfToken)
	case BrowserCredentialContinuation:
		return credential.sessionID == (identity.EntityID{}) && validApplyUUIDv7(credential.continuationID) &&
			validContinuationAuthority(credential.authority) &&
			validApplyInstant(credential.expiresAt) &&
			validCanonicalOpaqueCredential(credential.receipt)
	default:
		return false
	}
}

func (credential *BrowserCredential) destroyLocked() {
	clear(credential.sessionToken)
	clear(credential.csrfToken)
	clear(credential.receipt)
	credential.kind = ""
	credential.sessionID = identity.EntityID{}
	credential.continuationID = identity.EntityID{}
	credential.authority = ContinuationAuthorityTenant
	credential.expiresAt = time.Time{}
	credential.sessionToken = nil
	credential.csrfToken = nil
	credential.receipt = nil
	credential.consumed = true
}

// ApplyCredentialReservation couples digest-only persistence material to its
// independently owned browser credential. It is constructor-only so a caller
// cannot pair arbitrary plaintext with unrelated digests.
type ApplyCredentialReservation struct {
	session      mfa.SessionReservation
	continuation PostPrimaryContinuationReservation
	browser      *BrowserCredential
}

func NewSessionApplyCredentialReservation(
	reservation mfa.SessionReservation,
	sessionToken []byte,
	csrfToken []byte,
) (*ApplyCredentialReservation, error) {
	if reservation.IsZero() || !validCanonicalOpaqueCredential(sessionToken) ||
		!validCanonicalOpaqueCredential(csrfToken) || sha256.Sum256(sessionToken) != reservation.TokenDigest() ||
		sha256.Sum256(csrfToken) != reservation.CSRFDigest() {
		return nil, ErrInvalidInput
	}
	return &ApplyCredentialReservation{
		session: reservation,
		browser: &BrowserCredential{
			kind: BrowserCredentialSession, sessionID: reservation.SessionID(),
			sessionToken: append([]byte(nil), sessionToken...), csrfToken: append([]byte(nil), csrfToken...),
		},
	}, nil
}

func NewContinuationApplyCredentialReservation(
	reservation PostPrimaryContinuationReservation,
	receipt []byte,
) (*ApplyCredentialReservation, error) {
	digest, err := ContinuationReceiptDigest(reservation.Authority(), reservation.ContinuationID(), receipt)
	if reservation.IsZero() || err != nil || digest != reservation.ReceiptDigest() {
		return nil, ErrInvalidInput
	}
	return &ApplyCredentialReservation{
		continuation: reservation,
		browser: &BrowserCredential{
			kind: BrowserCredentialContinuation, continuationID: reservation.ContinuationID(),
			authority: reservation.Authority(),
			expiresAt: reservation.ExpiresAt(), receipt: append([]byte(nil), receipt...),
		},
	}, nil
}

func (reservation *ApplyCredentialReservation) Session() mfa.SessionReservation {
	if reservation == nil {
		return mfa.SessionReservation{}
	}
	return reservation.session
}

func (reservation *ApplyCredentialReservation) Continuation() PostPrimaryContinuationReservation {
	if reservation == nil {
		return PostPrimaryContinuationReservation{}
	}
	return reservation.continuation
}

func (reservation *ApplyCredentialReservation) Destroy() {
	if reservation == nil {
		return
	}
	if reservation.browser != nil {
		reservation.browser.Destroy()
	}
	reservation.session = mfa.SessionReservation{}
	reservation.continuation = PostPrimaryContinuationReservation{}
	reservation.browser = nil
}

func (reservation *ApplyCredentialReservation) release() *BrowserCredential {
	if reservation == nil {
		return nil
	}
	credential := reservation.browser
	reservation.session = mfa.SessionReservation{}
	reservation.continuation = PostPrimaryContinuationReservation{}
	reservation.browser = nil
	return credential
}

// ReleaseBrowserCredential transfers the one-use browser material only when
// the already-applied result identifies the exact reserved session or
// continuation. Persistence/application code remains responsible for calling
// this only after the corresponding atomic mutation commits.
func (reservation *ApplyCredentialReservation) ReleaseBrowserCredential(
	sessionID identity.EntityID,
	continuationID identity.EntityID,
) (*BrowserCredential, bool) {
	if reservation == nil || reservation.browser == nil {
		return nil, false
	}
	reservation.browser.guard.Lock()
	valid := !reservation.browser.consumed && reservation.browser.validLocked()
	if valid {
		switch reservation.browser.kind {
		case BrowserCredentialSession:
			valid = !reservation.session.IsZero() && reservation.continuation.IsZero() &&
				reservation.session.SessionID() == sessionID && continuationID == (identity.EntityID{}) &&
				reservation.browser.sessionID == sessionID
		case BrowserCredentialContinuation:
			valid = reservation.session.IsZero() && !reservation.continuation.IsZero() &&
				sessionID == (identity.EntityID{}) && reservation.continuation.ContinuationID() == continuationID &&
				reservation.browser.continuationID == continuationID
		default:
			valid = false
		}
	}
	reservation.browser.guard.Unlock()
	if !valid {
		return nil, false
	}
	return reservation.release(), true
}

func (reservation *ApplyCredentialReservation) validFor(request ApplyCredentialRequest) bool {
	if reservation == nil || reservation.browser == nil || !validApplyCredentialRequest(request) {
		return false
	}
	reservation.browser.guard.Lock()
	defer reservation.browser.guard.Unlock()
	if reservation.browser.consumed || !reservation.browser.validLocked() {
		return false
	}
	switch request.Disposition {
	case ApplySession:
		return reservation.continuation.IsZero() && reservation.session.ValidAt(request.IssuedAt.Truncate(time.Millisecond)) &&
			string(reservation.session.AuthenticationMethod()) == string(request.Method) &&
			reservation.browser.kind == BrowserCredentialSession &&
			reservation.browser.sessionID == reservation.session.SessionID() &&
			validRotationReservation(request.Rotation, reservation.session)
	case ApplyContinuation:
		return reservation.session.IsZero() && reservation.continuation.ValidAt(request.IssuedAt) &&
			reservation.continuation.Authority() == request.ContinuationAuthority &&
			reservation.browser.kind == BrowserCredentialContinuation &&
			reservation.browser.authority == request.ContinuationAuthority &&
			reservation.browser.continuationID == reservation.continuation.ContinuationID()
	default:
		return false
	}
}

func validRotationReservation(anchor *SessionRotationAnchor, reservation mfa.SessionReservation) bool {
	if anchor == nil {
		return true
	}
	return reservation.SessionID() != anchor.SessionID && reservation.FamilyID() == anchor.FamilyID &&
		reservation.AbsoluteExpiresAt().Equal(anchor.AbsoluteExpiresAt)
}

func (reservation *ApplyCredentialReservation) String() string {
	return "federatedauth.ApplyCredentialReservation{material:[REDACTED]}"
}

func (reservation *ApplyCredentialReservation) GoString() string { return reservation.String() }

type ApplyCredentialRequest struct {
	Disposition           ApplyDisposition
	Method                AuthenticationMethod
	ContinuationAuthority ContinuationAuthority
	IssuedAt              time.Time
	Rotation              *SessionRotationAnchor
}

type SessionRotationAnchor struct {
	SessionID         identity.EntityID
	FamilyID          identity.EntityID
	AbsoluteExpiresAt time.Time
}

type ApplyCredentialIssuer interface {
	ReserveApplyCredential(ApplyCredentialRequest) (*ApplyCredentialReservation, error)
}

func validApplyCredentialRequest(request ApplyCredentialRequest) bool {
	if !validApplyInstant(request.IssuedAt) {
		return false
	}
	switch request.Method {
	case AuthenticationMethodOIDC, AuthenticationMethodSAML, AuthenticationMethodPasskey, AuthenticationMethodLDAP:
	default:
		return false
	}
	if request.Disposition == ApplyContinuation {
		if request.Rotation != nil || !validContinuationAuthority(request.ContinuationAuthority) {
			return false
		}
		switch request.ContinuationAuthority {
		case ContinuationAuthorityTenant:
			return true
		case ContinuationAuthorityDirectPlatformOIDC:
			return request.Method == AuthenticationMethodOIDC
		case ContinuationAuthorityDirectPlatformSAML:
			return request.Method == AuthenticationMethodSAML
		default:
			return false
		}
	}
	if request.Disposition != ApplySession {
		return false
	}
	if request.ContinuationAuthority != ContinuationAuthorityTenant {
		return false
	}
	return request.Rotation == nil ||
		validApplyUUIDv7(request.Rotation.SessionID) && validApplyUUIDv7(request.Rotation.FamilyID) &&
			request.Rotation.SessionID != request.Rotation.FamilyID && validApplyInstant(request.Rotation.AbsoluteExpiresAt) &&
			request.Rotation.AbsoluteExpiresAt.After(request.IssuedAt)
}

func validContinuationAuthority(authority ContinuationAuthority) bool {
	return authority == ContinuationAuthorityTenant || authority == ContinuationAuthorityDirectPlatformOIDC ||
		authority == ContinuationAuthorityDirectPlatformSAML
}

func validCanonicalOpaqueCredential(value []byte) bool {
	if len(value) != 43 {
		return false
	}
	var decoded [sha256.Size]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	clear(decoded[:])
	return err == nil && written == len(decoded) && combined != 0
}

func validApplyUUIDv7(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func validApplyInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
