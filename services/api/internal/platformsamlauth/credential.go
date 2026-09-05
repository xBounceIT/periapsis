package platformsamlauth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	maximumContinuationLifetime = 15 * time.Minute
	continuationDigestDomain    = "periapsis/platform-saml/continuation-receipt/v1"
)

// ContinuationReservation is constructor-only, purpose-specific material for
// the future direct-platform SAML TOTP continuation. It cannot be relabeled as
// a tenant or OIDC continuation.
type ContinuationReservation struct {
	continuationID identity.EntityID
	factorID       identity.EntityID
	factorRevision uint64
	receiptDigest  [sha256.Size]byte
	expiresAt      time.Time
}

type ContinuationMaterial struct {
	ContinuationID identity.EntityID
	FactorID       identity.EntityID
	FactorRevision uint64
	ReceiptDigest  [sha256.Size]byte
	ExpiresAt      time.Time
}

func NewContinuationReservation(material ContinuationMaterial, issuedAt time.Time) (ContinuationReservation, error) {
	if !validUUIDv7(material.ContinuationID) || !validUUIDv7(material.FactorID) ||
		material.ContinuationID == material.FactorID || !validRevision(material.FactorRevision) ||
		material.ReceiptDigest == ([sha256.Size]byte{}) || !validInstant(issuedAt) ||
		!validInstant(material.ExpiresAt) || !material.ExpiresAt.After(issuedAt) ||
		material.ExpiresAt.After(issuedAt.Add(maximumContinuationLifetime)) {
		return ContinuationReservation{}, ErrAuthenticationDenied
	}
	return ContinuationReservation{
		continuationID: material.ContinuationID, factorID: material.FactorID,
		factorRevision: material.FactorRevision, receiptDigest: material.ReceiptDigest,
		expiresAt: material.ExpiresAt,
	}, nil
}

func (reservation ContinuationReservation) ContinuationID() identity.EntityID {
	return reservation.continuationID
}

func (reservation ContinuationReservation) FactorID() identity.EntityID { return reservation.factorID }
func (reservation ContinuationReservation) FactorRevision() uint64      { return reservation.factorRevision }
func (reservation ContinuationReservation) ReceiptDigest() [sha256.Size]byte {
	return reservation.receiptDigest
}
func (reservation ContinuationReservation) ExpiresAt() time.Time { return reservation.expiresAt }
func (reservation ContinuationReservation) IsZero() bool {
	return reservation == (ContinuationReservation{})
}

func (reservation ContinuationReservation) ValidAt(issuedAt time.Time) bool {
	rebuilt, err := NewContinuationReservation(ContinuationMaterial{
		ContinuationID: reservation.continuationID, FactorID: reservation.factorID,
		FactorRevision: reservation.factorRevision, ReceiptDigest: reservation.receiptDigest,
		ExpiresAt: reservation.expiresAt,
	}, issuedAt)
	return err == nil && rebuilt == reservation
}

func (reservation ContinuationReservation) String() string {
	return "platformsamlauth.ContinuationReservation{material:[REDACTED]}"
}

func (reservation ContinuationReservation) GoString() string { return reservation.String() }

// ContinuationReceiptDigest binds the browser receipt to this authority and
// exact continuation row. Raw receipt bytes never cross AtomicApplyPort.
func ContinuationReceiptDigest(continuationID identity.EntityID, receipt []byte) ([sha256.Size]byte, error) {
	if !validUUIDv7(continuationID) || !validOpaqueCredential(receipt) {
		return [sha256.Size]byte{}, ErrAuthenticationDenied
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(continuationDigestDomain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(continuationID[:])
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(receipt)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

type BrowserCredentialKind string

const (
	BrowserSessionCredential      BrowserCredentialKind = "session"
	BrowserContinuationCredential BrowserCredentialKind = "continuation"
)

type BrowserCredentialMaterial struct {
	Kind           BrowserCredentialKind
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
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
	return fmt.Sprintf("platformsamlauth.BrowserCredentialMaterial{kind:%q,material:[REDACTED]}", material.Kind)
}

func (material BrowserCredentialMaterial) GoString() string { return material.String() }

// BrowserCredential owns plaintext until one successful caller consumes it.
// Copies of the pointer share the same one-use state.
type BrowserCredential struct {
	guard          sync.Mutex
	kind           BrowserCredentialKind
	sessionID      identity.EntityID
	continuationID identity.EntityID
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
		ContinuationID: credential.continuationID, ExpiresAt: credential.expiresAt,
		SessionToken: credential.sessionToken, CSRFToken: credential.csrfToken, Receipt: credential.receipt,
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
	return "platformsamlauth.BrowserCredential{authority:direct_platform_saml,material:[REDACTED]}"
}

func (credential *BrowserCredential) GoString() string { return credential.String() }

func (credential *BrowserCredential) validLocked() bool {
	switch credential.kind {
	case BrowserSessionCredential:
		return validUUIDv7(credential.sessionID) && credential.continuationID == (identity.EntityID{}) &&
			credential.expiresAt.IsZero() && validOpaqueCredential(credential.sessionToken) &&
			validOpaqueCredential(credential.csrfToken)
	case BrowserContinuationCredential:
		return credential.sessionID == (identity.EntityID{}) && validUUIDv7(credential.continuationID) &&
			validInstant(credential.expiresAt) && validOpaqueCredential(credential.receipt)
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
	credential.expiresAt = time.Time{}
	credential.sessionToken = nil
	credential.csrfToken = nil
	credential.receipt = nil
	credential.consumed = true
}

type CredentialRequest struct {
	Disposition Disposition
	TOTP        *TOTPSelection
	IssuedAt    time.Time
	Rotation    *SessionRotationAnchor
}

// SessionRotationAnchor prevents a policy-refresh rotation from silently
// resetting the absolute lifetime or moving to another rotation family.
type SessionRotationAnchor struct {
	SessionID         identity.EntityID
	FamilyID          identity.EntityID
	AbsoluteExpiresAt time.Time
}

// CredentialIssuer performs only local randomness and reservation. It must
// not load provider, identity, policy, or network state. Constructors copy
// browser plaintext into the returned reservation; the issuer still owns and
// must clear every source buffer it generated.
type CredentialIssuer interface {
	ReserveDirectSAMLCredential(CredentialRequest) (*CredentialReservation, error)
}

type CredentialReservation struct {
	guard        sync.Mutex
	session      mfa.SessionReservation
	continuation ContinuationReservation
	browser      *BrowserCredential
}

func NewSessionCredentialReservation(
	reservation mfa.SessionReservation,
	sessionToken []byte,
	csrfToken []byte,
) (*CredentialReservation, error) {
	if reservation.IsZero() || reservation.AuthenticationMethod() != mfa.SessionAuthenticationSAML ||
		!validOpaqueCredential(sessionToken) || !validOpaqueCredential(csrfToken) ||
		sha256.Sum256(sessionToken) != reservation.TokenDigest() ||
		sha256.Sum256(csrfToken) != reservation.CSRFDigest() {
		return nil, ErrAuthenticationDenied
	}
	return &CredentialReservation{
		session: reservation,
		browser: &BrowserCredential{
			kind: BrowserSessionCredential, sessionID: reservation.SessionID(),
			sessionToken: append([]byte(nil), sessionToken...), csrfToken: append([]byte(nil), csrfToken...),
		},
	}, nil
}

func NewContinuationCredentialReservation(
	reservation ContinuationReservation,
	receipt []byte,
) (*CredentialReservation, error) {
	digest, err := ContinuationReceiptDigest(reservation.ContinuationID(), receipt)
	if reservation.IsZero() || err != nil || digest != reservation.ReceiptDigest() {
		return nil, ErrAuthenticationDenied
	}
	return &CredentialReservation{
		continuation: reservation,
		browser: &BrowserCredential{
			kind: BrowserContinuationCredential, continuationID: reservation.ContinuationID(),
			expiresAt: reservation.ExpiresAt(), receipt: append([]byte(nil), receipt...),
		},
	}, nil
}

func (reservation *CredentialReservation) Session() mfa.SessionReservation {
	if reservation == nil {
		return mfa.SessionReservation{}
	}
	reservation.guard.Lock()
	defer reservation.guard.Unlock()
	return reservation.session
}

func (reservation *CredentialReservation) Continuation() ContinuationReservation {
	if reservation == nil {
		return ContinuationReservation{}
	}
	reservation.guard.Lock()
	defer reservation.guard.Unlock()
	return reservation.continuation
}

func (reservation *CredentialReservation) Destroy() {
	if reservation == nil {
		return
	}
	reservation.guard.Lock()
	defer reservation.guard.Unlock()
	if reservation.browser != nil {
		reservation.browser.Destroy()
	}
	reservation.session = mfa.SessionReservation{}
	reservation.continuation = ContinuationReservation{}
	reservation.browser = nil
}

func (reservation *CredentialReservation) String() string {
	return "platformsamlauth.CredentialReservation{authority:direct_platform_saml,material:[REDACTED]}"
}

func (reservation *CredentialReservation) GoString() string { return reservation.String() }

func (reservation *CredentialReservation) validFor(request CredentialRequest) bool {
	if reservation == nil || !validCredentialRequest(request) {
		return false
	}
	reservation.guard.Lock()
	defer reservation.guard.Unlock()
	if reservation.browser == nil {
		return false
	}
	reservation.browser.guard.Lock()
	defer reservation.browser.guard.Unlock()
	if reservation.browser.consumed || !reservation.browser.validLocked() {
		return false
	}
	switch request.Disposition {
	case ImmediateSession:
		return request.TOTP == nil && reservation.continuation.IsZero() &&
			reservation.session.ValidAt(request.IssuedAt.Truncate(time.Millisecond)) &&
			reservation.session.AuthenticationMethod() == mfa.SessionAuthenticationSAML &&
			validDirectSAMLRotationReservation(request.Rotation, reservation.session) &&
			reservation.browser.kind == BrowserSessionCredential &&
			reservation.browser.sessionID == reservation.session.SessionID()
	case TOTPContinuation:
		return request.TOTP != nil && reservation.session.IsZero() &&
			reservation.continuation.ValidAt(request.IssuedAt) &&
			reservation.continuation.FactorID() == request.TOTP.FactorID &&
			reservation.continuation.FactorRevision() == request.TOTP.Revision &&
			reservation.browser.kind == BrowserContinuationCredential &&
			reservation.browser.continuationID == reservation.continuation.ContinuationID()
	default:
		return false
	}
}

func (reservation *CredentialReservation) release(sessionID, continuationID identity.EntityID) (*BrowserCredential, bool) {
	if reservation == nil {
		return nil, false
	}
	reservation.guard.Lock()
	defer reservation.guard.Unlock()
	if reservation.browser == nil {
		return nil, false
	}
	reservation.browser.guard.Lock()
	valid := !reservation.browser.consumed && reservation.browser.validLocked()
	if valid {
		switch reservation.browser.kind {
		case BrowserSessionCredential:
			valid = reservation.continuation.IsZero() && !reservation.session.IsZero() &&
				reservation.session.SessionID() == sessionID && continuationID == (identity.EntityID{})
		case BrowserContinuationCredential:
			valid = reservation.session.IsZero() && !reservation.continuation.IsZero() &&
				sessionID == (identity.EntityID{}) && reservation.continuation.ContinuationID() == continuationID
		default:
			valid = false
		}
	}
	reservation.browser.guard.Unlock()
	if !valid {
		return nil, false
	}
	credential := reservation.browser
	reservation.session = mfa.SessionReservation{}
	reservation.continuation = ContinuationReservation{}
	reservation.browser = nil
	return credential, true
}

func validCredentialRequest(request CredentialRequest) bool {
	if !validInstant(request.IssuedAt) {
		return false
	}
	switch request.Disposition {
	case ImmediateSession:
		return request.TOTP == nil && validDirectSAMLRotationAnchor(request.Rotation, request.IssuedAt)
	case TOTPContinuation:
		return request.Rotation == nil && request.TOTP != nil &&
			validUUIDv7(request.TOTP.FactorID) && validRevision(request.TOTP.Revision)
	default:
		return false
	}
}

func validDirectSAMLRotationAnchor(anchor *SessionRotationAnchor, issuedAt time.Time) bool {
	return anchor == nil || validUUIDv7(anchor.SessionID) && validUUIDv7(anchor.FamilyID) &&
		anchor.SessionID != anchor.FamilyID && validInstant(anchor.AbsoluteExpiresAt) &&
		anchor.AbsoluteExpiresAt.After(issuedAt)
}

func validDirectSAMLRotationReservation(
	anchor *SessionRotationAnchor,
	reservation mfa.SessionReservation,
) bool {
	return anchor == nil || reservation.SessionID() != anchor.SessionID &&
		reservation.FamilyID() == anchor.FamilyID &&
		reservation.AbsoluteExpiresAt().Equal(anchor.AbsoluteExpiresAt)
}

func validOpaqueCredential(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	var decoded [sha256.Size]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	clear(decoded[:])
	return err == nil && written == sha256.Size && combined != 0
}
