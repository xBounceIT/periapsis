package authentication

import (
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// EventContext contains bounded attribution fields, never credentials or login identifiers.
type EventContext struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	RemoteAddress netip.Addr
	UserAgent     string
}

type User struct {
	ID          uuid.UUID
	Email       *string
	DisplayName string
}

type Session struct {
	ID                   uuid.UUID
	RotationFamilyID     uuid.UUID
	User                 User
	CSRFDigest           []byte
	Permissions          []authorization.Permission
	ActiveTenantID       *uuid.UUID
	CreatedAt            time.Time
	LastSeenAt           time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	RevokedAt            *time.Time
	AuthenticationMethod string
}

// SessionCredential contains plaintext credentials only for immediate HTTP delivery.
type SessionCredential struct {
	Session      Session
	SessionToken string
	CSRFToken    string
}

// MFABrowserCredentialMaterial transfers ownership of plaintext credentials to
// the HTTP boundary. Call Destroy after constructing the response cookies.
type MFABrowserCredentialMaterial struct {
	SessionToken []byte `json:"-"`
	CSRFToken    []byte `json:"-"`
}

func (material *MFABrowserCredentialMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.SessionToken)
	clear(material.CSRFToken)
	*material = MFABrowserCredentialMaterial{}
}

func (material MFABrowserCredentialMaterial) String() string {
	return "authentication.MFABrowserCredentialMaterial{material:[REDACTED]}"
}

func (material MFABrowserCredentialMaterial) GoString() string { return material.String() }

type mfaBrowserCredential struct {
	guard        sync.Mutex
	sessionToken []byte
	csrfToken    []byte
	consumed     bool
}

// MFASessionReservation couples digest-only persistence material to a shared,
// one-use plaintext owner. Copies share the same consume/destroy state.
type MFASessionReservation struct {
	Reservation mfa.SessionReservation
	browser     *mfaBrowserCredential
}

func NewMFASessionReservation(
	reservation mfa.SessionReservation,
	sessionToken []byte,
	csrfToken []byte,
) (MFASessionReservation, error) {
	if reservation.IsZero() || !validOpaqueTokenBytes(sessionToken) ||
		!validOpaqueTokenBytes(csrfToken) || sha256.Sum256(sessionToken) != reservation.TokenDigest() ||
		sha256.Sum256(csrfToken) != reservation.CSRFDigest() {
		return MFASessionReservation{}, ErrInvalidInput
	}
	return MFASessionReservation{
		Reservation: reservation,
		browser: &mfaBrowserCredential{
			sessionToken: append([]byte(nil), sessionToken...),
			csrfToken:    append([]byte(nil), csrfToken...),
		},
	}, nil
}

func (reservation MFASessionReservation) Consume() (MFABrowserCredentialMaterial, bool) {
	if reservation.browser == nil {
		return MFABrowserCredentialMaterial{}, false
	}
	reservation.browser.guard.Lock()
	defer reservation.browser.guard.Unlock()
	if reservation.browser.consumed || !reservation.validLocked() {
		reservation.destroyLocked()
		return MFABrowserCredentialMaterial{}, false
	}
	material := MFABrowserCredentialMaterial{
		SessionToken: reservation.browser.sessionToken,
		CSRFToken:    reservation.browser.csrfToken,
	}
	reservation.browser.sessionToken = nil
	reservation.browser.csrfToken = nil
	reservation.browser.consumed = true
	return material, true
}

func (reservation MFASessionReservation) Destroy() {
	if reservation.browser == nil {
		return
	}
	reservation.browser.guard.Lock()
	defer reservation.browser.guard.Unlock()
	reservation.destroyLocked()
}

func (reservation MFASessionReservation) validLocked() bool {
	return !reservation.Reservation.IsZero() &&
		validOpaqueTokenBytes(reservation.browser.sessionToken) &&
		validOpaqueTokenBytes(reservation.browser.csrfToken) &&
		sha256.Sum256(reservation.browser.sessionToken) == reservation.Reservation.TokenDigest() &&
		sha256.Sum256(reservation.browser.csrfToken) == reservation.Reservation.CSRFDigest()
}

func validOpaqueTokenBytes(value []byte) bool {
	if len(value) != 43 {
		return false
	}
	var decoded [tokenBytes]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	clear(decoded[:])
	return err == nil && written == len(decoded) && combined != 0
}

func (reservation MFASessionReservation) destroyLocked() {
	clear(reservation.browser.sessionToken)
	clear(reservation.browser.csrfToken)
	reservation.browser.sessionToken = nil
	reservation.browser.csrfToken = nil
	reservation.browser.consumed = true
}

func (reservation MFASessionReservation) String() string {
	return "authentication.MFASessionReservation{material:[REDACTED]}"
}

func (reservation MFASessionReservation) GoString() string { return reservation.String() }

type SessionSummary struct {
	ID                   uuid.UUID
	Current              bool
	CreatedAt            time.Time
	LastSeenAt           time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	RevokedAt            *time.Time
	AuthenticationMethod string
}

type SessionPage struct {
	Items      []SessionSummary
	NextCursor *uuid.UUID
}

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	Status    string
	Timezone  string
	Locale    string
	Version   int32
	CreatedAt time.Time
	UpdatedAt time.Time
}

type TenantMembership struct {
	ID     uuid.UUID
	Tenant Tenant
	Role   string
}

type TenantMembershipPage struct {
	Items      []TenantMembership
	NextCursor *uuid.UUID
}

type BootstrapEnrollment struct {
	EnrollmentToken string
	ExpiresAt       time.Time
	TOTPSecret      string
	TOTPURI         string
}

type BootstrapConfirmation struct {
	EnrollmentToken string
	Email           string
	DisplayName     string
	Password        string
	Code            string
	Event           EventContext
}

type BootstrapResult struct {
	Credential    SessionCredential
	RecoveryCodes []string
}

type MFAChallenge struct {
	ChallengeToken string
	ExpiresAt      time.Time
	Methods        []string
}

type LocalCredential struct {
	User         User
	PasswordHash string
	Enabled      bool
}

type StoredBootstrapEnrollment struct {
	ID             uuid.UUID
	CanonicalEmail string
	EncryptedTOTP  EncryptedSecret
	ExpiresAt      time.Time
}

type StoredMFAChallenge struct {
	ID                  uuid.UUID
	User                User
	EncryptedTOTP       EncryptedSecret
	TOTPContextID       uuid.UUID
	LastAcceptedCounter int64
	ExpiresAt           time.Time
	Attempts            int32
	MaxAttempts         int32
}

type SessionMaterial struct {
	ID                   uuid.UUID
	FamilyID             uuid.UUID
	TokenDigest          []byte
	CSRFDigest           []byte
	CreatedAt            time.Time
	LastSeenAt           time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	AuthenticationMethod string
}

type RecoveryCodeMaterial struct {
	ID     uuid.UUID
	Digest []byte
}

type RateLimitKey struct {
	Scope  string
	Digest []byte
}

type RateLimitPolicy struct {
	Limit    int32
	Window   time.Duration
	BlockFor time.Duration
}
