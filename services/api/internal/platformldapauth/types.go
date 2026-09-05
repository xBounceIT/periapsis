// Package platformldapauth owns direct, tenantless LDAP authentication for
// existing platform users. Credentials and directory values are redacted at
// every formatting boundary.
package platformldapauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

var (
	ErrInvalidInput       = errors.New("platform LDAP authentication request rejected")
	ErrAuthentication     = errors.New("platform LDAP authentication failed")
	ErrRateLimited        = errors.New("platform LDAP authentication rate limited")
	ErrUnavailable        = errors.New("platform LDAP authentication unavailable")
	ErrReplayConflict     = errors.New("platform LDAP authentication replay conflict")
	ErrStaleConfiguration = errors.New("platform LDAP authentication configuration changed")
)

type Command struct {
	ProviderKey   string
	Username      string `json:"-"`
	Password      []byte `json:"-"`
	TOTPCode      []byte `json:"-"`
	ReturnPath    string
	ClientIP      netip.Addr
	UserAgent     string
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
}

func (command Command) String() string {
	return fmt.Sprintf(
		"platformldapauth.Command{provider:%t,returnPath:%t,material:[REDACTED]}",
		command.ProviderKey != "", command.ReturnPath != "",
	)
}

func (command Command) GoString() string { return command.String() }

type AuditMetadata struct {
	EventID              uuid.UUID
	RequestID            uuid.UUID
	CorrelationID        uuid.UUID
	ClientIP             netip.Addr
	UserAgent            string
	AuthenticationMethod string
}

type BeginRequest struct {
	RunID              uuid.UUID
	ReceiptDigest      [sha256.Size]byte
	NetworkRateDigest  [sha256.Size]byte
	AccountRateDigest  [sha256.Size]byte
	ProviderRateDigest [sha256.Size]byte
	ProviderKey        string
	Audit              AuditMetadata
}

type RunState string

const (
	RunPending   RunState = "pending"
	RunSucceeded RunState = "succeeded"
	RunDenied    RunState = "denied"
	RunFailed    RunState = "failed"
	RunStale     RunState = "stale"
)

type NetworkSnapshot struct {
	RunID                 uuid.UUID
	State                 RunState
	Allowed               bool
	FailureCategory       FailureCategory
	ProviderID            uuid.UUID
	ProviderVersion       int64
	ConfigurationRevision int64
	SecurityRevision      int64
	MappingRevision       int64
	Configuration         identityprovider.Configuration
	Endpoints             []identityprovider.Endpoint
	BindSecretID          uuid.UUID
	BindSecretRevision    int64
	BindSecret            identity.BindSecretEnvelope
	SessionID             identity.EntityID
	UserID                uuid.UUID
	CompletedAt           time.Time
}

func (snapshot *NetworkSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	clear(snapshot.BindSecret.Ciphertext)
	snapshot.BindSecret.Ciphertext = nil
	if snapshot.Configuration.CustomCAPEM != nil {
		*snapshot.Configuration.CustomCAPEM = ""
		snapshot.Configuration.CustomCAPEM = nil
	}
}

type LoadMFARequest struct {
	RunID                 uuid.UUID
	ProviderID            uuid.UUID
	ProviderVersion       int64
	ConfigurationRevision int64
	SecurityRevision      int64
	MappingRevision       int64
	ExternalIdentityID    uuid.UUID
	SubjectDigest         [sha256.Size]byte
	SubjectKeyVersion     int16
	Email                 *string
}

type TOTPFactor struct {
	ID                  uuid.UUID
	SecurityRevision    uint64
	Secret              platformoidcauth.DirectProtectedTOTPSecret
	LastAcceptedCounter *int64
}

func (factor *TOTPFactor) Destroy() {
	if factor == nil {
		return
	}
	factor.Secret.Destroy()
	if factor.LastAcceptedCounter != nil {
		*factor.LastAcceptedCounter = 0
	}
	*factor = TOTPFactor{}
}

type MappingMatcherType string

const (
	MappingExactDN MappingMatcherType = "exact_dn"
	MappingExactCN MappingMatcherType = "exact_cn"
	MappingRegex   MappingMatcherType = "regex"
)

type ReconciliationMode string

const (
	ReconciliationAuthoritative ReconciliationMode = "authoritative"
	ReconciliationAdditive      ReconciliationMode = "additive"
)

type Mapping struct {
	ID                 uuid.UUID
	MatcherType        MappingMatcherType
	MatcherValue       string `json:"-"`
	CaseSensitive      bool
	Priority           int
	PlatformRoleID     uuid.UUID
	PlatformRoleKey    string
	ReconciliationMode ReconciliationMode
}

func (mapping Mapping) String() string {
	return fmt.Sprintf("platformldapauth.Mapping{type:%q,priority:%d,role:%t,material:[REDACTED]}",
		mapping.MatcherType, mapping.Priority, mapping.PlatformRoleID != uuid.Nil)
}

func (mapping Mapping) GoString() string { return mapping.String() }

type MFASnapshot struct {
	RunID                      uuid.UUID
	UserID                     uuid.UUID
	UserAuthenticationRevision uint64
	ExternalIdentityID         uuid.UUID
	IdentityVersion            int64
	TOTP                       TOTPFactor
	Mappings                   []Mapping
}

func (snapshot *MFASnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	snapshot.TOTP.Destroy()
	clear(snapshot.Mappings)
	snapshot.Mappings = nil
}

type Profile struct {
	Username    string  `json:"-"`
	Email       *string `json:"-"`
	DisplayName string  `json:"-"`
	FirstName   *string `json:"-"`
	LastName    *string `json:"-"`
}

func (profile Profile) String() string {
	return fmt.Sprintf("platformldapauth.Profile{email:%t,first:%t,last:%t,material:[REDACTED]}",
		profile.Email != nil, profile.FirstName != nil, profile.LastName != nil)
}

func (profile Profile) GoString() string { return profile.String() }

type ApplyRequest struct {
	RunID                      uuid.UUID
	ProviderID                 uuid.UUID
	ProviderVersion            int64
	ConfigurationRevision      int64
	SecurityRevision           int64
	MappingRevision            int64
	UserID                     uuid.UUID
	UserAuthenticationRevision uint64
	ExternalIdentityID         uuid.UUID
	IdentityVersion            int64
	SubjectEnvelope            identity.ExternalSubjectEnvelope
	SubjectAlias               identity.SubjectAlias
	Profile                    Profile
	GroupsDigest               [sha256.Size]byte
	SelectedMappingIDs         []uuid.UUID
	TOTPFactorID               uuid.UUID
	TOTPSecurityRevision       uint64
	TOTPCounter                int64
	Session                    *federatedauth.ApplyCredentialReservation
	CompletedAt                time.Time
	ResultDigest               [sha256.Size]byte
	Audit                      AuditMetadata
}

type ApplyResult struct {
	RunID     uuid.UUID
	State     RunState
	SessionID identity.EntityID
	UserID    uuid.UUID
	Replayed  bool
}

type Result struct {
	RunID      uuid.UUID
	UserID     uuid.UUID
	SessionID  identity.EntityID
	ReturnPath string
	Replayed   bool
	Credential *federatedauth.BrowserCredential
}

func (result Result) String() string {
	return fmt.Sprintf("platformldapauth.Result{session:%t,replayed:%t,credential:%t,material:[REDACTED]}",
		result.SessionID != (identity.EntityID{}), result.Replayed, result.Credential != nil)
}

func (result Result) GoString() string { return result.String() }

type FailureCategory string

const (
	FailureCredentialsRejected FailureCategory = "credentials_rejected"
	FailureAccountDisabled     FailureCategory = "account_disabled"
	FailureIdentityUnmatched   FailureCategory = "identity_unmatched"
	FailureMappingUnmatched    FailureCategory = "mapping_unmatched"
	FailureMFARequired         FailureCategory = "mfa_required"
	FailureMFARejected         FailureCategory = "mfa_rejected"
	FailureRateLimited         FailureCategory = "rate_limited"
	FailureProviderUnavailable FailureCategory = "provider_unavailable"
	FailureProtocolFailed      FailureCategory = "protocol_failed"
	FailureStaleConfiguration  FailureCategory = "stale_configuration"
)

type FailureRequest struct {
	RunID    uuid.UUID
	Category FailureCategory
	Audit    AuditMetadata
}

type Repository interface {
	Begin(context.Context, BeginRequest) (NetworkSnapshot, error)
	LoadMFA(context.Context, LoadMFARequest) (MFASnapshot, error)
	Apply(context.Context, ApplyRequest) (ApplyResult, error)
	Fail(context.Context, FailureRequest) error
}

// DirectoryClient intentionally reuses the shared tenant LDAP adapter ABI.
type DirectoryClient = ldapauth.DirectoryClient
