// Package identitysync orchestrates bounded LDAP synchronization without
// holding database transactions across directory network operations.
package identitysync

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

const (
	maximumStagedObservations = 5_000
	maximumSubjectAliases     = 16
	workerUserAgent           = "Periapsis LDAP sync worker"
)

var (
	// ErrClaimLost means that a newer fencing epoch owns the run. The old
	// worker must stop without attempting another mutation.
	ErrClaimLost = errors.New("LDAP sync claim lost")
	// ErrInvalidSnapshot combines malformed, inconsistent, and out-of-bound
	// database projections without reflecting any customer value.
	ErrInvalidSnapshot = errors.New("invalid LDAP sync snapshot")
)

type runFailure struct {
	category string
	cause    error
}

func (failure runFailure) Error() string {
	return "LDAP sync " + failure.category
}

func (failure runFailure) Unwrap() error {
	return failure.cause
}

func categorizedFailure(category string, cause error) error {
	return runFailure{category: category, cause: cause}
}

// ClaimProof is generated once per claim attempt. Only ReceiptDigest crosses
// the database boundary; the opaque receipt is cleared immediately after its
// SHA-256 digest is produced.
type ClaimProof struct {
	ID            uuid.UUID
	ReceiptDigest [sha256.Size]byte
}

type SnapshotConfiguration struct {
	Template                   string  `json:"template"`
	VerifyCertificate          bool    `json:"verifyCertificate"`
	CustomCAPEM                *string `json:"customCaPem"`
	ConnectTimeoutMS           int     `json:"connectTimeoutMs"`
	OperationTimeoutMS         int     `json:"operationTimeoutMs"`
	BindDN                     string  `json:"bindDn"`
	UserBaseDN                 string  `json:"userBaseDn"`
	GroupBaseDN                *string `json:"groupBaseDn"`
	UserSearchFilter           string  `json:"userSearchFilter"`
	GroupSearchFilter          *string `json:"groupSearchFilter"`
	PageSize                   int     `json:"pageSize"`
	MaxPages                   int     `json:"maxPages"`
	MaxEntries                 int     `json:"maxEntries"`
	MaxResponseBytes           int     `json:"maxResponseBytes"`
	ReferralMode               string  `json:"referralMode"`
	MaxReferralHops            int     `json:"maxReferralHops"`
	NestedGroupMode            string  `json:"nestedGroupMode"`
	MaxNestedGroupDepth        int     `json:"maxNestedGroupDepth"`
	MaxGroups                  int     `json:"maxGroups"`
	FirstNameAttribute         string  `json:"firstNameAttribute"`
	LastNameAttribute          string  `json:"lastNameAttribute"`
	DisplayNameAttribute       string  `json:"displayNameAttribute"`
	UsernameAttribute          string  `json:"usernameAttribute"`
	AlternateUsernameAttribute *string `json:"alternateUsernameAttribute"`
	EmailAttribute             *string `json:"emailAttribute"`
	ImmutableSubjectAttribute  string  `json:"immutableSubjectAttribute"`
	ImmutableSubjectFormat     string  `json:"immutableSubjectFormat"`
	GroupMembershipAttribute   *string `json:"groupMembershipAttribute"`
	POSIXMemberUIDAttribute    *string `json:"posixMemberUidAttribute"`
	POSIXGIDNumberAttribute    *string `json:"posixGidNumberAttribute"`
	AccountStatusMode          string  `json:"accountStatusMode"`
	AccountStatusAttribute     *string `json:"accountStatusAttribute"`
	AccountDisabledValue       *string `json:"accountDisabledValue"`
	JITMode                    string  `json:"jitMode"`
	NoMatchPolicy              string  `json:"noMatchPolicy"`
	DeprovisionMode            string  `json:"deprovisionMode"`
	DeprovisionGraceSeconds    int     `json:"deprovisionGraceSeconds"`
	SyncIntervalSeconds        *int    `json:"syncIntervalSeconds"`
}

type SnapshotEndpoint struct {
	Priority        int                  `json:"priority"`
	Host            string               `json:"host"`
	Port            uint16               `json:"port"`
	Transport       ldapclient.Transport `json:"transport"`
	TLSServerName   string               `json:"tlsServerName"`
	ReferralAllowed bool                 `json:"referralAllowed"`
	Enabled         bool                 `json:"enabled"`
}

type PinnedMappingRevision struct {
	MappingID            uuid.UUID `json:"mappingId"`
	MappingVersion       int64     `json:"mappingVersion"`
	ConfigurationVersion int64     `json:"configurationRevision"`
	SourceEpochID        uuid.UUID `json:"sourceEpochId"`
	SourceID             uuid.UUID `json:"sourceId"`
	Priority             int32     `json:"priority"`
}

type StagedObservation struct {
	ObservationID      uuid.UUID  `json:"observationId"`
	Ordinal            int        `json:"ordinal"`
	DigestKeyVersion   int16      `json:"digestKeyVersion"`
	SubjectDigest      [32]byte   `json:"-"`
	ObservationDigest  [32]byte   `json:"-"`
	ExternalIdentityID *uuid.UUID `json:"externalIdentityId"`
	PlanningFence      *int64     `json:"planningFence"`
	Applied            bool       `json:"applied"`
}

// Claim is the complete immutable database snapshot for one fenced run.
// String intentionally reveals identifiers and safe state only.
type Claim struct {
	Proof                  ClaimProof
	RunID                  uuid.UUID
	TenantID               uuid.UUID
	Fence                  int64
	ExpiresAt              time.Time
	Status                 string
	Version                int
	ProviderID             uuid.UUID
	ProviderVersion        int
	ConfigurationVersion   int
	EndpointSnapshotDigest [32]byte
	Configuration          SnapshotConfiguration
	Endpoints              []SnapshotEndpoint
	SecretID               uuid.UUID
	SecretCiphertext       []byte
	SecretNonce            [12]byte
	SecretVersion          int
	SecretKeyVersion       int16
	SecretAlgorithm        string
	BindingID              uuid.UUID
	BindingVersion         int
	BindingAuthRevision    int
	BindingAccessEpochID   uuid.UUID
	RuleSetRevision        int64
	AuthorizationRevision  int64
	MappingRevisions       []PinnedMappingRevision
	Staged                 []StagedObservation
	QueuedAt               time.Time
	EnumerationStartedAt   *time.Time
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"identitysync.Claim{runID:%s,tenantID:%s,status:%s,version:%d,fence:%d,staged:%d,values:[REDACTED]}",
		claim.RunID, claim.TenantID, claim.Status, claim.Version, claim.Fence, len(claim.Staged),
	)
}

// ClearSensitive destroys retained ciphertext and nonce bytes once a run is
// terminal or relinquished.
func (claim *Claim) ClearSensitive() {
	if claim == nil {
		return
	}
	clear(claim.SecretCiphertext)
	claim.SecretCiphertext = nil
	clear(claim.SecretNonce[:])
}

type EnumerationCompletion struct {
	Status         string
	Version        int
	ObservedCount  int
	AbsenceAllowed bool
}

type PlanningProjection struct {
	RunID                    uuid.UUID
	ObservationID            uuid.UUID
	TenantID                 uuid.UUID
	Fence                    int64
	ProviderID               uuid.UUID
	ProviderVersion          int
	BindingID                uuid.UUID
	BindingVersion           int
	BindingAuthRevision      int
	BindingAccessEpochID     uuid.UUID
	ConfigurationRevision    int64
	RuleSetRevision          int64
	AuthorizationRevision    int64
	JITMode                  string
	NoMatchPolicy            string
	ProviderAccessSourceID   uuid.UUID
	ExternalIdentityID       *uuid.UUID
	UserID                   *uuid.UUID
	MembershipID             *uuid.UUID
	AccessGrantID            *uuid.UUID
	ExternalIdentityExists   bool
	UserActive               bool
	TenantMembershipExists   bool
	TenantMembershipActive   bool
	AccessGrantLive          bool
	Rules                    []byte
	SecurityGroups           []byte
	LiveAssignments          []byte
	RolePolicies             []byte
	ExistingEffectiveRoleIDs []uuid.UUID
	Delegation               []byte
	LiveOwnedEdges           []byte
}

type ApplyRequest struct {
	ObservationID  uuid.UUID
	ApplicationID  uuid.UUID
	PlanDigest     [32]byte
	Decision       string
	DenialCategory *string
	// Existing* IDs are proof inputs for a denied reconciliation. They are
	// deliberately separate from the admitted identity/access material below:
	// a denied plan can revoke an already-proven access path, but can never use
	// these values to create or grant one.
	ExistingExternalIdentityID *uuid.UUID
	ExistingUserID             *uuid.UUID
	ExistingMembershipID       *uuid.UUID
	ExistingAccessGrantID      *uuid.UUID
	RevocationEpochIDs         []uuid.UUID
	ExternalIdentityID         *uuid.UUID
	UserID                     *uuid.UUID
	MembershipID               *uuid.UUID
	AccessGrantID              *uuid.UUID
	ProfileContributionID      *uuid.UUID
	SubjectFormat              *string
	SubjectCiphertext          []byte
	SubjectNonce               []byte
	SubjectKeyVersion          *int16
	AliasIDs                   []uuid.UUID
	AliasKeyVersions           []int16
	AliasDigests               [][]byte
	DisplayName                *string
	FirstName                  *string
	LastName                   *string
	Username                   *string
	Email                      *string
	MatchedEpochIDs            []uuid.UUID
	ObservedAt                 time.Time
	AuditEventID               uuid.UUID
	RequestID                  uuid.UUID
	CorrelationID              uuid.UUID
}

func (request *ApplyRequest) ClearSensitive() {
	if request == nil {
		return
	}
	clear(request.SubjectCiphertext)
	request.SubjectCiphertext = nil
	clear(request.SubjectNonce)
	request.SubjectNonce = nil
	for _, digest := range request.AliasDigests {
		clear(digest)
	}
	request.AliasDigests = nil
}

type ApplyResult struct {
	ApplicationID      uuid.UUID
	Decision           string
	ExternalIdentityID *uuid.UUID
	UserID             *uuid.UUID
	MembershipID       *uuid.UUID
	AccessGrantID      *uuid.UUID
	EnsuredEdges       int
	RevokedEdges       int
	Replayed           bool
}

type AbsenceResult struct {
	Inspected int
	Revoked   int
	Remaining int
}

type TerminalResult struct {
	Status   string
	Version  int
	Replayed bool
}

type AuditIDs struct {
	EventID       uuid.UUID
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
}

// Repository is the narrow v13 worker ABI. Each method is one short database
// transaction and installs tenant context from Claim only after the initial
// tenant-derived claim has succeeded.
type Repository interface {
	Claim(context.Context, ClaimProof, int) (*Claim, error)
	Stage(context.Context, Claim, StagedObservation) (*uuid.UUID, error)
	CompleteEnumeration(
		context.Context, Claim, int, bool, bool, *[32]byte, *string, AuditIDs,
	) (EnumerationCompletion, error)
	Planning(context.Context, Claim, uuid.UUID, []identity.SubjectAlias) (PlanningProjection, error)
	Apply(context.Context, Claim, ApplyRequest) (ApplyResult, error)
	ApplyAbsence(context.Context, Claim, int, AuditIDs) (AbsenceResult, error)
	Complete(context.Context, Claim, int, AuditIDs) (int, error)
	Fail(context.Context, Claim, int, string, AuditIDs) (TerminalResult, error)
}

// DirectoryClient is implemented by ldapclient.Client. Both methods take
// ownership of bindSecret and must clear its backing array on every path.
type DirectoryClient interface {
	EnumerateDirectoryUsers(
		context.Context, ldapclient.DirectoryEnumerationRequest, []byte,
	) (ldapclient.DirectoryEnumerationResult, error)
	ObserveDirectory(
		context.Context, ldapclient.DirectoryRequest, []byte,
	) (ldapclient.DirectoryResult, error)
}
