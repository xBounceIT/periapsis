// Package ldapauth owns the anonymous interactive LDAP authentication use
// case. Directory passwords never cross its network boundary and every public
// formatter is intentionally redacted.
package ldapauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

var (
	ErrInvalidInput   = errors.New("LDAP authentication request rejected")
	ErrAuthentication = errors.New("LDAP authentication failed")
	ErrRateLimited    = errors.New("LDAP authentication rate limited")
	ErrUnavailable    = errors.New("LDAP authentication unavailable")
)

type Command struct {
	TenantSlug    string
	LoginKey      string
	Username      string `json:"-"`
	Password      []byte `json:"-"`
	ReturnPath    string
	ClientIP      netip.Addr
	UserAgent     string
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
}

func (command Command) String() string {
	return fmt.Sprintf("ldapauth.Command{tenant:%t,provider:%t,returnPath:%t,material:[REDACTED]}",
		command.TenantSlug != "", command.LoginKey != "", command.ReturnPath != "")
}
func (command Command) GoString() string { return command.String() }

type AuditMetadata struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	ClientIP      netip.Addr
	UserAgent     string
}

type BeginRequest struct {
	OperationRunID  uuid.UUID
	ReceiptDigest   [sha256.Size]byte
	TenantSlug      string
	LoginKey        string
	NetworkRateKey  [sha256.Size]byte
	AccountRateKey  [sha256.Size]byte
	ProviderRateKey [sha256.Size]byte
	AuditEventID    uuid.UUID
	Audit           AuditMetadata
}

type NetworkSnapshot struct {
	OperationRunID        uuid.UUID
	TenantID              uuid.UUID
	ProviderID            uuid.UUID
	ProviderVersion       int64
	ConfigurationVersion  int64
	Configuration         identityprovider.Configuration
	Endpoints             []identityprovider.Endpoint
	SecretID              uuid.UUID
	Secret                identity.BindSecretEnvelope
	BindingID             uuid.UUID
	BindingVersion        int64
	BindingAuthRevision   int64
	RuleSetRevision       int64
	AuthorizationRevision int64
	StartedAt             time.Time
	ExpiresAt             time.Time
}

func (snapshot *NetworkSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	clear(snapshot.Secret.Ciphertext)
	snapshot.Secret.Ciphertext = nil
	if snapshot.Configuration.CustomCAPEM != nil {
		snapshot.Configuration.CustomCAPEM = nil
	}
}

type ClaimRequest struct {
	OperationRunID uuid.UUID
	ReceiptDigest  [sha256.Size]byte
	SubjectAliases []identity.SubjectAlias
	EvaluatedAt    time.Time
	AuditEventID   uuid.UUID
	Audit          AuditMetadata
}

type Claim struct {
	AccessGrantID       uuid.UUID
	OperationRunID      uuid.UUID
	TenantID            uuid.UUID
	ProviderID          uuid.UUID
	BindingID           uuid.UUID
	BindingAuthRevision int64
	ExternalIdentityID  uuid.UUID
	UserID              uuid.UUID
	MembershipID        uuid.UUID
	Planning            identity.LDAPPlanningSnapshot
	Requirement         identity.EffectiveAssuranceRequirement
	HasEnrollableFactor bool
}

type ApplyRequest struct {
	OperationRunID        uuid.UUID
	ReceiptDigest         [sha256.Size]byte
	ApplicationID         uuid.UUID
	AuditEventID          uuid.UUID
	AuthorityAuditID      uuid.UUID
	Audit                 AuditMetadata
	ObservedAt            time.Time
	ReturnPath            string
	ExternalIdentityID    uuid.UUID
	UserID                uuid.UUID
	MembershipID          uuid.UUID
	AccessGrantID         uuid.UUID
	ProfileContributionID uuid.UUID
	AliasIDs              []uuid.UUID
	SubjectFormat         identity.SubjectFormat
	SubjectEnvelope       identity.ExternalSubjectEnvelope
	SubjectAliases        []identity.SubjectAlias
	Planning              identity.LDAPPlanningSnapshot
	Plan                  identity.LDAPMappingPlan
	Assurance             identity.AssuranceDecision
	Evidence              identity.AssuranceEvidence
	Session               *federatedauth.ApplyCredentialReservation
	Continuation          *federatedauth.ApplyCredentialReservation
}

type ApplyResult struct {
	UserID         uuid.UUID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	Replayed       bool
}

type Result struct {
	UserID         uuid.UUID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	Credential     *federatedauth.BrowserCredential
}

func (result Result) String() string {
	return fmt.Sprintf("ldapauth.Result{session:%t,continuation:%t,credential:%t,material:[REDACTED]}",
		result.SessionID != (identity.EntityID{}), result.ContinuationID != (identity.EntityID{}), result.Credential != nil)
}
func (result Result) GoString() string { return result.String() }

type FailureCategory string

const (
	FailureCredentials FailureCategory = "credentials_rejected"
	FailureDirectory   FailureCategory = "directory_unavailable"
	FailurePolicy      FailureCategory = "policy_denied"
	FailureStale       FailureCategory = "stale_snapshot"
)

type FailureRequest struct {
	OperationRunID uuid.UUID
	ReceiptDigest  [sha256.Size]byte
	Category       FailureCategory
	AuditEventID   uuid.UUID
	Audit          AuditMetadata
}

type Repository interface {
	Begin(context.Context, BeginRequest) (NetworkSnapshot, error)
	Claim(context.Context, ClaimRequest) (Claim, error)
	Apply(context.Context, ApplyRequest) (ApplyResult, error)
	CompleteFailure(context.Context, FailureRequest) error
}

type DirectoryClient interface {
	AuthenticateDirectory(
		context.Context,
		ldapclient.DirectoryRequest,
		[]byte,
		[]byte,
	) (ldapclient.DirectoryResult, error)
}
