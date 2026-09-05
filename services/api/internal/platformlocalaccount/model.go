// Package platformlocalaccount composes the pure local-account lifecycle
// planner through a protected platform administration boundary.
package platformlocalaccount

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

type Status string

const (
	StatusInvited            Status = "invited"
	StatusActive             Status = "active"
	StatusDisabled           Status = "disabled"
	StatusRecoveryRestricted Status = "recovery_restricted"
)

type LoginIdentifierStatus string

const (
	LoginIdentifierPending  LoginIdentifierStatus = "pending"
	LoginIdentifierVerified LoginIdentifierStatus = "verified"
	LoginIdentifierDisabled LoginIdentifierStatus = "disabled"
)

type CredentialStatus string

const (
	CredentialPending  CredentialStatus = "pending"
	CredentialActive   CredentialStatus = "active"
	CredentialDisabled CredentialStatus = "disabled"
)

// Account is the complete safe administration projection. Password hashes,
// invitation/recovery digests, MFA secrets, recovery codes, and session
// provenance are deliberately absent.
type Account struct {
	ID                         uuid.UUID
	UserID                     uuid.UUID
	DisplayName                string
	LoginIdentifier            string
	Status                     Status
	LoginIdentifierStatus      LoginIdentifierStatus
	CredentialStatus           CredentialStatus
	CredentialVersion          uint64
	ConfirmedAcceptableFactors uint16
	ProtectedRecoveryPrincipal bool
	Revision                   uint64
	IdentityEpoch              uint64
	InvitedAt                  time.Time
	ActivatedAt                *time.Time
	DisabledAt                 *time.Time
	RecoveryStartedAt          *time.Time
	UpdatedAt                  time.Time
}

func (account Account) String() string {
	return fmt.Sprintf(
		"platformlocalaccount.Account{status:%s,revision:%d,credentialVersion:%d,metadata:[REDACTED]}",
		account.Status, account.Revision, account.CredentialVersion,
	)
}

func (account Account) GoString() string { return account.String() }

type Page struct {
	Items      []Account
	NextCursor *uuid.UUID
}

type ListInput struct {
	After           *uuid.UUID
	Limit           int
	IncludeDisabled bool
}

type InviteInput struct {
	DisplayName                string
	LoginIdentifier            string
	ProtectedRecoveryPrincipal bool
	Reason                     string
	IdempotencyKey             string `json:"-"`
	Event                      authentication.EventContext
}

func (InviteInput) String() string {
	return "platformlocalaccount.InviteInput{material:[REDACTED]}"
}

func (input InviteInput) GoString() string { return input.String() }

type TransitionInput struct {
	Reason            string
	IdempotencyKey    string `json:"-"`
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

func (TransitionInput) String() string {
	return "platformlocalaccount.TransitionInput{material:[REDACTED]}"
}

func (input TransitionInput) GoString() string { return input.String() }

// ActivationInput owns all ceremony material. The repository verifies the
// one-time token and factor proof without putting either into SQL JSON, stages
// the credential and factor under lock, then invokes the planner against the
// resulting ready snapshot.
type ActivationInput struct {
	Reason            string
	IdempotencyKey    string `json:"-"`
	ExpectedEntityTag *string
	CeremonyToken     []byte `json:"-"`
	NewPassword       []byte `json:"-"`
	FactorProof       []byte `json:"-"`
	Event             authentication.EventContext
}

func (ActivationInput) String() string {
	return "platformlocalaccount.ActivationInput{material:[REDACTED]}"
}

func (input ActivationInput) GoString() string { return input.String() }

type PasswordTransitionInput struct {
	Reason            string
	IdempotencyKey    string `json:"-"`
	ExpectedEntityTag *string
	NewPassword       []byte `json:"-"`
	Event             authentication.EventContext
}

func (PasswordTransitionInput) String() string {
	return "platformlocalaccount.PasswordTransitionInput{material:[REDACTED]}"
}

func (input PasswordTransitionInput) GoString() string { return input.String() }

type artifactState struct {
	guard           sync.Mutex
	ceremonyToken   []byte
	totpSecret      []byte
	provisioningURI []byte
	consumed        bool
}

// EnrollmentArtifact is the owned value returned by Consume. Every buffer is
// secret-bearing and must be destroyed after the response is serialized.
type EnrollmentArtifact struct {
	CeremonyToken   []byte `json:"-"`
	TOTPSecret      []byte `json:"-"`
	ProvisioningURI []byte `json:"-"`
}

func (EnrollmentArtifact) String() string {
	return "platformlocalaccount.EnrollmentArtifact{material:[REDACTED]}"
}
func (artifact EnrollmentArtifact) GoString() string { return artifact.String() }

func (artifact *EnrollmentArtifact) Destroy() {
	if artifact == nil {
		return
	}
	clear(artifact.CeremonyToken)
	clear(artifact.TOTPSecret)
	clear(artifact.ProvisioningURI)
	*artifact = EnrollmentArtifact{}
}

// OneTimeArtifact owns an invitation or recovery enrollment bundle. Copies
// share a single consume/destroy state so transport can never serialize any
// token, secret, or provisioning URI twice.
type OneTimeArtifact struct {
	state *artifactState
}

func newOneTimeArtifact(token, secret, provisioningURI []byte) OneTimeArtifact {
	return OneTimeArtifact{state: &artifactState{
		ceremonyToken: token, totpSecret: secret, provisioningURI: provisioningURI,
	}}
}

func (artifact OneTimeArtifact) Consume() (EnrollmentArtifact, bool) {
	if artifact.state == nil {
		return EnrollmentArtifact{}, false
	}
	artifact.state.guard.Lock()
	defer artifact.state.guard.Unlock()
	if artifact.state.consumed || len(artifact.state.ceremonyToken) == 0 ||
		len(artifact.state.totpSecret) == 0 || len(artifact.state.provisioningURI) == 0 {
		artifact.destroyLocked()
		return EnrollmentArtifact{}, false
	}
	material := EnrollmentArtifact{
		CeremonyToken:   artifact.state.ceremonyToken,
		TOTPSecret:      artifact.state.totpSecret,
		ProvisioningURI: artifact.state.provisioningURI,
	}
	artifact.state.ceremonyToken = nil
	artifact.state.totpSecret = nil
	artifact.state.provisioningURI = nil
	artifact.state.consumed = true
	return material, true
}

func (artifact OneTimeArtifact) Destroy() {
	if artifact.state == nil {
		return
	}
	artifact.state.guard.Lock()
	defer artifact.state.guard.Unlock()
	artifact.destroyLocked()
}

func (artifact OneTimeArtifact) destroyLocked() {
	clear(artifact.state.ceremonyToken)
	clear(artifact.state.totpSecret)
	clear(artifact.state.provisioningURI)
	artifact.state.ceremonyToken = nil
	artifact.state.totpSecret = nil
	artifact.state.provisioningURI = nil
	artifact.state.consumed = true
}

func (OneTimeArtifact) String() string {
	return "platformlocalaccount.OneTimeArtifact{material:[REDACTED]}"
}

func (artifact OneTimeArtifact) GoString() string { return artifact.String() }

type MutationResult struct {
	Account  Account
	Replayed bool
	Artifact OneTimeArtifact
}

func (result *MutationResult) Destroy() {
	if result == nil {
		return
	}
	result.Artifact.Destroy()
	*result = MutationResult{}
}

func (result MutationResult) String() string {
	return fmt.Sprintf(
		"platformlocalaccount.MutationResult{status:%s,revision:%d,replayed:%t,material:[REDACTED]}",
		result.Account.Status, result.Account.Revision, result.Replayed,
	)
}

func (result MutationResult) GoString() string { return result.String() }
