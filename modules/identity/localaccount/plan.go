// Package localaccount defines pure, reason-bearing local account transition
// plans. It creates no token, hash, database row, session, or HTTP response.
package localaccount

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var ErrTransitionRejected = errors.New("local account transition rejected")

type Status uint8

const (
	StatusAbsent Status = iota
	StatusInvited
	StatusActive
	StatusDisabled
	StatusRecoveryRestricted
)

type LoginIdentifierStatus uint8

const (
	LoginIdentifierAbsent LoginIdentifierStatus = iota
	LoginIdentifierPending
	LoginIdentifierVerified
	LoginIdentifierDisabled
)

type CredentialStatus uint8

const (
	CredentialAbsent CredentialStatus = iota
	CredentialPending
	CredentialActive
	CredentialDisabled
)

type Action uint8

const (
	ActionInvite Action = iota + 1
	ActionActivate
	ActionDisable
	ActionRecover
	ActionEnable
	ActionRotatePassword
)

const maximumPersistentRevision = uint64(9_007_199_254_740_991)

// Snapshot separates User, identifier, credential, and factor lifecycle.
type Snapshot struct {
	AccountID                  identity.EntityID
	UserID                     identity.EntityID
	Revision                   uint64
	IdentityEpoch              uint64
	Status                     Status
	LoginIdentifier            LoginIdentifierStatus
	Credential                 CredentialStatus
	ConfirmedAcceptableFactors uint16
	ProtectedRecoveryPrincipal bool
}

// RecoveryFleet is an exact locked projection supplied by the protected
// writer. A plan cannot remove the last ready human recovery principal.
type RecoveryFleet struct {
	OtherReadyHumanPrincipals uint32
	CurrentPrincipalReady     bool
}

type Command struct {
	Action            Action
	ExpectedRevision  uint64
	ActorID           identity.EntityID
	At                time.Time
	Reason            string
	FreshLocalMFA     bool
	ProtectedWorkflow bool
	NewAccountID      identity.EntityID
	NewUserID         identity.EntityID
}

func (c Command) String() string {
	return fmt.Sprintf("localaccount.Command{action:%d,expectedRevision:%d,reason:[REDACTED]}",
		c.Action, c.ExpectedRevision)
}
func (c Command) GoString() string { return c.String() }

type AuditKind string

const (
	AuditInvited         AuditKind = "local_account_invited"
	AuditActivated       AuditKind = "local_account_activated"
	AuditDisabled        AuditKind = "local_account_disabled"
	AuditRecovered       AuditKind = "local_account_recovery_started"
	AuditEnabled         AuditKind = "local_account_enabled"
	AuditPasswordRotated AuditKind = "local_account_password_rotated"
)

// Plan is declarative. The eventual protected writer must recheck the exact
// revision and recovery fleet and apply all requested consequences atomically.
type Plan struct {
	AccountID                 identity.EntityID
	UserID                    identity.EntityID
	ExpectedRevision          uint64
	NextRevision              uint64
	ExpectedIdentityEpoch     uint64
	NextIdentityEpoch         uint64
	From                      Status
	To                        Status
	Reason                    string
	Audit                     AuditKind
	IssueInvitation           bool
	IssueRecoveryContinuation bool
	RevokeSessions            bool
	RetireChallenges          bool
	RotateCredential          bool
	EnableCredential          bool
	DisableCredential         bool
	RevokeFactors             bool
	RetireRecoverySets        bool
	RecheckRecoveryFloor      bool
}

func (p Plan) String() string {
	return fmt.Sprintf("localaccount.Plan{from:%d,to:%d,nextRevision:%d,nextIdentityEpoch:%d,reason:[REDACTED]}",
		p.From, p.To, p.NextRevision, p.NextIdentityEpoch)
}
func (p Plan) GoString() string { return p.String() }

// BuildPlan validates the complete state transition without mutating state.
func BuildPlan(snapshot Snapshot, fleet RecoveryFleet, command Command) (Plan, error) {
	if !validCommand(command) || !validSnapshot(snapshot) || command.ExpectedRevision != snapshot.Revision ||
		!validRecoveryFleet(snapshot, fleet) ||
		snapshot.Status != StatusAbsent &&
			(snapshot.Revision >= maximumPersistentRevision || snapshot.IdentityEpoch >= maximumPersistentRevision) {
		return Plan{}, ErrTransitionRejected
	}
	switch command.Action {
	case ActionInvite:
		return planInvite(snapshot, command)
	case ActionActivate:
		return planActivate(snapshot, command)
	case ActionDisable:
		return planDisable(snapshot, fleet, command)
	case ActionRecover:
		return planRecover(snapshot, fleet, command)
	case ActionEnable:
		return planEnable(snapshot, command)
	case ActionRotatePassword:
		return planRotatePassword(snapshot, command)
	default:
		return Plan{}, ErrTransitionRejected
	}
}

func planInvite(snapshot Snapshot, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if snapshot.Status != StatusAbsent || command.ExpectedRevision != 0 || command.NewAccountID == zero ||
		command.NewUserID == zero || !command.FreshLocalMFA || !command.ProtectedWorkflow {
		return Plan{}, ErrTransitionRejected
	}
	return Plan{
		AccountID: command.NewAccountID, UserID: command.NewUserID,
		ExpectedRevision: 0, NextRevision: 1, ExpectedIdentityEpoch: 0, NextIdentityEpoch: 1,
		From: StatusAbsent, To: StatusInvited, Reason: command.Reason, Audit: AuditInvited,
		IssueInvitation: true, RetireChallenges: true, RecheckRecoveryFloor: true,
	}, nil
}

func planActivate(snapshot Snapshot, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if (snapshot.Status != StatusInvited && snapshot.Status != StatusRecoveryRestricted) ||
		snapshot.AccountID == zero || snapshot.UserID == zero || command.NewAccountID != zero || command.NewUserID != zero ||
		!command.FreshLocalMFA || !command.ProtectedWorkflow ||
		snapshot.LoginIdentifier != LoginIdentifierVerified || snapshot.Credential != CredentialActive ||
		snapshot.ConfirmedAcceptableFactors == 0 {
		return Plan{}, ErrTransitionRejected
	}
	return basePlan(snapshot, command, StatusActive, AuditActivated, func(plan *Plan) {
		plan.RevokeSessions = snapshot.Status == StatusRecoveryRestricted
		plan.RetireChallenges = true
		plan.RecheckRecoveryFloor = true
	}), nil
}

func planDisable(snapshot Snapshot, fleet RecoveryFleet, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if (snapshot.Status != StatusActive && snapshot.Status != StatusRecoveryRestricted) ||
		snapshot.AccountID == zero || snapshot.UserID == zero || command.NewAccountID != zero || command.NewUserID != zero ||
		!command.FreshLocalMFA || !command.ProtectedWorkflow ||
		removesLastRecoveryPrincipal(snapshot, fleet) {
		return Plan{}, ErrTransitionRejected
	}
	return basePlan(snapshot, command, StatusDisabled, AuditDisabled, func(plan *Plan) {
		plan.RevokeSessions = true
		plan.RetireChallenges = true
		plan.DisableCredential = true
		plan.RecheckRecoveryFloor = true
	}), nil
}

func planRecover(snapshot Snapshot, fleet RecoveryFleet, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if (snapshot.Status != StatusActive && snapshot.Status != StatusDisabled) ||
		snapshot.AccountID == zero || snapshot.UserID == zero || command.NewAccountID != zero || command.NewUserID != zero ||
		!command.FreshLocalMFA || !command.ProtectedWorkflow ||
		removesLastRecoveryPrincipal(snapshot, fleet) {
		return Plan{}, ErrTransitionRejected
	}
	return basePlan(snapshot, command, StatusRecoveryRestricted, AuditRecovered, func(plan *Plan) {
		plan.IssueRecoveryContinuation = true
		plan.RevokeSessions = true
		plan.RetireChallenges = true
		plan.RotateCredential = true
		plan.RevokeFactors = true
		plan.RetireRecoverySets = true
		plan.RecheckRecoveryFloor = true
	}), nil
}

func planEnable(snapshot Snapshot, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if snapshot.Status != StatusDisabled || snapshot.AccountID == zero || snapshot.UserID == zero ||
		command.NewAccountID != zero || command.NewUserID != zero || !command.FreshLocalMFA ||
		!command.ProtectedWorkflow || snapshot.LoginIdentifier != LoginIdentifierVerified ||
		snapshot.Credential != CredentialDisabled || snapshot.ConfirmedAcceptableFactors == 0 {
		return Plan{}, ErrTransitionRejected
	}
	return basePlan(snapshot, command, StatusActive, AuditEnabled, func(plan *Plan) {
		plan.EnableCredential = true
		plan.RetireChallenges = true
		plan.RecheckRecoveryFloor = true
	}), nil
}

func planRotatePassword(snapshot Snapshot, command Command) (Plan, error) {
	zero := identity.EntityID{}
	if snapshot.Status != StatusActive || snapshot.AccountID == zero || snapshot.UserID == zero ||
		command.NewAccountID != zero || command.NewUserID != zero || !command.FreshLocalMFA ||
		!command.ProtectedWorkflow || snapshot.LoginIdentifier != LoginIdentifierVerified ||
		snapshot.Credential != CredentialActive || snapshot.ConfirmedAcceptableFactors == 0 {
		return Plan{}, ErrTransitionRejected
	}
	return basePlan(snapshot, command, StatusActive, AuditPasswordRotated, func(plan *Plan) {
		plan.RotateCredential = true
		plan.RevokeSessions = true
		plan.RetireChallenges = true
		plan.RecheckRecoveryFloor = true
	}), nil
}

func basePlan(snapshot Snapshot, command Command, target Status, audit AuditKind, configure func(*Plan)) Plan {
	plan := Plan{
		AccountID: snapshot.AccountID, UserID: snapshot.UserID,
		ExpectedRevision: snapshot.Revision, NextRevision: snapshot.Revision + 1,
		ExpectedIdentityEpoch: snapshot.IdentityEpoch, NextIdentityEpoch: snapshot.IdentityEpoch + 1,
		From: snapshot.Status, To: target, Reason: command.Reason, Audit: audit,
	}
	configure(&plan)
	return plan
}

func removesLastRecoveryPrincipal(snapshot Snapshot, fleet RecoveryFleet) bool {
	return snapshot.ProtectedRecoveryPrincipal && fleet.CurrentPrincipalReady && fleet.OtherReadyHumanPrincipals == 0
}

func validRecoveryFleet(snapshot Snapshot, fleet RecoveryFleet) bool {
	currentReady := snapshot.ProtectedRecoveryPrincipal && snapshot.Status == StatusActive &&
		snapshot.LoginIdentifier == LoginIdentifierVerified && snapshot.Credential == CredentialActive &&
		snapshot.ConfirmedAcceptableFactors > 0
	return fleet.CurrentPrincipalReady == currentReady
}

func validSnapshot(value Snapshot) bool {
	zero := identity.EntityID{}
	if value.Status == StatusAbsent {
		return value.AccountID == zero && value.UserID == zero && value.Revision == 0 && value.IdentityEpoch == 0 &&
			value.LoginIdentifier == LoginIdentifierAbsent && value.Credential == CredentialAbsent &&
			value.ConfirmedAcceptableFactors == 0 && !value.ProtectedRecoveryPrincipal
	}
	if value.AccountID == zero || value.UserID == zero || value.Revision == 0 ||
		value.Revision > maximumPersistentRevision || value.IdentityEpoch == 0 ||
		value.IdentityEpoch > maximumPersistentRevision ||
		value.Status < StatusInvited || value.Status > StatusRecoveryRestricted ||
		value.LoginIdentifier < LoginIdentifierPending || value.LoginIdentifier > LoginIdentifierDisabled ||
		value.Credential < CredentialPending || value.Credential > CredentialDisabled {
		return false
	}
	return true
}

func validCommand(value Command) bool {
	zero := identity.EntityID{}
	if !validAction(value.Action) || value.ActorID == zero ||
		!validTime(value.At) || !validReason(value.Reason) {
		return false
	}
	return value.ExpectedRevision <= maximumPersistentRevision
}

func validAction(value Action) bool {
	switch value {
	case ActionInvite, ActionActivate, ActionDisable, ActionRecover, ActionEnable, ActionRotatePassword:
		return true
	default:
		return false
	}
}

func validReason(value string) bool {
	if len(value) == 0 || len(value) > 500 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}
