package platformlocalaccount

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

// Repository is the transaction-owned local-account persistence boundary.
// Apply must lock the actor session, target lifecycle rows, password history,
// the pending enrollment/attempt meter, and the protected recovery fleet in
// deterministic order. It must re-resolve live platform authority and fresh
// local step-up. Invite/recover persist the supplied encrypted pending TOTP and
// retire any prior pending enrollment required by the plan. Activate verifies
// the ceremony digest, invokes ConfirmTOTPEnrollment exactly once, and stages
// its confirmed factor before calling Plan exactly once. An idempotent replay
// invokes no callbacks and never opens an envelope. Every plan consequence,
// including session/challenge/factor/recovery-set revocation, and redacted audit
// append commits atomically; ValidateResult must run before commit.
type Repository interface {
	List(context.Context, ListParams) ([]Account, error)
	Get(context.Context, GetParams) (Account, error)
	Apply(context.Context, ApplyParams) (ApplyResult, error)
}

type SessionParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

type ListParams struct {
	SessionParams
	After           *uuid.UUID
	Limit           int32
	IncludeDisabled bool
}

type GetParams struct {
	SessionParams
	AccountID uuid.UUID
}

// PlanningState is derived only from rows locked by the protected writer.
// Neither assurance flag is accepted from HTTP or trusted from the session
// projection carried into the application service.
type PlanningState struct {
	Snapshot          localaccount.Snapshot
	RecoveryFleet     localaccount.RecoveryFleet
	FreshLocalMFA     bool
	ProtectedWorkflow bool
}

type PlanTransition func(PlanningState) (localaccount.Plan, error)

// PasswordHistoryValidator runs while credential history is locked. The
// repository transfers temporary PHC buffers to the callback and must clear
// its own copies immediately afterwards.
type PasswordHistoryValidator func([][]byte) error

// TOTPEnrollmentConfirmer runs exactly once while the pending enrollment,
// ceremony attempt meter, and target account are locked. The repository
// transfers the encrypted pending envelope and proof counter to the callback,
// persists only its confirmed rewrapped result, and clears all buffers. The
// plaintext factor proof is closure-owned and never crosses this port as data.
type TOTPEnrollmentConfirmer func(PendingTOTPEnrollment, *int64) (ConfirmedTOTPFactor, error)

type ResultValidator func(ApplyResult) (ApplyResult, error)

type ApplyParams struct {
	SessionParams
	CommandID                   uuid.UUID
	Action                      localaccount.Action
	AccountID                   uuid.UUID
	NewAccountID                uuid.UUID
	NewUserID                   uuid.UUID
	ExpectedRevision            uint64
	At                          time.Time
	DisplayName                 string
	CanonicalLoginIdentifier    string
	ProtectedRecoveryPrincipal  bool
	Reason                      string
	IdempotencyKeyDigest        [sha256.Size]byte
	PublicRequestDigest         [sha256.Size]byte
	CeremonyTokenDigest         [sha256.Size]byte
	ReplacementPasswordPHC      []byte `json:"-"`
	IssueCeremonyTokenDigest    [sha256.Size]byte
	IssueCeremonyTokenExpiresAt time.Time
	PendingTOTPEnrollment       *PendingTOTPEnrollment `json:"-"`
	Event                       authentication.EventContext
	Plan                        PlanTransition
	ValidatePasswordHistory     PasswordHistoryValidator
	ConfirmTOTPEnrollment       TOTPEnrollmentConfirmer
	ValidateResult              ResultValidator
}

func (params ApplyParams) String() string {
	return fmt.Sprintf(
		"platformlocalaccount.ApplyParams{action:%d,expectedRevision:%d,digests:true,material:[REDACTED]}",
		params.Action, params.ExpectedRevision,
	)
}

func (params ApplyParams) GoString() string { return params.String() }

type ApplyResult struct {
	Account        Account
	Replayed       bool
	ArtifactIssued bool
}

func (result ApplyResult) String() string {
	return fmt.Sprintf(
		"platformlocalaccount.ApplyResult{status:%s,revision:%d,replayed:%t,artifactIssued:%t,metadata:[REDACTED]}",
		result.Account.Status, result.Account.Revision, result.Replayed, result.ArtifactIssued,
	)
}

func (result ApplyResult) GoString() string { return result.String() }

func plannerID(value uuid.UUID) identity.EntityID { return identity.EntityID(value) }
