package platformidentityaccount

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

// SubjectProtector is the narrow identity-keyring surface required by manual
// prelink. identity.Keyring satisfies this interface.
type SubjectProtector interface {
	ActiveVersion() int16
	SubjectAliases(identity.ProviderContext, identity.Subject) ([]identity.SubjectAlias, error)
	EncryptExternalSubject(identity.ExternalSubjectContext, identity.Subject) (identity.ExternalSubjectEnvelope, error)
}

// Repository is the protected platform-account persistence boundary. An
// implementation must use only a reviewed security-definer ABI. Every method
// must reinstall and revalidate the exact actor session and current platform
// permission in the same transaction as its read or mutation.
//
// Prelink must compare Issuer with the exact live OIDC provider configuration,
// require a live User, bind KeyDigest to one operation, and compare
// PublicRequestDigest in constant time. PublicRequestDigest deliberately omits
// the confidential subject. Replay subject equality must instead be proven by
// resolving every supplied provider-scoped, versioned alias (including retained
// retirement tombstones) and requiring every match to converge on the command's
// original account ID. For an existing command-key replay, no alias match, a
// match to another account, or a changed public payload is
// authentication.ErrConflict; ambiguous or corrupt alias state is
// authentication.ErrUnavailable. A new command may create only when no alias is
// reserved by any active or retired account. The mutation atomically persists the
// envelope, every supplied alias, the command result account ID, and a
// reason-bearing platform audit event. Before an identity key is retired, its
// successor alias must be backfilled for every active and retired account.
// Subject aliases remain reserved after retirement. An exact replay returns the
// original account's current safe projection, even when retired, without
// repeating state or audit. Retire is irreversible; it atomically appends its
// reason-bearing platform audit event and invalidates every session/provenance
// path that depends on the account.
//
// Parameter buffers and validator closures are borrowed only for the synchronous
// duration of the call. Implementations must not retain them or invoke a
// validator after returning. A mutation validator is called on the database
// result while the transaction and its authority locks are still live; a
// validation failure aborts the transaction. Retire must read the prior safe
// account projection in the same transaction, compare both components of the
// composite validator, and pass that exact prior projection to ValidateResult
// before commit.
type Repository interface {
	List(context.Context, ListParams) ([]Account, error)
	Get(context.Context, GetParams) (Account, error)
	Prelink(context.Context, PrelinkParams) (PrelinkResult, error)
	Retire(context.Context, RetireParams) (RetireResult, error)
}

type SessionParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

type ListParams struct {
	SessionParams
	ProviderID     uuid.UUID
	After          *uuid.UUID
	Limit          int32
	IncludeRetired bool
}

type GetParams struct {
	SessionParams
	ProviderID uuid.UUID
	AccountID  uuid.UUID
}

// ProtectedSubject is the only subject representation accepted by
// persistence. The exact issuer remains separately available only so the
// protected command can compare it with the provider configuration.
type ProtectedSubject struct {
	Aliases  []identity.SubjectAlias
	Envelope identity.ExternalSubjectEnvelope
}

func (subject ProtectedSubject) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.ProtectedSubject{aliases:%d,envelope:%q,material:[REDACTED]}",
		len(subject.Aliases), subject.Envelope.String(),
	)
}

func (subject ProtectedSubject) GoString() string { return subject.String() }

type PrelinkResultValidator func(PrelinkResult) (PrelinkResult, error)
type RetireResultValidator func(Account, RetireResult) (RetireResult, error)

type PrelinkParams struct {
	SessionParams
	CommandID           uuid.UUID
	AccountID           uuid.UUID
	ProviderID          uuid.UUID
	UserID              uuid.UUID
	Issuer              string `json:"-"`
	Subject             ProtectedSubject
	KeyDigest           [sha256.Size]byte
	PublicRequestDigest [sha256.Size]byte
	Reason              string
	Event               authentication.EventContext
	ValidateResult      PrelinkResultValidator
}

func (params PrelinkParams) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.PrelinkParams{aliases:%d,digests:true,material:[REDACTED]}",
		len(params.Subject.Aliases),
	)
}

func (params PrelinkParams) GoString() string { return params.String() }

type RetireParams struct {
	SessionParams
	ProviderID          uuid.UUID
	AccountID           uuid.UUID
	ExpectedVersion     int64
	ExpectedUserVersion int64
	Reason              string
	Event               authentication.EventContext
	ValidateResult      RetireResultValidator
}

func (params RetireParams) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.RetireParams{expected_version:%d,expected_user_version:%d,material:[REDACTED]}",
		params.ExpectedVersion, params.ExpectedUserVersion,
	)
}

func (params RetireParams) GoString() string { return params.String() }

type PrelinkReceiptInput struct {
	AccountID uuid.UUID
	Version   int64
	Replayed  bool
}

type PrelinkReceipt struct {
	accountID uuid.UUID
	version   int64
	replayed  bool
}

func RestorePrelinkReceipt(input PrelinkReceiptInput) (PrelinkReceipt, error) {
	if !validUUIDv7(input.AccountID) || input.Version != 1 {
		return PrelinkReceipt{}, authentication.ErrInvalidInput
	}
	return PrelinkReceipt{accountID: input.AccountID, version: input.Version, replayed: input.Replayed}, nil
}

func (receipt PrelinkReceipt) AccountID() uuid.UUID { return receipt.accountID }
func (receipt PrelinkReceipt) Version() int64       { return receipt.version }
func (receipt PrelinkReceipt) Replayed() bool       { return receipt.replayed }

func (receipt PrelinkReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.PrelinkReceipt{version:%d,replayed:%t,metadata:[REDACTED]}",
		receipt.version, receipt.replayed,
	)
}

func (receipt PrelinkReceipt) GoString() string { return receipt.String() }

type PrelinkResultInput struct {
	AccountID uuid.UUID
	Version   int64
	Replayed  bool
	Account   Account
}

type PrelinkResult struct {
	receipt PrelinkReceipt
	account Account
}

func RestorePrelinkResult(input PrelinkResultInput) (PrelinkResult, error) {
	receipt, err := RestorePrelinkReceipt(PrelinkReceiptInput{
		AccountID: input.AccountID, Version: input.Version, Replayed: input.Replayed,
	})
	if err != nil || input.Account.ID != input.AccountID || !validAccount(input.Account) ||
		(!input.Replayed && input.Account.Version != input.Version) ||
		(input.Replayed && input.Account.Version < input.Version) {
		return PrelinkResult{}, authentication.ErrInvalidInput
	}
	return PrelinkResult{receipt: receipt, account: cloneAccount(input.Account)}, nil
}

func (result PrelinkResult) AccountID() uuid.UUID { return result.receipt.AccountID() }
func (result PrelinkResult) Version() int64       { return result.receipt.Version() }
func (result PrelinkResult) Replayed() bool       { return result.receipt.Replayed() }
func (result PrelinkResult) Account() Account     { return cloneAccount(result.account) }

func (result PrelinkResult) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.PrelinkResult{receipt_version:%d,projection_version:%d,replayed:%t,metadata:[REDACTED]}",
		result.Version(), result.account.Version, result.Replayed(),
	)
}

func (result PrelinkResult) GoString() string { return result.String() }

type RetireReceiptInput struct {
	AccountID uuid.UUID
	Version   int64
}

type RetireReceipt struct {
	accountID uuid.UUID
	version   int64
}

func RestoreRetireReceipt(input RetireReceiptInput) (RetireReceipt, error) {
	if !validUUIDv7(input.AccountID) || !validResourceVersion(input.Version) || input.Version < 2 {
		return RetireReceipt{}, authentication.ErrInvalidInput
	}
	return RetireReceipt{accountID: input.AccountID, version: input.Version}, nil
}

func (receipt RetireReceipt) AccountID() uuid.UUID { return receipt.accountID }
func (receipt RetireReceipt) Version() int64       { return receipt.version }

func (receipt RetireReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.RetireReceipt{version:%d,metadata:[REDACTED]}", receipt.version,
	)
}

func (receipt RetireReceipt) GoString() string { return receipt.String() }

type RetireResultInput struct {
	AccountID uuid.UUID
	Version   int64
	Account   Account
}

type RetireResult struct {
	receipt  RetireReceipt
	account  Account
	previous *Account
}

func RestoreRetireResult(input RetireResultInput) (RetireResult, error) {
	receipt, err := RestoreRetireReceipt(RetireReceiptInput{
		AccountID: input.AccountID, Version: input.Version,
	})
	if err != nil || input.Account.ID != input.AccountID || input.Account.Version != input.Version ||
		!validAccount(input.Account) || input.Account.State != AccountStateRetired {
		return RetireResult{}, authentication.ErrInvalidInput
	}
	return RetireResult{receipt: receipt, account: cloneAccount(input.Account)}, nil
}

func (result RetireResult) AccountID() uuid.UUID { return result.receipt.AccountID() }
func (result RetireResult) Version() int64       { return result.receipt.Version() }
func (result RetireResult) Account() Account     { return cloneAccount(result.account) }

func (result RetireResult) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.RetireResult{version:%d,metadata:[REDACTED]}", result.Version(),
	)
}

func (result RetireResult) GoString() string { return result.String() }
