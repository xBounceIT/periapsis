package platformidentityprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

// Repository is the protected platform-provider persistence boundary. An
// implementation must use only the security-definer ABI, which revalidates
// the exact session and current platform permission in every transaction.
type Repository interface {
	List(context.Context, ListParams) ([]ProviderSummary, error)
	Get(context.Context, GetParams) (Provider, error)
	Create(context.Context, CreateParams) (CreateResult, error)
	Update(context.Context, UpdateParams) (UpdateResult, error)
	Archive(context.Context, ArchiveParams) (MutationReceipt, error)
	ReplaceOIDCClientSecret(context.Context, ReplaceOIDCClientSecretParams) (SecretMutationReceipt, error)
	Activate(context.Context, ActivationParams) (UpdateResult, error)
	Deactivate(context.Context, DeactivationParams) (UpdateResult, error)
	ActivateDirectLogin(context.Context, DirectLoginParams) (UpdateResult, error)
	DeactivateDirectLogin(context.Context, DirectLoginParams) (UpdateResult, error)
}

// LDAPAdministrationRepository is an optional protocol-specific extension.
// The service fails closed when the adapter is absent.
type LDAPAdministrationRepository interface {
	UpdateLDAP(context.Context, UpdateLDAPParams) (UpdateResult, error)
	ReplaceLDAPBindSecret(context.Context, ReplaceLDAPBindSecretParams) (SecretMutationReceipt, error)
	PutLDAPMapping(context.Context, PutLDAPMappingParams) (UpdateResult, error)
	SetLDAPLoginState(context.Context, SetLDAPLoginStateParams) (UpdateResult, error)
}

// LDAPTestRepository is the two-phase persistence boundary for bounded,
// redacted platform-directory diagnostics. Begin commits the exact provider,
// configuration, mapping, and secret revisions before any network I/O;
// Complete revalidates those pins while atomically storing the sanitized
// result and audit event.
type LDAPTestRepository interface {
	BeginLDAPTest(context.Context, BeginLDAPTestParams) (LDAPTestSnapshot, error)
	CompleteLDAPTest(context.Context, CompleteLDAPTestParams) (LDAPDiagnostic, error)
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
	IncludeArchived bool
}

type GetParams struct {
	SessionParams
	ProviderID uuid.UUID
}

// CreateResultValidator is supplied by the use case so a transactional
// repository can validate the complete, deployment-aware projection before
// committing the mutation and its audit event.
type CreateResultValidator func(CreateResult) (CreateResult, error)

// UpdateResultValidator is the update counterpart of CreateResultValidator.
type UpdateResultValidator func(UpdateResult) (UpdateResult, error)

type CreateParams struct {
	SessionParams
	CommandID      uuid.UUID
	ProviderID     uuid.UUID
	Kind           ProviderKind
	Key            string
	DisplayName    string
	Description    string
	Configuration  CreateConfiguration
	KeyDigest      [sha256.Size]byte
	RequestDigest  [sha256.Size]byte
	Reason         string
	Event          authentication.EventContext
	ValidateResult CreateResultValidator
}

func (params CreateParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.CreateParams{kind:%s,digests:true,material:[REDACTED]}",
		params.Kind,
	)
}

func (params CreateParams) GoString() string { return params.String() }

type UpdateParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Key             string
	DisplayName     string
	Description     string
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

func (params UpdateParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.UpdateParams{expected_version:%d,material:[REDACTED]}",
		params.ExpectedVersion,
	)
}

func (params UpdateParams) GoString() string { return params.String() }

type ArchiveParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
	Event           authentication.EventContext
}

func (params ArchiveParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ArchiveParams{expected_version:%d,material:[REDACTED]}",
		params.ExpectedVersion,
	)
}

func (params ArchiveParams) GoString() string { return params.String() }

type ReplaceOIDCClientSecretParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Secret          EncryptedOIDCClientSecret
	Reason          string
	Event           authentication.EventContext
}

type ActivationParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	AccountMode     AccountMode
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

type DeactivationParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

// DirectLoginParams carries the common protected writer inputs for the two
// explicit direct-login lifecycle transitions. The repository method name is
// the operation discriminator; no caller-controlled mode reaches PostgreSQL.
type DirectLoginParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

type UpdateLDAPParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Key             string
	DisplayName     string
	Description     string
	Configuration   identityprovider.Configuration
	Endpoints       []LDAPEndpoint
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

type EncryptedLDAPBindSecret struct {
	SecretID uuid.UUID
	Envelope identity.BindSecretEnvelope
}

type ReplaceLDAPBindSecretParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Secret          EncryptedLDAPBindSecret
	Reason          string
	Event           authentication.EventContext
}

type PutLDAPMappingParams struct {
	SessionParams
	ProviderID         uuid.UUID
	MappingID          uuid.UUID
	ExpectedVersion    *int64
	MatcherType        identityprovider.MappingMatcherType
	MatcherValue       string
	CaseSensitive      bool
	Priority           int
	PlatformRoleID     uuid.UUID
	ReconciliationMode identityprovider.ReconciliationMode
	Enabled            bool
	Notes              string
	Reason             string
	Event              authentication.EventContext
	ValidateResult     UpdateResultValidator
}

type SetLDAPLoginStateParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Enabled         bool
	Reason          string
	Event           authentication.EventContext
	ValidateResult  UpdateResultValidator
}

type BeginLDAPTestParams struct {
	SessionParams
	ProviderID uuid.UUID
	TestID     uuid.UUID
	Kind       LDAPTestKind
	Event      authentication.EventContext
}

type LDAPTestSnapshot struct {
	TestID                uuid.UUID
	ProviderID            uuid.UUID
	Kind                  LDAPTestKind
	ProviderVersion       int64
	ConfigurationRevision int64
	MappingRevision       int64
	Configuration         identityprovider.Configuration
	Endpoints             []LDAPEndpoint
	Mappings              []LDAPMapping
	BindSecret            *EncryptedLDAPBindSecret
	SecretRevision        *int64
}

func (snapshot *LDAPTestSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	if snapshot.BindSecret != nil {
		clear(snapshot.BindSecret.Envelope.Ciphertext)
		snapshot.BindSecret.Envelope.Ciphertext = nil
		snapshot.BindSecret = nil
	}
	if snapshot.Configuration.CustomCAPEM != nil {
		*snapshot.Configuration.CustomCAPEM = ""
		snapshot.Configuration.CustomCAPEM = nil
	}
	clear(snapshot.Endpoints)
	clear(snapshot.Mappings)
	snapshot.Endpoints = nil
	snapshot.Mappings = nil
}

type CompleteLDAPTestParams struct {
	SessionParams
	TestID            uuid.UUID
	Outcome           string
	Category          string
	EndpointPriority  *int
	Duration          time.Duration
	MatchedEntryCount *int
	Attributes        []string
	CompletedAt       time.Time
	Reason            string
	Event             authentication.EventContext
}

func (params ReplaceOIDCClientSecretParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ReplaceOIDCClientSecretParams{expected_version:%d,material:[REDACTED]}",
		params.ExpectedVersion,
	)
}

func (params ReplaceOIDCClientSecretParams) GoString() string { return params.String() }

type CreateReceiptInput struct {
	ProviderID uuid.UUID
	Version    int64
	Replayed   bool
}

type CreateReceipt struct {
	providerID uuid.UUID
	version    int64
	replayed   bool
}

func RestoreCreateReceipt(input CreateReceiptInput) (CreateReceipt, error) {
	if !validUUIDv7(input.ProviderID) || !validResourceVersion(input.Version) || input.Version != 1 {
		return CreateReceipt{}, authentication.ErrInvalidInput
	}
	return CreateReceipt{providerID: input.ProviderID, version: input.Version, replayed: input.Replayed}, nil
}

func (receipt CreateReceipt) ProviderID() uuid.UUID { return receipt.providerID }
func (receipt CreateReceipt) Version() int64        { return receipt.version }
func (receipt CreateReceipt) Replayed() bool        { return receipt.replayed }

func (receipt CreateReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.CreateReceipt{version:%d,replayed:%t,metadata:[REDACTED]}",
		receipt.version, receipt.replayed,
	)
}

func (receipt CreateReceipt) GoString() string { return receipt.String() }

// CreateResult couples the stable idempotency receipt to the live sanitized
// provider projection produced by the same database transaction. On replay,
// the receipt remains at version 1 while the projection may reflect later
// committed metadata changes.
type CreateResult struct {
	receipt  CreateReceipt
	provider Provider
}

type CreateResultInput struct {
	ProviderID uuid.UUID
	Version    int64
	Replayed   bool
	Provider   Provider
}

func RestoreCreateResult(input CreateResultInput) (CreateResult, error) {
	receipt, err := RestoreCreateReceipt(CreateReceiptInput{
		ProviderID: input.ProviderID,
		Version:    input.Version,
		Replayed:   input.Replayed,
	})
	if err != nil || input.Provider.ID != input.ProviderID ||
		!validResourceVersion(input.Provider.Version) ||
		(!input.Replayed && input.Provider.Version != input.Version) ||
		(input.Replayed && input.Provider.Version < input.Version) {
		return CreateResult{}, authentication.ErrInvalidInput
	}
	return CreateResult{receipt: receipt, provider: cloneProvider(input.Provider)}, nil
}

func (result CreateResult) ProviderID() uuid.UUID { return result.receipt.ProviderID() }
func (result CreateResult) Version() int64        { return result.receipt.Version() }
func (result CreateResult) Replayed() bool        { return result.receipt.Replayed() }
func (result CreateResult) Provider() Provider    { return cloneProvider(result.provider) }

func (result CreateResult) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.CreateResult{receipt_version:%d,projection_version:%d,replayed:%t,metadata:[REDACTED]}",
		result.Version(), result.provider.Version, result.Replayed(),
	)
}

func (result CreateResult) GoString() string { return result.String() }

type MutationReceiptInput struct {
	ProviderID uuid.UUID
	Version    int64
}

type MutationReceipt struct {
	providerID uuid.UUID
	version    int64
}

func RestoreMutationReceipt(input MutationReceiptInput) (MutationReceipt, error) {
	if !validUUIDv7(input.ProviderID) || !validResourceVersion(input.Version) || input.Version < 2 {
		return MutationReceipt{}, authentication.ErrInvalidInput
	}
	return MutationReceipt{providerID: input.ProviderID, version: input.Version}, nil
}

func (receipt MutationReceipt) ProviderID() uuid.UUID { return receipt.providerID }
func (receipt MutationReceipt) Version() int64        { return receipt.version }

func (receipt MutationReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.MutationReceipt{version:%d,metadata:[REDACTED]}",
		receipt.version,
	)
}

func (receipt MutationReceipt) GoString() string { return receipt.String() }

// UpdateResult couples the CAS receipt and the sanitized post-mutation
// projection returned under the same live read/manage authorization locks.
type UpdateResult struct {
	receipt  MutationReceipt
	provider Provider
}

type UpdateResultInput struct {
	ProviderID uuid.UUID
	Version    int64
	Provider   Provider
}

func RestoreUpdateResult(input UpdateResultInput) (UpdateResult, error) {
	receipt, err := RestoreMutationReceipt(MutationReceiptInput{
		ProviderID: input.ProviderID,
		Version:    input.Version,
	})
	if err != nil || input.Provider.ID != input.ProviderID || input.Provider.Version != input.Version {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	return UpdateResult{receipt: receipt, provider: cloneProvider(input.Provider)}, nil
}

func (result UpdateResult) ProviderID() uuid.UUID { return result.receipt.ProviderID() }
func (result UpdateResult) Version() int64        { return result.receipt.Version() }
func (result UpdateResult) Provider() Provider    { return cloneProvider(result.provider) }

func (result UpdateResult) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.UpdateResult{version:%d,metadata:[REDACTED]}",
		result.Version(),
	)
}

func (result UpdateResult) GoString() string { return result.String() }

type SecretMutationReceiptInput struct {
	ProviderID     uuid.UUID
	Version        int64
	SecretRevision int64
}

type SecretMutationReceipt struct {
	providerID     uuid.UUID
	version        int64
	secretRevision int64
}

func RestoreSecretMutationReceipt(input SecretMutationReceiptInput) (SecretMutationReceipt, error) {
	if !validUUIDv7(input.ProviderID) || !validResourceVersion(input.Version) || input.Version < 2 ||
		!validProviderRevision(input.SecretRevision) || input.SecretRevision < 2 {
		return SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	return SecretMutationReceipt{
		providerID: input.ProviderID, version: input.Version, secretRevision: input.SecretRevision,
	}, nil
}

func (receipt SecretMutationReceipt) ProviderID() uuid.UUID { return receipt.providerID }
func (receipt SecretMutationReceipt) Version() int64        { return receipt.version }
func (receipt SecretMutationReceipt) SecretRevision() int64 { return receipt.secretRevision }

func (receipt SecretMutationReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.SecretMutationReceipt{version:%d,secret_revision:%d,metadata:[REDACTED]}",
		receipt.version, receipt.secretRevision,
	)
}

func (receipt SecretMutationReceipt) GoString() string { return receipt.String() }
