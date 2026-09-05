package ticketing

import (
	"errors"
	"fmt"
	"reflect"
	"time"
)

const (
	TicketExportProjectionVersion = uint64(1)
	TicketExportMaximumAttempts   = uint8(5)

	TicketExportOperatorMaximumRows  = uint32(100_000)
	TicketExportCustomerMaximumRows  = uint32(10_000)
	TicketExportOperatorMaximumBytes = uint64(512 * 1024 * 1024)
	TicketExportCustomerMaximumBytes = uint64(64 * 1024 * 1024)
	TicketExportMaximumColumns       = 64
	TicketExportMaximumCellBytes     = 128 * 1024

	TicketExportMinimumRetention = 15 * time.Minute
	TicketExportMaximumRetention = 7 * 24 * time.Hour
	TicketExportMinimumLease     = 30 * time.Second
	TicketExportMaximumLease     = 15 * time.Minute
	TicketExportMinimumRetry     = time.Second
	TicketExportMaximumRetry     = time.Hour
)

var (
	ErrInvalidTicketExport       = errors.New("invalid ticket export")
	ErrTicketExportConflict      = errors.New("ticket export revision conflict")
	ErrTicketExportNoChange      = errors.New("ticket export command has no change")
	ErrTicketExportNotClaimable  = errors.New("ticket export is not claimable")
	ErrTicketExportFenceMismatch = errors.New("ticket export fence mismatch")
	ErrTicketExportCancelled     = errors.New("ticket export cancellation requested")
	ErrTicketExportTerminal      = errors.New("ticket export is terminal")
	ErrTicketExportOutputLimit   = errors.New("ticket export output limit exceeded")
	ErrTicketExportWriteFailed   = errors.New("ticket export write failed")
)

// TicketExportAudience is route intent captured at request time. It must come
// from live capability and relationship checks, never a role-name classifier.
type TicketExportAudience uint8

const (
	TicketExportAudienceOperator TicketExportAudience = iota + 1
	TicketExportAudienceCustomer
)

func (audience TicketExportAudience) String() string {
	switch audience {
	case TicketExportAudienceOperator:
		return "operator"
	case TicketExportAudienceCustomer:
		return "customer"
	default:
		return "unknown"
	}
}

func validTicketExportAudience(audience TicketExportAudience) bool {
	return audience == TicketExportAudienceOperator || audience == TicketExportAudienceCustomer
}

type TicketExportCommentScope uint8

const (
	TicketExportCommentsNone TicketExportCommentScope = iota + 1
	TicketExportCommentsPublic
	TicketExportCommentsPublicAndPrivate
)

func (scope TicketExportCommentScope) String() string {
	switch scope {
	case TicketExportCommentsNone:
		return "none"
	case TicketExportCommentsPublic:
		return "public"
	case TicketExportCommentsPublicAndPrivate:
		return "public_and_private"
	default:
		return "unknown"
	}
}

func validTicketExportCommentScope(scope TicketExportCommentScope) bool {
	return scope >= TicketExportCommentsNone && scope <= TicketExportCommentsPublicAndPrivate
}

type TicketExportQuerySource uint8

const (
	TicketExportQueryInline TicketExportQuerySource = iota + 1
	TicketExportQuerySavedView
)

func (source TicketExportQuerySource) String() string {
	switch source {
	case TicketExportQueryInline:
		return "inline"
	case TicketExportQuerySavedView:
		return "saved_view"
	default:
		return "unknown"
	}
}

type TicketExportFormat uint8

const (
	TicketExportCSV TicketExportFormat = iota + 1
)

func (format TicketExportFormat) String() string {
	if format == TicketExportCSV {
		return "csv"
	}
	return "unknown"
}

// TicketExportSavedViewPin binds an export to the exact owner, revision, and
// canonical spec digest that were authorized when it was requested.
type TicketExportSavedViewPin struct {
	id       EntityID
	owner    EntityID
	revision uint64
	digest   [32]byte
}

func NewTicketExportSavedViewPin(
	id EntityID,
	owner EntityID,
	revision uint64,
	digest [32]byte,
) (TicketExportSavedViewPin, error) {
	if !validEntityID(id) || !validEntityID(owner) || revision == 0 || revision > maxVersion ||
		digest == ([32]byte{}) {
		return TicketExportSavedViewPin{}, ErrInvalidTicketExport
	}
	return TicketExportSavedViewPin{id: id, owner: owner, revision: revision, digest: digest}, nil
}

func (pin TicketExportSavedViewPin) ID() EntityID     { return pin.id }
func (pin TicketExportSavedViewPin) Owner() EntityID  { return pin.owner }
func (pin TicketExportSavedViewPin) Revision() uint64 { return pin.revision }
func (pin TicketExportSavedViewPin) Digest() [32]byte { return pin.digest }
func (pin TicketExportSavedViewPin) String() string {
	return fmt.Sprintf("TicketExportSavedViewPin{revision:%d,metadata:[REDACTED]}", pin.revision)
}
func (pin TicketExportSavedViewPin) GoString() string { return pin.String() }

func validTicketExportSavedViewPin(pin TicketExportSavedViewPin) bool {
	rebuilt, err := NewTicketExportSavedViewPin(pin.id, pin.owner, pin.revision, pin.digest)
	return err == nil && rebuilt == pin
}

// TicketExportDefinition contains only immutable authorization and query pins.
// The full canonical query document remains a separately validated repository
// snapshot so the queue row cannot become an unrestricted data container.
type TicketExportDefinition struct {
	id                EntityID
	tenant            EntityID
	requester         EntityID
	ownerMembership   EntityID
	customerContact   *EntityID
	kind              AggregateKind
	audience          TicketExportAudience
	comments          TicketExportCommentScope
	querySource       TicketExportQuerySource
	savedView         *TicketExportSavedViewPin
	queryDigest       [32]byte
	catalogDigest     [32]byte
	projectionVersion uint64
	format            TicketExportFormat
	maximumRows       uint32
	maximumBytes      uint64
	maximumAttempts   uint8
}

type TicketExportDefinitionInput struct {
	ID                EntityID
	Tenant            EntityID
	Requester         EntityID
	OwnerMembership   EntityID
	CustomerContact   *EntityID
	Kind              AggregateKind
	Audience          TicketExportAudience
	Comments          TicketExportCommentScope
	QuerySource       TicketExportQuerySource
	SavedView         *TicketExportSavedViewPin
	QueryDigest       [32]byte
	CatalogDigest     [32]byte
	ProjectionVersion uint64
	Format            TicketExportFormat
	MaximumRows       uint32
	MaximumBytes      uint64
	MaximumAttempts   uint8
}

func (input TicketExportDefinitionInput) String() string {
	return fmt.Sprintf(
		"TicketExportDefinitionInput{kind:%s,audience:%s,comments:%s,source:%s,format:%s,maximum_rows:%d,maximum_bytes:%d,metadata:[REDACTED]}",
		input.Kind, input.Audience, input.Comments, input.QuerySource, input.Format,
		input.MaximumRows, input.MaximumBytes,
	)
}

func (input TicketExportDefinitionInput) GoString() string { return input.String() }

func NewTicketExportDefinition(input TicketExportDefinitionInput) (TicketExportDefinition, error) {
	if !validEntityID(input.ID) || !validEntityID(input.Tenant) || !validEntityID(input.Requester) ||
		!validEntityID(input.OwnerMembership) || !validAggregateKind(input.Kind) ||
		!validTicketExportAudience(input.Audience) || !validTicketExportCommentScope(input.Comments) ||
		input.QuerySource != TicketExportQueryInline && input.QuerySource != TicketExportQuerySavedView ||
		input.QueryDigest == ([32]byte{}) || input.CatalogDigest == ([32]byte{}) ||
		input.ProjectionVersion != TicketExportProjectionVersion || input.Format != TicketExportCSV ||
		input.MaximumAttempts == 0 || input.MaximumAttempts > TicketExportMaximumAttempts ||
		!validTicketExportBounds(input.Audience, input.MaximumRows, input.MaximumBytes) {
		return TicketExportDefinition{}, ErrInvalidTicketExport
	}
	if input.Audience == TicketExportAudienceCustomer {
		if input.CustomerContact == nil || !validEntityID(*input.CustomerContact) ||
			input.Comments == TicketExportCommentsPublicAndPrivate ||
			input.QuerySource != TicketExportQueryInline || input.SavedView != nil {
			return TicketExportDefinition{}, ErrInvalidTicketExport
		}
	} else if input.CustomerContact != nil {
		return TicketExportDefinition{}, ErrInvalidTicketExport
	}
	if input.QuerySource == TicketExportQuerySavedView {
		if input.SavedView == nil || !validTicketExportSavedViewPin(*input.SavedView) ||
			input.SavedView.owner != input.OwnerMembership || input.SavedView.digest != input.QueryDigest {
			return TicketExportDefinition{}, ErrInvalidTicketExport
		}
	} else if input.SavedView != nil {
		return TicketExportDefinition{}, ErrInvalidTicketExport
	}
	return TicketExportDefinition{
		id: input.ID, tenant: input.Tenant, requester: input.Requester,
		ownerMembership: input.OwnerMembership, customerContact: cloneTicketExportEntity(input.CustomerContact),
		kind: input.Kind, audience: input.Audience, comments: input.Comments,
		querySource: input.QuerySource, savedView: cloneTicketExportSavedViewPin(input.SavedView),
		queryDigest: input.QueryDigest, catalogDigest: input.CatalogDigest,
		projectionVersion: input.ProjectionVersion, format: input.Format,
		maximumRows: input.MaximumRows, maximumBytes: input.MaximumBytes,
		maximumAttempts: input.MaximumAttempts,
	}, nil
}

func validTicketExportBounds(audience TicketExportAudience, rows uint32, bytes uint64) bool {
	if rows == 0 || bytes == 0 {
		return false
	}
	if audience == TicketExportAudienceCustomer {
		return rows <= TicketExportCustomerMaximumRows && bytes <= TicketExportCustomerMaximumBytes
	}
	return audience == TicketExportAudienceOperator &&
		rows <= TicketExportOperatorMaximumRows && bytes <= TicketExportOperatorMaximumBytes
}

func (definition TicketExportDefinition) ID() EntityID        { return definition.id }
func (definition TicketExportDefinition) Tenant() EntityID    { return definition.tenant }
func (definition TicketExportDefinition) Requester() EntityID { return definition.requester }
func (definition TicketExportDefinition) OwnerMembership() EntityID {
	return definition.ownerMembership
}
func (definition TicketExportDefinition) CustomerContact() *EntityID {
	return cloneTicketExportEntity(definition.customerContact)
}
func (definition TicketExportDefinition) Kind() AggregateKind            { return definition.kind }
func (definition TicketExportDefinition) Audience() TicketExportAudience { return definition.audience }
func (definition TicketExportDefinition) Comments() TicketExportCommentScope {
	return definition.comments
}
func (definition TicketExportDefinition) QuerySource() TicketExportQuerySource {
	return definition.querySource
}
func (definition TicketExportDefinition) SavedView() *TicketExportSavedViewPin {
	return cloneTicketExportSavedViewPin(definition.savedView)
}
func (definition TicketExportDefinition) QueryDigest() [32]byte   { return definition.queryDigest }
func (definition TicketExportDefinition) CatalogDigest() [32]byte { return definition.catalogDigest }
func (definition TicketExportDefinition) ProjectionVersion() uint64 {
	return definition.projectionVersion
}
func (definition TicketExportDefinition) Format() TicketExportFormat { return definition.format }
func (definition TicketExportDefinition) MaximumRows() uint32        { return definition.maximumRows }
func (definition TicketExportDefinition) MaximumBytes() uint64       { return definition.maximumBytes }
func (definition TicketExportDefinition) MaximumAttempts() uint8     { return definition.maximumAttempts }
func (definition TicketExportDefinition) String() string {
	return fmt.Sprintf(
		"TicketExportDefinition{kind:%s,audience:%s,comments:%s,source:%s,format:%s,maximum_rows:%d,maximum_bytes:%d,metadata:[REDACTED]}",
		definition.kind, definition.audience, definition.comments, definition.querySource,
		definition.format, definition.maximumRows, definition.maximumBytes,
	)
}
func (definition TicketExportDefinition) GoString() string { return definition.String() }

func validTicketExportDefinition(definition TicketExportDefinition) bool {
	rebuilt, err := NewTicketExportDefinition(TicketExportDefinitionInput{
		ID: definition.id, Tenant: definition.tenant, Requester: definition.requester,
		OwnerMembership: definition.ownerMembership, CustomerContact: definition.customerContact,
		Kind: definition.kind, Audience: definition.audience, Comments: definition.comments,
		QuerySource: definition.querySource, SavedView: definition.savedView,
		QueryDigest: definition.queryDigest, CatalogDigest: definition.catalogDigest,
		ProjectionVersion: definition.projectionVersion, Format: definition.format,
		MaximumRows: definition.maximumRows, MaximumBytes: definition.maximumBytes,
		MaximumAttempts: definition.maximumAttempts,
	})
	return err == nil && reflect.DeepEqual(rebuilt, definition)
}

type TicketExportState uint8

const (
	TicketExportPending TicketExportState = iota + 1
	TicketExportRunning
	TicketExportCancellationRequested
	TicketExportSucceeded
	TicketExportFailed
	TicketExportCancelledState
)

func (state TicketExportState) String() string {
	switch state {
	case TicketExportPending:
		return "pending"
	case TicketExportRunning:
		return "running"
	case TicketExportCancellationRequested:
		return "cancellation_requested"
	case TicketExportSucceeded:
		return "succeeded"
	case TicketExportFailed:
		return "failed"
	case TicketExportCancelledState:
		return "cancelled"
	default:
		return "unknown"
	}
}

func validTicketExportState(state TicketExportState) bool {
	return state >= TicketExportPending && state <= TicketExportCancelledState
}

type TicketExportFailureCode uint8

const (
	TicketExportFailureNone TicketExportFailureCode = iota
	TicketExportFailureTransientStorage
	TicketExportFailureTransientDatabase
	TicketExportFailureAuthorizationRevoked
	TicketExportFailureSnapshotStale
	TicketExportFailureOutputLimit
	TicketExportFailureLeaseExpired
	TicketExportFailureExpired
	TicketExportFailureInternal
)

func (code TicketExportFailureCode) String() string {
	switch code {
	case TicketExportFailureNone:
		return "none"
	case TicketExportFailureTransientStorage:
		return "transient_storage"
	case TicketExportFailureTransientDatabase:
		return "transient_database"
	case TicketExportFailureAuthorizationRevoked:
		return "authorization_revoked"
	case TicketExportFailureSnapshotStale:
		return "snapshot_stale"
	case TicketExportFailureOutputLimit:
		return "output_limit"
	case TicketExportFailureLeaseExpired:
		return "lease_expired"
	case TicketExportFailureExpired:
		return "expired"
	case TicketExportFailureInternal:
		return "internal"
	default:
		return "unknown"
	}
}

func validTicketExportFailureCode(code TicketExportFailureCode) bool {
	return code >= TicketExportFailureTransientStorage && code <= TicketExportFailureInternal
}

func workerTicketExportFailureCode(code TicketExportFailureCode) bool {
	switch code {
	case TicketExportFailureTransientStorage, TicketExportFailureTransientDatabase,
		TicketExportFailureSnapshotStale, TicketExportFailureOutputLimit, TicketExportFailureInternal:
		return true
	default:
		return false
	}
}

func retryableTicketExportFailureCode(code TicketExportFailureCode) bool {
	return code == TicketExportFailureTransientStorage ||
		code == TicketExportFailureTransientDatabase ||
		code == TicketExportFailureInternal
}

type TicketExportLease struct {
	worker    EntityID
	fence     [32]byte
	claimedAt time.Time
	expiresAt time.Time
}

func NewTicketExportLease(
	worker EntityID,
	fence [32]byte,
	claimedAt time.Time,
	expiresAt time.Time,
) (TicketExportLease, error) {
	if !validEntityID(worker) || fence == ([32]byte{}) || !validInstant(claimedAt) ||
		!validInstant(expiresAt) || !expiresAt.After(claimedAt) ||
		expiresAt.Sub(claimedAt) < TicketExportMinimumLease ||
		expiresAt.Sub(claimedAt) > TicketExportMaximumLease {
		return TicketExportLease{}, ErrInvalidTicketExport
	}
	return TicketExportLease{worker: worker, fence: fence, claimedAt: claimedAt, expiresAt: expiresAt}, nil
}

func (lease TicketExportLease) Worker() EntityID     { return lease.worker }
func (lease TicketExportLease) Fence() [32]byte      { return lease.fence }
func (lease TicketExportLease) ClaimedAt() time.Time { return lease.claimedAt }
func (lease TicketExportLease) ExpiresAt() time.Time { return lease.expiresAt }
func (lease TicketExportLease) String() string {
	return "TicketExportLease{identity:[REDACTED],fence:[REDACTED],timestamps:[REDACTED]}"
}
func (lease TicketExportLease) GoString() string { return lease.String() }

func validTicketExportLease(lease TicketExportLease) bool {
	rebuilt, err := NewTicketExportLease(lease.worker, lease.fence, lease.claimedAt, lease.expiresAt)
	return err == nil && rebuilt == lease
}

type TicketExportArtifact struct {
	id        EntityID
	digest    [32]byte
	rows      uint32
	bytes     uint64
	expiresAt time.Time
}

func NewTicketExportArtifact(
	id EntityID,
	digest [32]byte,
	rows uint32,
	bytes uint64,
	expiresAt time.Time,
) (TicketExportArtifact, error) {
	if !validEntityID(id) || digest == ([32]byte{}) || bytes == 0 || !validInstant(expiresAt) {
		return TicketExportArtifact{}, ErrInvalidTicketExport
	}
	return TicketExportArtifact{id: id, digest: digest, rows: rows, bytes: bytes, expiresAt: expiresAt}, nil
}

func (artifact TicketExportArtifact) ID() EntityID         { return artifact.id }
func (artifact TicketExportArtifact) Digest() [32]byte     { return artifact.digest }
func (artifact TicketExportArtifact) Rows() uint32         { return artifact.rows }
func (artifact TicketExportArtifact) Bytes() uint64        { return artifact.bytes }
func (artifact TicketExportArtifact) ExpiresAt() time.Time { return artifact.expiresAt }
func (artifact TicketExportArtifact) String() string {
	return fmt.Sprintf("TicketExportArtifact{rows:%d,bytes:%d,metadata:[REDACTED]}", artifact.rows, artifact.bytes)
}
func (artifact TicketExportArtifact) GoString() string { return artifact.String() }

func validTicketExportArtifact(artifact TicketExportArtifact) bool {
	rebuilt, err := NewTicketExportArtifact(
		artifact.id, artifact.digest, artifact.rows, artifact.bytes, artifact.expiresAt,
	)
	return err == nil && rebuilt == artifact
}

// TicketExportJobSnapshot is the persistence reconstruction boundary. All
// pointer values are copied on entry and exit.
type TicketExportJobSnapshot struct {
	Definition  TicketExportDefinition
	State       TicketExportState
	Revision    uint64
	Attempts    uint8
	FailureCode TicketExportFailureCode
	RequestedAt time.Time
	UpdatedAt   time.Time
	AvailableAt time.Time
	ExpiresAt   time.Time
	Lease       *TicketExportLease
	Artifact    *TicketExportArtifact
	TerminalAt  *time.Time
}

func (snapshot TicketExportJobSnapshot) String() string {
	return fmt.Sprintf(
		"TicketExportJobSnapshot{state:%s,revision:%d,attempts:%d,failure:%s,metadata:[REDACTED]}",
		snapshot.State, snapshot.Revision, snapshot.Attempts, snapshot.FailureCode,
	)
}
func (snapshot TicketExportJobSnapshot) GoString() string { return snapshot.String() }

type TicketExportJob struct {
	definition  TicketExportDefinition
	state       TicketExportState
	revision    uint64
	attempts    uint8
	failureCode TicketExportFailureCode
	requestedAt time.Time
	updatedAt   time.Time
	availableAt time.Time
	expiresAt   time.Time
	lease       *TicketExportLease
	artifact    *TicketExportArtifact
	terminalAt  *time.Time
}

func RestoreTicketExportJob(snapshot TicketExportJobSnapshot) (TicketExportJob, error) {
	if !validTicketExportDefinition(snapshot.Definition) || !validTicketExportState(snapshot.State) ||
		snapshot.Revision == 0 || snapshot.Revision > maxVersion ||
		snapshot.Attempts > snapshot.Definition.maximumAttempts ||
		!validInstant(snapshot.RequestedAt) || !validInstant(snapshot.UpdatedAt) ||
		!validInstant(snapshot.AvailableAt) || !validInstant(snapshot.ExpiresAt) ||
		snapshot.UpdatedAt.Before(snapshot.RequestedAt) ||
		snapshot.AvailableAt.Before(snapshot.RequestedAt) ||
		!snapshot.ExpiresAt.After(snapshot.RequestedAt) ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) < TicketExportMinimumRetention ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) > TicketExportMaximumRetention ||
		snapshot.AvailableAt.After(snapshot.ExpiresAt) {
		return TicketExportJob{}, ErrInvalidTicketExport
	}
	if !validTicketExportJobShape(snapshot) {
		return TicketExportJob{}, ErrInvalidTicketExport
	}
	return TicketExportJob{
		definition: cloneTicketExportDefinition(snapshot.Definition),
		state:      snapshot.State, revision: snapshot.Revision,
		attempts: snapshot.Attempts, failureCode: snapshot.FailureCode,
		requestedAt: snapshot.RequestedAt, updatedAt: snapshot.UpdatedAt,
		availableAt: snapshot.AvailableAt, expiresAt: snapshot.ExpiresAt,
		lease: cloneTicketExportLease(snapshot.Lease), artifact: cloneTicketExportArtifact(snapshot.Artifact),
		terminalAt: cloneTicketExportTime(snapshot.TerminalAt),
	}, nil
}

func validTicketExportJobShape(snapshot TicketExportJobSnapshot) bool {
	if snapshot.Revision < uint64(snapshot.Attempts)+1 {
		return false
	}
	hasLease := snapshot.Lease != nil
	hasArtifact := snapshot.Artifact != nil
	hasTerminal := snapshot.TerminalAt != nil
	if hasLease && (!validTicketExportLease(*snapshot.Lease) ||
		snapshot.Lease.claimedAt.Before(snapshot.RequestedAt) ||
		snapshot.Lease.claimedAt.Before(snapshot.AvailableAt) ||
		snapshot.Lease.claimedAt.After(snapshot.UpdatedAt) ||
		snapshot.Lease.expiresAt.After(snapshot.ExpiresAt)) {
		return false
	}
	if hasArtifact && (!validTicketExportArtifact(*snapshot.Artifact) ||
		snapshot.Artifact.rows > snapshot.Definition.maximumRows ||
		snapshot.Artifact.bytes > snapshot.Definition.maximumBytes ||
		!snapshot.Artifact.expiresAt.Equal(snapshot.ExpiresAt)) {
		return false
	}
	if hasTerminal && (!validInstant(*snapshot.TerminalAt) ||
		snapshot.TerminalAt.Before(snapshot.RequestedAt) ||
		snapshot.TerminalAt.After(snapshot.UpdatedAt) ||
		snapshot.TerminalAt.After(snapshot.ExpiresAt)) {
		return false
	}
	switch snapshot.State {
	case TicketExportPending:
		return !hasLease && !hasArtifact && !hasTerminal &&
			(snapshot.Attempts == 0 && snapshot.Revision == 1 &&
				snapshot.FailureCode == TicketExportFailureNone &&
				snapshot.UpdatedAt.Equal(snapshot.RequestedAt) &&
				snapshot.AvailableAt.Equal(snapshot.RequestedAt) ||
				snapshot.Attempts > 0 &&
					!snapshot.AvailableAt.Before(snapshot.UpdatedAt) &&
					(retryableTicketExportFailureCode(snapshot.FailureCode) ||
						snapshot.FailureCode == TicketExportFailureLeaseExpired))
	case TicketExportRunning:
		return hasLease && !hasArtifact && !hasTerminal && snapshot.Attempts > 0 &&
			snapshot.FailureCode == TicketExportFailureNone &&
			snapshot.Lease.expiresAt.After(snapshot.UpdatedAt)
	case TicketExportCancellationRequested:
		return hasLease && !hasArtifact && !hasTerminal && snapshot.Attempts > 0 &&
			snapshot.FailureCode == TicketExportFailureNone
	case TicketExportSucceeded:
		return !hasLease && hasArtifact && hasTerminal && snapshot.Attempts > 0 &&
			snapshot.FailureCode == TicketExportFailureNone &&
			snapshot.TerminalAt.Equal(snapshot.UpdatedAt) &&
			snapshot.Artifact.expiresAt.After(*snapshot.TerminalAt)
	case TicketExportFailed:
		return !hasLease && !hasArtifact && hasTerminal &&
			validTicketExportFailureCode(snapshot.FailureCode) &&
			snapshot.TerminalAt.Equal(snapshot.UpdatedAt) &&
			(snapshot.Attempts > 0 || snapshot.FailureCode == TicketExportFailureExpired ||
				snapshot.FailureCode == TicketExportFailureAuthorizationRevoked) &&
			(snapshot.FailureCode != TicketExportFailureExpired ||
				snapshot.TerminalAt.Equal(snapshot.ExpiresAt)) &&
			(snapshot.FailureCode != TicketExportFailureAuthorizationRevoked ||
				snapshot.TerminalAt.Before(snapshot.ExpiresAt)) &&
			(snapshot.FailureCode != TicketExportFailureLeaseExpired ||
				snapshot.Attempts == snapshot.Definition.maximumAttempts)
	case TicketExportCancelledState:
		return !hasLease && !hasArtifact && hasTerminal &&
			snapshot.FailureCode == TicketExportFailureNone && snapshot.TerminalAt.Equal(snapshot.UpdatedAt)
	default:
		return false
	}
}

func (job TicketExportJob) Definition() TicketExportDefinition {
	return cloneTicketExportDefinition(job.definition)
}
func (job TicketExportJob) State() TicketExportState             { return job.state }
func (job TicketExportJob) Revision() uint64                     { return job.revision }
func (job TicketExportJob) Attempts() uint8                      { return job.attempts }
func (job TicketExportJob) FailureCode() TicketExportFailureCode { return job.failureCode }
func (job TicketExportJob) RequestedAt() time.Time               { return job.requestedAt }
func (job TicketExportJob) UpdatedAt() time.Time                 { return job.updatedAt }
func (job TicketExportJob) AvailableAt() time.Time               { return job.availableAt }
func (job TicketExportJob) ExpiresAt() time.Time                 { return job.expiresAt }
func (job TicketExportJob) Lease() *TicketExportLease            { return cloneTicketExportLease(job.lease) }
func (job TicketExportJob) Artifact() *TicketExportArtifact {
	return cloneTicketExportArtifact(job.artifact)
}
func (job TicketExportJob) TerminalAt() *time.Time { return cloneTicketExportTime(job.terminalAt) }
func (job TicketExportJob) Snapshot() TicketExportJobSnapshot {
	return TicketExportJobSnapshot{
		Definition: cloneTicketExportDefinition(job.definition), State: job.state,
		Revision: job.revision, Attempts: job.attempts, FailureCode: job.failureCode,
		RequestedAt: job.requestedAt, UpdatedAt: job.updatedAt,
		AvailableAt: job.availableAt, ExpiresAt: job.expiresAt,
		Lease: cloneTicketExportLease(job.lease), Artifact: cloneTicketExportArtifact(job.artifact),
		TerminalAt: cloneTicketExportTime(job.terminalAt),
	}
}
func (job TicketExportJob) String() string {
	return fmt.Sprintf(
		"TicketExportJob{kind:%s,audience:%s,state:%s,revision:%d,attempts:%d,failure:%s,metadata:[REDACTED]}",
		job.definition.kind, job.definition.audience, job.state, job.revision, job.attempts, job.failureCode,
	)
}
func (job TicketExportJob) GoString() string { return job.String() }

func ValidateTicketExportJob(job TicketExportJob) error {
	rebuilt, err := RestoreTicketExportJob(job.Snapshot())
	if err != nil || !reflect.DeepEqual(rebuilt, job) {
		return ErrInvalidTicketExport
	}
	return nil
}

func SameTicketExportJob(left, right TicketExportJob) bool {
	return reflect.DeepEqual(left.Snapshot(), right.Snapshot())
}

type TicketExportAction uint8

const (
	TicketExportCreate TicketExportAction = iota + 1
	TicketExportClaim
	TicketExportExpireLease
	TicketExportRenewLease
	TicketExportRequestCancellation
	TicketExportAcknowledgeCancellation
	TicketExportExpireCancellation
	TicketExportRevokeAuthorization
	TicketExportSucceed
	TicketExportRetry
	TicketExportFail
	TicketExportExpire
)

func (action TicketExportAction) String() string {
	switch action {
	case TicketExportCreate:
		return "create"
	case TicketExportClaim:
		return "claim"
	case TicketExportExpireLease:
		return "expire_lease"
	case TicketExportRenewLease:
		return "renew_lease"
	case TicketExportRequestCancellation:
		return "request_cancellation"
	case TicketExportAcknowledgeCancellation:
		return "acknowledge_cancellation"
	case TicketExportExpireCancellation:
		return "expire_cancellation"
	case TicketExportRevokeAuthorization:
		return "revoke_authorization"
	case TicketExportSucceed:
		return "succeed"
	case TicketExportRetry:
		return "retry"
	case TicketExportFail:
		return "fail"
	case TicketExportExpire:
		return "expire"
	default:
		return "unknown"
	}
}

type TicketExportPlan struct {
	action           TicketExportAction
	expectedRevision uint64
	next             TicketExportJob
}

func (plan TicketExportPlan) Action() TicketExportAction { return plan.action }
func (plan TicketExportPlan) ExpectedRevision() uint64   { return plan.expectedRevision }
func (plan TicketExportPlan) Next() TicketExportJob      { return cloneTicketExportJob(plan.next) }
func (plan TicketExportPlan) String() string {
	return fmt.Sprintf(
		"TicketExportPlan{action:%s,expected_revision:%d,next_revision:%d,state:%s,metadata:[REDACTED]}",
		plan.action, plan.expectedRevision, plan.next.revision, plan.next.state,
	)
}
func (plan TicketExportPlan) GoString() string { return plan.String() }

func PlanTicketExportCreation(
	definition TicketExportDefinition,
	requestedAt time.Time,
	expiresAt time.Time,
) (TicketExportPlan, error) {
	job, err := RestoreTicketExportJob(TicketExportJobSnapshot{
		Definition: definition, State: TicketExportPending, Revision: 1,
		RequestedAt: requestedAt, UpdatedAt: requestedAt, AvailableAt: requestedAt,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{action: TicketExportCreate, next: job}, nil
}

func PlanTicketExportClaim(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	now time.Time,
	leaseUntil time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	claimable := current.state == TicketExportPending && !current.availableAt.After(now) ||
		current.state == TicketExportRunning && current.lease != nil && !current.lease.expiresAt.After(now)
	if !claimable || current.attempts >= current.definition.maximumAttempts {
		return TicketExportPlan{}, ErrTicketExportNotClaimable
	}
	if current.lease != nil && current.lease.fence == fence {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	lease, err := NewTicketExportLease(worker, fence, now, leaseUntil)
	if err != nil || leaseUntil.After(current.expiresAt) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	next := current.Snapshot()
	next.State, next.Revision, next.Attempts = TicketExportRunning, current.revision+1, current.attempts+1
	next.FailureCode, next.UpdatedAt, next.Lease = TicketExportFailureNone, now, &lease
	job, err := RestoreTicketExportJob(next)
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{action: TicketExportClaim, expectedRevision: current.revision, next: job}, nil
}

func PlanTicketExportLeaseRenewal(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	now time.Time,
	leaseUntil time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state == TicketExportCancellationRequested {
		return TicketExportPlan{}, ErrTicketExportCancelled
	}
	if current.state != TicketExportRunning {
		return TicketExportPlan{}, ticketExportStateError(current.state)
	}
	if err := validateTicketExportFence(current, worker, fence, now); err != nil {
		return TicketExportPlan{}, err
	}
	if !leaseUntil.After(current.lease.expiresAt) || leaseUntil.After(current.expiresAt) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	lease, err := NewTicketExportLease(worker, fence, now, leaseUntil)
	if err != nil {
		return TicketExportPlan{}, err
	}
	next := current.Snapshot()
	next.Revision, next.UpdatedAt, next.Lease = current.revision+1, now, &lease
	job, err := RestoreTicketExportJob(next)
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{action: TicketExportRenewLease, expectedRevision: current.revision, next: job}, nil
}

// PlanTicketExportLeaseExpiry releases a crashed worker without waiting for
// the job retention deadline. The attempt is terminal at the ceiling and is
// otherwise made immediately eligible for another fenced claim.
func PlanTicketExportLeaseExpiry(
	current TicketExportJob,
	now time.Time,
) (TicketExportPlan, error) {
	if ValidateTicketExportJob(current) != nil || !validInstant(now) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	if !now.Before(current.expiresAt) {
		return PlanTicketExportExpiry(current, now)
	}
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state != TicketExportRunning || current.lease == nil ||
		current.lease.expiresAt.After(now) {
		return TicketExportPlan{}, ErrTicketExportNotClaimable
	}
	if current.attempts >= current.definition.maximumAttempts {
		return terminalTicketExportPlan(
			current, TicketExportExpireLease, TicketExportFailed,
			TicketExportFailureLeaseExpired, nil, now,
		)
	}
	next := current.Snapshot()
	next.State, next.Revision = TicketExportPending, current.revision+1
	next.FailureCode, next.UpdatedAt, next.AvailableAt = TicketExportFailureLeaseExpired, now, now
	next.Lease = nil
	job, err := RestoreTicketExportJob(next)
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{
		action: TicketExportExpireLease, expectedRevision: current.revision, next: job,
	}, nil
}

func PlanTicketExportCancellation(
	current TicketExportJob,
	expectedRevision uint64,
	now time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportExpectedTransition(current, expectedRevision, now); err != nil {
		return TicketExportPlan{}, err
	}
	next := current.Snapshot()
	next.Revision, next.UpdatedAt = current.revision+1, now
	switch current.state {
	case TicketExportPending:
		next.State, next.FailureCode, next.TerminalAt =
			TicketExportCancelledState, TicketExportFailureNone, &now
	case TicketExportRunning:
		next.State = TicketExportCancellationRequested
	case TicketExportCancellationRequested:
		return TicketExportPlan{}, ErrTicketExportNoChange
	default:
		return TicketExportPlan{}, ErrTicketExportTerminal
	}
	job, err := RestoreTicketExportJob(next)
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{
		action: TicketExportRequestCancellation, expectedRevision: current.revision, next: job,
	}, nil
}

func PlanTicketExportCancellationAcknowledgement(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	now time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state != TicketExportCancellationRequested {
		return TicketExportPlan{}, ticketExportStateError(current.state)
	}
	if err := validateTicketExportFence(current, worker, fence, now); err != nil {
		return TicketExportPlan{}, err
	}
	return terminalTicketExportPlan(current, TicketExportAcknowledgeCancellation,
		TicketExportCancelledState, TicketExportFailureNone, nil, now)
}

func PlanTicketExportCancellationExpiry(
	current TicketExportJob,
	now time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state != TicketExportCancellationRequested || current.lease == nil ||
		current.lease.expiresAt.After(now) {
		return TicketExportPlan{}, ErrTicketExportNotClaimable
	}
	return terminalTicketExportPlan(current, TicketExportExpireCancellation,
		TicketExportCancelledState, TicketExportFailureNone, nil, now)
}

// PlanTicketExportAuthorizationRevocation is a terminal-only cleanup path for
// a service that has proved the original requester/resource authorization is
// no longer live. It grants no query or artifact access and still requires the
// repository CAS on the returned expected revision.
func PlanTicketExportAuthorizationRevocation(
	current TicketExportJob,
	now time.Time,
) (TicketExportPlan, error) {
	if ValidateTicketExportJob(current) != nil || !validInstant(now) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	if !now.Before(current.expiresAt) {
		return PlanTicketExportExpiry(current, now)
	}
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state == TicketExportSucceeded || current.state == TicketExportFailed ||
		current.state == TicketExportCancelledState {
		return TicketExportPlan{}, ErrTicketExportTerminal
	}
	return terminalTicketExportPlan(
		current, TicketExportRevokeAuthorization, TicketExportFailed,
		TicketExportFailureAuthorizationRevoked, nil, now,
	)
}

func PlanTicketExportSuccess(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	artifact TicketExportArtifact,
	now time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state == TicketExportCancellationRequested {
		return TicketExportPlan{}, ErrTicketExportCancelled
	}
	if current.state != TicketExportRunning {
		return TicketExportPlan{}, ticketExportStateError(current.state)
	}
	if err := validateTicketExportFence(current, worker, fence, now); err != nil {
		return TicketExportPlan{}, err
	}
	if !validTicketExportArtifact(artifact) || artifact.rows > current.definition.maximumRows ||
		artifact.bytes > current.definition.maximumBytes || !artifact.expiresAt.After(now) ||
		!artifact.expiresAt.Equal(current.expiresAt) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	return terminalTicketExportPlan(
		current, TicketExportSucceed, TicketExportSucceeded, TicketExportFailureNone, &artifact, now,
	)
}

func PlanTicketExportFailure(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	code TicketExportFailureCode,
	retryAt *time.Time,
	now time.Time,
) (TicketExportPlan, error) {
	if err := validateTicketExportTransition(current, now); err != nil {
		return TicketExportPlan{}, err
	}
	if current.state == TicketExportCancellationRequested {
		return TicketExportPlan{}, ErrTicketExportCancelled
	}
	if current.state != TicketExportRunning {
		return TicketExportPlan{}, ticketExportStateError(current.state)
	}
	if err := validateTicketExportFence(current, worker, fence, now); err != nil {
		return TicketExportPlan{}, err
	}
	if !workerTicketExportFailureCode(code) ||
		retryAt != nil && !retryableTicketExportFailureCode(code) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	if retryAt != nil && (!validInstant(*retryAt) ||
		retryAt.Sub(now) < TicketExportMinimumRetry ||
		retryAt.Sub(now) > TicketExportMaximumRetry) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	if retryAt != nil && current.attempts < current.definition.maximumAttempts &&
		retryAt.Before(current.expiresAt) {
		next := current.Snapshot()
		next.State, next.Revision = TicketExportPending, current.revision+1
		next.FailureCode, next.UpdatedAt, next.AvailableAt = code, now, *retryAt
		next.Lease = nil
		job, err := RestoreTicketExportJob(next)
		if err != nil {
			return TicketExportPlan{}, err
		}
		return TicketExportPlan{action: TicketExportRetry, expectedRevision: current.revision, next: job}, nil
	}
	return terminalTicketExportPlan(current, TicketExportFail, TicketExportFailed, code, nil, now)
}

func PlanTicketExportExpiry(current TicketExportJob, now time.Time) (TicketExportPlan, error) {
	if ValidateTicketExportJob(current) != nil || !validInstant(now) {
		return TicketExportPlan{}, ErrInvalidTicketExport
	}
	if now.Before(current.expiresAt) {
		return TicketExportPlan{}, ErrTicketExportNotClaimable
	}
	if current.state == TicketExportSucceeded || current.state == TicketExportFailed ||
		current.state == TicketExportCancelledState {
		return TicketExportPlan{}, ErrTicketExportTerminal
	}
	if current.state == TicketExportCancellationRequested {
		return terminalTicketExportPlan(current, TicketExportExpire,
			TicketExportCancelledState, TicketExportFailureNone, nil, current.expiresAt)
	}
	return terminalTicketExportPlan(current, TicketExportExpire,
		TicketExportFailed, TicketExportFailureExpired, nil, current.expiresAt)
}

func terminalTicketExportPlan(
	current TicketExportJob,
	action TicketExportAction,
	state TicketExportState,
	code TicketExportFailureCode,
	artifact *TicketExportArtifact,
	now time.Time,
) (TicketExportPlan, error) {
	next := current.Snapshot()
	next.State, next.Revision, next.UpdatedAt = state, current.revision+1, now
	next.FailureCode, next.Lease, next.Artifact, next.TerminalAt = code, nil, cloneTicketExportArtifact(artifact), &now
	job, err := RestoreTicketExportJob(next)
	if err != nil {
		return TicketExportPlan{}, err
	}
	return TicketExportPlan{action: action, expectedRevision: current.revision, next: job}, nil
}

func validateTicketExportExpectedTransition(
	current TicketExportJob,
	expectedRevision uint64,
	now time.Time,
) error {
	if err := validateTicketExportTransition(current, now); err != nil {
		return err
	}
	if expectedRevision == 0 || current.revision != expectedRevision {
		return ErrTicketExportConflict
	}
	return nil
}

func validateTicketExportTransition(current TicketExportJob, now time.Time) error {
	if ValidateTicketExportJob(current) != nil || !validInstant(now) || current.revision == maxVersion ||
		now.Before(current.updatedAt) || now.After(current.expiresAt) {
		return ErrInvalidTicketExport
	}
	return nil
}

func validateTicketExportFence(
	current TicketExportJob,
	worker EntityID,
	fence [32]byte,
	now time.Time,
) error {
	if !validEntityID(worker) || fence == ([32]byte{}) || current.lease == nil ||
		current.lease.worker != worker || current.lease.fence != fence ||
		!current.lease.expiresAt.After(now) {
		return ErrTicketExportFenceMismatch
	}
	return nil
}

func ticketExportStateError(state TicketExportState) error {
	if state == TicketExportCancellationRequested {
		return ErrTicketExportCancelled
	}
	if state == TicketExportSucceeded || state == TicketExportFailed || state == TicketExportCancelledState {
		return ErrTicketExportTerminal
	}
	return ErrTicketExportNotClaimable
}

func cloneTicketExportDefinition(value TicketExportDefinition) TicketExportDefinition {
	result := value
	result.customerContact = cloneTicketExportEntity(value.customerContact)
	result.savedView = cloneTicketExportSavedViewPin(value.savedView)
	return result
}

func cloneTicketExportJob(value TicketExportJob) TicketExportJob {
	result := value
	result.definition = cloneTicketExportDefinition(value.definition)
	result.lease = cloneTicketExportLease(value.lease)
	result.artifact = cloneTicketExportArtifact(value.artifact)
	result.terminalAt = cloneTicketExportTime(value.terminalAt)
	return result
}

func cloneTicketExportEntity(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketExportSavedViewPin(value *TicketExportSavedViewPin) *TicketExportSavedViewPin {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketExportLease(value *TicketExportLease) *TicketExportLease {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketExportArtifact(value *TicketExportArtifact) *TicketExportArtifact {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketExportTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
