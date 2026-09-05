package ticketing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	AsyncExportDefaultRows      = uint32(10_000)
	AsyncExportDefaultBytes     = uint64(64 * 1024 * 1024)
	AsyncExportDefaultRetention = 24 * time.Hour
	AsyncExportDefaultPageSize  = 500
	AsyncExportMaximumPageSize  = 1_000
	AsyncExportMaximumPageBytes = 4 * 1024 * 1024
	AsyncExportMaximumCellBytes = 128 * 1024
	AsyncExportWorkerPurpose    = "ticket_export"
	asyncExportCatalogDomain    = "periapsis.ticketing.async-export.catalog.v1"
)

type AsyncExportCapability string

const (
	AsyncExportCapabilityRequest AsyncExportCapability = "ticket_export.request"
	AsyncExportCapabilityRead    AsyncExportCapability = "ticket_export.read"
	AsyncExportCapabilityCancel  AsyncExportCapability = "ticket_export.cancel"
	AsyncExportCapabilityClaim   AsyncExportCapability = "ticket_export.claim"
	AsyncExportCapabilityExecute AsyncExportCapability = "ticket_export.execute"
)

func validAsyncExportHumanCapability(capability AsyncExportCapability) bool {
	switch capability {
	case AsyncExportCapabilityRequest, AsyncExportCapabilityRead, AsyncExportCapabilityCancel:
		return true
	default:
		return false
	}
}

// AsyncExportAccess is fresh authority for one exact human route intent. Role
// names are deliberately absent; the adapter resolves live capability/scope
// and, for customer routes, the exact current contact relationship.
type AsyncExportAccess struct {
	tenant          uuid.UUID
	actor           uuid.UUID
	membership      uuid.UUID
	kind            kernel.AggregateKind
	audience        kernel.TicketExportAudience
	capability      AsyncExportCapability
	principal       kernel.PrincipalKind
	customerContact *uuid.UUID
	publicComments  bool
	privateComments bool
	allowed         bool
}

func NewAsyncExportAccess(
	tenant uuid.UUID,
	actor uuid.UUID,
	membership uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
	principal kernel.PrincipalKind,
	customerContact *uuid.UUID,
	publicComments bool,
	privateComments bool,
	allowed bool,
) (AsyncExportAccess, error) {
	if !validWorkflowUUID(tenant) || !validWorkflowUUID(actor) || !validWorkflowUUID(membership) ||
		!validSavedViewKind(kind) || !validAsyncExportAudience(audience) ||
		!validAsyncExportHumanCapability(capability) ||
		principal != kernel.PrincipalOperator && principal != kernel.PrincipalCustomer &&
			principal != kernel.PrincipalServiceAccount {
		return AsyncExportAccess{}, ErrInvalidInput
	}
	if audience == kernel.TicketExportAudienceCustomer {
		if customerContact == nil || !validWorkflowUUID(*customerContact) || privateComments {
			return AsyncExportAccess{}, ErrInvalidInput
		}
	} else if customerContact != nil {
		return AsyncExportAccess{}, ErrInvalidInput
	}
	return AsyncExportAccess{
		tenant: tenant, actor: actor, membership: membership, kind: kind,
		audience: audience, capability: capability, principal: principal,
		customerContact: cloneAsyncExportUUID(customerContact),
		publicComments:  publicComments, privateComments: privateComments, allowed: allowed,
	}, nil
}

func (access AsyncExportAccess) Tenant() uuid.UUID                     { return access.tenant }
func (access AsyncExportAccess) Actor() uuid.UUID                      { return access.actor }
func (access AsyncExportAccess) Membership() uuid.UUID                 { return access.membership }
func (access AsyncExportAccess) Kind() kernel.AggregateKind            { return access.kind }
func (access AsyncExportAccess) Audience() kernel.TicketExportAudience { return access.audience }
func (access AsyncExportAccess) Capability() AsyncExportCapability     { return access.capability }
func (access AsyncExportAccess) Principal() kernel.PrincipalKind       { return access.principal }
func (access AsyncExportAccess) CustomerContact() *uuid.UUID {
	return cloneAsyncExportUUID(access.customerContact)
}
func (access AsyncExportAccess) PublicCommentsAllowed() bool  { return access.publicComments }
func (access AsyncExportAccess) PrivateCommentsAllowed() bool { return access.privateComments }
func (access AsyncExportAccess) Allowed() bool                { return access.allowed }
func (access AsyncExportAccess) String() string               { return "AsyncExportAccess{authority:[REDACTED]}" }
func (access AsyncExportAccess) GoString() string             { return access.String() }

type AsyncExportWorker struct {
	ServiceAccountID uuid.UUID
	WorkerID         uuid.UUID
	Purpose          string
}

func (worker AsyncExportWorker) String() string {
	return "AsyncExportWorker{identity:[REDACTED],purpose:[REDACTED]}"
}
func (worker AsyncExportWorker) GoString() string { return worker.String() }

func validAsyncExportWorker(worker AsyncExportWorker) bool {
	return validWorkflowUUID(worker.ServiceAccountID) && validWorkflowUUID(worker.WorkerID) &&
		worker.Purpose == AsyncExportWorkerPurpose
}

// AsyncExportWorkerAccess is a least-privileged service-purpose grant for one
// tenant/kind/audience queue. It conveys no cross-tenant scan authority.
type AsyncExportWorkerAccess struct {
	tenant         uuid.UUID
	serviceAccount uuid.UUID
	kind           kernel.AggregateKind
	audience       kernel.TicketExportAudience
	capability     AsyncExportCapability
	allowed        bool
}

func NewAsyncExportWorkerAccess(
	tenant uuid.UUID,
	serviceAccount uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
	allowed bool,
) (AsyncExportWorkerAccess, error) {
	if !validWorkflowUUID(tenant) || !validWorkflowUUID(serviceAccount) ||
		!validSavedViewKind(kind) || !validAsyncExportAudience(audience) ||
		capability != AsyncExportCapabilityClaim && capability != AsyncExportCapabilityExecute {
		return AsyncExportWorkerAccess{}, ErrInvalidInput
	}
	return AsyncExportWorkerAccess{
		tenant: tenant, serviceAccount: serviceAccount, kind: kind,
		audience: audience, capability: capability, allowed: allowed,
	}, nil
}

func (access AsyncExportWorkerAccess) Tenant() uuid.UUID                     { return access.tenant }
func (access AsyncExportWorkerAccess) ServiceAccount() uuid.UUID             { return access.serviceAccount }
func (access AsyncExportWorkerAccess) Kind() kernel.AggregateKind            { return access.kind }
func (access AsyncExportWorkerAccess) Audience() kernel.TicketExportAudience { return access.audience }
func (access AsyncExportWorkerAccess) Capability() AsyncExportCapability     { return access.capability }
func (access AsyncExportWorkerAccess) Allowed() bool                         { return access.allowed }
func (access AsyncExportWorkerAccess) String() string {
	return "AsyncExportWorkerAccess{authority:[REDACTED]}"
}
func (access AsyncExportWorkerAccess) GoString() string { return access.String() }

type AsyncExportSavedViewSourceInput struct {
	ID                 uuid.UUID
	ExpectedRevision   uint64
	ExpectedSpecDigest [sha256.Size]byte
}

func (input AsyncExportSavedViewSourceInput) String() string {
	return fmt.Sprintf(
		"AsyncExportSavedViewSourceInput{expected_revision:%d,metadata:[REDACTED]}",
		input.ExpectedRevision,
	)
}
func (input AsyncExportSavedViewSourceInput) GoString() string { return input.String() }

type AsyncExportSourceInput struct {
	Inline    *SavedViewSpecInput
	SavedView *AsyncExportSavedViewSourceInput
}

func (input AsyncExportSourceInput) String() string {
	source := "invalid"
	if input.Inline != nil && input.SavedView == nil {
		source = "inline"
	}
	if input.Inline == nil && input.SavedView != nil {
		source = "saved_view"
	}
	return fmt.Sprintf("AsyncExportSourceInput{source:%s,query:[REDACTED]}", source)
}
func (input AsyncExportSourceInput) GoString() string { return input.String() }

type AsyncExportRequestInput struct {
	Audience       kernel.TicketExportAudience
	Comments       kernel.TicketExportCommentScope
	Source         AsyncExportSourceInput
	MaximumRows    uint32
	MaximumBytes   uint64
	Retention      time.Duration
	IdempotencyKey string
}

func (input AsyncExportRequestInput) String() string {
	return fmt.Sprintf(
		"AsyncExportRequestInput{audience:%s,comments:%s,source:%s,maximum_rows:%d,maximum_bytes:%d,retention:%s,idempotency_key:[REDACTED]}",
		input.Audience, input.Comments, input.Source, input.MaximumRows, input.MaximumBytes, input.Retention,
	)
}
func (input AsyncExportRequestInput) GoString() string { return input.String() }

type AsyncExportCancelInput struct {
	ExpectedRevision uint64
	IdempotencyKey   string
}

func (input AsyncExportCancelInput) String() string {
	return fmt.Sprintf(
		"AsyncExportCancelInput{expected_revision:%d,idempotency_key:[REDACTED]}",
		input.ExpectedRevision,
	)
}
func (input AsyncExportCancelInput) GoString() string { return input.String() }

// AsyncExportQuerySnapshot is canonical query state resolved under current
// authorization. Saved-view source is operator-only and pinned to the exact
// current owner/revision/digest; customer requests use a closed inline shape.
type AsyncExportQuerySnapshot struct {
	tenant        uuid.UUID
	kind          kernel.AggregateKind
	source        kernel.TicketExportQuerySource
	spec          kernel.SavedViewSpec
	savedView     *kernel.TicketExportSavedViewPin
	queryDigest   [sha256.Size]byte
	catalogDigest [sha256.Size]byte
}

func NewAsyncExportQuerySnapshot(
	tenant uuid.UUID,
	kind kernel.AggregateKind,
	source kernel.TicketExportQuerySource,
	spec kernel.SavedViewSpec,
	savedView *kernel.TicketExportSavedViewPin,
) (AsyncExportQuerySnapshot, error) {
	tenantEntity, err := entityID(tenant)
	if err != nil || !validSavedViewKind(kind) ||
		source != kernel.TicketExportQueryInline && source != kernel.TicketExportQuerySavedView ||
		kernel.ValidateSavedViewSpec(tenantEntity, kind, spec) != nil {
		return AsyncExportQuerySnapshot{}, ErrInvalidInput
	}
	queryDigest, err := SavedViewSpecDigest(tenantEntity, kind, spec)
	if err != nil {
		return AsyncExportQuerySnapshot{}, err
	}
	if source == kernel.TicketExportQuerySavedView {
		if savedView == nil || savedView.Revision() > maxResourceVersion ||
			savedView.Digest() != queryDigest {
			return AsyncExportQuerySnapshot{}, ErrInvalidInput
		}
	} else if savedView != nil {
		return AsyncExportQuerySnapshot{}, ErrInvalidInput
	}
	catalogDigest, err := asyncExportCatalogDigest(spec)
	if err != nil {
		return AsyncExportQuerySnapshot{}, err
	}
	return AsyncExportQuerySnapshot{
		tenant: tenant, kind: kind, source: source, spec: spec,
		savedView:   cloneAsyncExportSavedViewPin(savedView),
		queryDigest: queryDigest, catalogDigest: catalogDigest,
	}, nil
}

func (snapshot AsyncExportQuerySnapshot) Tenant() uuid.UUID          { return snapshot.tenant }
func (snapshot AsyncExportQuerySnapshot) Kind() kernel.AggregateKind { return snapshot.kind }
func (snapshot AsyncExportQuerySnapshot) Source() kernel.TicketExportQuerySource {
	return snapshot.source
}
func (snapshot AsyncExportQuerySnapshot) Spec() kernel.SavedViewSpec { return snapshot.spec }
func (snapshot AsyncExportQuerySnapshot) SavedView() *kernel.TicketExportSavedViewPin {
	return cloneAsyncExportSavedViewPin(snapshot.savedView)
}
func (snapshot AsyncExportQuerySnapshot) QueryDigest() [sha256.Size]byte { return snapshot.queryDigest }
func (snapshot AsyncExportQuerySnapshot) CatalogDigest() [sha256.Size]byte {
	return snapshot.catalogDigest
}
func (snapshot AsyncExportQuerySnapshot) String() string {
	return fmt.Sprintf(
		"AsyncExportQuerySnapshot{kind:%s,source:%s,columns:%d,query:[REDACTED],catalog:[REDACTED]}",
		snapshot.kind, snapshot.source, len(snapshot.spec.Columns()),
	)
}
func (snapshot AsyncExportQuerySnapshot) GoString() string { return snapshot.String() }

func normalizeAsyncExportQuerySnapshot(snapshot AsyncExportQuerySnapshot) (AsyncExportQuerySnapshot, bool) {
	rebuilt, err := NewAsyncExportQuerySnapshot(
		snapshot.tenant, snapshot.kind, snapshot.source, snapshot.spec, snapshot.savedView,
	)
	return rebuilt, err == nil && rebuilt.queryDigest == snapshot.queryDigest &&
		rebuilt.catalogDigest == snapshot.catalogDigest
}

type asyncExportCatalogPin struct {
	Source  string `json:"source"`
	ID      string `json:"id"`
	Tenant  string `json:"tenant"`
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Version uint64 `json:"version"`
	Digest  string `json:"digest"`
}

type asyncExportCatalogEnvelope struct {
	Domain string                  `json:"domain"`
	Pins   []asyncExportCatalogPin `json:"pins"`
}

func asyncExportCatalogDigest(spec kernel.SavedViewSpec) ([sha256.Size]byte, error) {
	pins := make(map[string]asyncExportCatalogPin)
	for _, filter := range spec.Filters().Custom() {
		pin := filter.Definition()
		if pin.Version() > maxResourceVersion {
			return [sha256.Size]byte{}, ErrInvalidInput
		}
		addAsyncExportCatalogPin(pins, kernel.SavedViewColumnCustomField.String(), pin)
	}
	for _, column := range spec.Columns() {
		pin, dynamic := column.Definition()
		if dynamic {
			if pin.Version() > maxResourceVersion {
				return [sha256.Size]byte{}, ErrInvalidInput
			}
			addAsyncExportCatalogPin(pins, column.Source().String(), pin)
		}
	}
	if pin, dynamic := spec.Sort().Definition(); dynamic {
		if pin.Version() > maxResourceVersion {
			return [sha256.Size]byte{}, ErrInvalidInput
		}
		addAsyncExportCatalogPin(pins, spec.Sort().Source().String(), pin)
	}
	keys := make([]string, 0, len(pins))
	for key := range pins {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]asyncExportCatalogPin, len(keys))
	for index, key := range keys {
		ordered[index] = pins[key]
	}
	encoded, err := json.Marshal(asyncExportCatalogEnvelope{Domain: asyncExportCatalogDomain, Pins: ordered})
	if err != nil {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	return sha256.Sum256(encoded), nil
}

func addAsyncExportCatalogPin(
	result map[string]asyncExportCatalogPin,
	source string,
	pin kernel.SavedViewDefinitionPin,
) {
	digest := pin.Digest()
	key := source + ":" + pin.ID().String()
	result[key] = asyncExportCatalogPin{
		Source: source, ID: pin.ID().String(), Tenant: pin.Tenant().String(),
		Kind: pin.Kind().String(), Key: pin.Key().String(), Version: pin.Version(),
		Digest: hex.EncodeToString(digest[:]),
	}
}

type AsyncExportRecord struct {
	Job   kernel.TicketExportJob
	Query AsyncExportQuerySnapshot
}

func (record AsyncExportRecord) String() string {
	return fmt.Sprintf("AsyncExportRecord{job:%s,query:[REDACTED]}", record.Job)
}
func (record AsyncExportRecord) GoString() string { return record.String() }

type AsyncExportResult struct {
	Record   AsyncExportRecord
	Replayed bool
}

func (result AsyncExportResult) String() string {
	return fmt.Sprintf("AsyncExportResult{replayed:%t,record:[REDACTED]}", result.Replayed)
}
func (result AsyncExportResult) GoString() string { return result.String() }

type AsyncExportRevocationResult struct {
	Job kernel.TicketExportJob
}

func (result AsyncExportRevocationResult) String() string {
	return fmt.Sprintf("AsyncExportRevocationResult{job:%s}", result.Job)
}
func (result AsyncExportRevocationResult) GoString() string { return result.String() }

type AsyncExportRowKind uint8

const (
	AsyncExportTicketRow AsyncExportRowKind = iota + 1
	AsyncExportPublicCommentRow
	AsyncExportPrivateCommentRow
)

func (kind AsyncExportRowKind) String() string {
	switch kind {
	case AsyncExportTicketRow:
		return "ticket"
	case AsyncExportPublicCommentRow:
		return "public_comment"
	case AsyncExportPrivateCommentRow:
		return "private_comment"
	default:
		return "unknown"
	}
}

type AsyncExportRow struct {
	Kind  AsyncExportRowKind
	Cells []string
}

func (row AsyncExportRow) String() string {
	return fmt.Sprintf("AsyncExportRow{kind:%s,cells:%d,values:[REDACTED]}", row.Kind, len(row.Cells))
}
func (row AsyncExportRow) GoString() string { return row.String() }

type AsyncExportPage struct {
	Rows       []AsyncExportRow
	NextCursor string
}

func (page AsyncExportPage) String() string {
	return fmt.Sprintf("AsyncExportPage{rows:%d,next_cursor:[REDACTED]}", len(page.Rows))
}
func (page AsyncExportPage) GoString() string { return page.String() }

type AsyncExportPageInput struct {
	ExpectedRevision uint64
	Fence            [sha256.Size]byte
	After            string
	Limit            int
}

func (input AsyncExportPageInput) String() string {
	return fmt.Sprintf(
		"AsyncExportPageInput{expected_revision:%d,limit:%d,fence:[REDACTED],cursor:[REDACTED]}",
		input.ExpectedRevision, input.Limit,
	)
}
func (input AsyncExportPageInput) GoString() string { return input.String() }

type AsyncExportClaimInput struct {
	LeaseDuration time.Duration
}

type AsyncExportRenewInput struct {
	ExpectedRevision uint64
	Fence            [sha256.Size]byte
	LeaseDuration    time.Duration
}

func (input AsyncExportRenewInput) String() string {
	return fmt.Sprintf(
		"AsyncExportRenewInput{expected_revision:%d,lease_duration:%s,fence:[REDACTED]}",
		input.ExpectedRevision, input.LeaseDuration,
	)
}
func (input AsyncExportRenewInput) GoString() string { return input.String() }

type AsyncExportArtifactInput struct {
	ID        uuid.UUID
	Digest    [sha256.Size]byte
	Rows      uint32
	Bytes     uint64
	ExpiresAt time.Time
}

func (input AsyncExportArtifactInput) String() string {
	return fmt.Sprintf("AsyncExportArtifactInput{rows:%d,bytes:%d,metadata:[REDACTED]}", input.Rows, input.Bytes)
}
func (input AsyncExportArtifactInput) GoString() string { return input.String() }

type AsyncExportFinishAction uint8

const (
	AsyncExportFinishSuccess AsyncExportFinishAction = iota + 1
	AsyncExportFinishFailure
	AsyncExportFinishCancellation
)

type AsyncExportFinishInput struct {
	ExpectedRevision uint64
	Fence            [sha256.Size]byte
	Action           AsyncExportFinishAction
	Artifact         *AsyncExportArtifactInput
	FailureCode      kernel.TicketExportFailureCode
	RetryAt          *time.Time
}

func (input AsyncExportFinishInput) String() string {
	return fmt.Sprintf(
		"AsyncExportFinishInput{expected_revision:%d,action:%d,failure:%s,artifact:[REDACTED],fence:[REDACTED]}",
		input.ExpectedRevision, input.Action, input.FailureCode,
	)
}
func (input AsyncExportFinishInput) GoString() string { return input.String() }

func validAsyncExportAudience(audience kernel.TicketExportAudience) bool {
	return audience == kernel.TicketExportAudienceOperator || audience == kernel.TicketExportAudienceCustomer
}

func cloneAsyncExportUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneAsyncExportSavedViewPin(
	value *kernel.TicketExportSavedViewPin,
) *kernel.TicketExportSavedViewPin {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneAsyncExportSpecInput(value *SavedViewSpecInput) *SavedViewSpecInput {
	if value == nil {
		return nil
	}
	result := *value
	result.Filters.States = slices.Clone(value.Filters.States)
	result.Filters.Severities = slices.Clone(value.Filters.Severities)
	result.Filters.Priorities = slices.Clone(value.Filters.Priorities)
	result.Filters.AssignedTeamID = cloneSavedViewUUID(value.Filters.AssignedTeamID)
	result.Filters.AssigneeUserID = cloneSavedViewUUID(value.Filters.AssigneeUserID)
	result.Filters.ClaimedBy = cloneSavedViewUUID(value.Filters.ClaimedBy)
	result.Filters.CustomerVisible = cloneSavedViewBoolean(value.Filters.CustomerVisible)
	result.Filters.Custom = make([]SavedViewCustomFilterInput, len(value.Filters.Custom))
	for index, filter := range value.Filters.Custom {
		result.Filters.Custom[index] = filter
		result.Filters.Custom[index].Value = slices.Clone(filter.Value)
	}
	result.Columns = slices.Clone(value.Columns)
	for index := range result.Columns {
		result.Columns[index].DefinitionID = cloneSavedViewUUID(value.Columns[index].DefinitionID)
	}
	result.Sort.DefinitionID = cloneSavedViewUUID(value.Sort.DefinitionID)
	return &result
}

func cloneAsyncExportSourceInput(value AsyncExportSourceInput) AsyncExportSourceInput {
	result := value
	result.Inline = cloneAsyncExportSpecInput(value.Inline)
	if value.SavedView != nil {
		saved := *value.SavedView
		result.SavedView = &saved
	}
	return result
}

func validAsyncExportCell(value string) bool {
	if len(value) > AsyncExportMaximumCellBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || asyncExportDirectionalControl(character) {
			return false
		}
	}
	return true
}

func asyncExportDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}
