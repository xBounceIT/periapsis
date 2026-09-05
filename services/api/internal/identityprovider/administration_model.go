package identityprovider

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// Binding is the tenant-scoped login selector and its current access-source
// epoch. Closed epoch history remains behind the application boundary.
type Binding struct {
	ID                   uuid.UUID
	TenantID             uuid.UUID
	ProviderID           uuid.UUID
	LoginKey             string
	Enabled              bool
	ProfilePriority      int
	AuthRevision         int
	CurrentAccessEpochID *uuid.UUID
	ArchivedAt           *time.Time
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type BindingPage struct {
	Items      []Binding
	NextCursor *uuid.UUID
}

type ListBindingsInput struct {
	PageInput
	IncludeArchived bool
}

type CreateBindingInput struct {
	ProviderID      uuid.UUID
	LoginKey        string
	Enabled         bool
	ProfilePriority int
	IdempotencyKey  string
	Audit           authorization.AuditContext
}

type UpdateBindingInput struct {
	LoginKey          string
	Enabled           bool
	ProfilePriority   int
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type ArchiveBindingInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type DirectoryFilterKind string

const (
	DirectoryFilterKindUser  DirectoryFilterKind = "user"
	DirectoryFilterKindGroup DirectoryFilterKind = "group"
)

type UserSearchTestInput struct {
	Username string
	Audit    authorization.AuditContext
}

type FilterTestInput struct {
	Kind           DirectoryFilterKind
	FilterTemplate string
	Username       string
	UserDN         *string
	GIDNumber      *int
	MaxResults     int
	Audit          authorization.AuditContext
}

type RedactedEntryAttribute struct {
	Name       string
	ValueCount int
	Truncated  bool
}

type RedactedEntry struct {
	Ordinal         int
	DNPresent       bool
	Attributes      []RedactedEntryAttribute
	GroupValueCount int
}

type DirectoryTestResult struct {
	Diagnostic        TestResult
	MatchedEntryCount int
	Truncated         bool
	Entries           []RedactedEntry
}

type MappingCaseMode string

const (
	MappingCaseSensitive   MappingCaseMode = "sensitive"
	MappingCaseInsensitive MappingCaseMode = "insensitive"
)

type MappingMatcherType string

const (
	MappingMatcherExactDN MappingMatcherType = "exact_dn"
	MappingMatcherExactCN MappingMatcherType = "exact_cn"
	MappingMatcherRegex   MappingMatcherType = "regex"
)

type MappingMatcher struct {
	Type     MappingMatcherType
	Value    string
	CaseMode MappingCaseMode
}

type OperatorTeamAssignmentTarget struct {
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
}

type MappingTarget struct {
	TenantSecurityGroupID  uuid.UUID
	RoleIDs                []uuid.UUID
	OperatorTeamAssignment *OperatorTeamAssignmentTarget
}

type ReconciliationMode string

const (
	ReconciliationAdditive      ReconciliationMode = "additive"
	ReconciliationAuthoritative ReconciliationMode = "authoritative"
)

type MappingSourceEpoch struct {
	ID                 uuid.UUID
	Sequence           int
	ReconciliationMode ReconciliationMode
	ActivatedAt        time.Time
}

type Mapping struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	BindingID          uuid.UUID
	Matcher            MappingMatcher
	Priority           int
	Target             MappingTarget
	ReconciliationMode ReconciliationMode
	Enabled            bool
	Notes              string
	CurrentSourceEpoch *MappingSourceEpoch
	LastMatchedAt      *time.Time
	ArchivedAt         *time.Time
	Version            int64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type MappingPage struct {
	Items      []Mapping
	NextCursor *MappingCursor
}

type ListMappingsInput struct {
	After           *MappingCursor
	Limit           int
	IncludeArchived bool
	BindingID       *uuid.UUID
}

type CreateMappingInput struct {
	BindingID          uuid.UUID
	Matcher            MappingMatcher
	Priority           int
	Target             MappingTarget
	ReconciliationMode ReconciliationMode
	Notes              string
	Reason             string
	IdempotencyKey     string
	Audit              authorization.AuditContext
}

type UpdateMappingInput struct {
	Matcher            MappingMatcher
	Priority           int
	Target             MappingTarget
	ReconciliationMode ReconciliationMode
	Enabled            bool
	Notes              string
	Reason             string
	ExpectedEntityTag  *string
	Audit              authorization.AuditContext
}

type ArchiveMappingInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type PinnedMappingRevision struct {
	MappingID           uuid.UUID
	MappingVersion      int64
	SourceEpochID       *uuid.UUID
	SourceEpochSequence *int
}

type PinnedPlannerSnapshot struct {
	ProviderID            uuid.UUID
	ProviderVersion       int64
	BindingID             uuid.UUID
	BindingVersion        int64
	ConfigurationRevision int
	AccessEpochID         uuid.UUID
	MappingRevisions      []PinnedMappingRevision
}

type DryRunAction string

const (
	DryRunActionAdd     DryRunAction = "add"
	DryRunActionRefresh DryRunAction = "refresh"
	DryRunActionRetain  DryRunAction = "retain"
	DryRunActionRevoke  DryRunAction = "revoke"
	DryRunActionNone    DryRunAction = "none"
)

type DryRunGroupAction struct {
	TenantSecurityGroupID uuid.UUID
	Action                DryRunAction
	SourceMappingIDs      []uuid.UUID
}

type DryRunRoleAction struct {
	RoleID           uuid.UUID
	Action           DryRunAction
	SourceMappingIDs []uuid.UUID
}

type DryRunOperatorTeamAction struct {
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
	Action            DryRunAction
	SourceMappingIDs  []uuid.UUID
}

type DryRunPlan struct {
	ProfileAction        string
	ProviderAccessAction DryRunAction
	GroupActions         []DryRunGroupAction
	RoleActions          []DryRunRoleAction
	OperatorTeamActions  []DryRunOperatorTeamAction
}

type DryRunInput struct {
	BindingID                 uuid.UUID
	Username                  string
	IncludeDisabledMappingIDs []uuid.UUID
	Audit                     authorization.AuditContext
}

type DryRunResult struct {
	ID                  uuid.UUID
	Outcome             string
	Decision            string
	IdentityDisposition string
	ObservationComplete bool
	DenialReasons       []string
	MatchedMappingIDs   []uuid.UUID
	Snapshot            PinnedPlannerSnapshot
	Plan                DryRunPlan
	GeneratedAt         time.Time
}

type SyncRunState string

const (
	SyncRunQueued      SyncRunState = "queued"
	SyncRunEnumerating SyncRunState = "enumerating"
	SyncRunApplying    SyncRunState = "applying"
	SyncRunSucceeded   SyncRunState = "succeeded"
	SyncRunFailed      SyncRunState = "failed"
	SyncRunCancelled   SyncRunState = "cancelled"
	SyncRunStale       SyncRunState = "stale"
)

type SyncEnumeration struct {
	State                         string
	Complete                      bool
	Truncated                     bool
	AbsenceBasedRevocationAllowed bool
	EntryCount                    int
	PageCount                     int
	ResponseBytes                 int
	CursorState                   string
	ErrorCategory                 *string
}

type SyncCounters struct {
	Observed                int
	Staged                  int
	IdentitiesCreated       int
	IdentitiesLinked        int
	ProviderAccessAdded     int
	ProviderAccessSuspended int
	GroupEdgesAdded         int
	GroupEdgesRefreshed     int
	GroupEdgesRevoked       int
	RoleEdgesAdded          int
	RoleEdgesRefreshed      int
	RoleEdgesRevoked        int
	RosterEdgesAdded        int
	RosterEdgesRefreshed    int
	RosterEdgesRevoked      int
	Failed                  int
}

type SyncRun struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	BindingID        uuid.UUID
	ProviderID       uuid.UUID
	Trigger          string
	ManualReason     *string
	State            SyncRunState
	Snapshot         PinnedPlannerSnapshot
	Enumeration      SyncEnumeration
	Counters         SyncCounters
	RunErrorCategory *string
	CreatedAt        time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
	Version          int64
	UpdatedAt        time.Time
}

type SyncRunPage struct {
	Items      []SyncRun
	NextCursor *uuid.UUID
}

type SyncStatus struct {
	BindingID           uuid.UUID
	ScheduleState       string
	SyncIntervalSeconds *int
	ActiveRunID         *uuid.UUID
	LastRunID           *uuid.UUID
	LastRunState        *SyncRunState
	LastCompletedAt     *time.Time
	NextScheduledAt     *time.Time
	Version             int64
	UpdatedAt           time.Time
}

type StartManualSyncInput struct {
	Reason            string
	IdempotencyKey    string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}
