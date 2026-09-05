package identityprovider

import (
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type ProviderTemplate string

const (
	ProviderTemplateActiveDirectory ProviderTemplate = "active_directory"
	ProviderTemplateOpenLDAP        ProviderTemplate = "openldap"
	ProviderTemplatePOSIX           ProviderTemplate = "posix"
	ProviderTemplateCustom          ProviderTemplate = "custom"
)

type ReferralMode string

const (
	ReferralModeDisabled            ReferralMode = "disabled"
	ReferralModeConfiguredEndpoints ReferralMode = "configured_endpoints"
)

type NestedGroupMode string

const (
	NestedGroupModeDisabled        NestedGroupMode = "disabled"
	NestedGroupModeActiveDirectory NestedGroupMode = "active_directory"
	NestedGroupModeReverseSearch   NestedGroupMode = "reverse_search"
	NestedGroupModePOSIXMemberUID  NestedGroupMode = "posix_member_uid"
)

type SubjectFormat string

const (
	SubjectFormatADObjectGUID SubjectFormat = "ad_object_guid"
	SubjectFormatEntryUUID    SubjectFormat = "entry_uuid"
	SubjectFormatUTF8Exact    SubjectFormat = "utf8_exact"
	SubjectFormatUTF8Casefold SubjectFormat = "utf8_casefold"
)

type AccountStatusMode string

const (
	AccountStatusModeNone               AccountStatusMode = "none"
	AccountStatusModeActiveDirectoryUAC AccountStatusMode = "active_directory_uac"
	AccountStatusModeAttributeEquals    AccountStatusMode = "attribute_equals"
)

type JITMode string

const (
	JITModeDisabled         JITMode = "disabled"
	JITModeExistingIdentity JITMode = "existing_identity"
	JITModeCreate           JITMode = "create"
)

type NoMatchPolicy string

const (
	NoMatchPolicyDeny               NoMatchPolicy = "deny"
	NoMatchPolicyProviderAccessOnly NoMatchPolicy = "provider_access_only"
)

type DeprovisionMode string

const (
	DeprovisionModeRetain    DeprovisionMode = "retain"
	DeprovisionModeImmediate DeprovisionMode = "immediate"
	DeprovisionModeGrace     DeprovisionMode = "grace"
)

// Configuration is the complete typed LDAP provider document. Optional
// strings are pointers so JSON null remains distinct from an empty string and
// every database field is represented explicitly.
type Configuration struct {
	Template                   ProviderTemplate  `json:"template"`
	VerifyCertificate          bool              `json:"verifyCertificate"`
	CustomCAPEM                *string           `json:"customCaPem"`
	ConnectTimeoutMS           int               `json:"connectTimeoutMs"`
	OperationTimeoutMS         int               `json:"operationTimeoutMs"`
	BindDN                     string            `json:"bindDn"`
	UserBaseDN                 string            `json:"userBaseDn"`
	GroupBaseDN                *string           `json:"groupBaseDn"`
	UserSearchFilter           string            `json:"userSearchFilter"`
	GroupSearchFilter          *string           `json:"groupSearchFilter"`
	UserDNTemplate             *string           `json:"userDnTemplate"`
	PageSize                   int               `json:"pageSize"`
	MaxPages                   int               `json:"maxPages"`
	MaxEntries                 int               `json:"maxEntries"`
	MaxResponseBytes           int               `json:"maxResponseBytes"`
	ReferralMode               ReferralMode      `json:"referralMode"`
	MaxReferralHops            int               `json:"maxReferralHops"`
	NestedGroupMode            NestedGroupMode   `json:"nestedGroupMode"`
	MaxNestedGroupDepth        int               `json:"maxNestedGroupDepth"`
	MaxGroups                  int               `json:"maxGroups"`
	FirstNameAttribute         string            `json:"firstNameAttribute"`
	LastNameAttribute          string            `json:"lastNameAttribute"`
	DisplayNameAttribute       string            `json:"displayNameAttribute"`
	UsernameAttribute          string            `json:"usernameAttribute"`
	AlternateUsernameAttribute *string           `json:"alternateUsernameAttribute"`
	EmailAttribute             *string           `json:"emailAttribute"`
	ImmutableSubjectAttribute  string            `json:"immutableSubjectAttribute"`
	ImmutableSubjectFormat     SubjectFormat     `json:"immutableSubjectFormat"`
	GroupMembershipAttribute   *string           `json:"groupMembershipAttribute"`
	POSIXMemberUIDAttribute    *string           `json:"posixMemberUidAttribute"`
	POSIXGIDNumberAttribute    *string           `json:"posixGidNumberAttribute"`
	AccountStatusMode          AccountStatusMode `json:"accountStatusMode"`
	AccountStatusAttribute     *string           `json:"accountStatusAttribute"`
	AccountDisabledValue       *string           `json:"accountDisabledValue"`
	JITMode                    JITMode           `json:"jitMode"`
	NoMatchPolicy              NoMatchPolicy     `json:"noMatchPolicy"`
	DeprovisionMode            DeprovisionMode   `json:"deprovisionMode"`
	DeprovisionGraceSeconds    int               `json:"deprovisionGraceSeconds"`
	SyncIntervalSeconds        *int              `json:"syncIntervalSeconds"`
}

type Endpoint struct {
	Priority        int                  `json:"priority"`
	Host            string               `json:"host"`
	Port            uint16               `json:"port"`
	Transport       ldapclient.Transport `json:"transport"`
	TLSServerName   string               `json:"tlsServerName"`
	ReferralAllowed bool                 `json:"referralAllowed"`
	Enabled         bool                 `json:"enabled"`
}

type ProviderSummary struct {
	ID                   uuid.UUID
	TenantID             uuid.UUID
	Key                  string
	DisplayName          string
	Description          string
	Enabled              bool
	Template             ProviderTemplate
	BindSecretConfigured bool
	EnabledEndpointCount int
	ArchivedAt           *time.Time
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type Provider struct {
	ProviderSummary
	Configuration       Configuration
	Endpoints           []Endpoint
	BindSecretRotatedAt *time.Time
	ArchiveReason       *string
}

type PageInput struct {
	After *uuid.UUID
	Limit int
}

type ListInput struct {
	PageInput
	IncludeArchived bool
}

type ProviderPage struct {
	Items      []ProviderSummary
	NextCursor *uuid.UUID
}

type CreateInput struct {
	Key            string
	DisplayName    string
	Description    string
	Configuration  Configuration
	Endpoints      []Endpoint
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type CreateResult struct {
	ProviderID uuid.UUID
	Version    int64
	Replayed   bool
}

type UpdateInput struct {
	Key               string
	DisplayName       string
	Description       string
	Enabled           bool
	Configuration     Configuration
	Endpoints         []Endpoint
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type ArchiveInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type RotateBindSecretInput struct {
	// Secret ownership transfers to RotateBindSecret. Its backing bytes are
	// cleared before the method returns on every path.
	Secret            []byte
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type ClearBindSecretInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type TestInput struct {
	Audit authorization.AuditContext
}

type TestKind string

const (
	TestKindConnection TestKind = "connection"
	TestKindBind       TestKind = "bind"
)

type TestOutcome string

const (
	TestOutcomeSuccess      TestOutcome = "success"
	TestOutcomeFailure      TestOutcome = "failure"
	TestOutcomeInconclusive TestOutcome = "inconclusive"
)

type TestCategory string

const (
	TestCategorySuccess             TestCategory = "success"
	TestCategoryDNSFailed           TestCategory = "dns_failed"
	TestCategoryDestinationBlocked  TestCategory = "destination_blocked"
	TestCategoryConnectTimeout      TestCategory = "connect_timeout"
	TestCategoryConnectFailed       TestCategory = "connect_failed"
	TestCategoryTLSFailed           TestCategory = "tls_failed"
	TestCategoryCertificateRejected TestCategory = "certificate_rejected"
	TestCategoryBindRejected        TestCategory = "bind_rejected"
	TestCategoryProtocolFailed      TestCategory = "protocol_failed"
	TestCategoryCancelled           TestCategory = "cancelled"
	TestCategoryStaleConfiguration  TestCategory = "stale_configuration"
)

type TestResult struct {
	TestRunID        uuid.UUID
	Outcome          TestOutcome
	Category         TestCategory
	EndpointPriority *int
	Duration         time.Duration
	Stale            bool
	CompletedAt      time.Time
}

// EncryptedBindSecret is the only secret-bearing value allowed across the
// persistence boundary. It must never be exposed by a read API.
type EncryptedBindSecret struct {
	SecretID uuid.UUID
	Envelope identity.BindSecretEnvelope
}

type TestSnapshot struct {
	TestRunID            uuid.UUID
	ProviderID           uuid.UUID
	ProviderVersion      int64
	ConfigurationVersion int64
	SecretVersion        *int64
	Configuration        Configuration
	Endpoints            []Endpoint
	Secret               *EncryptedBindSecret
	StartedAt            time.Time
}
