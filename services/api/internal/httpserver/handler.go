// Package httpserver exposes the generated OpenAPI contract with secure middleware.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	customfieldkernel "github.com/periapsis-im/periapsis/modules/customfields"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	slakernel "github.com/periapsis-im/periapsis/modules/sla"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationcustomfieldimport "github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
	applicationcustomfields "github.com/periapsis-im/periapsis/services/api/internal/customfields"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformldapauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/telemetry"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	requestIDHeader       = "X-Request-ID"
	defaultRequestTimeout = 15 * time.Second
	maximumRequestBody    = 1024*1024 + 4*1024
	readinessCacheTTL     = time.Second
)

var accessLogRoutePattern = regexp.MustCompile(`^(?:[A-Z]+ )?/[A-Za-z0-9_./{}*:-]{0,240}$`)

// ReadinessChecker checks required dependencies under the request deadline.
type ReadinessChecker interface {
	Check(context.Context) []postgres.DependencyCheck
}

// Handler implements the generated OpenAPI server interface.
type Handler struct {
	alerts                      AlertService
	asyncExports                AsyncExportService
	authentication              AuthenticationService
	sessionLogout               SessionLogoutService
	authorization               AuthorizationService
	audit                       SecurityAuditService
	auditOperations             AuditOperationsService
	checker                     ReadinessChecker
	cookie                      sessionCookiePolicy
	mfaCookie                   sessionCookiePolicy
	customFields                CustomFieldService
	customFieldImports          CustomFieldImportService
	contacts                    ContactService
	dfir                        DFIRService
	alertInvestigation          AlertInvestigationService
	federated                   federatedBrowserTransport
	federatedContinuationCookie sessionCookiePolicy
	logoutContinuationCookie    sessionCookiePolicy
	logger                      *slog.Logger
	mfa                         MFAService
	mfaPolicies                 MFAPolicyService
	identityProviders           IdentityProviderService
	ldapAdministration          LDAPAdministrationService
	ldapAuthentication          LDAPAuthenticationService
	tenantFederation            TenantFederationAdministrationService
	notifications               NotificationAdministrationService
	notificationInbox           NotificationInboxService
	operatorTeams               OperatorTeamService
	platform                    PlatformService
	platformTenantAccess        PlatformTenantAccessService
	platformOIDCBrowser         PlatformOIDCBrowserAuthentication
	platformSAMLBrowser         PlatformSAMLBrowserAuthentication
	platformSAMLContinuation    PlatformSAMLContinuationService
	platformIdentityAccounts    PlatformIdentityAccountService
	platformIdentityBindings    PlatformIdentityBindingService
	platformIdentityProviders   PlatformIdentityProviderService
	platformLDAPAuthentication  PlatformLDAPAuthenticationService
	platformLocalAccounts       PlatformLocalAccountService
	platformOperations          PlatformOperationsService
	tenantLifecycle             TenantLifecycleService
	tenantSettings              TenantSettingsService
	ticketNumbering             TicketNumberingService
	webhookURLPolicy            WebhookURLPolicyService
	publicOrigin                string
	readinessTimeout            time.Duration
	requestTimeout              time.Duration
	release                     string
	serviceAccounts             ServiceAccountService
	sla                         SLAService
	savedViews                  SavedViewService
	ticketBulk                  TicketBulkService
	ticketing                   TicketingService
	workflowAdministration      WorkflowAdministrationService
	readinessMu                 sync.Mutex
	readinessRefresh            *readinessRefresh
	readinessSnapshot           atomic.Pointer[readinessSnapshot]
	trustedProxies              []netip.Prefix
}

// SLAService is the tenant-scoped SLA application boundary used by the HTTP
// adapter. Implementations re-resolve live authority and keep mutations
// transactionally coupled to audit/outbox state.
type SLAService interface {
	ListCalendars(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.CalendarPage, error)
	GetCalendar(context.Context, applicationsla.Actor, uuid.UUID, slakernel.EntityID) (applicationsla.CalendarRecord, error)
	PublishCalendar(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.CalendarPublishCommand) (applicationsla.PublicationResult[slakernel.BusinessCalendar], error)
	ListPolicies(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.PolicyPage, error)
	GetPolicy(context.Context, applicationsla.Actor, uuid.UUID, slakernel.EntityID) (applicationsla.PolicyRecord, error)
	PublishPolicy(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.PolicyPublishCommand) (applicationsla.PublicationResult[slakernel.Policy], error)
	ListColumns(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.ColumnPage, error)
	GetColumn(context.Context, applicationsla.Actor, uuid.UUID, slakernel.EntityID) (applicationsla.ColumnRecord, error)
	PublishColumn(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ColumnPublishCommand) (applicationsla.PublicationResult[slakernel.ColumnDefinition], error)
	Archive(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ArchiveCommand) (uint64, bool, error)
	Simulate(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.SimulationCommand) (applicationsla.SimulationResult, error)
	ProjectObject(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ObjectProjectionCommand) (applicationsla.ObjectProjection, error)
	Override(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.OverrideRequest) (applicationsla.OverrideResult, error)
}

type readinessSnapshot struct {
	ready     bool
	checks    map[string]contract.DependencyCheck
	checkedAt time.Time
	expiresAt time.Time
}

type readinessRefresh struct {
	done     chan struct{}
	snapshot *readinessSnapshot
}

// AuthenticationService is the domain boundary used by HTTP transport code.
type AuthenticationService interface {
	BootstrapStatus(context.Context) (bool, error)
	StartBootstrap(context.Context, string, string, authentication.EventContext) (authentication.BootstrapEnrollment, error)
	ConfirmBootstrap(context.Context, string, authentication.BootstrapConfirmation) (authentication.BootstrapResult, error)
	StartPasswordLogin(context.Context, string, string, authentication.EventContext) (authentication.MFAChallenge, error)
	CompleteMFA(context.Context, string, string, string, authentication.EventContext) (authentication.SessionCredential, error)
	CurrentSession(context.Context, string) (authentication.SessionCredential, error)
	RotateCurrentSession(context.Context, string, authentication.EventContext) (authentication.SessionCredential, error)
	Authenticate(context.Context, string) (authentication.Session, error)
	ValidateCSRF(authentication.Session, string) error
	Logout(context.Context, string, string, authentication.EventContext) error
	Sessions(context.Context, string, *uuid.UUID, int) (authentication.SessionPage, error)
	RevokeSession(context.Context, string, string, uuid.UUID, authentication.EventContext) error
	TenantMemberships(context.Context, string, *uuid.UUID, int) (authentication.TenantMembershipPage, error)
	SwitchTenant(context.Context, string, string, uuid.UUID, authentication.EventContext) (authentication.SessionCredential, error)
	ReserveMFASession(*authentication.Session, mfa.SessionAuthenticationMethod) (authentication.MFASessionReservation, error)
	ReserveMFASessionAt(*authentication.Session, mfa.SessionAuthenticationMethod, time.Time) (authentication.MFASessionReservation, error)
}

// SessionLogoutService proves the session and CSRF credentials without
// resolving live membership or user authority, then revokes locally before
// producing any optional browser-delivery upstream artifact.
type SessionLogoutService interface {
	Logout(context.Context, string, string, sessionlogout.EventContext) (sessionlogout.Result, error)
	Continue(context.Context, identity.EntityID, []byte) (string, error)
}

type unavailableSessionLogoutService struct{}

func (unavailableSessionLogoutService) Logout(
	context.Context,
	string,
	string,
	sessionlogout.EventContext,
) (sessionlogout.Result, error) {
	return sessionlogout.Result{}, sessionlogout.ErrUnavailable
}

func (unavailableSessionLogoutService) Continue(
	context.Context,
	identity.EntityID,
	[]byte,
) (string, error) {
	return "", sessionlogout.ErrUnavailable
}

// MFAService is the public, rate-limited local-assurance boundary. Every
// method re-resolves pinned live authority and commits proof, session rotation,
// and audit through one transaction-owned application use case.
type MFAService interface {
	Admission(netip.Addr, identity.EntityID, string) (mfaauth.AdmissionContext, error)
	PrepareCompletion(context.Context, mfaauth.CompletionTicketRequest) (mfaauth.CompletionTicket, error)
	StartLocalStepUp(context.Context, mfaauth.StartLocalStepUpCommand) (mfaauth.LocalStepUpStartArtifact, error)
	CompleteTOTP(context.Context, mfaauth.CompleteTOTPCommand) (mfa.StepUpArtifact, error)
	CompleteRecovery(context.Context, mfaauth.CompleteRecoveryCommand) (mfa.StepUpArtifact, error)
	StartTOTP(context.Context, mfaauth.AuthorityLookup) (mfaauth.TOTPEnrollmentStartArtifact, error)
	FinishTOTP(context.Context, mfaauth.FinishTOTPEnrollmentCommand) (mfaauth.TOTPEnrollmentApplyResult, error)
	RegenerateRecoveryCodes(context.Context, mfaauth.RegenerateRecoveryCodesCommand) (mfaauth.RecoveryCodesArtifact, error)
	StartPasskeyRegistration(context.Context, mfaauth.PasskeyLookup) (webauthn.StartArtifact, error)
	StartPasskeyAuthentication(context.Context, mfaauth.PasskeyLookup) (webauthn.StartArtifact, error)
	FinishPasskeyRegistration(context.Context, mfaauth.FinishPasskeyRegistrationCommand) (mfaauth.PasskeyRegistrationResult, error)
	FinishPasskeyAuthentication(context.Context, mfaauth.FinishPasskeyAuthenticationCommand) (mfaauth.PasskeyAuthenticationResult, error)
	ListDevices(context.Context, mfaauth.DeviceAuthority, mfaauth.DeviceListInput) (mfaauth.DevicePage, error)
	RenamePasskey(context.Context, mfaauth.DeviceAuthority, identity.EntityID, string, uint64) (mfaauth.DeviceMutationResult, error)
	RevokeDevice(context.Context, mfaauth.DeviceAuthority, identity.EntityID, mfaauth.DeviceKind, uint64) (mfaauth.DeviceMutationResult, error)
}

// MFAPolicyService is the deny-by-default administration boundary for the
// platform floor and tenant-scoped MFA policies. Concrete repositories repeat
// authority, assurance, CAS, replay, recovery, audit, and invalidation checks
// within the mutation transaction.
type MFAPolicyService interface {
	ListPlatform(context.Context, authentication.Session, mfapolicy.ListInput) (mfapolicy.Page, error)
	ListTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.ListInput) (mfapolicy.Page, error)
	GetPlatform(context.Context, authentication.Session, uuid.UUID, int64) (mfa.PolicyDocument, error)
	GetTenant(context.Context, authentication.Session, uuid.UUID, uuid.UUID, int64) (mfa.PolicyDocument, error)
	SimulatePlatform(context.Context, authentication.Session, mfapolicy.SimulationInput) (mfa.PolicySimulation, error)
	SimulateTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.SimulationInput) (mfa.PolicySimulation, error)
	PublishPlatform(context.Context, authentication.Session, mfapolicy.PublishInput) (mfapolicy.MutationResult, error)
	PublishTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.PublishInput) (mfapolicy.MutationResult, error)
	RetirePlatform(context.Context, authentication.Session, mfapolicy.RetireInput) (mfapolicy.MutationResult, error)
	RetireTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.RetireInput) (mfapolicy.MutationResult, error)
}

// PlatformService is the domain boundary for explicitly authorized platform actions.
type PlatformService interface {
	ListTenants(context.Context, authentication.Session, *uuid.UUID, int) (platform.TenantPage, error)
	CreateTenant(context.Context, authentication.Session, platform.CreateTenantInput) (authentication.Tenant, error)
}

// TenantLifecycleService is the explicit platform control-plane mutation
// boundary. The concrete platform service rechecks platform.tenant.manage and
// the repository repeats that permission check with the optimistic version in
// the same transaction as the redacted audit event.
type TenantLifecycleService interface {
	Change(
		context.Context,
		authentication.Session,
		platform.TenantLifecycleCommand,
		authentication.EventContext,
	) (platform.TenantLifecycleReceipt, error)
}

// PlatformTenantAccessService is the explicit elevated-entry boundary. The
// concrete service and database independently require the dedicated platform
// permission; successful entry creates ordinary tenant authority, never an RLS bypass.
type PlatformTenantAccessService interface {
	Authorize(
		context.Context,
		authentication.Session,
		platform.PlatformTenantAccessCommand,
		authentication.EventContext,
	) (platform.PlatformTenantAccessReceipt, error)
}

// PlatformIdentityProviderService is the disabled-by-default platform
// federation administration boundary. The concrete service and PostgreSQL ABI
// both revalidate the exact live platform permission for every operation.
type PlatformIdentityProviderService interface {
	List(context.Context, authentication.Session, platformidentityprovider.ListInput) (platformidentityprovider.ProviderPage, error)
	Get(context.Context, authentication.Session, uuid.UUID) (platformidentityprovider.Provider, error)
	Create(context.Context, authentication.Session, platformidentityprovider.CreateInput) (platformidentityprovider.CreateResult, error)
	Update(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.UpdateInput) (platformidentityprovider.UpdateResult, error)
	Archive(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ArchiveInput) (platformidentityprovider.MutationReceipt, error)
	ReplaceOIDCClientSecret(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ReplaceOIDCClientSecretInput) (platformidentityprovider.SecretMutationReceipt, error)
	ReplaceSAMLMetadata(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ReplaceSAMLMetadataInput) (platformidentityprovider.SAMLMaterialMutationReceipt, error)
	ReplaceSAMLSPKey(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ReplaceSAMLSPKeyInput) (platformidentityprovider.SAMLMaterialMutationReceipt, error)
	ClearSAMLSPKey(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ClearSAMLSPKeyInput) (platformidentityprovider.SAMLMaterialMutationReceipt, error)
	Activate(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ActivateInput) (platformidentityprovider.UpdateResult, error)
	Deactivate(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.DeactivateInput) (platformidentityprovider.UpdateResult, error)
	ActivateDirectLogin(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.DirectLoginInput) (platformidentityprovider.UpdateResult, error)
	DeactivateDirectLogin(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.DirectLoginInput) (platformidentityprovider.UpdateResult, error)
}

// PlatformLDAPAuthenticationService owns the anonymous, tenantless LDAP
// login transaction. It always produces a platform session and never a
// post-primary continuation or a newly-created user.
type PlatformLDAPAuthenticationService interface {
	Authenticate(context.Context, platformldapauth.Command) (platformldapauth.Result, error)
}

// PlatformIdentityAccountService is the provider-global account-link
// administration boundary. Exact issuer/subject material is accepted only by
// Prelink and no method returns it. The concrete service and database ABI both
// revalidate live platform account permissions for every operation.
type PlatformIdentityAccountService interface {
	List(context.Context, authentication.Session, uuid.UUID, platformidentityaccount.ListInput) (platformidentityaccount.AccountPage, error)
	Get(context.Context, authentication.Session, uuid.UUID, uuid.UUID) (platformidentityaccount.Account, error)
	Prelink(context.Context, authentication.Session, uuid.UUID, platformidentityaccount.PrelinkInput) (platformidentityaccount.PrelinkResult, error)
	Retire(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentityaccount.RetireInput) (platformidentityaccount.RetireResult, error)
}

// PlatformLocalAccountService is the protected local break-glass lifecycle
// boundary. Concrete repositories repeat platform authorization, fresh local
// MFA, CAS, replay, recovery-floor, revocation, and redacted-audit checks while
// holding the relevant rows in one mutation transaction.
type PlatformLocalAccountService interface {
	List(context.Context, authentication.Session, platformlocalaccount.ListInput) (platformlocalaccount.Page, error)
	Get(context.Context, authentication.Session, uuid.UUID) (platformlocalaccount.Account, error)
	Invite(context.Context, authentication.Session, platformlocalaccount.InviteInput) (platformlocalaccount.MutationResult, error)
	Activate(context.Context, authentication.Session, uuid.UUID, platformlocalaccount.ActivationInput) (platformlocalaccount.MutationResult, error)
	Disable(context.Context, authentication.Session, uuid.UUID, platformlocalaccount.TransitionInput) (platformlocalaccount.MutationResult, error)
	Enable(context.Context, authentication.Session, uuid.UUID, platformlocalaccount.TransitionInput) (platformlocalaccount.MutationResult, error)
	Recover(context.Context, authentication.Session, uuid.UUID, platformlocalaccount.TransitionInput) (platformlocalaccount.MutationResult, error)
	RotatePassword(context.Context, authentication.Session, uuid.UUID, platformlocalaccount.PasswordTransitionInput) (platformlocalaccount.MutationResult, error)
}

// PlatformIdentityBindingService is the disabled-only cross-boundary control
// plane. The concrete service and database ABI independently revalidate live
// platform binding authority; no method in this interface can activate login.
type PlatformIdentityBindingService interface {
	List(context.Context, authentication.Session, uuid.UUID, platformidentitybinding.ListInput) (platformidentitybinding.BindingPage, error)
	Get(context.Context, authentication.Session, uuid.UUID, uuid.UUID) (platformidentitybinding.Binding, error)
	Create(context.Context, authentication.Session, uuid.UUID, platformidentitybinding.CreateInput) (platformidentitybinding.CreateResult, error)
	Update(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentitybinding.UpdateInput) (platformidentitybinding.UpdateResult, error)
	Archive(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentitybinding.ArchiveInput) (platformidentitybinding.MutationReceipt, error)
	Activate(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentitybinding.ActivateInput) (platformidentitybinding.UpdateResult, error)
	Deactivate(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentitybinding.DeactivateInput) (platformidentitybinding.UpdateResult, error)
}

// SecurityAuditService is the redacted tenant/platform audit reader. Reads are
// intentionally modeled as stateful use cases because the repository appends a
// separate access or verification event in the same transaction.
type SecurityAuditService interface {
	ListTenant(context.Context, authorization.Actor, uuid.UUID, securityaudit.Query, authorization.AuditContext) (securityaudit.Page, error)
	VerifyTenant(context.Context, authorization.Actor, uuid.UUID, authorization.AuditContext) (securityaudit.Verification, error)
	ListPlatform(context.Context, authentication.Session, securityaudit.Query, authentication.EventContext) (securityaudit.Page, error)
	VerifyPlatform(context.Context, authentication.Session, authentication.EventContext) (securityaudit.Verification, error)
}

// AuthorizationService is the tenant-RBAC application boundary used by the
// HTTP transport. Implementations re-resolve live authority for every call.
type AuthorizationService interface {
	GetTenantAuthority(context.Context, authorization.Actor, uuid.UUID) (authorization.TenantAuthority, error)
	ListTenantPermissions(context.Context, authorization.Actor, uuid.UUID, authorization.PageInput) (authorization.TenantPermissionPage, error)
	ListTenantRoles(context.Context, authorization.Actor, uuid.UUID, authorization.ListTenantRolesInput) (authorization.TenantRolePage, error)
	CreateTenantRole(context.Context, authorization.Actor, uuid.UUID, authorization.CreateTenantRoleInput) (authorization.TenantRole, error)
	GetTenantRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (authorization.TenantRole, error)
	UpdateTenantRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.UpdateTenantRoleInput) (authorization.TenantRole, error)
	ArchiveTenantRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ArchiveTenantRoleInput) error
	ReplaceTenantRolePolicy(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ReplaceTenantRolePolicyInput) (authorization.TenantRole, error)
	ListTenantUsers(context.Context, authorization.Actor, uuid.UUID, authorization.PageInput) (authorization.TenantUserPage, error)
	ChangeTenantMembershipLifecycle(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.MembershipStatus, authorization.TenantMembershipLifecycleInput) (authorization.TenantMembershipLifecycleReceipt, error)
	ListUserRoleGrants(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ListUserRoleGrantsInput) (authorization.DirectUserRoleGrantPage, error)
	GrantUserRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.GrantUserRoleInput) (authorization.DirectUserRoleGrant, error)
	RevokeRoleGrant(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.RevokeRoleGrantInput) error
	ListTenantSecurityGroups(context.Context, authorization.Actor, uuid.UUID, authorization.ListTenantSecurityGroupsInput) (authorization.TenantSecurityGroupPage, error)
	CreateTenantSecurityGroup(context.Context, authorization.Actor, uuid.UUID, authorization.CreateTenantSecurityGroupInput) (authorization.TenantSecurityGroup, error)
	GetTenantSecurityGroup(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (authorization.TenantSecurityGroup, error)
	UpdateTenantSecurityGroup(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.UpdateTenantSecurityGroupInput) (authorization.TenantSecurityGroup, error)
	ArchiveTenantSecurityGroup(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ArchiveTenantSecurityGroupInput) error
	ListTenantSecurityGroupMemberships(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ListTenantSecurityGroupEdgesInput) (authorization.TenantSecurityGroupMembershipPage, error)
	AddTenantSecurityGroupMembership(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.AddTenantSecurityGroupMembershipInput) (authorization.TenantSecurityGroupMembership, error)
	RevokeTenantSecurityGroupMembership(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, authorization.RevokeTenantSecurityGroupMembershipInput) error
	ListTenantSecurityGroupRoleGrants(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ListTenantSecurityGroupEdgesInput) (authorization.TenantSecurityGroupRoleGrantPage, error)
	GrantTenantSecurityGroupRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.GrantTenantSecurityGroupRoleInput) (authorization.TenantSecurityGroupRoleGrant, error)
	RevokeTenantSecurityGroupRoleGrant(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, authorization.RevokeTenantSecurityGroupRoleGrantInput) error
}

// IdentityProviderService is the tenant LDAP-provider application boundary.
// Implementations re-resolve exact live human authority on every call and
// never expose plaintext or encrypted bind-secret material.
type IdentityProviderService interface {
	List(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListInput) (identityprovider.ProviderPage, error)
	Get(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Provider, error)
	Create(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateInput) (identityprovider.CreateResult, error)
	Update(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateInput) (int64, error)
	Archive(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveInput) (int64, error)
	RotateBindSecret(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.RotateBindSecretInput) (int64, error)
	ClearBindSecret(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ClearBindSecretInput) (int64, error)
	TestConnection(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error)
	TestBind(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error)
}

// LDAPAdministrationService is the application boundary for tenant LDAP
// bindings, bounded administrative searches, mapping plans, and sync runs.
// Concrete implementations must re-resolve live human authority on every call;
// the HTTP adapter never treats a generated request as authorization evidence.
type LDAPAdministrationService interface {
	SearchUser(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UserSearchTestInput) (identityprovider.DirectoryTestResult, error)
	TestFilter(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FilterTestInput) (identityprovider.DirectoryTestResult, error)
	ListBindings(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListBindingsInput) (identityprovider.BindingPage, error)
	CreateBinding(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateBindingInput) (identityprovider.Binding, error)
	GetBinding(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Binding, error)
	UpdateBinding(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateBindingInput) (identityprovider.Binding, error)
	ArchiveBinding(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveBindingInput) (int64, error)
	ListMappings(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListMappingsInput) (identityprovider.MappingPage, error)
	CreateMapping(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateMappingInput) (identityprovider.Mapping, error)
	DryRunMappings(context.Context, authorization.Actor, uuid.UUID, identityprovider.DryRunInput) (identityprovider.DryRunResult, error)
	GetMapping(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Mapping, error)
	UpdateMapping(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateMappingInput) (identityprovider.Mapping, error)
	ArchiveMapping(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveMappingInput) (int64, error)
	GetSyncStatus(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.SyncStatus, error)
	ListSyncRuns(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.PageInput) (identityprovider.SyncRunPage, error)
	StartManualSync(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.StartManualSyncInput) (identityprovider.SyncRun, error)
	GetSyncRun(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (identityprovider.SyncRun, error)
}

// TenantFederationAdministrationService is the tenant-owned OIDC/SAML
// administration boundary. Implementations re-resolve live human authority on
// every call and expose only redacted provider projections.
type TenantFederationAdministrationService interface {
	List(context.Context, authorization.Actor, uuid.UUID, identityprovider.FederationListInput) (identityprovider.FederationProviderPage, error)
	Get(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationProvider, error)
	Create(context.Context, authorization.Actor, uuid.UUID, identityprovider.FederationCreateInput) (identityprovider.FederationCreateResult, error)
	Update(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationUpdateInput) (identityprovider.FederationProvider, error)
	Archive(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationArchiveInput) (int64, error)
	ReplaceOIDCClientSecret(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error)
	ClearOIDCClientSecret(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationClearOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error)
	RefreshOIDCTrustDocuments(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationOIDCTrustDocumentsInput) (identityprovider.FederationOIDCTrustDocumentsReceipt, error)
	ReplaceSAMLMetadata(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLMetadataInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
	ReplaceSAMLSPCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
	ClearSAMLSPCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationClearSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
	GetMappingPolicy(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationMappingPolicy, error)
	ReplaceMappingPolicy(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceMappingPolicyInput) (identityprovider.FederationPolicyMutationReceipt, error)
	GetAssurancePolicy(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationAssurancePolicy, error)
	ReplaceAssurancePolicy(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceAssurancePolicyInput) (identityprovider.FederationPolicyMutationReceipt, error)
}

// CustomFieldService is the application boundary for tenant definition
// administration and Alert/Case value projections. Implementations recheck
// live permission, audience, object visibility, and field edit policy.
type CustomFieldService interface {
	ListDefinitions(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.DefinitionListInput) (applicationcustomfields.DefinitionPage, error)
	GetDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.ObjectType, customfieldkernel.EntityID) (customfieldkernel.Definition, error)
	CreateDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.CreateDefinitionInput) (applicationcustomfields.DefinitionResult, error)
	ReplaceDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.EntityID, applicationcustomfields.ReplaceDefinitionInput) (applicationcustomfields.DefinitionResult, error)
	ArchiveDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.ObjectType, customfieldkernel.EntityID, applicationcustomfields.ArchiveDefinitionInput) (applicationcustomfields.DefinitionResult, error)
	ValidateAndCommitObjectFields(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.ObjectWriteInput) (applicationcustomfields.ObjectWriteResult, error)
	ProjectObjectFields(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.ProjectionInput) (applicationcustomfields.Projection, error)
}

type CustomFieldImportService interface {
	Request(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, applicationcustomfieldimport.RequestInput) (applicationcustomfieldimport.Result, error)
	Get(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID) (applicationcustomfieldimport.Record, error)
	Cancel(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID, applicationcustomfieldimport.CancelInput) (applicationcustomfieldimport.Result, error)
	ListResults(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID, uint32, int) (applicationcustomfieldimport.ResultPage, error)
}

type unavailableCustomFieldImportService struct{}

func (unavailableCustomFieldImportService) Request(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, applicationcustomfieldimport.RequestInput) (applicationcustomfieldimport.Result, error) {
	return applicationcustomfieldimport.Result{}, applicationcustomfieldimport.ErrUnavailable
}
func (unavailableCustomFieldImportService) Get(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID) (applicationcustomfieldimport.Record, error) {
	return applicationcustomfieldimport.Record{}, applicationcustomfieldimport.ErrUnavailable
}
func (unavailableCustomFieldImportService) Cancel(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID, applicationcustomfieldimport.CancelInput) (applicationcustomfieldimport.Result, error) {
	return applicationcustomfieldimport.Result{}, applicationcustomfieldimport.ErrUnavailable
}
func (unavailableCustomFieldImportService) ListResults(context.Context, applicationcustomfieldimport.Actor, uuid.UUID, customfieldkernel.ObjectType, uuid.UUID, uint32, int) (applicationcustomfieldimport.ResultPage, error) {
	return applicationcustomfieldimport.ResultPage{}, applicationcustomfieldimport.ErrUnavailable
}

// ContactService is the deny-by-default customer contact and exact resource
// relationship boundary. Implementations re-resolve live authority and linked
// contact evidence for every call.
type ContactService interface {
	ListContacts(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.ContactListInput) (applicationcontacts.ContactPage, error)
	GetContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID) (contactkernel.Contact, error)
	CreateContact(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.CreateContactInput) (applicationcontacts.ContactResult, error)
	ReplaceContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ReplaceContactInput) (applicationcontacts.ContactResult, error)
	ArchiveContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ArchiveInput) (applicationcontacts.ContactResult, error)
	SelfContact(context.Context, applicationcontacts.Actor, uuid.UUID) (contactkernel.CustomerSafeContact, error)
	UpdatePortalPreferences(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.PreferenceInput) (applicationcontacts.ContactResult, error)
	ListGroups(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.GroupListInput) (applicationcontacts.GroupPage, error)
	GetGroup(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID) (contactkernel.RecipientGroup, error)
	CreateGroup(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.CreateGroupInput) (applicationcontacts.GroupResult, error)
	VersionGroup(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.VersionGroupInput) (applicationcontacts.GroupResult, error)
	ListLinks(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.LinkListInput) (applicationcontacts.LinkPage, error)
	LinkContact(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.LinkInput) (applicationcontacts.LinkResult, error)
	ArchiveLink(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ArchiveLinkInput) (applicationcontacts.LinkResult, error)
}

// DFIRService is the Case and autonomous Alert investigation boundary.
// Storage URLs and customer evidence values remain confined to no-store
// response objects.
type DFIRService interface {
	Workspace(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.Workspace, error)
	AlertWorkspace(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error)
	CreateIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	ReplaceIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	CreateAlertIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	ReplaceAlertIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	CreateAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	ReplaceAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	CreateAlertAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	ReplaceAlertAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	CreateTimelineEvent(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error)
	CreateAlertTimelineEvent(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error)
	CreateTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	TransitionTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskTransitionCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	ReplaceTaskDetails(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	AssignTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	RescheduleTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDueDateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	ReplaceTaskChecklist(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskChecklistCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	ReplaceTaskComments(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	CreateRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error)
	RetractRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error)
	PrepareUpload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.PrepareUploadCommand) (applicationdfir.PreparedUpload, error)
	PrepareDownload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.DownloadCommand) (applicationdfir.PreparedDownload, error)
	PrepareAlertUpload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error)
	PrepareAlertDownload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error)
	CollectEvidence(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.EvidenceCommand) (applicationdfir.MutationResult[dfirkernel.Evidence], error)
	AppendCustody(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.CustodyCommand) (applicationdfir.MutationResult[dfirkernel.Evidence], error)
}

// AlertInvestigationService owns the Alert-rooted evidence, task and general
// relationship aggregates. It is deliberately separate from the historical
// Case DFIR boundary so Alert replay/CAS semantics cannot silently fall back
// to the legacy Case implementation.
type AlertInvestigationService interface {
	Workspace(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertInvestigationWorkspace, error)
	CollectEvidence(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertEvidenceCollectCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error)
	AppendCustody(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertCustodyCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error)
	CreateTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	TransitionTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskTransitionCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	ReplaceTaskDetails(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	AssignTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	RescheduleTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskDueDateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	ReplaceTaskChecklist(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskChecklistCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	ReplaceTaskComments(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	CreateRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertRelationshipCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error)
	RetractRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertRelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error)
}

type CustomerPortalAttachmentService interface {
	ListCustomerPortalAttachments(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.PortalAttachmentRoot, applicationdfir.CustomerPortalAttachmentListInput) (applicationdfir.CustomerPortalAttachmentPage, error)
	PrepareCustomerPortalAttachmentDownload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.PortalAttachmentRoot, dfirkernel.EntityID, applicationdfir.AuditContext) (applicationdfir.CustomerPortalPreparedDownload, error)
}

// NotificationAdministrationService is the public API use-case boundary.
// The Node notifier never implements this interface or exposes public routes.
type NotificationAdministrationService interface {
	ListRules(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.RulePage, error)
	GetRule(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.Rule, error)
	CreateRule(context.Context, authorization.Actor, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error)
	VersionRule(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error)
	ListTemplates(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.TemplatePage, error)
	GetTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, *int64) (notification.Template, error)
	CreateTemplate(context.Context, authorization.Actor, uuid.UUID, notification.TemplateWriteInput) (notification.Template, error)
	VersionTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateWriteInput) (notification.Template, error)
	PreviewTemplate(context.Context, authorization.Actor, uuid.UUID, notification.Audience, notification.TemplateFields, map[string]any) (notification.Preview, error)
	DuplicateTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateDuplicateInput) (notification.Template, error)
	RollbackTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateRollbackInput) (notification.Template, error)
	TestSendTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateTestSendInput) (notification.Delivery, error)
	GetTenantSMTP(context.Context, authorization.Actor, uuid.UUID) (notification.SMTPConfiguration, error)
	VersionTenantSMTP(context.Context, authorization.Actor, uuid.UUID, notification.SMTPWriteInput) (notification.SMTPConfiguration, error)
	TestTenantSMTP(context.Context, authorization.Actor, uuid.UUID, notification.SMTPTestInput) (notification.SMTPHealth, error)
	GetPlatformSMTP(context.Context, authentication.Session) (notification.SMTPConfiguration, error)
	VersionPlatformSMTP(context.Context, authentication.Session, notification.SMTPWriteInput) (notification.SMTPConfiguration, error)
	TestPlatformSMTP(context.Context, authentication.Session, notification.SMTPTestInput) (notification.SMTPHealth, error)
	ListDeliveries(context.Context, authorization.Actor, uuid.UUID, notification.DeliveryListInput) (notification.DeliveryPage, error)
	GetDelivery(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.Delivery, error)
	RetryDelivery(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.ManualRetryInput) (notification.Delivery, error)
	ListWebhooks(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.WebhookPage, error)
	GetWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.WebhookConfiguration, error)
	CreateWebhook(context.Context, authorization.Actor, uuid.UUID, notification.WebhookWriteInput) (notification.WebhookConfiguration, error)
	VersionWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.WebhookWriteInput) (notification.WebhookConfiguration, error)
	TestWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.WebhookTestInput) (notification.Delivery, error)
}

// NotificationInboxService is the human-session-only personal inbox boundary.
// Implementations resolve the current principal and authorization relationships
// from live database state for every operation.
type NotificationInboxService interface {
	List(context.Context, notificationinbox.Actor, uuid.UUID, notificationinbox.ListInput) (notificationinbox.Page, error)
	CountUnread(context.Context, notificationinbox.Actor, uuid.UUID) (notificationinbox.UnreadState, error)
	SetReadState(context.Context, notificationinbox.Actor, uuid.UUID, notificationinbox.SetReadStateInput) (notificationinbox.ReadStateResult, error)
	MarkAllRead(context.Context, notificationinbox.Actor, uuid.UUID, notificationinbox.MarkAllReadInput) (notificationinbox.MarkAllReadResult, error)
}

// ServiceAccountService is the human-administration boundary for tenant-owned
// machine identities. Implementations must re-resolve live human authority for
// every call and keep credential secrets out of metadata projections.
type ServiceAccountService interface {
	ListAccounts(context.Context, authorization.Actor, uuid.UUID, serviceaccount.ListAccountsInput) (serviceaccount.AccountPage, error)
	GetAccount(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (serviceaccount.Account, error)
	CreateAccount(context.Context, authorization.Actor, uuid.UUID, serviceaccount.CreateAccountInput) (serviceaccount.Account, error)
	UpdateAccount(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.UpdateAccountInput) (serviceaccount.Account, error)
	ArchiveAccount(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.ArchiveAccountInput) error
	ListRoleGrants(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.ListRoleGrantsInput) (serviceaccount.RoleGrantPage, error)
	GetRoleGrant(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (serviceaccount.RoleGrant, error)
	GrantRole(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.GrantRoleInput) (serviceaccount.RoleGrant, error)
	RevokeRoleGrant(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, serviceaccount.RevokeRoleGrantInput) error
	ListCredentials(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.ListCredentialsInput) (serviceaccount.CredentialPage, error)
	GetCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (serviceaccount.CredentialMetadata, error)
	IssueCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.IssueCredentialInput) (serviceaccount.CredentialSecret, error)
	RotateCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, serviceaccount.RotateCredentialInput) (serviceaccount.CredentialSecret, error)
	RevokeCredential(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, serviceaccount.RevokeCredentialInput) error
}

// AlertService is the dual-principal boundary for the minimal alert.create
// slice. Separate methods prevent one authentication mode falling back to the
// other after a failed authentication attempt.
type AlertService interface {
	CreateAsHuman(context.Context, authorization.Actor, uuid.UUID, alert.CreateInput) (alert.Alert, error)
	CreateAsBearer(context.Context, uuid.UUID, alert.BearerCreateInput) (alert.Alert, error)
}

// TicketingService is the human Alert/Case application boundary. Every method
// re-resolves live principal class, permission scopes, and resource relations.
type TicketingService interface {
	List(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.ListInput) (applicationticketing.Page, error)
	ListPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.ListInput) (applicationticketing.Page, error)
	Get(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.View, error)
	GetPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.View, error)
	Activities(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.ActivityPage, error)
	ActivityFeed(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.CursorPageInput) (applicationticketing.ActivityPage, error)
	ActivitiesPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.ActivityPage, error)
	Comments(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.CommentPage, error)
	CommentsPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.CommentPage, error)
	ExportPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.CustomerPortalExport, error)
	AddComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentInput) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	AddPortalComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentInput) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	PreviewComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentPreviewInput) (applicationticketing.CommentPreview, error)
	PreviewPortalComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentPreviewInput) (applicationticketing.CommentPreview, error)
	CommentMentionCandidates(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentMentionCandidateInput) (applicationticketing.CommentMentionCandidateList, error)
	EditComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentEditInput) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	EditPortalComment(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentEditInput) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	CommentRevisions(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentRevisionPageInput) (applicationticketing.CommentRevisionPage, error)
	CommentRevisionsPortal(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentRevisionPageInput) (applicationticketing.CommentRevisionPage, error)
	Links(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.LinkPage, error)
	AlertRelations(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.AlertRelationPage, error)
	CreateAlertRelation(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.AlertRelationCreateInput) (applicationticketing.AlertRelationMutationReceipt, error)
	RetractAlertRelation(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.AlertRelationRetractionInput) (applicationticketing.AlertRelationMutationReceipt, error)
	CreateCase(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.CreateCaseInput) (applicationticketing.MutationResult, error)
	DeleteAlert(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.DeleteAlertInput) (applicationticketing.DeleteAlertReceipt, error)
	ReplaceAlertMetadata(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error)
	ReplaceCaseMetadata(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error)
	ListAlertWatchers(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID) (applicationticketing.TicketWatcherProjection, error)
	ListCaseWatchers(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID) (applicationticketing.TicketWatcherProjection, error)
	AddAlertWatcher(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.WatcherMutationInput) (applicationticketing.WatcherMutationResult, error)
	AddCaseWatcher(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.WatcherMutationInput) (applicationticketing.WatcherMutationResult, error)
	RemoveAlertWatcher(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.WatcherMutationInput) (applicationticketing.WatcherMutationResult, error)
	RemoveCaseWatcher(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.WatcherMutationInput) (applicationticketing.WatcherMutationResult, error)
	Mutate(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, kernel.Action, applicationticketing.MutationInput) (applicationticketing.MutationResult, error)
	Escalate(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.EscalationInput) (applicationticketing.EscalationResult, error)
	Link(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.EscalationInput) (applicationticketing.EscalationResult, error)
	Unlink(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.UnlinkInput) (applicationticketing.UnlinkReceipt, error)
}

// WorkflowAdministrationService is the operator-only tenant boundary for the
// mutable workflow catalog, immutable publications, and explanatory simulator.
// Every method re-resolves live workflow authority in the use case and the
// repository repeats it inside the same database transaction.
type WorkflowAdministrationService interface {
	ListWorkflows(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowAdminListInput) (applicationticketing.WorkflowAdminPage, error)
	GetWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID) (applicationticketing.WorkflowAdminRecord, error)
	ListWorkflowVersions(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowVersionListInput) (applicationticketing.WorkflowVersionPage, error)
	GetWorkflowVersion(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uint64) (applicationticketing.WorkflowVersionRecord, error)
	SimulateWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowSimulationInput) (applicationticketing.WorkflowSimulationResult, error)
	CreateWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowCreateInput) (applicationticketing.WorkflowAdminMutationResult, error)
	PublishWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowPublishInput) (applicationticketing.WorkflowAdminMutationResult, error)
	UpdateWorkflowMetadata(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error)
	SetDefaultWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error)
	ArchiveWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error)
	RestoreWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error)
}

// SavedViewService is the private operator view boundary. Implementations
// re-resolve the exact human membership, ticket-read permission, catalog pins,
// optimistic revision, audit, and idempotency evidence on every call.
type SavedViewService interface {
	ListSavedViews(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.SavedViewListInput) (applicationticketing.SavedViewPage, error)
	GetSavedView(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.SavedViewRecord, error)
	CreateSavedView(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.SavedViewCreateInput) (applicationticketing.SavedViewMutationResult, error)
	ReplaceSavedView(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.SavedViewReplaceInput) (applicationticketing.SavedViewMutationResult, error)
	ArchiveSavedView(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.SavedViewLifecycleInput) (applicationticketing.SavedViewMutationResult, error)
	RestoreSavedView(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.SavedViewLifecycleInput) (applicationticketing.SavedViewMutationResult, error)
}

// TicketBulkService is the operator-only asynchronous bulk-mutation boundary.
// Implementations materialize immutable targets and re-resolve live authority
// for request, read, cancellation, and result-list operations.
type TicketBulkService interface {
	Request(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.TicketBulkRequestInput) (applicationticketing.TicketBulkResult, error)
	Get(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.TicketBulkRecord, error)
	Cancel(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.TicketBulkCancelInput) (applicationticketing.TicketBulkResult, error)
	ListResults(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.TicketBulkResultListInput) (applicationticketing.TicketBulkResultPage, error)
}

// AsyncExportService is the operator-only ticket-export owner boundary. The
// application service resolves live ticket and comment authority and persists
// one immutable inline or exact saved-view snapshot before enqueueing work.
type AsyncExportService interface {
	Request(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.AsyncExportRequestInput) (applicationticketing.AsyncExportResult, error)
	Get(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, kernel.TicketExportAudience, uuid.UUID) (applicationticketing.AsyncExportRecord, error)
	Cancel(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, kernel.TicketExportAudience, uuid.UUID, applicationticketing.AsyncExportCancelInput) (applicationticketing.AsyncExportResult, error)
	PrepareDownload(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, kernel.TicketExportAudience, uuid.UUID) (applicationticketing.AsyncExportPreparedDownload, error)
}

// OperatorTeamService is the platform and tenant application boundary for
// global operator-team identities and their tenant-owned assignment epochs.
// Implementations remain responsible for live permission evaluation.
type OperatorTeamService interface {
	ListOperatorTeams(context.Context, authentication.Session, operatorteam.ListOperatorTeamsInput) (operatorteam.OperatorTeamPage, error)
	GetOperatorTeam(context.Context, authentication.Session, uuid.UUID) (operatorteam.OperatorTeam, error)
	CreateOperatorTeam(context.Context, authentication.Session, operatorteam.CreateOperatorTeamInput) (operatorteam.OperatorTeam, error)
	PatchOperatorTeam(context.Context, authentication.Session, uuid.UUID, operatorteam.PatchOperatorTeamInput) (operatorteam.OperatorTeam, error)
	ArchiveOperatorTeam(context.Context, authentication.Session, uuid.UUID, operatorteam.ArchiveOperatorTeamInput) error
	ListTenantAssignments(context.Context, authorization.Actor, uuid.UUID, operatorteam.ListTenantAssignmentsInput) (operatorteam.TenantAssignmentPage, error)
	GetTenantAssignment(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (operatorteam.TenantAssignment, error)
	StartTenantAssignment(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, operatorteam.StartTenantAssignmentInput) (operatorteam.TenantAssignment, error)
	EndTenantAssignment(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.EndTenantAssignmentInput) error
	ListRosterEntries(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.ListRosterEntriesInput) (operatorteam.RosterEntryPage, error)
	AddRosterEntry(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.AddRosterEntryInput) (operatorteam.RosterEntry, error)
	RevokeRosterEntry(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.RevokeRosterEntryInput) error
}

// ApplicationOptions configures the authenticated HTTP surface.
type ApplicationOptions struct {
	Alerts                     AlertService
	AsyncExports               AsyncExportService
	Audit                      SecurityAuditService
	AuditOperations            AuditOperationsService
	Authentication             AuthenticationService
	SessionLogout              SessionLogoutService
	Authorization              AuthorizationService
	CustomFields               CustomFieldService
	CustomFieldImports         CustomFieldImportService
	Contacts                   ContactService
	DFIR                       DFIRService
	AlertInvestigation         AlertInvestigationService
	Environment                string
	FederatedBrowser           *FederatedBrowserOptions
	IdentityProviders          IdentityProviderService
	LDAPAdministration         LDAPAdministrationService
	LDAPAuthentication         LDAPAuthenticationService
	TenantFederation           TenantFederationAdministrationService
	MFA                        MFAService
	MFAPolicies                MFAPolicyService
	Notifications              NotificationAdministrationService
	NotificationInbox          NotificationInboxService
	OperatorTeams              OperatorTeamService
	Platform                   PlatformService
	PlatformTenantAccess       PlatformTenantAccessService
	PlatformOIDCBrowser        PlatformOIDCBrowserAuthentication
	PlatformSAMLBrowser        PlatformSAMLBrowserAuthentication
	PlatformSAMLContinuation   PlatformSAMLContinuationService
	PlatformIdentityAccounts   PlatformIdentityAccountService
	PlatformIdentityBindings   PlatformIdentityBindingService
	PlatformIdentityProviders  PlatformIdentityProviderService
	PlatformLDAPAuthentication PlatformLDAPAuthenticationService
	PlatformLocalAccounts      PlatformLocalAccountService
	PlatformOperations         PlatformOperationsService
	TenantLifecycle            TenantLifecycleService
	TenantSettings             TenantSettingsService
	TicketNumbering            TicketNumberingService
	WebhookURLPolicy           WebhookURLPolicyService
	PublicOrigin               string
	RequestTimeout             time.Duration
	ServiceAccounts            ServiceAccountService
	SLA                        SLAService
	SavedViews                 SavedViewService
	TicketBulk                 TicketBulkService
	Ticketing                  TicketingService
	WorkflowAdministration     WorkflowAdministrationService
	TrustedProxyCIDRs          []netip.Prefix
}

// NewHandler returns a fail-closed health and status handler.
func NewHandler(
	checker ReadinessChecker,
	logger *slog.Logger,
	release string,
	readinessTimeout time.Duration,
) *Handler {
	handler := &Handler{
		checker:          checker,
		logger:           logger,
		readinessTimeout: readinessTimeout,
		requestTimeout:   defaultRequestTimeout,
		release:          release,
	}
	handler.readinessSnapshot.Store(&readinessSnapshot{checkedAt: time.Now().UTC()})
	return handler
}

// NewApplicationHandler returns a handler with the authenticated platform and
// tenant-authorization surfaces.
func NewApplicationHandler(
	checker ReadinessChecker,
	logger *slog.Logger,
	release string,
	readinessTimeout time.Duration,
	options ApplicationOptions,
) (*Handler, error) {
	if options.Alerts == nil || options.Audit == nil || options.Authentication == nil || options.Authorization == nil ||
		options.Contacts == nil ||
		options.CustomFields == nil || options.DFIR == nil ||
		options.IdentityProviders == nil || options.LDAPAdministration == nil || options.MFA == nil || options.OperatorTeams == nil ||
		options.Notifications == nil || options.Platform == nil || options.ServiceAccounts == nil || options.SLA == nil || options.Ticketing == nil ||
		options.WorkflowAdministration == nil {
		return nil, errors.New("alert, audit, authentication, authorization, contact, custom-field, DFIR, identity-provider, LDAP administration, MFA, notification, operator team, platform, service-account, SLA, ticketing, and workflow-administration services are required")
	}
	if options.PublicOrigin == "" {
		return nil, errors.New("public origin is required")
	}
	cookie, err := newSessionCookiePolicy(options.Environment, options.PublicOrigin)
	if err != nil {
		return nil, err
	}
	mfaCookie, err := newMFACookiePolicy(options.Environment, options.PublicOrigin)
	if err != nil {
		return nil, err
	}
	federatedContinuationCookie, err := newFederatedContinuationCookiePolicy(options.Environment, options.PublicOrigin)
	if err != nil {
		return nil, err
	}
	logoutContinuationCookie, err := newLogoutContinuationCookiePolicy(options.Environment, options.PublicOrigin)
	if err != nil {
		return nil, err
	}
	federated, err := newFederatedBrowserTransport(options.Environment, options.PublicOrigin, options.FederatedBrowser)
	if err != nil {
		return nil, err
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaultRequestTimeout
	}
	if options.RequestTimeout < time.Second || options.RequestTimeout > 25*time.Second {
		return nil, errors.New("request timeout must be between 1s and 25s")
	}
	handler := NewHandler(checker, logger, release, readinessTimeout)
	handler.alerts = options.Alerts
	handler.asyncExports = options.AsyncExports
	if handler.asyncExports == nil {
		handler.asyncExports = unavailableAsyncExportService{}
	}
	handler.audit = options.Audit
	handler.auditOperations = options.AuditOperations
	if auditOperationsServiceIsNil(handler.auditOperations) {
		handler.auditOperations = unavailableAuditOperationsService{}
	}
	handler.authentication = options.Authentication
	handler.sessionLogout = options.SessionLogout
	if handler.sessionLogout == nil {
		handler.sessionLogout = unavailableSessionLogoutService{}
	}
	handler.authorization = options.Authorization
	handler.customFields = options.CustomFields
	handler.customFieldImports = options.CustomFieldImports
	if handler.customFieldImports == nil {
		handler.customFieldImports = unavailableCustomFieldImportService{}
	}
	handler.contacts = options.Contacts
	handler.dfir = options.DFIR
	handler.alertInvestigation = options.AlertInvestigation
	if handler.alertInvestigation == nil {
		handler.alertInvestigation = unavailableAlertInvestigationService{}
	}
	handler.federated = federated
	handler.federatedContinuationCookie = federatedContinuationCookie
	handler.logoutContinuationCookie = logoutContinuationCookie
	handler.identityProviders = options.IdentityProviders
	handler.ldapAdministration = options.LDAPAdministration
	handler.ldapAuthentication = options.LDAPAuthentication
	if handler.ldapAuthentication == nil {
		handler.ldapAuthentication = unavailableLDAPAuthenticationService{}
	}
	handler.tenantFederation = options.TenantFederation
	if tenantFederationAdministrationServiceIsNil(handler.tenantFederation) {
		handler.tenantFederation = unavailableTenantFederationAdministrationService{}
	}
	handler.notifications = options.Notifications
	handler.notificationInbox = options.NotificationInbox
	if handler.notificationInbox == nil {
		handler.notificationInbox = unavailableNotificationInboxService{}
	}
	handler.operatorTeams = options.OperatorTeams
	handler.platform = options.Platform
	handler.platformTenantAccess = options.PlatformTenantAccess
	if platformTenantAccessServiceIsNil(handler.platformTenantAccess) {
		handler.platformTenantAccess = unavailablePlatformTenantAccessService{}
	}
	handler.platformOIDCBrowser = options.PlatformOIDCBrowser
	if platformOIDCBrowserAuthenticationIsNil(handler.platformOIDCBrowser) {
		handler.platformOIDCBrowser = unavailablePlatformOIDCBrowserAuthentication{}
	}
	handler.platformSAMLBrowser = options.PlatformSAMLBrowser
	if platformSAMLBrowserAuthenticationIsNil(handler.platformSAMLBrowser) {
		handler.platformSAMLBrowser = unavailablePlatformSAMLBrowserAuthentication{}
	}
	handler.platformSAMLContinuation = options.PlatformSAMLContinuation
	if platformSAMLContinuationServiceIsNil(handler.platformSAMLContinuation) {
		handler.platformSAMLContinuation = unavailablePlatformSAMLContinuationService{}
	}
	handler.platformIdentityAccounts = options.PlatformIdentityAccounts
	if platformIdentityAccountServiceIsNil(handler.platformIdentityAccounts) {
		handler.platformIdentityAccounts = unavailablePlatformIdentityAccountService{}
	}
	handler.platformIdentityBindings = options.PlatformIdentityBindings
	if platformIdentityBindingServiceIsNil(handler.platformIdentityBindings) {
		handler.platformIdentityBindings = unavailablePlatformIdentityBindingService{}
	}
	handler.platformIdentityProviders = options.PlatformIdentityProviders
	if platformIdentityProviderServiceIsNil(handler.platformIdentityProviders) {
		handler.platformIdentityProviders = unavailablePlatformIdentityProviderService{}
	}
	handler.platformLDAPAuthentication = options.PlatformLDAPAuthentication
	if platformLDAPAuthenticationServiceIsNil(handler.platformLDAPAuthentication) {
		handler.platformLDAPAuthentication = unavailablePlatformLDAPAuthenticationService{}
	}
	handler.platformLocalAccounts = options.PlatformLocalAccounts
	if platformLocalAccountServiceIsNil(handler.platformLocalAccounts) {
		handler.platformLocalAccounts = unavailablePlatformLocalAccountService{}
	}
	handler.platformOperations = options.PlatformOperations
	if platformOperationsServiceIsNil(handler.platformOperations) {
		handler.platformOperations = unavailablePlatformOperationsService{}
	}
	handler.tenantLifecycle = options.TenantLifecycle
	if tenantLifecycleServiceIsNil(handler.tenantLifecycle) {
		handler.tenantLifecycle = unavailableTenantLifecycleService{}
	}
	handler.tenantSettings = options.TenantSettings
	if tenantSettingsServiceIsNil(handler.tenantSettings) {
		handler.tenantSettings = unavailableTenantSettingsService{}
	}
	handler.ticketNumbering = options.TicketNumbering
	if ticketNumberingServiceIsNil(handler.ticketNumbering) {
		handler.ticketNumbering = unavailableTicketNumberingService{}
	}
	handler.webhookURLPolicy = options.WebhookURLPolicy
	if webhookURLPolicyServiceIsNil(handler.webhookURLPolicy) {
		handler.webhookURLPolicy = unavailableWebhookURLPolicyService{}
	}
	handler.cookie = cookie
	handler.mfaCookie = mfaCookie
	handler.mfa = options.MFA
	handler.mfaPolicies = options.MFAPolicies
	if mfaPolicyServiceIsNil(handler.mfaPolicies) {
		handler.mfaPolicies = unavailableMFAPolicyService{}
	}
	handler.publicOrigin = options.PublicOrigin
	handler.requestTimeout = options.RequestTimeout
	handler.serviceAccounts = options.ServiceAccounts
	handler.sla = options.SLA
	handler.savedViews = options.SavedViews
	if handler.savedViews == nil {
		handler.savedViews = unavailableSavedViewService{}
	}
	handler.ticketBulk = options.TicketBulk
	if handler.ticketBulk == nil {
		handler.ticketBulk = unavailableTicketBulkService{}
	}
	handler.ticketing = options.Ticketing
	handler.workflowAdministration = options.WorkflowAdministration
	handler.trustedProxies = append([]netip.Prefix(nil), options.TrustedProxyCIDRs...)
	return handler, nil
}

// GetLiveness reports process liveness without checking downstream dependencies.
func (h *Handler) GetLiveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, contract.Liveness{
		Service: contract.LivenessServiceApi,
		Status:  contract.Alive,
		Version: h.release,
	})
}

// GetReadiness reports whether all required dependencies can receive traffic.
func (h *Handler) GetReadiness(w http.ResponseWriter, r *http.Request) {
	snapshot, err := h.readiness(r.Context())
	if err != nil || !snapshot.ready {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required dependency is unavailable.")
		return
	}

	writeJSON(w, http.StatusOK, contract.Readiness{
		Status: contract.ReadinessStatusReady,
		Checks: snapshot.checks,
	})
}

// GetSystemStatus reports non-sensitive build and tenant-boundary readiness.
func (h *Handler) GetSystemStatus(w http.ResponseWriter, r *http.Request) {
	snapshot := h.readinessSnapshot.Load()
	if snapshot == nil {
		snapshot = &readinessSnapshot{checkedAt: time.Now().UTC()}
	}
	status := contract.SystemStatusStatusReady
	if !snapshot.ready {
		status = contract.SystemStatusStatusDegraded
	}

	writeJSON(w, http.StatusOK, contract.SystemStatus{
		CheckedAt:   snapshot.checkedAt,
		Product:     contract.SystemStatusProductPeriapsis,
		Service:     contract.SystemStatusServiceApi,
		Status:      status,
		TenancyMode: contract.SharedSchemaRls,
		Version:     h.release,
	})
}

func (h *Handler) readiness(ctx context.Context) (*readinessSnapshot, error) {
	now := time.Now().UTC()
	if snapshot := h.readinessSnapshot.Load(); readinessSnapshotIsFresh(snapshot, now) {
		return snapshot, nil
	}

	h.readinessMu.Lock()
	if snapshot := h.readinessSnapshot.Load(); readinessSnapshotIsFresh(snapshot, time.Now().UTC()) {
		h.readinessMu.Unlock()
		return snapshot, nil
	}
	refresh := h.readinessRefresh
	if refresh == nil {
		refresh = &readinessRefresh{done: make(chan struct{})}
		h.readinessRefresh = refresh
		go h.runReadinessRefresh(refresh)
	}
	h.readinessMu.Unlock()

	select {
	case <-refresh.done:
		return refresh.snapshot, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Handler) runReadinessRefresh(refresh *readinessRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), h.readinessTimeout)
	defer cancel()
	results := h.checker.Check(ctx)
	checks := make(map[string]contract.DependencyCheck, len(results))
	ready := len(results) > 0
	for _, result := range results {
		latencyMS := int(result.Latency.Milliseconds())
		status := contract.DependencyCheckStatusUnavailable
		if result.Ready {
			status = contract.DependencyCheckStatusReady
		} else {
			ready = false
		}
		checks[result.Name] = contract.DependencyCheck{
			LatencyMs: &latencyMS,
			Status:    status,
		}
	}
	completedAt := time.Now().UTC()
	snapshot := &readinessSnapshot{
		ready: ready, checks: checks, checkedAt: completedAt,
		expiresAt: completedAt.Add(readinessCacheTTL),
	}

	h.readinessMu.Lock()
	if h.readinessRefresh == refresh {
		refresh.snapshot = snapshot
		h.readinessSnapshot.Store(snapshot)
		h.readinessRefresh = nil
		close(refresh.done)
	}
	h.readinessMu.Unlock()
}

func readinessSnapshotIsFresh(snapshot *readinessSnapshot, now time.Time) bool {
	return snapshot != nil && !snapshot.expiresAt.IsZero() && !now.Before(snapshot.checkedAt) &&
		now.Before(snapshot.expiresAt)
}

// RouterObservability keeps process instrumentation inside the ServeMux route
// boundary so registered templates, rather than raw URLs, reach logs, metrics,
// and traces.
type RouterObservability struct {
	Metrics     *telemetry.Metrics
	Tracing     *telemetry.Runtime
	RateLimiter APIRateLimiter
}

// Router creates the complete anonymous Phase 1 HTTP surface.
func Router(
	handler *Handler,
	logger *slog.Logger,
	docsEnabled bool,
	observabilityOptions ...RouterObservability,
) http.Handler {
	if len(observabilityOptions) > 1 {
		panic("httpserver: at most one observability configuration is supported")
	}
	var observability RouterObservability
	if len(observabilityOptions) == 1 {
		observability = observabilityOptions[0]
		if observability.Metrics == nil && observability.Tracing == nil && observability.RateLimiter == nil {
			panic("httpserver: observability configuration is empty")
		}
	}
	mux := http.NewServeMux()
	contract.HandlerWithOptions(handler, contract.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Cache-Control", "no-store")
			var requiredHeader *contract.RequiredHeaderError
			if errors.As(err, &requiredHeader) && requiredHeader.ParamName == ifMatchHeader {
				writeProblem(
					w,
					r,
					http.StatusPreconditionRequired,
					"precondition_required",
					"Precondition required",
					"A current strong If-Match entity tag is required.",
				)
				return
			}
			writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is malformed.")
		},
	})
	registerDocumentation(mux, docsEnabled)
	if observability.Metrics != nil {
		mux.Handle("/metrics", observability.Metrics.Handler())
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested resource does not exist.")
	})

	var routed http.Handler = mux
	if observability.RateLimiter != nil {
		limited := apiRateLimitMiddleware(handler, observability.RateLimiter, routed)
		routed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r != nil {
				_, r.Pattern = mux.Handler(r)
			}
			limited.ServeHTTP(w, r)
		})
	}
	if observability.Metrics != nil {
		routed = observability.Metrics.WrapHTTP(routed)
	}
	routed = accessLogMiddleware(logger, routed)
	if observability.Tracing != nil {
		routed = observability.Tracing.WrapHTTP(routed)
	}
	routed = requestBodyLimitMiddleware(routed)
	routed = requestTimeoutMiddleware(handler.requestTimeout, routed)
	routed = recoveryMiddleware(logger, routed)
	routed = securityHeadersMiddleware(routed)
	routed = requestIDMiddleware(routed)
	routed = federatedSessionCookiePolicyMiddleware(
		handler.cookie, handler.mfaCookie, handler.federatedContinuationCookie, routed,
	)
	return routed
}

func requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maximum := maximumRequestBody
		if r != nil && r.Method == http.MethodPost && r.URL != nil &&
			r.URL.Path == platformsamlauth.DirectSAMLACSURL {
			maximum = maximumPlatformSAMLCallbackBodyBytes
		}
		http.MaxBytesHandler(next, int64(maximum)).ServeHTTP(w, r)
	})
}

func requestTimeoutMiddleware(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.Nil
		if values := r.Header.Values(requestIDHeader); len(values) == 1 {
			if parsed, err := uuid.Parse(values[0]); err == nil &&
				parsed.Version() == 7 && parsed.Variant() == uuid.RFC4122 {
				requestID = parsed
			}
		}
		if requestID == uuid.Nil {
			requestID = uuid.Must(uuid.NewV7())
		}
		canonicalRequestID := requestID.String()
		w.Header().Set(requestIDHeader, canonicalRequestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, canonicalRequestID)))
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentSecurityPolicy := "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
		if r.URL.Path == "/docs" || r.URL.Path == "/docs/" || len(r.URL.Path) > len("/docs/") && r.URL.Path[:len("/docs/")] == "/docs/" {
			contentSecurityPolicy = "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'"
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func recoveryMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(
					r.Context(), "request panic", "panic_type", fmt.Sprintf("%T", recovered),
					"stack", string(debug.Stack()),
				)
				writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func accessLogMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			panicked := recover()
			status := recorder.status
			if panicked != nil {
				status = http.StatusInternalServerError
			}
			logger.InfoContext(
				r.Context(),
				"http request",
				"method", canonicalAccessLogMethod(r.Method),
				"route", canonicalAccessLogRoute(r.Pattern),
				"status", status,
				"duration_ms", time.Since(startedAt).Milliseconds(),
				"request_id", requestIDFromContext(r.Context()),
			)
			if panicked != nil {
				panic(panicked)
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

func canonicalAccessLogMethod(value string) string {
	if len(value) < 1 || len(value) > 16 {
		return "OTHER"
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return "OTHER"
		}
	}
	return value
}

func canonicalAccessLogRoute(value string) string {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "?\r\n") || !accessLogRoutePattern.MatchString(value) {
		return "unmatched"
	}
	return value
}

type requestIDKey struct{}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	requestID, parseErr := uuid.Parse(requestIDFromContext(r.Context()))
	if parseErr != nil {
		requestID = uuid.Nil
	}
	instance := r.URL.Path
	problemType := "about:blank"
	problem := contract.Problem{
		Code: code, Detail: &detail, Instance: &instance, RequestId: requestID,
		Status: status, Title: title, Type: problemType,
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
