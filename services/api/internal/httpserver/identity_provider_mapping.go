package httpserver

import (
	"errors"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func tenantLDAPConfigurationInput(
	value contract.TenantLDAPAuthProviderConfiguration,
) (identityprovider.Configuration, error) {
	if value.SyncIntervalSeconds != nil {
		return identityprovider.Configuration{}, errors.New("LDAP sync is unavailable")
	}
	return identityprovider.Configuration{
		Template:                   identityprovider.ProviderTemplate(value.Template),
		VerifyCertificate:          bool(value.VerifyCertificate),
		CustomCAPEM:                cloneStringPointer(value.CustomCaPem),
		ConnectTimeoutMS:           value.ConnectTimeoutMs,
		OperationTimeoutMS:         value.OperationTimeoutMs,
		BindDN:                     value.BindDn,
		UserBaseDN:                 value.UserBaseDn,
		GroupBaseDN:                cloneStringPointer(value.GroupBaseDn),
		UserSearchFilter:           value.UserSearchFilter,
		GroupSearchFilter:          cloneStringPointer(value.GroupSearchFilter),
		UserDNTemplate:             cloneStringPointer(value.UserDnTemplate),
		PageSize:                   value.PageSize,
		MaxPages:                   value.MaxPages,
		MaxEntries:                 value.MaxEntries,
		MaxResponseBytes:           value.MaxResponseBytes,
		ReferralMode:               identityprovider.ReferralMode(value.ReferralMode),
		MaxReferralHops:            value.MaxReferralHops,
		NestedGroupMode:            identityprovider.NestedGroupMode(value.NestedGroupMode),
		MaxNestedGroupDepth:        value.MaxNestedGroupDepth,
		MaxGroups:                  value.MaxGroups,
		FirstNameAttribute:         value.FirstNameAttribute,
		LastNameAttribute:          value.LastNameAttribute,
		DisplayNameAttribute:       value.DisplayNameAttribute,
		UsernameAttribute:          value.UsernameAttribute,
		AlternateUsernameAttribute: cloneStringPointer(value.AlternateUsernameAttribute),
		EmailAttribute:             cloneStringPointer(value.EmailAttribute),
		ImmutableSubjectAttribute:  value.ImmutableSubjectAttribute,
		ImmutableSubjectFormat:     identityprovider.SubjectFormat(value.ImmutableSubjectFormat),
		GroupMembershipAttribute:   cloneStringPointer(value.GroupMembershipAttribute),
		POSIXMemberUIDAttribute:    cloneStringPointer(value.PosixMemberUidAttribute),
		POSIXGIDNumberAttribute:    cloneStringPointer(value.PosixGidNumberAttribute),
		AccountStatusMode:          identityprovider.AccountStatusMode(value.AccountStatusMode),
		AccountStatusAttribute:     cloneStringPointer(value.AccountStatusAttribute),
		AccountDisabledValue:       cloneStringPointer(value.AccountDisabledValue),
		JITMode:                    identityprovider.JITMode(value.JitMode),
		NoMatchPolicy:              identityprovider.NoMatchPolicy(value.NoMatchPolicy),
		DeprovisionMode:            identityprovider.DeprovisionMode(value.DeprovisionMode),
		DeprovisionGraceSeconds:    int(value.DeprovisionGraceSeconds),
		SyncIntervalSeconds:        nil,
	}, nil
}

func tenantLDAPEndpointsInput(
	values []contract.TenantLDAPAuthProviderEndpoint,
) ([]identityprovider.Endpoint, error) {
	result := make([]identityprovider.Endpoint, len(values))
	for index, value := range values {
		if value.Port < 1 || value.Port > 65535 {
			return nil, errors.New("LDAP endpoint port is outside uint16")
		}
		result[index] = identityprovider.Endpoint{
			Priority: value.Priority, Host: value.Host, Port: uint16(value.Port),
			Transport: ldapclient.Transport(value.Transport), TLSServerName: value.TlsServerName,
			ReferralAllowed: value.ReferralAllowed, Enabled: value.Enabled,
		}
	}
	return result, nil
}

func mapTenantLDAPProviderSummary(
	value identityprovider.ProviderSummary,
) (contract.TenantLDAPAuthProviderSummary, error) {
	template := contract.TenantLDAPAuthProviderSummaryTemplate(value.Template)
	if !template.Valid() {
		return contract.TenantLDAPAuthProviderSummary{}, errors.New("invalid LDAP provider template")
	}
	return contract.TenantLDAPAuthProviderSummary{
		Id: value.ID, TenantId: value.TenantID, Kind: contract.TenantLDAPAuthProviderSummaryKindLdap,
		Key: value.Key, DisplayName: value.DisplayName, Description: value.Description,
		Enabled: value.Enabled, Template: template, BindSecretConfigured: value.BindSecretConfigured,
		EnabledEndpointCount: value.EnabledEndpointCount, ArchivedAt: utcTimePointer(value.ArchivedAt),
		Version: contract.ResourceVersion(value.Version), CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapTenantLDAPProvider(value identityprovider.Provider) (contract.TenantLDAPAuthProvider, error) {
	summary, err := mapTenantLDAPProviderSummary(value.ProviderSummary)
	if err != nil || identityprovider.ProviderTemplate(value.Configuration.Template) != value.Template {
		return contract.TenantLDAPAuthProvider{}, errors.New("inconsistent LDAP provider projection")
	}
	configuration, err := mapTenantLDAPConfiguration(value.Configuration)
	if err != nil {
		return contract.TenantLDAPAuthProvider{}, err
	}
	endpoints, err := mapTenantLDAPEndpoints(value.Endpoints)
	if err != nil {
		return contract.TenantLDAPAuthProvider{}, err
	}
	template := contract.TenantLDAPAuthProviderTemplate(value.Template)
	if !template.Valid() {
		return contract.TenantLDAPAuthProvider{}, errors.New("invalid LDAP provider template")
	}
	return contract.TenantLDAPAuthProvider{
		Id: summary.Id, TenantId: summary.TenantId, Kind: contract.TenantLDAPAuthProviderKindLdap,
		Key: summary.Key, DisplayName: summary.DisplayName, Description: summary.Description,
		Enabled: summary.Enabled, Template: template, BindSecretConfigured: summary.BindSecretConfigured,
		EnabledEndpointCount: summary.EnabledEndpointCount, ArchivedAt: summary.ArchivedAt,
		Version: summary.Version, CreatedAt: summary.CreatedAt, UpdatedAt: summary.UpdatedAt,
		Configuration: configuration, Endpoints: endpoints,
		BindSecretRotatedAt: utcTimePointer(value.BindSecretRotatedAt),
		ArchiveReason:       cloneStringPointer(value.ArchiveReason),
	}, nil
}

func mapTenantLDAPConfiguration(
	value identityprovider.Configuration,
) (contract.TenantLDAPAuthProviderConfiguration, error) {
	result := contract.TenantLDAPAuthProviderConfiguration{
		Template:                   contract.TenantLDAPAuthProviderConfigurationTemplate(value.Template),
		VerifyCertificate:          contract.TenantLDAPAuthProviderConfigurationVerifyCertificate(value.VerifyCertificate),
		CustomCaPem:                cloneStringPointer(value.CustomCAPEM),
		ConnectTimeoutMs:           value.ConnectTimeoutMS,
		OperationTimeoutMs:         value.OperationTimeoutMS,
		BindDn:                     value.BindDN,
		UserBaseDn:                 value.UserBaseDN,
		GroupBaseDn:                cloneStringPointer(value.GroupBaseDN),
		UserSearchFilter:           value.UserSearchFilter,
		GroupSearchFilter:          cloneStringPointer(value.GroupSearchFilter),
		UserDnTemplate:             cloneStringPointer(value.UserDNTemplate),
		PageSize:                   value.PageSize,
		MaxPages:                   value.MaxPages,
		MaxEntries:                 value.MaxEntries,
		MaxResponseBytes:           value.MaxResponseBytes,
		ReferralMode:               contract.TenantLDAPAuthProviderConfigurationReferralMode(value.ReferralMode),
		MaxReferralHops:            value.MaxReferralHops,
		NestedGroupMode:            contract.TenantLDAPAuthProviderConfigurationNestedGroupMode(value.NestedGroupMode),
		MaxNestedGroupDepth:        value.MaxNestedGroupDepth,
		MaxGroups:                  value.MaxGroups,
		FirstNameAttribute:         value.FirstNameAttribute,
		LastNameAttribute:          value.LastNameAttribute,
		DisplayNameAttribute:       value.DisplayNameAttribute,
		UsernameAttribute:          value.UsernameAttribute,
		AlternateUsernameAttribute: cloneStringPointer(value.AlternateUsernameAttribute),
		EmailAttribute:             cloneStringPointer(value.EmailAttribute),
		ImmutableSubjectAttribute:  value.ImmutableSubjectAttribute,
		ImmutableSubjectFormat:     contract.TenantLDAPAuthProviderConfigurationImmutableSubjectFormat(value.ImmutableSubjectFormat),
		GroupMembershipAttribute:   cloneStringPointer(value.GroupMembershipAttribute),
		PosixMemberUidAttribute:    cloneStringPointer(value.POSIXMemberUIDAttribute),
		PosixGidNumberAttribute:    cloneStringPointer(value.POSIXGIDNumberAttribute),
		AccountStatusMode:          contract.TenantLDAPAuthProviderConfigurationAccountStatusMode(value.AccountStatusMode),
		AccountStatusAttribute:     cloneStringPointer(value.AccountStatusAttribute),
		AccountDisabledValue:       cloneStringPointer(value.AccountDisabledValue),
		JitMode:                    contract.TenantLDAPAuthProviderConfigurationJitMode(value.JITMode),
		NoMatchPolicy:              contract.TenantLDAPAuthProviderConfigurationNoMatchPolicy(value.NoMatchPolicy),
		DeprovisionMode:            contract.TenantLDAPAuthProviderConfigurationDeprovisionMode(value.DeprovisionMode),
		DeprovisionGraceSeconds:    contract.TenantLDAPAuthProviderConfigurationDeprovisionGraceSeconds(value.DeprovisionGraceSeconds),
		SyncIntervalSeconds:        nil,
	}
	if !result.Template.Valid() || !result.ReferralMode.Valid() || !result.NestedGroupMode.Valid() ||
		!result.ImmutableSubjectFormat.Valid() || !result.AccountStatusMode.Valid() ||
		!result.JitMode.Valid() || !result.NoMatchPolicy.Valid() || !result.DeprovisionMode.Valid() {
		return contract.TenantLDAPAuthProviderConfiguration{}, errors.New("invalid LDAP configuration enum")
	}
	return result, nil
}

func mapTenantLDAPEndpoints(
	values []identityprovider.Endpoint,
) ([]contract.TenantLDAPAuthProviderEndpoint, error) {
	result := make([]contract.TenantLDAPAuthProviderEndpoint, len(values))
	for index, value := range values {
		transport := contract.TenantLDAPAuthProviderEndpointTransport(value.Transport)
		if !transport.Valid() {
			return nil, errors.New("invalid LDAP endpoint transport")
		}
		result[index] = contract.TenantLDAPAuthProviderEndpoint{
			Priority: value.Priority, Host: value.Host, Port: int(value.Port), Transport: transport,
			TlsServerName: value.TLSServerName, ReferralAllowed: value.ReferralAllowed, Enabled: value.Enabled,
		}
	}
	return result, nil
}

func mapTenantLDAPDiagnostic(
	value identityprovider.TestResult,
) (contract.TenantLDAPAuthProviderDiagnostic, error) {
	outcome := contract.TenantLDAPAuthProviderDiagnosticOutcome(value.Outcome)
	category := contract.TenantLDAPAuthProviderDiagnosticCategory(value.Category)
	if !outcome.Valid() || !category.Valid() || value.Duration < 0 || value.Duration > 120*time.Second ||
		value.Duration%time.Millisecond != 0 {
		return contract.TenantLDAPAuthProviderDiagnostic{}, errors.New("invalid LDAP diagnostic")
	}
	return contract.TenantLDAPAuthProviderDiagnostic{
		TestRunId: value.TestRunID, Outcome: outcome, Category: category,
		EndpointPriority: cloneIntPointer(value.EndpointPriority), DurationMs: int(value.Duration / time.Millisecond),
		Stale: value.Stale, CompletedAt: value.CompletedAt.UTC(),
	}, nil
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}
