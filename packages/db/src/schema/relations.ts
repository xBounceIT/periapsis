import { relations } from "drizzle-orm";

import { alertActivities, alertCommands, alerts } from "./alerts.js";
import {
  tenantAuthorizationCommands,
  tenantAuthorizationSources,
  tenantAuthorizationStates,
  tenantMembershipRoleGrants,
  tenantPermissions,
  tenantPermissionScopes,
  tenantRoleDelegationCeilings,
  tenantRolePermissions,
  tenantRoles,
  tenantSecurityGroupMemberships,
  tenantSecurityGroupRoleGrants,
  tenantSecurityGroups,
} from "./authorization.js";
import {
  authChallenges,
  authSessions,
  localBreakGlassCredentials,
  recoveryCodes,
  totpCredentials,
} from "./authentication.js";
import { auditChainHeads, auditEvents } from "./audit.js";
import {
  tenantMemberships,
  tenantUserProfiles,
  userLoginIdentifiers,
  users,
} from "./identity.js";
import {
  tenantAuthProviderBindings,
  tenantIdentityProviderAccessEpochs,
  tenantLdapExternalIdentities,
  tenantLdapExternalIdentitySubjectAliases,
  tenantLdapProviderAccessGrants,
  tenantLdapProviderProfileContributions,
  tenantUserManualProfileOverrides,
} from "./identity-access.js";
import {
  tenantLdapDirectoryOperationRuns,
  tenantLdapDirectoryRunMappings,
} from "./identity-directory-operations.js";
import {
  tenantLdapMappingRuleEpochs,
  tenantLdapMappingRuleRoleTargets,
  tenantLdapMappingRules,
} from "./identity-mappings.js";
import {
  platformAuthProviders,
  platformFederatedProviderPolicies,
  platformFederatedTrustRules,
  platformIdentityProviderCommands,
  platformIdentityProviderTestRuns,
  platformOidcClaimRules,
  platformOidcClientSecrets,
  platformOidcDiscoverySnapshots,
  platformOidcJwksSnapshots,
  platformOidcProviderConfigurations,
  platformSamlAttributeRules,
  platformSamlMetadataSnapshots,
  platformSamlProviderConfigurations,
  platformSamlSpCertificates,
  platformSamlSpKeys,
} from "./identity-platform-federation.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
  tenantLdapProviderConfigs,
  tenantLdapProviderSecrets,
  tenantLdapProviderTestRuns,
  tenantLdapProviderUrls,
} from "./identity-providers.js";
import {
  operatorTeamAssignmentEpochs,
  operatorTeamRosterEntries,
  operatorTeams,
  platformCommands,
} from "./operator-teams.js";
import { outboxEvents } from "./outbox.js";
import {
  platformAuditEvents,
  platformBootstrapEnrollments,
  platformBootstrapState,
  platformPermissions,
  platformRolePermissions,
  platformRoles,
  userPlatformRoles,
} from "./platform.js";
import {
  tenantApiCredentialCommands,
  tenantApiCredentialNetworks,
  tenantApiCredentialPermissions,
  tenantApiCredentials,
  tenantServiceAccountRoleGrants,
  tenantServiceAccounts,
} from "./service-accounts.js";
import { tenants } from "./tenancy.js";

export const tenantsRelations = relations(tenants, ({ many, one }) => ({
  memberships: many(tenantMemberships),
  userProfiles: many(tenantUserProfiles),
  authProviders: many(tenantAuthProviders),
  authProviderBindings: many(tenantAuthProviderBindings),
  identityProviderAccessEpochs: many(tenantIdentityProviderAccessEpochs),
  ldapExternalIdentities: many(tenantLdapExternalIdentities),
  ldapExternalIdentitySubjectAliases: many(
    tenantLdapExternalIdentitySubjectAliases,
  ),
  ldapProviderAccessGrants: many(tenantLdapProviderAccessGrants),
  ldapProviderProfileContributions: many(
    tenantLdapProviderProfileContributions,
  ),
  userManualProfileOverrides: many(tenantUserManualProfileOverrides),
  ldapMappingRules: many(tenantLdapMappingRules),
  ldapMappingRuleEpochs: many(tenantLdapMappingRuleEpochs),
  ldapMappingRuleRoleTargets: many(tenantLdapMappingRuleRoleTargets),
  ldapProviderConfigs: many(tenantLdapProviderConfigs),
  ldapProviderUrls: many(tenantLdapProviderUrls),
  ldapProviderSecrets: many(tenantLdapProviderSecrets),
  ldapProviderTestRuns: many(tenantLdapProviderTestRuns),
  ldapDirectoryOperationRuns: many(tenantLdapDirectoryOperationRuns),
  ldapDirectoryRunMappings: many(tenantLdapDirectoryRunMappings),
  authorizationSources: many(tenantAuthorizationSources),
  authorizationCommands: many(tenantAuthorizationCommands),
  authorizationState: one(tenantAuthorizationStates),
  roles: many(tenantRoles),
  membershipRoleGrants: many(tenantMembershipRoleGrants),
  securityGroups: many(tenantSecurityGroups),
  securityGroupMemberships: many(tenantSecurityGroupMemberships),
  securityGroupRoleGrants: many(tenantSecurityGroupRoleGrants),
  operatorTeamAssignmentEpochs: many(operatorTeamAssignmentEpochs),
  operatorTeamRosterEntries: many(operatorTeamRosterEntries),
  serviceAccounts: many(tenantServiceAccounts),
  serviceAccountRoleGrants: many(tenantServiceAccountRoleGrants),
  apiCredentials: many(tenantApiCredentials),
  apiCredentialPermissions: many(tenantApiCredentialPermissions),
  apiCredentialNetworks: many(tenantApiCredentialNetworks),
  apiCredentialCommands: many(tenantApiCredentialCommands),
  alerts: many(alerts),
  alertActivities: many(alertActivities),
  alertCommands: many(alertCommands),
  auditEvents: many(auditEvents),
  auditChainHead: one(auditChainHeads),
  outboxEvents: many(outboxEvents),
}));

export const usersRelations = relations(users, ({ many, one }) => ({
  memberships: many(tenantMemberships),
  loginIdentifiers: many(userLoginIdentifiers),
  tenantProfiles: many(tenantUserProfiles),
  ldapExternalIdentities: many(tenantLdapExternalIdentities),
  tenantManualProfileOverrides: many(tenantUserManualProfileOverrides),
  createdAlerts: many(alerts),
  auditEvents: many(auditEvents, { relationName: "auditActor" }),
  impersonatedAuditEvents: many(auditEvents, {
    relationName: "auditImpersonator",
  }),
  authChallenges: many(authChallenges),
  authSessions: many(authSessions),
  recoveryCodes: many(recoveryCodes),
  platformRoles: many(userPlatformRoles, { relationName: "platformRoleUser" }),
  platformRolesGranted: many(userPlatformRoles, {
    relationName: "platformRoleGrantor",
  }),
  platformRolesRevoked: many(userPlatformRoles, {
    relationName: "platformRoleRevoker",
  }),
  platformAuditEvents: many(platformAuditEvents),
  platformAuthProvidersCreated: many(platformAuthProviders, {
    relationName: "platformAuthProviderCreator",
  }),
  platformAuthProvidersUpdated: many(platformAuthProviders, {
    relationName: "platformAuthProviderUpdater",
  }),
  platformAuthProvidersArchived: many(platformAuthProviders, {
    relationName: "platformAuthProviderArchiver",
  }),
  platformIdentityProviderCommands: many(platformIdentityProviderCommands),
  platformIdentityProviderTestRuns: many(platformIdentityProviderTestRuns),
  operatorTeamsCreated: many(operatorTeams, {
    relationName: "operatorTeamCreator",
  }),
  operatorTeamsArchived: many(operatorTeams, {
    relationName: "operatorTeamArchiver",
  }),
  platformCommands: many(platformCommands),
  bootstrapEnrollmentsConsumed: many(platformBootstrapEnrollments),
  localBreakGlassCredential: one(localBreakGlassCredentials),
  totpCredential: one(totpCredentials),
}));

export const tenantMembershipsRelations = relations(
  tenantMemberships,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantMemberships.tenantId],
      references: [tenants.id],
    }),
    user: one(users, {
      fields: [tenantMemberships.userId],
      references: [users.id],
    }),
    profile: one(tenantUserProfiles),
    roleGrants: many(tenantMembershipRoleGrants, {
      relationName: "tenantMembershipRoleGrantTarget",
    }),
    rolesCreated: many(tenantRoles),
    permissionsCreated: many(tenantRolePermissions),
    ceilingsCreated: many(tenantRoleDelegationCeilings),
    roleGrantsCreated: many(tenantMembershipRoleGrants, {
      relationName: "tenantMembershipRoleGrantGrantor",
    }),
    roleGrantsRevoked: many(tenantMembershipRoleGrants, {
      relationName: "tenantMembershipRoleGrantRevoker",
    }),
    authorizationCommands: many(tenantAuthorizationCommands),
    securityGroupsCreated: many(tenantSecurityGroups),
    securityGroupMemberships: many(tenantSecurityGroupMemberships, {
      relationName: "tenantSecurityGroupMembershipTarget",
    }),
    securityGroupMembershipsGranted: many(tenantSecurityGroupMemberships, {
      relationName: "tenantSecurityGroupMembershipGrantor",
    }),
    securityGroupMembershipsRevoked: many(tenantSecurityGroupMemberships, {
      relationName: "tenantSecurityGroupMembershipRevoker",
    }),
    securityGroupRoleGrantsGranted: many(tenantSecurityGroupRoleGrants, {
      relationName: "tenantSecurityGroupRoleGrantGrantor",
    }),
    securityGroupRoleGrantsRevoked: many(tenantSecurityGroupRoleGrants, {
      relationName: "tenantSecurityGroupRoleGrantRevoker",
    }),
    operatorTeamAssignmentsCreated: many(operatorTeamAssignmentEpochs, {
      relationName: "operatorTeamAssignmentAssigner",
    }),
    operatorTeamAssignmentsEnded: many(operatorTeamAssignmentEpochs, {
      relationName: "operatorTeamAssignmentEnder",
    }),
    operatorTeamRosterEntries: many(operatorTeamRosterEntries, {
      relationName: "operatorTeamRosterTarget",
    }),
    operatorTeamRosterEntriesGranted: many(operatorTeamRosterEntries, {
      relationName: "operatorTeamRosterGrantor",
    }),
    operatorTeamRosterEntriesRevoked: many(operatorTeamRosterEntries, {
      relationName: "operatorTeamRosterRevoker",
    }),
    serviceAccountsCreated: many(tenantServiceAccounts, {
      relationName: "tenantServiceAccountCreator",
    }),
    serviceAccountsArchived: many(tenantServiceAccounts, {
      relationName: "tenantServiceAccountArchiver",
    }),
    serviceAccountRoleGrantsGranted: many(tenantServiceAccountRoleGrants, {
      relationName: "tenantServiceAccountRoleGrantGrantor",
    }),
    serviceAccountRoleGrantsRevoked: many(tenantServiceAccountRoleGrants, {
      relationName: "tenantServiceAccountRoleGrantRevoker",
    }),
    apiCredentialsIssued: many(tenantApiCredentials, {
      relationName: "tenantApiCredentialIssuer",
    }),
    apiCredentialsRevoked: many(tenantApiCredentials, {
      relationName: "tenantApiCredentialRevoker",
    }),
    apiCredentialCommands: many(tenantApiCredentialCommands),
    authProvidersCreated: many(tenantAuthProviders, {
      relationName: "tenantAuthProviderCreator",
    }),
    authProvidersUpdated: many(tenantAuthProviders, {
      relationName: "tenantAuthProviderUpdater",
    }),
    authProvidersArchived: many(tenantAuthProviders, {
      relationName: "tenantAuthProviderArchiver",
    }),
    ldapProviderConfigsUpdated: many(tenantLdapProviderConfigs),
    ldapProviderSecretsRotated: many(tenantLdapProviderSecrets),
    ldapProviderTestsStarted: many(tenantLdapProviderTestRuns, {
      relationName: "tenantLdapProviderTestStarter",
    }),
    ldapProviderTestsCompleted: many(tenantLdapProviderTestRuns, {
      relationName: "tenantLdapProviderTestCompleter",
    }),
    authProviderBindingsCreated: many(tenantAuthProviderBindings, {
      relationName: "tenantAuthProviderBindingCreator",
    }),
    authProviderBindingsUpdated: many(tenantAuthProviderBindings, {
      relationName: "tenantAuthProviderBindingUpdater",
    }),
    authProviderBindingsArchived: many(tenantAuthProviderBindings, {
      relationName: "tenantAuthProviderBindingArchiver",
    }),
    identityProviderAccessEpochsStarted: many(
      tenantIdentityProviderAccessEpochs,
      { relationName: "tenantIdentityProviderAccessEpochStarter" },
    ),
    identityProviderAccessEpochsEnded: many(
      tenantIdentityProviderAccessEpochs,
      { relationName: "tenantIdentityProviderAccessEpochEnder" },
    ),
    ldapMappingRulesCreated: many(tenantLdapMappingRules, {
      relationName: "tenantLdapMappingRuleCreator",
    }),
    ldapMappingRulesUpdated: many(tenantLdapMappingRules, {
      relationName: "tenantLdapMappingRuleUpdater",
    }),
    ldapMappingRulesArchived: many(tenantLdapMappingRules, {
      relationName: "tenantLdapMappingRuleArchiver",
    }),
    ldapMappingRuleEpochsActivated: many(tenantLdapMappingRuleEpochs, {
      relationName: "tenantLdapMappingRuleEpochActivator",
    }),
    ldapMappingRuleEpochsEnded: many(tenantLdapMappingRuleEpochs, {
      relationName: "tenantLdapMappingRuleEpochEnder",
    }),
    ldapProviderAccessGrants: many(tenantLdapProviderAccessGrants),
    manualProfileOverrides: many(tenantUserManualProfileOverrides, {
      relationName: "tenantUserManualProfileOverrideTarget",
    }),
    manualProfileOverridesUpdated: many(tenantUserManualProfileOverrides, {
      relationName: "tenantUserManualProfileOverrideUpdater",
    }),
    alertsCreated: many(alerts, { relationName: "alertCreatorMembership" }),
    alertActivities: many(alertActivities, {
      relationName: "alertActivityActorMembership",
    }),
    alertCommands: many(alertCommands, {
      relationName: "alertCommandActorMembership",
    }),
  }),
);

export const userLoginIdentifiersRelations = relations(
  userLoginIdentifiers,
  ({ one }) => ({
    user: one(users, {
      fields: [userLoginIdentifiers.userId],
      references: [users.id],
    }),
    localCredential: one(localBreakGlassCredentials),
  }),
);

export const tenantUserProfilesRelations = relations(
  tenantUserProfiles,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantUserProfiles.tenantId],
      references: [tenants.id],
    }),
    membership: one(tenantMemberships, {
      fields: [tenantUserProfiles.membershipId],
      references: [tenantMemberships.id],
    }),
    user: one(users, {
      fields: [tenantUserProfiles.userId],
      references: [users.id],
    }),
  }),
);

export const identityKeyringVersionsRelations = relations(
  identityKeyringVersions,
  ({ many }) => ({
    tenantLdapProviderSecrets: many(tenantLdapProviderSecrets),
    tenantLdapExternalIdentities: many(tenantLdapExternalIdentities),
    tenantLdapExternalIdentitySubjectAliases: many(
      tenantLdapExternalIdentitySubjectAliases,
    ),
    tenantLdapDirectoryOperationRuns: many(tenantLdapDirectoryOperationRuns),
    platformOidcClientSecrets: many(platformOidcClientSecrets),
    platformSamlSpKeys: many(platformSamlSpKeys),
  }),
);

export const platformAuthProvidersRelations = relations(
  platformAuthProviders,
  ({ many, one }) => ({
    creator: one(users, {
      relationName: "platformAuthProviderCreator",
      fields: [platformAuthProviders.createdByUserId],
      references: [users.id],
    }),
    updater: one(users, {
      relationName: "platformAuthProviderUpdater",
      fields: [platformAuthProviders.updatedByUserId],
      references: [users.id],
    }),
    archiver: one(users, {
      relationName: "platformAuthProviderArchiver",
      fields: [platformAuthProviders.archivedByUserId],
      references: [users.id],
    }),
    policy: one(platformFederatedProviderPolicies),
    oidcConfiguration: one(platformOidcProviderConfigurations),
    samlConfiguration: one(platformSamlProviderConfigurations),
    commands: many(platformIdentityProviderCommands),
    testRuns: many(platformIdentityProviderTestRuns),
  }),
);

export const platformIdentityProviderCommandsRelations = relations(
  platformIdentityProviderCommands,
  ({ one }) => ({
    actor: one(users, {
      fields: [platformIdentityProviderCommands.actorUserId],
      references: [users.id],
    }),
    provider: one(platformAuthProviders, {
      fields: [platformIdentityProviderCommands.resultProviderId],
      references: [platformAuthProviders.id],
    }),
  }),
);

export const platformIdentityProviderTestRunsRelations = relations(
  platformIdentityProviderTestRuns,
  ({ one }) => ({
    actor: one(users, {
      fields: [platformIdentityProviderTestRuns.actorUserId],
      references: [users.id],
    }),
    provider: one(platformAuthProviders, {
      fields: [platformIdentityProviderTestRuns.providerId],
      references: [platformAuthProviders.id],
    }),
  }),
);

export const platformFederatedProviderPoliciesRelations = relations(
  platformFederatedProviderPolicies,
  ({ many, one }) => ({
    provider: one(platformAuthProviders, {
      fields: [platformFederatedProviderPolicies.providerId],
      references: [platformAuthProviders.id],
    }),
    trustRules: many(platformFederatedTrustRules),
  }),
);

export const platformOidcProviderConfigurationsRelations = relations(
  platformOidcProviderConfigurations,
  ({ many, one }) => ({
    provider: one(platformAuthProviders, {
      fields: [platformOidcProviderConfigurations.providerId],
      references: [platformAuthProviders.id],
    }),
    claimRules: many(platformOidcClaimRules),
    discoverySnapshots: many(platformOidcDiscoverySnapshots),
    jwksSnapshots: many(platformOidcJwksSnapshots),
    clientSecrets: many(platformOidcClientSecrets),
  }),
);

export const platformOidcClaimRulesRelations = relations(
  platformOidcClaimRules,
  ({ one }) => ({
    configuration: one(platformOidcProviderConfigurations, {
      fields: [platformOidcClaimRules.providerId],
      references: [platformOidcProviderConfigurations.providerId],
    }),
  }),
);

export const platformOidcDiscoverySnapshotsRelations = relations(
  platformOidcDiscoverySnapshots,
  ({ one }) => ({
    configuration: one(platformOidcProviderConfigurations, {
      fields: [platformOidcDiscoverySnapshots.providerId],
      references: [platformOidcProviderConfigurations.providerId],
    }),
  }),
);

export const platformOidcJwksSnapshotsRelations = relations(
  platformOidcJwksSnapshots,
  ({ one }) => ({
    configuration: one(platformOidcProviderConfigurations, {
      fields: [platformOidcJwksSnapshots.providerId],
      references: [platformOidcProviderConfigurations.providerId],
    }),
  }),
);

export const platformOidcClientSecretsRelations = relations(
  platformOidcClientSecrets,
  ({ one }) => ({
    configuration: one(platformOidcProviderConfigurations, {
      fields: [platformOidcClientSecrets.providerId],
      references: [platformOidcProviderConfigurations.providerId],
    }),
    keyringVersion: one(identityKeyringVersions, {
      fields: [platformOidcClientSecrets.keyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
  }),
);

export const platformSamlProviderConfigurationsRelations = relations(
  platformSamlProviderConfigurations,
  ({ many, one }) => ({
    provider: one(platformAuthProviders, {
      fields: [platformSamlProviderConfigurations.providerId],
      references: [platformAuthProviders.id],
    }),
    attributeRules: many(platformSamlAttributeRules),
    metadataSnapshots: many(platformSamlMetadataSnapshots),
    spKeys: many(platformSamlSpKeys),
  }),
);

export const platformSamlAttributeRulesRelations = relations(
  platformSamlAttributeRules,
  ({ one }) => ({
    configuration: one(platformSamlProviderConfigurations, {
      fields: [platformSamlAttributeRules.providerId],
      references: [platformSamlProviderConfigurations.providerId],
    }),
  }),
);

export const platformSamlMetadataSnapshotsRelations = relations(
  platformSamlMetadataSnapshots,
  ({ one }) => ({
    configuration: one(platformSamlProviderConfigurations, {
      fields: [platformSamlMetadataSnapshots.providerId],
      references: [platformSamlProviderConfigurations.providerId],
    }),
  }),
);

export const platformSamlSpKeysRelations = relations(
  platformSamlSpKeys,
  ({ many, one }) => ({
    configuration: one(platformSamlProviderConfigurations, {
      fields: [platformSamlSpKeys.providerId],
      references: [platformSamlProviderConfigurations.providerId],
    }),
    keyringVersion: one(identityKeyringVersions, {
      fields: [platformSamlSpKeys.keyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
    certificates: many(platformSamlSpCertificates),
  }),
);

export const platformSamlSpCertificatesRelations = relations(
  platformSamlSpCertificates,
  ({ one }) => ({
    key: one(platformSamlSpKeys, {
      fields: [platformSamlSpCertificates.keyId],
      references: [platformSamlSpKeys.id],
    }),
  }),
);

export const platformFederatedTrustRulesRelations = relations(
  platformFederatedTrustRules,
  ({ one }) => ({
    policy: one(platformFederatedProviderPolicies, {
      fields: [platformFederatedTrustRules.providerId],
      references: [platformFederatedProviderPolicies.providerId],
    }),
  }),
);

export const tenantAuthProvidersRelations = relations(
  tenantAuthProviders,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantAuthProviders.tenantId],
      references: [tenants.id],
    }),
    creator: one(tenantMemberships, {
      relationName: "tenantAuthProviderCreator",
      fields: [tenantAuthProviders.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
    updater: one(tenantMemberships, {
      relationName: "tenantAuthProviderUpdater",
      fields: [tenantAuthProviders.updatedByMembershipId],
      references: [tenantMemberships.id],
    }),
    archiver: one(tenantMemberships, {
      relationName: "tenantAuthProviderArchiver",
      fields: [tenantAuthProviders.archivedByMembershipId],
      references: [tenantMemberships.id],
    }),
    ldapConfig: one(tenantLdapProviderConfigs),
    ldapUrls: many(tenantLdapProviderUrls),
    ldapSecret: one(tenantLdapProviderSecrets),
    ldapTestRuns: many(tenantLdapProviderTestRuns),
    ldapDirectoryOperationRuns: many(tenantLdapDirectoryOperationRuns),
    bindings: many(tenantAuthProviderBindings),
    externalIdentities: many(tenantLdapExternalIdentities),
  }),
);

export const tenantAuthProviderBindingsRelations = relations(
  tenantAuthProviderBindings,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantAuthProviderBindings.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    creator: one(tenantMemberships, {
      relationName: "tenantAuthProviderBindingCreator",
      fields: [tenantAuthProviderBindings.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
    updater: one(tenantMemberships, {
      relationName: "tenantAuthProviderBindingUpdater",
      fields: [tenantAuthProviderBindings.updatedByMembershipId],
      references: [tenantMemberships.id],
    }),
    archiver: one(tenantMemberships, {
      relationName: "tenantAuthProviderBindingArchiver",
      fields: [tenantAuthProviderBindings.archivedByMembershipId],
      references: [tenantMemberships.id],
    }),
    currentAccessEpoch: one(tenantIdentityProviderAccessEpochs, {
      relationName: "tenantAuthProviderBindingCurrentEpoch",
      fields: [tenantAuthProviderBindings.currentAccessEpochId],
      references: [tenantIdentityProviderAccessEpochs.id],
    }),
    accessEpochs: many(tenantIdentityProviderAccessEpochs, {
      relationName: "tenantAuthProviderBindingEpochs",
    }),
    accessGrants: many(tenantLdapProviderAccessGrants),
    ldapMappingRules: many(tenantLdapMappingRules),
    ldapMappingRuleEpochs: many(tenantLdapMappingRuleEpochs),
    ldapDirectoryOperationRuns: many(tenantLdapDirectoryOperationRuns),
    ldapDirectoryRunMappings: many(tenantLdapDirectoryRunMappings),
  }),
);

export const tenantLdapMappingRulesRelations = relations(
  tenantLdapMappingRules,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapMappingRules.tenantId],
      references: [tenants.id],
    }),
    binding: one(tenantAuthProviderBindings, {
      fields: [tenantLdapMappingRules.bindingId],
      references: [tenantAuthProviderBindings.id],
    }),
    securityGroup: one(tenantSecurityGroups, {
      fields: [tenantLdapMappingRules.tenantSecurityGroupId],
      references: [tenantSecurityGroups.id],
    }),
    operatorTeamAssignmentEpoch: one(operatorTeamAssignmentEpochs, {
      fields: [tenantLdapMappingRules.operatorTeamAssignmentEpochId],
      references: [operatorTeamAssignmentEpochs.id],
    }),
    creator: one(tenantMemberships, {
      relationName: "tenantLdapMappingRuleCreator",
      fields: [tenantLdapMappingRules.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
    updater: one(tenantMemberships, {
      relationName: "tenantLdapMappingRuleUpdater",
      fields: [tenantLdapMappingRules.updatedByMembershipId],
      references: [tenantMemberships.id],
    }),
    archiver: one(tenantMemberships, {
      relationName: "tenantLdapMappingRuleArchiver",
      fields: [tenantLdapMappingRules.archivedByMembershipId],
      references: [tenantMemberships.id],
    }),
    currentSourceEpoch: one(tenantLdapMappingRuleEpochs, {
      relationName: "tenantLdapMappingRuleCurrentEpoch",
      fields: [tenantLdapMappingRules.currentSourceEpochId],
      references: [tenantLdapMappingRuleEpochs.id],
    }),
    sourceEpochs: many(tenantLdapMappingRuleEpochs, {
      relationName: "tenantLdapMappingRuleEpochs",
    }),
    roleTargets: many(tenantLdapMappingRuleRoleTargets),
    ldapDirectoryRunMappings: many(tenantLdapDirectoryRunMappings),
  }),
);

export const tenantLdapDirectoryOperationRunsRelations = relations(
  tenantLdapDirectoryOperationRuns,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapDirectoryOperationRuns.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapDirectoryOperationRuns.tenantId,
        tenantLdapDirectoryOperationRuns.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    binding: one(tenantAuthProviderBindings, {
      fields: [
        tenantLdapDirectoryOperationRuns.tenantId,
        tenantLdapDirectoryOperationRuns.bindingId,
      ],
      references: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
      ],
    }),
    bindSecretKeyVersion: one(identityKeyringVersions, {
      fields: [tenantLdapDirectoryOperationRuns.bindSecretKeyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
    bindingAccessEpoch: one(tenantIdentityProviderAccessEpochs, {
      fields: [
        tenantLdapDirectoryOperationRuns.tenantId,
        tenantLdapDirectoryOperationRuns.bindingAccessEpochId,
      ],
      references: [
        tenantIdentityProviderAccessEpochs.tenantId,
        tenantIdentityProviderAccessEpochs.id,
      ],
    }),
    starter: one(tenantMemberships, {
      relationName: "tenantLdapDirectoryOperationStarter",
      fields: [tenantLdapDirectoryOperationRuns.startedByMembershipId],
      references: [tenantMemberships.id],
    }),
    completer: one(tenantMemberships, {
      relationName: "tenantLdapDirectoryOperationCompleter",
      fields: [tenantLdapDirectoryOperationRuns.completedByMembershipId],
      references: [tenantMemberships.id],
    }),
    mappings: many(tenantLdapDirectoryRunMappings),
  }),
);

export const tenantLdapDirectoryRunMappingsRelations = relations(
  tenantLdapDirectoryRunMappings,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapDirectoryRunMappings.tenantId],
      references: [tenants.id],
    }),
    operationRun: one(tenantLdapDirectoryOperationRuns, {
      fields: [
        tenantLdapDirectoryRunMappings.tenantId,
        tenantLdapDirectoryRunMappings.operationRunId,
      ],
      references: [
        tenantLdapDirectoryOperationRuns.tenantId,
        tenantLdapDirectoryOperationRuns.id,
      ],
    }),
    binding: one(tenantAuthProviderBindings, {
      fields: [
        tenantLdapDirectoryRunMappings.tenantId,
        tenantLdapDirectoryRunMappings.bindingId,
      ],
      references: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
      ],
    }),
    mappingRule: one(tenantLdapMappingRules, {
      fields: [
        tenantLdapDirectoryRunMappings.tenantId,
        tenantLdapDirectoryRunMappings.mappingRuleId,
      ],
      references: [tenantLdapMappingRules.tenantId, tenantLdapMappingRules.id],
    }),
    sourceEpoch: one(tenantLdapMappingRuleEpochs, {
      fields: [
        tenantLdapDirectoryRunMappings.tenantId,
        tenantLdapDirectoryRunMappings.sourceEpochId,
      ],
      references: [
        tenantLdapMappingRuleEpochs.tenantId,
        tenantLdapMappingRuleEpochs.id,
      ],
    }),
  }),
);

export const tenantLdapMappingRuleRoleTargetsRelations = relations(
  tenantLdapMappingRuleRoleTargets,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapMappingRuleRoleTargets.tenantId],
      references: [tenants.id],
    }),
    mappingRule: one(tenantLdapMappingRules, {
      fields: [tenantLdapMappingRuleRoleTargets.mappingRuleId],
      references: [tenantLdapMappingRules.id],
    }),
    role: one(tenantRoles, {
      fields: [tenantLdapMappingRuleRoleTargets.roleId],
      references: [tenantRoles.id],
    }),
  }),
);

export const tenantLdapMappingRuleEpochsRelations = relations(
  tenantLdapMappingRuleEpochs,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapMappingRuleEpochs.tenantId],
      references: [tenants.id],
    }),
    mappingRule: one(tenantLdapMappingRules, {
      relationName: "tenantLdapMappingRuleEpochs",
      fields: [tenantLdapMappingRuleEpochs.mappingRuleId],
      references: [tenantLdapMappingRules.id],
    }),
    currentForRules: many(tenantLdapMappingRules, {
      relationName: "tenantLdapMappingRuleCurrentEpoch",
    }),
    binding: one(tenantAuthProviderBindings, {
      fields: [tenantLdapMappingRuleEpochs.bindingId],
      references: [tenantAuthProviderBindings.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantLdapMappingRuleEpochs.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    securityGroup: one(tenantSecurityGroups, {
      fields: [tenantLdapMappingRuleEpochs.tenantSecurityGroupId],
      references: [tenantSecurityGroups.id],
    }),
    operatorTeamAssignmentEpoch: one(operatorTeamAssignmentEpochs, {
      fields: [tenantLdapMappingRuleEpochs.operatorTeamAssignmentEpochId],
      references: [operatorTeamAssignmentEpochs.id],
    }),
    activator: one(tenantMemberships, {
      relationName: "tenantLdapMappingRuleEpochActivator",
      fields: [tenantLdapMappingRuleEpochs.activatedByMembershipId],
      references: [tenantMemberships.id],
    }),
    ender: one(tenantMemberships, {
      relationName: "tenantLdapMappingRuleEpochEnder",
      fields: [tenantLdapMappingRuleEpochs.endedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantIdentityProviderAccessEpochsRelations = relations(
  tenantIdentityProviderAccessEpochs,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantIdentityProviderAccessEpochs.tenantId],
      references: [tenants.id],
    }),
    binding: one(tenantAuthProviderBindings, {
      relationName: "tenantAuthProviderBindingEpochs",
      fields: [tenantIdentityProviderAccessEpochs.bindingId],
      references: [tenantAuthProviderBindings.id],
    }),
    currentForBindings: many(tenantAuthProviderBindings, {
      relationName: "tenantAuthProviderBindingCurrentEpoch",
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantIdentityProviderAccessEpochs.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    starter: one(tenantMemberships, {
      relationName: "tenantIdentityProviderAccessEpochStarter",
      fields: [tenantIdentityProviderAccessEpochs.startedByMembershipId],
      references: [tenantMemberships.id],
    }),
    ender: one(tenantMemberships, {
      relationName: "tenantIdentityProviderAccessEpochEnder",
      fields: [tenantIdentityProviderAccessEpochs.endedByMembershipId],
      references: [tenantMemberships.id],
    }),
    accessGrants: many(tenantLdapProviderAccessGrants),
  }),
);

export const tenantLdapExternalIdentitiesRelations = relations(
  tenantLdapExternalIdentities,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapExternalIdentities.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    user: one(users, {
      fields: [tenantLdapExternalIdentities.userId],
      references: [users.id],
    }),
    keyringVersion: one(identityKeyringVersions, {
      fields: [tenantLdapExternalIdentities.keyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
    aliases: many(tenantLdapExternalIdentitySubjectAliases),
    accessGrants: many(tenantLdapProviderAccessGrants),
  }),
);

export const tenantLdapExternalIdentitySubjectAliasesRelations = relations(
  tenantLdapExternalIdentitySubjectAliases,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapExternalIdentitySubjectAliases.tenantId],
      references: [tenants.id],
    }),
    externalIdentity: one(tenantLdapExternalIdentities, {
      fields: [tenantLdapExternalIdentitySubjectAliases.externalIdentityId],
      references: [tenantLdapExternalIdentities.id],
    }),
    keyringVersion: one(identityKeyringVersions, {
      fields: [tenantLdapExternalIdentitySubjectAliases.digestKeyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
  }),
);

export const tenantLdapProviderAccessGrantsRelations = relations(
  tenantLdapProviderAccessGrants,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderAccessGrants.tenantId],
      references: [tenants.id],
    }),
    binding: one(tenantAuthProviderBindings, {
      fields: [tenantLdapProviderAccessGrants.bindingId],
      references: [tenantAuthProviderBindings.id],
    }),
    accessEpoch: one(tenantIdentityProviderAccessEpochs, {
      fields: [tenantLdapProviderAccessGrants.accessEpochId],
      references: [tenantIdentityProviderAccessEpochs.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantLdapProviderAccessGrants.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    externalIdentity: one(tenantLdapExternalIdentities, {
      fields: [tenantLdapProviderAccessGrants.externalIdentityId],
      references: [tenantLdapExternalIdentities.id],
    }),
    membership: one(tenantMemberships, {
      fields: [tenantLdapProviderAccessGrants.membershipId],
      references: [tenantMemberships.id],
    }),
    profileContributions: many(tenantLdapProviderProfileContributions),
  }),
);

export const tenantLdapProviderProfileContributionsRelations = relations(
  tenantLdapProviderProfileContributions,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderProfileContributions.tenantId],
      references: [tenants.id],
    }),
    accessGrant: one(tenantLdapProviderAccessGrants, {
      fields: [tenantLdapProviderProfileContributions.accessGrantId],
      references: [tenantLdapProviderAccessGrants.id],
    }),
  }),
);

export const tenantUserManualProfileOverridesRelations = relations(
  tenantUserManualProfileOverrides,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantUserManualProfileOverrides.tenantId],
      references: [tenants.id],
    }),
    membership: one(tenantMemberships, {
      relationName: "tenantUserManualProfileOverrideTarget",
      fields: [tenantUserManualProfileOverrides.membershipId],
      references: [tenantMemberships.id],
    }),
    user: one(users, {
      fields: [tenantUserManualProfileOverrides.userId],
      references: [users.id],
    }),
    updater: one(tenantMemberships, {
      relationName: "tenantUserManualProfileOverrideUpdater",
      fields: [tenantUserManualProfileOverrides.updatedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantLdapProviderConfigsRelations = relations(
  tenantLdapProviderConfigs,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderConfigs.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapProviderConfigs.tenantId,
        tenantLdapProviderConfigs.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    updater: one(tenantMemberships, {
      fields: [tenantLdapProviderConfigs.updatedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantLdapProviderUrlsRelations = relations(
  tenantLdapProviderUrls,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderUrls.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapProviderUrls.tenantId,
        tenantLdapProviderUrls.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
  }),
);

export const tenantLdapProviderSecretsRelations = relations(
  tenantLdapProviderSecrets,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderSecrets.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapProviderSecrets.tenantId,
        tenantLdapProviderSecrets.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    keyringVersion: one(identityKeyringVersions, {
      fields: [tenantLdapProviderSecrets.keyVersion],
      references: [identityKeyringVersions.keyVersion],
    }),
    rotator: one(tenantMemberships, {
      fields: [tenantLdapProviderSecrets.rotatedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantLdapProviderTestRunsRelations = relations(
  tenantLdapProviderTestRuns,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantLdapProviderTestRuns.tenantId],
      references: [tenants.id],
    }),
    provider: one(tenantAuthProviders, {
      fields: [
        tenantLdapProviderTestRuns.tenantId,
        tenantLdapProviderTestRuns.providerId,
      ],
      references: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    }),
    starter: one(tenantMemberships, {
      relationName: "tenantLdapProviderTestStarter",
      fields: [tenantLdapProviderTestRuns.startedByMembershipId],
      references: [tenantMemberships.id],
    }),
    completer: one(tenantMemberships, {
      relationName: "tenantLdapProviderTestCompleter",
      fields: [tenantLdapProviderTestRuns.completedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantPermissionsRelations = relations(
  tenantPermissions,
  ({ many }) => ({
    scopes: many(tenantPermissionScopes),
    rolePermissions: many(tenantRolePermissions),
    credentialPermissions: many(tenantApiCredentialPermissions),
  }),
);

export const tenantPermissionScopesRelations = relations(
  tenantPermissionScopes,
  ({ one }) => ({
    permission: one(tenantPermissions, {
      fields: [tenantPermissionScopes.permissionId],
      references: [tenantPermissions.id],
    }),
  }),
);

export const tenantAuthorizationSourcesRelations = relations(
  tenantAuthorizationSources,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantAuthorizationSources.tenantId],
      references: [tenants.id],
    }),
    roleGrants: many(tenantMembershipRoleGrants),
    securityGroupMemberships: many(tenantSecurityGroupMemberships),
    securityGroupRoleGrants: many(tenantSecurityGroupRoleGrants),
    operatorTeamRosterEntries: many(operatorTeamRosterEntries),
    serviceAccountRoleGrants: many(tenantServiceAccountRoleGrants),
    identityProviderAccessEpochs: many(tenantIdentityProviderAccessEpochs),
    ldapProviderAccessGrants: many(tenantLdapProviderAccessGrants),
    ldapMappingRuleEpochs: many(tenantLdapMappingRuleEpochs),
  }),
);

export const tenantAuthorizationStatesRelations = relations(
  tenantAuthorizationStates,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantAuthorizationStates.tenantId],
      references: [tenants.id],
    }),
  }),
);

export const tenantAuthorizationCommandsRelations = relations(
  tenantAuthorizationCommands,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantAuthorizationCommands.tenantId],
      references: [tenants.id],
    }),
    actor: one(tenantMemberships, {
      fields: [tenantAuthorizationCommands.actorMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantRolesRelations = relations(tenantRoles, ({ many, one }) => ({
  tenant: one(tenants, {
    fields: [tenantRoles.tenantId],
    references: [tenants.id],
  }),
  creator: one(tenantMemberships, {
    fields: [tenantRoles.createdByMembershipId],
    references: [tenantMemberships.id],
  }),
  permissions: many(tenantRolePermissions),
  delegationCeiling: many(tenantRoleDelegationCeilings),
  membershipGrants: many(tenantMembershipRoleGrants),
  securityGroupGrants: many(tenantSecurityGroupRoleGrants),
  serviceAccountGrants: many(tenantServiceAccountRoleGrants),
  ldapMappingRoleTargets: many(tenantLdapMappingRuleRoleTargets),
}));

export const tenantRolePermissionsRelations = relations(
  tenantRolePermissions,
  ({ many, one }) => ({
    role: one(tenantRoles, {
      fields: [tenantRolePermissions.roleId],
      references: [tenantRoles.id],
    }),
    permission: one(tenantPermissions, {
      fields: [tenantRolePermissions.permissionId],
      references: [tenantPermissions.id],
    }),
    creator: one(tenantMemberships, {
      fields: [tenantRolePermissions.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
    delegationCeiling: many(tenantRoleDelegationCeilings),
  }),
);

export const tenantRoleDelegationCeilingsRelations = relations(
  tenantRoleDelegationCeilings,
  ({ one }) => ({
    role: one(tenantRoles, {
      fields: [tenantRoleDelegationCeilings.roleId],
      references: [tenantRoles.id],
    }),
    permission: one(tenantPermissions, {
      fields: [tenantRoleDelegationCeilings.permissionId],
      references: [tenantPermissions.id],
    }),
    creator: one(tenantMemberships, {
      fields: [tenantRoleDelegationCeilings.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantMembershipRoleGrantsRelations = relations(
  tenantMembershipRoleGrants,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantMembershipRoleGrants.tenantId],
      references: [tenants.id],
    }),
    membership: one(tenantMemberships, {
      relationName: "tenantMembershipRoleGrantTarget",
      fields: [tenantMembershipRoleGrants.membershipId],
      references: [tenantMemberships.id],
    }),
    role: one(tenantRoles, {
      fields: [tenantMembershipRoleGrants.roleId],
      references: [tenantRoles.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantMembershipRoleGrants.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    grantor: one(tenantMemberships, {
      relationName: "tenantMembershipRoleGrantGrantor",
      fields: [tenantMembershipRoleGrants.grantedByMembershipId],
      references: [tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "tenantMembershipRoleGrantRevoker",
      fields: [tenantMembershipRoleGrants.revokedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantSecurityGroupsRelations = relations(
  tenantSecurityGroups,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantSecurityGroups.tenantId],
      references: [tenants.id],
    }),
    creator: one(tenantMemberships, {
      fields: [tenantSecurityGroups.createdByMembershipId],
      references: [tenantMemberships.id],
    }),
    memberships: many(tenantSecurityGroupMemberships),
    roleGrants: many(tenantSecurityGroupRoleGrants),
    ldapMappingRules: many(tenantLdapMappingRules),
    ldapMappingRuleEpochs: many(tenantLdapMappingRuleEpochs),
  }),
);

export const tenantSecurityGroupMembershipsRelations = relations(
  tenantSecurityGroupMemberships,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantSecurityGroupMemberships.tenantId],
      references: [tenants.id],
    }),
    group: one(tenantSecurityGroups, {
      fields: [tenantSecurityGroupMemberships.groupId],
      references: [tenantSecurityGroups.id],
    }),
    membership: one(tenantMemberships, {
      relationName: "tenantSecurityGroupMembershipTarget",
      fields: [tenantSecurityGroupMemberships.membershipId],
      references: [tenantMemberships.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantSecurityGroupMemberships.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    grantor: one(tenantMemberships, {
      relationName: "tenantSecurityGroupMembershipGrantor",
      fields: [tenantSecurityGroupMemberships.grantedByMembershipId],
      references: [tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "tenantSecurityGroupMembershipRevoker",
      fields: [tenantSecurityGroupMemberships.revokedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const tenantSecurityGroupRoleGrantsRelations = relations(
  tenantSecurityGroupRoleGrants,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantSecurityGroupRoleGrants.tenantId],
      references: [tenants.id],
    }),
    group: one(tenantSecurityGroups, {
      fields: [tenantSecurityGroupRoleGrants.groupId],
      references: [tenantSecurityGroups.id],
    }),
    role: one(tenantRoles, {
      fields: [tenantSecurityGroupRoleGrants.roleId],
      references: [tenantRoles.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [tenantSecurityGroupRoleGrants.sourceId],
      references: [tenantAuthorizationSources.id],
    }),
    grantor: one(tenantMemberships, {
      relationName: "tenantSecurityGroupRoleGrantGrantor",
      fields: [tenantSecurityGroupRoleGrants.grantedByMembershipId],
      references: [tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "tenantSecurityGroupRoleGrantRevoker",
      fields: [tenantSecurityGroupRoleGrants.revokedByMembershipId],
      references: [tenantMemberships.id],
    }),
  }),
);

export const operatorTeamsRelations = relations(
  operatorTeams,
  ({ many, one }) => ({
    creator: one(users, {
      relationName: "operatorTeamCreator",
      fields: [operatorTeams.createdByUserId],
      references: [users.id],
    }),
    archiver: one(users, {
      relationName: "operatorTeamArchiver",
      fields: [operatorTeams.archivedByUserId],
      references: [users.id],
    }),
    assignmentEpochs: many(operatorTeamAssignmentEpochs),
  }),
);

export const platformCommandsRelations = relations(
  platformCommands,
  ({ one }) => ({
    actor: one(users, {
      fields: [platformCommands.actorUserId],
      references: [users.id],
    }),
  }),
);

export const operatorTeamAssignmentEpochsRelations = relations(
  operatorTeamAssignmentEpochs,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [operatorTeamAssignmentEpochs.tenantId],
      references: [tenants.id],
    }),
    operatorTeam: one(operatorTeams, {
      fields: [operatorTeamAssignmentEpochs.operatorTeamId],
      references: [operatorTeams.id],
    }),
    assigner: one(tenantMemberships, {
      relationName: "operatorTeamAssignmentAssigner",
      fields: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.assignedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    ender: one(tenantMemberships, {
      relationName: "operatorTeamAssignmentEnder",
      fields: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.endedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    rosterEntries: many(operatorTeamRosterEntries),
    ldapMappingRules: many(tenantLdapMappingRules),
    ldapMappingRuleEpochs: many(tenantLdapMappingRuleEpochs),
  }),
);

export const operatorTeamRosterEntriesRelations = relations(
  operatorTeamRosterEntries,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [operatorTeamRosterEntries.tenantId],
      references: [tenants.id],
    }),
    assignmentEpoch: one(operatorTeamAssignmentEpochs, {
      fields: [
        operatorTeamRosterEntries.tenantId,
        operatorTeamRosterEntries.assignmentEpochId,
      ],
      references: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.id,
      ],
    }),
    membership: one(tenantMemberships, {
      relationName: "operatorTeamRosterTarget",
      fields: [
        operatorTeamRosterEntries.tenantId,
        operatorTeamRosterEntries.membershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [
        operatorTeamRosterEntries.tenantId,
        operatorTeamRosterEntries.sourceId,
      ],
      references: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    }),
    grantor: one(tenantMemberships, {
      relationName: "operatorTeamRosterGrantor",
      fields: [
        operatorTeamRosterEntries.tenantId,
        operatorTeamRosterEntries.grantedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "operatorTeamRosterRevoker",
      fields: [
        operatorTeamRosterEntries.tenantId,
        operatorTeamRosterEntries.revokedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
  }),
);

export const tenantServiceAccountsRelations = relations(
  tenantServiceAccounts,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantServiceAccounts.tenantId],
      references: [tenants.id],
    }),
    creator: one(tenantMemberships, {
      relationName: "tenantServiceAccountCreator",
      fields: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.createdByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    archiver: one(tenantMemberships, {
      relationName: "tenantServiceAccountArchiver",
      fields: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.archivedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    roleGrants: many(tenantServiceAccountRoleGrants),
    credentials: many(tenantApiCredentials),
    credentialCommands: many(tenantApiCredentialCommands),
    alertsCreated: many(alerts, {
      relationName: "alertCreatorServiceAccount",
    }),
    alertActivities: many(alertActivities, {
      relationName: "alertActivityActorServiceAccount",
    }),
    alertCommands: many(alertCommands, {
      relationName: "alertCommandActorServiceAccount",
    }),
    auditEvents: many(auditEvents, {
      relationName: "auditServiceAccountActor",
    }),
  }),
);

export const tenantServiceAccountRoleGrantsRelations = relations(
  tenantServiceAccountRoleGrants,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantServiceAccountRoleGrants.tenantId],
      references: [tenants.id],
    }),
    serviceAccount: one(tenantServiceAccounts, {
      fields: [
        tenantServiceAccountRoleGrants.tenantId,
        tenantServiceAccountRoleGrants.serviceAccountId,
      ],
      references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
    }),
    role: one(tenantRoles, {
      fields: [
        tenantServiceAccountRoleGrants.tenantId,
        tenantServiceAccountRoleGrants.roleId,
        tenantServiceAccountRoleGrants.rolePrincipalKind,
      ],
      references: [
        tenantRoles.tenantId,
        tenantRoles.id,
        tenantRoles.principalKind,
      ],
    }),
    source: one(tenantAuthorizationSources, {
      fields: [
        tenantServiceAccountRoleGrants.tenantId,
        tenantServiceAccountRoleGrants.sourceId,
      ],
      references: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    }),
    grantor: one(tenantMemberships, {
      relationName: "tenantServiceAccountRoleGrantGrantor",
      fields: [
        tenantServiceAccountRoleGrants.tenantId,
        tenantServiceAccountRoleGrants.grantedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "tenantServiceAccountRoleGrantRevoker",
      fields: [
        tenantServiceAccountRoleGrants.tenantId,
        tenantServiceAccountRoleGrants.revokedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
  }),
);

export const tenantApiCredentialsRelations = relations(
  tenantApiCredentials,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantApiCredentials.tenantId],
      references: [tenants.id],
    }),
    serviceAccount: one(tenantServiceAccounts, {
      fields: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.serviceAccountId,
      ],
      references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
    }),
    issuer: one(tenantMemberships, {
      relationName: "tenantApiCredentialIssuer",
      fields: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.issuedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    revoker: one(tenantMemberships, {
      relationName: "tenantApiCredentialRevoker",
      fields: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.revokedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    rotatedFrom: one(tenantApiCredentials, {
      relationName: "tenantApiCredentialRotation",
      fields: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.serviceAccountId,
        tenantApiCredentials.rotatedFromCredentialId,
      ],
      references: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.serviceAccountId,
        tenantApiCredentials.id,
      ],
    }),
    replacements: many(tenantApiCredentials, {
      relationName: "tenantApiCredentialRotation",
    }),
    permissions: many(tenantApiCredentialPermissions),
    networks: many(tenantApiCredentialNetworks),
    commandResults: many(tenantApiCredentialCommands),
  }),
);

export const tenantApiCredentialPermissionsRelations = relations(
  tenantApiCredentialPermissions,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantApiCredentialPermissions.tenantId],
      references: [tenants.id],
    }),
    credential: one(tenantApiCredentials, {
      fields: [
        tenantApiCredentialPermissions.tenantId,
        tenantApiCredentialPermissions.credentialId,
      ],
      references: [tenantApiCredentials.tenantId, tenantApiCredentials.id],
    }),
    permission: one(tenantPermissions, {
      fields: [
        tenantApiCredentialPermissions.permissionId,
        tenantApiCredentialPermissions.permissionServiceAccountAllowed,
      ],
      references: [
        tenantPermissions.id,
        tenantPermissions.serviceAccountAllowed,
      ],
    }),
    permissionScope: one(tenantPermissionScopes, {
      fields: [
        tenantApiCredentialPermissions.permissionId,
        tenantApiCredentialPermissions.scope,
      ],
      references: [
        tenantPermissionScopes.permissionId,
        tenantPermissionScopes.scope,
      ],
    }),
  }),
);

export const tenantApiCredentialNetworksRelations = relations(
  tenantApiCredentialNetworks,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantApiCredentialNetworks.tenantId],
      references: [tenants.id],
    }),
    credential: one(tenantApiCredentials, {
      fields: [
        tenantApiCredentialNetworks.tenantId,
        tenantApiCredentialNetworks.credentialId,
      ],
      references: [tenantApiCredentials.tenantId, tenantApiCredentials.id],
    }),
  }),
);

export const tenantApiCredentialCommandsRelations = relations(
  tenantApiCredentialCommands,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantApiCredentialCommands.tenantId],
      references: [tenants.id],
    }),
    serviceAccount: one(tenantServiceAccounts, {
      fields: [
        tenantApiCredentialCommands.tenantId,
        tenantApiCredentialCommands.serviceAccountId,
      ],
      references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
    }),
    actor: one(tenantMemberships, {
      fields: [
        tenantApiCredentialCommands.tenantId,
        tenantApiCredentialCommands.actorMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    result: one(tenantApiCredentials, {
      fields: [
        tenantApiCredentialCommands.tenantId,
        tenantApiCredentialCommands.serviceAccountId,
        tenantApiCredentialCommands.resultCredentialId,
      ],
      references: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.serviceAccountId,
        tenantApiCredentials.id,
      ],
    }),
  }),
);

export const alertsRelations = relations(alerts, ({ many, one }) => ({
  tenant: one(tenants, {
    fields: [alerts.tenantId],
    references: [tenants.id],
  }),
  creator: one(users, {
    fields: [alerts.createdBy],
    references: [users.id],
  }),
  creatorMembership: one(tenantMemberships, {
    relationName: "alertCreatorMembership",
    fields: [alerts.tenantId, alerts.createdByMembershipId],
    references: [tenantMemberships.tenantId, tenantMemberships.id],
  }),
  creatorServiceAccount: one(tenantServiceAccounts, {
    relationName: "alertCreatorServiceAccount",
    fields: [alerts.tenantId, alerts.createdByServiceAccountId],
    references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
  }),
  activities: many(alertActivities),
  commands: many(alertCommands),
}));

export const alertActivitiesRelations = relations(
  alertActivities,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [alertActivities.tenantId],
      references: [tenants.id],
    }),
    alert: one(alerts, {
      fields: [alertActivities.tenantId, alertActivities.alertId],
      references: [alerts.tenantId, alerts.id],
    }),
    actorMembership: one(tenantMemberships, {
      relationName: "alertActivityActorMembership",
      fields: [alertActivities.tenantId, alertActivities.actorMembershipId],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
    actorServiceAccount: one(tenantServiceAccounts, {
      relationName: "alertActivityActorServiceAccount",
      fields: [alertActivities.tenantId, alertActivities.actorServiceAccountId],
      references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
    }),
  }),
);

export const alertCommandsRelations = relations(alertCommands, ({ one }) => ({
  tenant: one(tenants, {
    fields: [alertCommands.tenantId],
    references: [tenants.id],
  }),
  resultAlert: one(alerts, {
    fields: [alertCommands.tenantId, alertCommands.resultAlertId],
    references: [alerts.tenantId, alerts.id],
  }),
  actorMembership: one(tenantMemberships, {
    relationName: "alertCommandActorMembership",
    fields: [alertCommands.tenantId, alertCommands.actorMembershipId],
    references: [tenantMemberships.tenantId, tenantMemberships.id],
  }),
  actorServiceAccount: one(tenantServiceAccounts, {
    relationName: "alertCommandActorServiceAccount",
    fields: [alertCommands.tenantId, alertCommands.actorServiceAccountId],
    references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
  }),
}));

export const auditEventsRelations = relations(auditEvents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [auditEvents.tenantId],
    references: [tenants.id],
  }),
  actor: one(users, {
    relationName: "auditActor",
    fields: [auditEvents.actorUserId],
    references: [users.id],
  }),
  impersonator: one(users, {
    relationName: "auditImpersonator",
    fields: [auditEvents.impersonatedByUserId],
    references: [users.id],
  }),
  serviceAccountActor: one(tenantServiceAccounts, {
    relationName: "auditServiceAccountActor",
    fields: [auditEvents.tenantId, auditEvents.actorServiceAccountId],
    references: [tenantServiceAccounts.tenantId, tenantServiceAccounts.id],
  }),
}));

export const auditChainHeadsRelations = relations(
  auditChainHeads,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [auditChainHeads.tenantId],
      references: [tenants.id],
    }),
  }),
);

export const outboxEventsRelations = relations(outboxEvents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [outboxEvents.tenantId],
    references: [tenants.id],
  }),
}));

export const localBreakGlassCredentialsRelations = relations(
  localBreakGlassCredentials,
  ({ one }) => ({
    user: one(users, {
      fields: [localBreakGlassCredentials.userId],
      references: [users.id],
    }),
    loginIdentifier: one(userLoginIdentifiers, {
      fields: [localBreakGlassCredentials.loginIdentifierId],
      references: [userLoginIdentifiers.id],
    }),
  }),
);

export const totpCredentialsRelations = relations(
  totpCredentials,
  ({ many, one }) => ({
    user: one(users, {
      fields: [totpCredentials.userId],
      references: [users.id],
    }),
    recoveryCodes: many(recoveryCodes),
  }),
);

export const recoveryCodesRelations = relations(recoveryCodes, ({ one }) => ({
  user: one(users, {
    fields: [recoveryCodes.userId],
    references: [users.id],
  }),
  totpCredential: one(totpCredentials, {
    fields: [recoveryCodes.totpCredentialId],
    references: [totpCredentials.id],
  }),
}));

export const authChallengesRelations = relations(authChallenges, ({ one }) => ({
  user: one(users, {
    fields: [authChallenges.userId],
    references: [users.id],
  }),
}));

export const authSessionsRelations = relations(authSessions, ({ one }) => ({
  user: one(users, {
    fields: [authSessions.userId],
    references: [users.id],
  }),
  activeTenant: one(tenants, {
    fields: [authSessions.activeTenantId],
    references: [tenants.id],
  }),
  rotatedFrom: one(authSessions, {
    fields: [authSessions.rotatedFromSessionId],
    references: [authSessions.id],
  }),
}));

export const platformRolesRelations = relations(platformRoles, ({ many }) => ({
  permissions: many(platformRolePermissions),
  userGrants: many(userPlatformRoles),
}));

export const platformPermissionsRelations = relations(
  platformPermissions,
  ({ many }) => ({ roleGrants: many(platformRolePermissions) }),
);

export const platformRolePermissionsRelations = relations(
  platformRolePermissions,
  ({ one }) => ({
    role: one(platformRoles, {
      fields: [platformRolePermissions.roleId],
      references: [platformRoles.id],
    }),
    permission: one(platformPermissions, {
      fields: [platformRolePermissions.permissionId],
      references: [platformPermissions.id],
    }),
  }),
);

export const userPlatformRolesRelations = relations(
  userPlatformRoles,
  ({ one }) => ({
    user: one(users, {
      relationName: "platformRoleUser",
      fields: [userPlatformRoles.userId],
      references: [users.id],
    }),
    role: one(platformRoles, {
      fields: [userPlatformRoles.roleId],
      references: [platformRoles.id],
    }),
    grantor: one(users, {
      relationName: "platformRoleGrantor",
      fields: [userPlatformRoles.grantedByUserId],
      references: [users.id],
    }),
    revoker: one(users, {
      relationName: "platformRoleRevoker",
      fields: [userPlatformRoles.revokedByUserId],
      references: [users.id],
    }),
  }),
);

export const platformAuditEventsRelations = relations(
  platformAuditEvents,
  ({ one }) => ({
    actor: one(users, {
      fields: [platformAuditEvents.actorUserId],
      references: [users.id],
    }),
  }),
);

export const platformBootstrapEnrollmentsRelations = relations(
  platformBootstrapEnrollments,
  ({ one }) => ({
    consumedBy: one(users, {
      fields: [platformBootstrapEnrollments.consumedByUserId],
      references: [users.id],
    }),
  }),
);

export const platformBootstrapStateRelations = relations(
  platformBootstrapState,
  ({ one }) => ({
    completedBy: one(users, {
      fields: [platformBootstrapState.completedByUserId],
      references: [users.id],
    }),
    enrollment: one(platformBootstrapEnrollments, {
      fields: [platformBootstrapState.enrollmentId],
      references: [platformBootstrapEnrollments.id],
    }),
  }),
);
