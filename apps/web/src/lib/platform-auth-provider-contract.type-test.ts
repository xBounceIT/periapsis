import type {
  PlatformAuthProviderCreateInput,
  PlatformAuthProviderActivationInput,
  PlatformAuthProviderArchiveInput,
  PlatformAuthProviderDeactivationInput,
  PlatformAuthProviderTenantBindingActivationInput,
  PlatformAuthProviderTenantBindingArchiveInput,
  PlatformAuthProviderTenantBindingCreateInput,
  PlatformAuthProviderTenantBindingDeactivationInput,
  PlatformAuthProviderTenantBindingUpdateInput,
  PlatformAuthProviderTenantBindingView,
  PlatformAuthProviderUpdateInput,
  PlatformAuthProviderView,
} from "./phase-two-types";

type Assert<T extends true> = T;
type ExactKeys<T, Keys extends PropertyKey> = [keyof T] extends [Keys]
  ? [Keys] extends [keyof T]
    ? true
    : false
  : false;
type AllKeysRequired<T> = T extends Required<T> ? true : false;
type RequiredKey<T, K extends keyof T> =
  object extends Pick<T, K> ? false : true;

type SamlCreateConfiguration = Extract<
  PlatformAuthProviderCreateInput,
  { kind: "saml" }
>["configuration"];
type PersistentCreateConfiguration = Extract<
  SamlCreateConfiguration,
  { subjectSource: "persistent_nameid" }
>;
type OidcCreateConfiguration = Extract<
  PlatformAuthProviderCreateInput,
  { kind: "oidc" }
>["configuration"];
type ImmutableCreateConfiguration = Extract<
  SamlCreateConfiguration,
  { subjectSource: "immutable_attribute" }
>;
type OidcProjectionConfiguration = Extract<
  PlatformAuthProviderView,
  { kind: "oidc" }
>["configuration"];

export type PersistentCreateOmitsSubjectAttributeName = Assert<
  "subjectAttributeName" extends keyof PersistentCreateConfiguration
    ? false
    : true
>;
export type PersistentCreateOmitsSubjectAttributeNameFormat = Assert<
  "subjectAttributeNameFormat" extends keyof PersistentCreateConfiguration
    ? false
    : true
>;
export type ImmutableCreateRequiresSubjectAttributeName = Assert<
  RequiredKey<ImmutableCreateConfiguration, "subjectAttributeName">
>;
export type ImmutableCreateRequiresSubjectAttributeNameFormat = Assert<
  RequiredKey<ImmutableCreateConfiguration, "subjectAttributeNameFormat">
>;
export type ProviderCreateKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderCreateInput,
    "configuration" | "description" | "displayName" | "key" | "kind"
  >
>;
export type ProviderCreateConfigurationIsRequired = Assert<
  RequiredKey<PlatformAuthProviderCreateInput, "configuration">
>;
export type ProviderCreateDisplayNameIsRequired = Assert<
  RequiredKey<PlatformAuthProviderCreateInput, "displayName">
>;
export type ProviderCreateKeyIsRequired = Assert<
  RequiredKey<PlatformAuthProviderCreateInput, "key">
>;
export type ProviderCreateKindIsRequired = Assert<
  RequiredKey<PlatformAuthProviderCreateInput, "kind">
>;
export type ProviderCreateDescriptionRemainsOptional = Assert<
  RequiredKey<PlatformAuthProviderCreateInput, "description"> extends false
    ? true
    : false
>;
export type OidcCreateConfigurationKeysAreExact = Assert<
  ExactKeys<
    OidcCreateConfiguration,
    | "allowRefreshToken"
    | "clientId"
    | "extraScopes"
    | "issuer"
    | "postLogoutRedirectUri"
    | "redirectUri"
    | "tenantRedirectUri"
    | "useUserInfo"
  >
>;
export type PersistentSamlCreateConfigurationKeysAreExact = Assert<
  ExactKeys<
    PersistentCreateConfiguration,
    | "acsUrl"
    | "clockSkewNanoseconds"
    | "encryptionPolicy"
    | "expectedEntityId"
    | "maxAuthenticationAgeNanoseconds"
    | "redirectSignatureAlgorithm"
    | "requestedAuthnContexts"
    | "signaturePolicy"
    | "spEntityId"
    | "subjectSource"
  >
>;
export type ImmutableSamlCreateConfigurationKeysAreExact = Assert<
  ExactKeys<
    ImmutableCreateConfiguration,
    | keyof PersistentCreateConfiguration
    | "subjectAttributeName"
    | "subjectAttributeNameFormat"
  >
>;
export type ProviderUpdateKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderUpdateInput,
    "description" | "displayName" | "expectedVersion" | "key"
  >
>;
export type ProviderUpdateKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderUpdateInput>
>;
export type ProviderArchiveKeysAreExact = Assert<
  ExactKeys<PlatformAuthProviderArchiveInput, "expectedVersion">
>;
export type ProviderArchiveKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderArchiveInput>
>;

type SamlProjectionConfiguration = Extract<
  PlatformAuthProviderView,
  { kind: "saml" }
>["configuration"];
type PersistentProjectionConfiguration = Extract<
  SamlProjectionConfiguration,
  { subjectSource: "persistent_nameid" }
>;
type ImmutableProjectionConfiguration = Extract<
  SamlProjectionConfiguration,
  { subjectSource: "immutable_attribute" }
>;

export type PersistentProjectionOmitsSubjectAttributes = Assert<
  "subjectAttributeName" extends keyof PersistentProjectionConfiguration
    ? false
    : true
>;
export type ImmutableProjectionRequiresSubjectAttributeName = Assert<
  RequiredKey<ImmutableProjectionConfiguration, "subjectAttributeName">
>;
export type ImmutableProjectionRequiresSubjectAttributeNameFormat = Assert<
  RequiredKey<ImmutableProjectionConfiguration, "subjectAttributeNameFormat">
>;
export type ProviderProjectionKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderView,
    | "accountMode"
    | "activationAvailable"
    | "archivedAt"
    | "assurancePolicyRevision"
    | "configuration"
    | "configurationRevision"
    | "configured"
    | "createdAt"
    | "description"
    | "displayName"
    | "enabled"
    | "id"
    | "key"
    | "kind"
    | "planRevision"
    | "platformLoginActivationAvailable"
    | "platformLoginEnabled"
    | "secretPresent"
    | "securityRevision"
    | "updatedAt"
    | "version"
  >
>;
export type ProviderProjectionKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderView>
>;
export type OidcProjectionConfigurationKeysAreExact = Assert<
  ExactKeys<
    OidcProjectionConfiguration,
    | "allowRefreshToken"
    | "clientId"
    | "clientSecretPresent"
    | "clientSecretRevision"
    | "discoveryRevision"
    | "extraScopes"
    | "issuer"
    | "jwksRevision"
    | "postLogoutRedirectUri"
    | "redirectUri"
    | "tenantRedirectUri"
    | "useUserInfo"
  >
>;
export type PersistentSamlProjectionConfigurationKeysAreExact = Assert<
  ExactKeys<
    PersistentProjectionConfiguration,
    | "acsUrl"
    | "clockSkewNanoseconds"
    | "encryptionPolicy"
    | "expectedEntityId"
    | "maxAuthenticationAgeNanoseconds"
    | "metadataRevision"
    | "redirectSignatureAlgorithm"
    | "requestedAuthnContexts"
    | "signaturePolicy"
    | "spEntityId"
    | "spKeyPresent"
    | "spKeyRevision"
    | "subjectSource"
  >
>;
export type ImmutableSamlProjectionConfigurationKeysAreExact = Assert<
  ExactKeys<
    ImmutableProjectionConfiguration,
    | keyof PersistentProjectionConfiguration
    | "subjectAttributeName"
    | "subjectAttributeNameFormat"
  >
>;

export type BindingCreateOmitsActivation = Assert<
  "enabled" extends keyof PlatformAuthProviderTenantBindingCreateInput
    ? false
    : true
>;
export type BindingCreateRequiresTenant = Assert<
  RequiredKey<PlatformAuthProviderTenantBindingCreateInput, "tenantId">
>;
export type BindingUpdateOmitsTenantAndActivation = Assert<
  "tenantId" extends keyof PlatformAuthProviderTenantBindingUpdateInput
    ? false
    : "enabled" extends keyof PlatformAuthProviderTenantBindingUpdateInput
      ? false
      : true
>;
export type BindingUpdateRequiresTenantVersion = Assert<
  RequiredKey<
    PlatformAuthProviderTenantBindingUpdateInput,
    "expectedTenantVersion"
  >
>;
export type BindingArchiveRequiresTenantVersion = Assert<
  RequiredKey<
    PlatformAuthProviderTenantBindingArchiveInput,
    "expectedTenantVersion"
  >
>;
export type BindingProjectionIncludesTenantVersion = Assert<
  RequiredKey<PlatformAuthProviderTenantBindingView["tenant"], "version">
>;
export type BindingProjectionOriginIsPlatform = Assert<
  PlatformAuthProviderTenantBindingView["origin"] extends "platform"
    ? true
    : false
>;
export type BindingProjectionEnabledIsBoolean = Assert<
  PlatformAuthProviderTenantBindingView["enabled"] extends boolean
    ? true
    : false
>;
export type BindingProjectionActivationIsBoolean = Assert<
  PlatformAuthProviderTenantBindingView["activationAvailable"] extends boolean
    ? true
    : false
>;
export type BindingProjectionAccessEpochIsNullable = Assert<
  PlatformAuthProviderTenantBindingView["currentAccessEpochId"] extends
    string | null
    ? true
    : false
>;
export type BindingCreateKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingCreateInput,
    "loginKey" | "profilePriority" | "tenantId"
  >
>;
export type BindingCreateKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingCreateInput>
>;
export type BindingUpdateKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingUpdateInput,
    "expectedTenantVersion" | "expectedVersion" | "loginKey" | "profilePriority"
  >
>;
export type BindingUpdateKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingUpdateInput>
>;
export type BindingArchiveKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingArchiveInput,
    "expectedTenantVersion" | "expectedVersion"
  >
>;
export type BindingArchiveKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingArchiveInput>
>;
export type ProviderActivationKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderActivationInput,
    "accountMode" | "expectedVersion"
  >
>;
export type ProviderActivationKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderActivationInput>
>;
export type ProviderDeactivationKeysAreExact = Assert<
  ExactKeys<PlatformAuthProviderDeactivationInput, "expectedVersion">
>;
export type ProviderDeactivationKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderDeactivationInput>
>;
export type BindingActivationKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingActivationInput,
    "expectedTenantVersion" | "expectedVersion" | "jitMode" | "noMatchPolicy"
  >
>;
export type BindingActivationKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingActivationInput>
>;
export type BindingDeactivationKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingDeactivationInput,
    "expectedTenantVersion" | "expectedVersion"
  >
>;
export type BindingDeactivationKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingDeactivationInput>
>;
export type BindingProjectionKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingView,
    | "activationAvailable"
    | "archivedAt"
    | "authRevision"
    | "createdAt"
    | "currentAccessEpochId"
    | "enabled"
    | "id"
    | "jitMode"
    | "loginKey"
    | "mappingRevision"
    | "noMatchPolicy"
    | "origin"
    | "profilePriority"
    | "providerId"
    | "tenant"
    | "updatedAt"
    | "version"
  >
>;
export type BindingProjectionKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingView>
>;
export type BindingTenantProjectionKeysAreExact = Assert<
  ExactKeys<
    PlatformAuthProviderTenantBindingView["tenant"],
    "id" | "name" | "slug" | "status" | "version"
  >
>;
export type BindingTenantProjectionKeysAreRequired = Assert<
  AllKeysRequired<PlatformAuthProviderTenantBindingView["tenant"]>
>;
