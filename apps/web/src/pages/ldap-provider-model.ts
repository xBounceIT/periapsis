import type {
  TenantLdapAuthProviderConfigurationView,
  TenantLdapAuthProviderCreateInput,
  TenantLdapAuthProviderDiagnosticView,
  TenantLdapAuthProviderEndpointView,
  TenantLdapAuthProviderUpdateInput,
  TenantLdapAuthProviderView,
} from "../lib/phase-two-types";

export type LdapTemplateKind = "active_directory" | "openldap" | "posix";

export interface LdapProviderDraft {
  configuration: TenantLdapAuthProviderConfigurationView;
  description: string;
  displayName: string;
  enabled: boolean;
  endpoints: TenantLdapAuthProviderEndpointView[];
  key: string;
}

const attributePattern =
  /^(?:[A-Za-z][A-Za-z0-9-]{0,127}|[0-9]+(?:\.[0-9]+)+)$/;
const providerKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/;
const endpointNamePattern = /^[a-z0-9:.][a-z0-9.:-]{0,252}$/;
const placeholderPattern = /\{[^{}]+\}/g;
const utf8 = new TextEncoder();

export const ldapTemplateOptions: readonly {
  description: string;
  label: string;
  value: LdapTemplateKind;
}[] = [
  {
    description: "objectGUID identity, sAMAccountName login, memberOf groups",
    label: "Active Directory",
    value: "active_directory",
  },
  {
    description: "entryUUID identity, uid login, reverse group lookup",
    label: "OpenLDAP",
    value: "openldap",
  },
  {
    description: "entryUUID identity with posixGroup memberUid membership",
    label: "POSIX LDAP",
    value: "posix",
  },
];

export function createLdapProviderDraft(
  template: LdapTemplateKind,
): LdapProviderDraft {
  const common = commonConfiguration(template);
  switch (template) {
    case "active_directory":
      return {
        configuration: {
          ...common,
          accountDisabledValue: null,
          accountStatusAttribute: "userAccountControl",
          accountStatusMode: "active_directory_uac",
          alternateUsernameAttribute: "userPrincipalName",
          bindDn: "CN=svc-periapsis,OU=Service Accounts,DC=example,DC=com",
          displayNameAttribute: "displayName",
          emailAttribute: "mail",
          firstNameAttribute: "givenName",
          groupBaseDn: "DC=example,DC=com",
          groupMembershipAttribute: "memberOf",
          groupSearchFilter: null,
          immutableSubjectAttribute: "objectGUID",
          immutableSubjectFormat: "ad_object_guid",
          lastNameAttribute: "sn",
          nestedGroupMode: "disabled",
          posixGidNumberAttribute: null,
          posixMemberUidAttribute: null,
          userBaseDn: "DC=example,DC=com",
          userSearchFilter:
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
          usernameAttribute: "sAMAccountName",
        },
        description: "",
        displayName: "Active Directory",
        enabled: false,
        endpoints: [defaultEndpoint("ad.example.com")],
        key: "active_directory",
      };
    case "openldap":
      return {
        configuration: {
          ...common,
          accountDisabledValue: null,
          accountStatusAttribute: null,
          accountStatusMode: "none",
          alternateUsernameAttribute: null,
          bindDn: "cn=readonly,dc=example,dc=org",
          displayNameAttribute: "cn",
          emailAttribute: "mail",
          firstNameAttribute: "givenName",
          groupBaseDn: "ou=groups,dc=example,dc=org",
          groupMembershipAttribute: null,
          groupSearchFilter: "(member={userDn})",
          immutableSubjectAttribute: "entryUUID",
          immutableSubjectFormat: "entry_uuid",
          lastNameAttribute: "sn",
          maxNestedGroupDepth: 5,
          nestedGroupMode: "reverse_search",
          posixGidNumberAttribute: null,
          posixMemberUidAttribute: null,
          userBaseDn: "ou=people,dc=example,dc=org",
          userSearchFilter: "(uid={username})",
          usernameAttribute: "uid",
        },
        description: "",
        displayName: "OpenLDAP",
        enabled: false,
        endpoints: [defaultEndpoint("ldap.example.org")],
        key: "openldap",
      };
    case "posix":
      return {
        configuration: {
          ...common,
          accountDisabledValue: null,
          accountStatusAttribute: null,
          accountStatusMode: "none",
          alternateUsernameAttribute: null,
          bindDn: "uid=readonly,ou=service,dc=example,dc=org",
          displayNameAttribute: "cn",
          emailAttribute: "mail",
          firstNameAttribute: "givenName",
          groupBaseDn: "ou=groups,dc=example,dc=org",
          groupMembershipAttribute: null,
          groupSearchFilter:
            "(&(objectClass=posixGroup)(memberUid={username}))",
          immutableSubjectAttribute: "entryUUID",
          immutableSubjectFormat: "entry_uuid",
          lastNameAttribute: "sn",
          maxNestedGroupDepth: 1,
          nestedGroupMode: "posix_member_uid",
          posixGidNumberAttribute: "gidNumber",
          posixMemberUidAttribute: "memberUid",
          userBaseDn: "ou=people,dc=example,dc=org",
          userSearchFilter: "(uid={username})",
          usernameAttribute: "uid",
        },
        description: "",
        displayName: "POSIX LDAP",
        enabled: false,
        endpoints: [defaultEndpoint("ldap.example.org")],
        key: "posix_ldap",
      };
    default:
      throw new Error("Unsupported LDAP provider template.");
  }
}

export function draftFromLdapProvider(
  provider: TenantLdapAuthProviderView,
): LdapProviderDraft {
  return {
    configuration: { ...provider.configuration },
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    endpoints: provider.endpoints.map((endpoint) => ({ ...endpoint })),
    key: provider.key,
  };
}

export function toLdapProviderCreateInput(
  draft: LdapProviderDraft,
): TenantLdapAuthProviderCreateInput {
  return {
    kind: "ldap",
    key: draft.key,
    displayName: draft.displayName,
    description: draft.description,
    configuration: { ...draft.configuration },
    endpoints: orderedEndpoints(draft.endpoints),
  };
}

export function toLdapProviderUpdateInput(
  draft: LdapProviderDraft,
): TenantLdapAuthProviderUpdateInput {
  return {
    key: draft.key,
    displayName: draft.displayName,
    description: draft.description,
    enabled: draft.enabled,
    configuration: { ...draft.configuration },
    endpoints: orderedEndpoints(draft.endpoints),
  };
}

export function validateLdapProviderDraft(
  draft: LdapProviderDraft,
  policy: "platform_global" | "tenant" = "tenant",
): readonly string[] {
  const errors: string[] = [];
  if (!providerKeyPattern.test(draft.key)) {
    errors.push(
      "Key must be 3–64 lowercase characters and start with a letter.",
    );
  }
  boundedText(errors, draft.displayName, "Display name", 1, 120, true);
  boundedText(errors, draft.description, "Description", 0, 1000, false);
  validateConfiguration(errors, draft.configuration, policy);
  validateEndpoints(errors, draft.endpoints);
  return errors;
}

export function validateBindSecret(secret: string): string | null {
  if (secret.length === 0) return "Enter the new bind secret.";
  if (secret.includes(String.fromCharCode(0)) || !isValidUtf16(secret)) {
    return "The bind secret must be valid UTF-8 text without NUL bytes.";
  }
  if (utf8.encode(secret).byteLength > 8176) {
    return "The bind secret must be at most 8176 UTF-8 bytes.";
  }
  return null;
}

export function validateAdministrativeReason(reason: string): string | null {
  if (reason.trim() === "") return "Enter an audit reason.";
  if (reason.length > 500 || hasControlCharacter(reason)) {
    return "The audit reason must be at most 500 characters without control characters.";
  }
  return null;
}

export function diagnosticCategoryLabel(
  diagnostic: TenantLdapAuthProviderDiagnosticView,
): string {
  const labels: Readonly<
    Record<TenantLdapAuthProviderDiagnosticView["category"], string>
  > = {
    bind_rejected: "Bind rejected",
    cancelled: "Cancelled",
    certificate_rejected: "Certificate rejected",
    connect_failed: "Connection failed",
    connect_timeout: "Connection timed out",
    destination_blocked: "Destination blocked",
    dns_failed: "DNS resolution failed",
    protocol_failed: "LDAP protocol failed",
    stale_configuration: "Configuration changed during test",
    success: "Succeeded",
    tls_failed: "TLS establishment failed",
  };
  return labels[diagnostic.category];
}

export function providerIdFromLocation(location: string): string | null {
  const match = /\/auth-providers\/([0-9a-f-]{36})$/.exec(location);
  return match?.[1] ?? null;
}

function commonConfiguration(
  template: LdapTemplateKind,
): TenantLdapAuthProviderConfigurationView {
  return {
    accountDisabledValue: null,
    accountStatusAttribute: null,
    accountStatusMode: "none",
    alternateUsernameAttribute: null,
    bindDn: "cn=readonly,dc=example,dc=org",
    connectTimeoutMs: 3000,
    customCaPem: null,
    deprovisionGraceSeconds: 0,
    deprovisionMode: "retain",
    displayNameAttribute: "cn",
    emailAttribute: "mail",
    firstNameAttribute: "givenName",
    groupBaseDn: null,
    groupMembershipAttribute: null,
    groupSearchFilter: null,
    immutableSubjectAttribute: "entryUUID",
    immutableSubjectFormat: "entry_uuid",
    jitMode: "disabled",
    lastNameAttribute: "sn",
    maxEntries: 5000,
    maxGroups: 1000,
    maxNestedGroupDepth: 0,
    maxPages: 100,
    maxReferralHops: 0,
    maxResponseBytes: 10_485_760,
    nestedGroupMode: "disabled",
    noMatchPolicy: "deny",
    operationTimeoutMs: 10_000,
    pageSize: 200,
    posixGidNumberAttribute: null,
    posixMemberUidAttribute: null,
    referralMode: "disabled",
    syncIntervalSeconds: null,
    template,
    userBaseDn: "ou=people,dc=example,dc=org",
    userDnTemplate: null,
    userSearchFilter: "(uid={username})",
    usernameAttribute: "uid",
    verifyCertificate: true,
  };
}

function defaultEndpoint(host: string): TenantLdapAuthProviderEndpointView {
  return {
    enabled: true,
    host,
    port: 636,
    priority: 1,
    referralAllowed: false,
    tlsServerName: host,
    transport: "ldaps",
  };
}

function orderedEndpoints(
  endpoints: readonly TenantLdapAuthProviderEndpointView[],
): TenantLdapAuthProviderEndpointView[] {
  return endpoints
    .map((endpoint) => ({ ...endpoint }))
    .toSorted((left, right) => left.priority - right.priority);
}

function validateConfiguration(
  errors: string[],
  configuration: TenantLdapAuthProviderConfigurationView,
  policy: "platform_global" | "tenant",
): void {
  if (
    !configuration.verifyCertificate ||
    configuration.jitMode !==
      (policy === "platform_global" ? "existing_identity" : "disabled") ||
    configuration.noMatchPolicy !== "deny" ||
    configuration.deprovisionMode !== "retain" ||
    configuration.deprovisionGraceSeconds !== 0 ||
    configuration.syncIntervalSeconds !== null
  ) {
    errors.push("Foundation safety policy fields cannot be changed.");
  }
  boundedInteger(
    errors,
    configuration.connectTimeoutMs,
    "Connect timeout",
    100,
    30_000,
  );
  boundedInteger(
    errors,
    configuration.operationTimeoutMs,
    "Operation timeout",
    100,
    60_000,
  );
  if (configuration.operationTimeoutMs < configuration.connectTimeoutMs) {
    errors.push("Operation timeout must be at least the connect timeout.");
  }
  boundedDn(errors, configuration.bindDn, "Bind DN");
  boundedDn(errors, configuration.userBaseDn, "User base DN");
  if (configuration.groupBaseDn !== null) {
    boundedDn(errors, configuration.groupBaseDn, "Group base DN");
  }
  boundedText(
    errors,
    configuration.userSearchFilter,
    "User search filter",
    1,
    4096,
    true,
  );
  validatePlaceholders(
    errors,
    configuration.userSearchFilter,
    ["username"],
    ["username"],
    "User search filter",
  );
  if (configuration.userDnTemplate !== null) {
    boundedText(
      errors,
      configuration.userDnTemplate,
      "User DN template",
      1,
      2048,
      true,
    );
    validatePlaceholders(
      errors,
      configuration.userDnTemplate,
      ["username"],
      ["username"],
      "User DN template",
    );
  }
  validateGroupFilter(errors, configuration);
  boundedInteger(errors, configuration.pageSize, "Page size", 1, 1000);
  boundedInteger(errors, configuration.maxPages, "Maximum pages", 1, 1000);
  boundedInteger(
    errors,
    configuration.maxEntries,
    "Maximum entries",
    1,
    100_000,
  );
  boundedInteger(
    errors,
    configuration.maxResponseBytes,
    "Maximum response bytes",
    1024,
    52_428_800,
  );
  boundedInteger(errors, configuration.maxGroups, "Maximum groups", 1, 10_000);
  if (configuration.referralMode === "disabled") {
    if (configuration.maxReferralHops !== 0)
      errors.push("Referral hops must be zero while referrals are disabled.");
  } else {
    boundedInteger(
      errors,
      configuration.maxReferralHops,
      "Maximum referral hops",
      1,
      3,
    );
  }
  if (configuration.nestedGroupMode === "disabled") {
    if (configuration.maxNestedGroupDepth !== 0)
      errors.push(
        "Nested depth must be zero while nested groups are disabled.",
      );
  } else {
    boundedInteger(
      errors,
      configuration.maxNestedGroupDepth,
      "Maximum nested depth",
      1,
      20,
    );
  }
  for (const [label, value] of [
    ["First-name attribute", configuration.firstNameAttribute],
    ["Last-name attribute", configuration.lastNameAttribute],
    ["Display-name attribute", configuration.displayNameAttribute],
    ["Username attribute", configuration.usernameAttribute],
    ["Immutable-subject attribute", configuration.immutableSubjectAttribute],
  ] as const) {
    validateAttribute(errors, value, label);
  }
  for (const [label, value] of [
    ["Alternate username attribute", configuration.alternateUsernameAttribute],
    ["Email attribute", configuration.emailAttribute],
    ["Group membership attribute", configuration.groupMembershipAttribute],
    ["POSIX memberUid attribute", configuration.posixMemberUidAttribute],
    ["POSIX gidNumber attribute", configuration.posixGidNumberAttribute],
  ] as const) {
    if (value !== null) validateAttribute(errors, value, label);
  }
  if (configuration.customCaPem !== null) {
    boundedPemText(
      errors,
      configuration.customCaPem,
      "Custom CA PEM",
      131_072,
      131_072,
    );
  }
  if (configuration.accountStatusMode === "none") {
    if (
      configuration.accountStatusAttribute !== null ||
      configuration.accountDisabledValue !== null
    ) {
      errors.push(
        "Account-status attribute and disabled value must be empty in none mode.",
      );
    }
  } else if (configuration.accountStatusMode === "active_directory_uac") {
    if (configuration.accountStatusAttribute === null)
      errors.push("Active Directory account status needs an attribute.");
    if (configuration.accountDisabledValue !== null)
      errors.push("Active Directory UAC mode cannot use a disabled value.");
  } else if (
    configuration.accountStatusAttribute === null ||
    configuration.accountDisabledValue === null
  ) {
    errors.push(
      "Attribute-equals account status needs both an attribute and disabled value.",
    );
  }
}

function validateGroupFilter(
  errors: string[],
  configuration: TenantLdapAuthProviderConfigurationView,
): void {
  const filter = configuration.groupSearchFilter;
  if (configuration.nestedGroupMode === "disabled") {
    if (filter !== null)
      errors.push(
        "Group search filter must be empty while nested groups are disabled.",
      );
    return;
  }
  if (filter === null) {
    errors.push(
      "The selected nested-group mode requires a group search filter.",
    );
    return;
  }
  boundedText(errors, filter, "Group search filter", 1, 4096, true);
  if (configuration.nestedGroupMode === "posix_member_uid") {
    validatePlaceholders(
      errors,
      filter,
      ["username"],
      ["username", "gidNumber"],
      "Group search filter",
    );
  } else {
    validatePlaceholders(
      errors,
      filter,
      ["userDn"],
      ["userDn", "username"],
      "Group search filter",
    );
  }
}

function validateEndpoints(
  errors: string[],
  endpoints: readonly TenantLdapAuthProviderEndpointView[],
): void {
  if (endpoints.length < 1 || endpoints.length > 8) {
    errors.push("Configure between one and eight endpoints.");
    return;
  }
  const priorities = new Set<number>();
  const identities = new Set<string>();
  for (const [index, endpoint] of endpoints.entries()) {
    const label = `Endpoint ${index + 1}`;
    boundedInteger(errors, endpoint.priority, `${label} priority`, 1, 8);
    boundedInteger(errors, endpoint.port, `${label} port`, 1, 65_535);
    if (!endpointNamePattern.test(endpoint.host))
      errors.push(
        `${label} host must be a canonical lowercase DNS name or IP literal.`,
      );
    if (!endpointNamePattern.test(endpoint.tlsServerName))
      errors.push(`${label} TLS server name must be canonical lowercase text.`);
    if (priorities.has(endpoint.priority))
      errors.push("Endpoint priorities must be unique.");
    priorities.add(endpoint.priority);
    const identity = `${endpoint.transport}\u0000${endpoint.host}\u0000${endpoint.port}`;
    if (identities.has(identity))
      errors.push(
        "Endpoint transport, host, and port identities must be unique.",
      );
    identities.add(identity);
  }
}

function boundedDn(errors: string[], value: string, label: string): void {
  boundedText(errors, value, label, 1, 2048, true, 8192);
}

function boundedText(
  errors: string[],
  value: string,
  label: string,
  minimumCodePoints: number,
  maximumCodePoints: number,
  requireNonWhitespace: boolean,
  maximumBytes?: number,
): void {
  const codePoints = Array.from(value).length;
  if (
    !isValidUtf16(value) ||
    codePoints < minimumCodePoints ||
    codePoints > maximumCodePoints ||
    (maximumBytes !== undefined &&
      utf8.encode(value).byteLength > maximumBytes) ||
    hasControlCharacter(value) ||
    (requireNonWhitespace && value.trim() === "")
  ) {
    errors.push(`${label} is outside its allowed text bounds.`);
  }
}

function boundedPemText(
  errors: string[],
  value: string,
  label: string,
  maximumCodePoints: number,
  maximumBytes: number,
): void {
  const codePoints = Array.from(value).length;
  if (
    !isValidUtf16(value) ||
    codePoints < 1 ||
    codePoints > maximumCodePoints ||
    utf8.encode(value).byteLength > maximumBytes ||
    value.trim() === "" ||
    hasPemDisallowedControl(value)
  ) {
    errors.push(`${label} is outside its allowed PEM text bounds.`);
  }
}

function boundedInteger(
  errors: string[],
  value: number,
  label: string,
  minimum: number,
  maximum: number,
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    errors.push(`${label} must be an integer from ${minimum} to ${maximum}.`);
  }
}

function validateAttribute(
  errors: string[],
  value: string,
  label: string,
): void {
  if (!attributePattern.test(value))
    errors.push(`${label} is not a valid LDAP attribute description or OID.`);
}

function validatePlaceholders(
  errors: string[],
  value: string,
  required: readonly string[],
  allowed: readonly string[],
  label: string,
): void {
  const placeholders =
    value.match(placeholderPattern)?.map((match) => match.slice(1, -1)) ?? [];
  const allowedNames = new Set(allowed);
  if (
    required.some(
      (name) =>
        placeholders.filter((candidate) => candidate === name).length !== 1,
    ) ||
    placeholders.some((name) => !allowedNames.has(name)) ||
    new Set(placeholders).size !== placeholders.length
  ) {
    errors.push(`${label} uses an invalid or repeated placeholder.`);
  }
}

function isValidUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      return true;
    }
  }
  return false;
}

function hasPemDisallowedControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      codePoint !== 0x0a &&
      codePoint !== 0x0d &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      return true;
    }
  }
  return false;
}
