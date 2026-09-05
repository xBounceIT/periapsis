import { pgEnum } from "drizzle-orm/pg-core";

export const tenantStatus = pgEnum("tenant_status", ["active", "suspended"]);

export const membershipRole = pgEnum("membership_role", [
  "tenant_admin",
  "soc_manager",
  "senior_analyst",
  "analyst",
  "customer_manager",
  "customer_user",
  "read_only",
]);

export const membershipStatus = pgEnum("membership_status", [
  "invited",
  "active",
  "suspended",
]);

export const authorizationScope = pgEnum("authorization_scope", [
  "own",
  "assigned",
  "operator_team",
  "tenant",
  "platform",
]);

export const authorizationSourceKind = pgEnum("authorization_source_kind", [
  "system",
  "tenant_creation",
  "manual",
  "identity_provider_access",
  "identity_mapping",
  "platform_recovery",
]);

export const tenantPrincipalKind = pgEnum("tenant_principal_kind", [
  "human",
  "service_account",
]);

export const alertStatus = pgEnum("alert_status", [
  "new",
  "in_progress",
  "closed",
]);

export const alertSeverity = pgEnum("alert_severity", [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);

export const auditActorType = pgEnum("audit_actor_type", [
  "user",
  "service_account",
  "system",
]);

export const auditOutcome = pgEnum("audit_outcome", [
  "success",
  "failure",
  "denied",
]);

export const authChallengePurpose = pgEnum("auth_challenge_purpose", [
  "local_login",
  "mfa_login",
  "totp_enrollment",
  "step_up",
]);

export const authRateLimitScope = pgEnum("auth_rate_limit_scope", [
  "api_network",
  "api_credential",
  "api_tenant_subject",
  "bootstrap_totp",
  "local_login",
  "ldap_network",
  "ldap_account",
  "ldap_provider",
  "platform_oidc_network",
  "platform_oidc_account",
  "platform_oidc_provider",
  "platform_saml_network",
  "platform_saml_account",
  "platform_saml_provider",
  "mfa_challenge",
  "recovery_code",
  "tenant_switch",
]);

export const loginIdentifierKind = pgEnum("login_identifier_kind", [
  "local_email",
]);

export const authProviderKind = pgEnum("auth_provider_kind", [
  "ldap",
  "oidc",
  "saml",
]);

export const ldapProviderTemplate = pgEnum("ldap_provider_template", [
  "active_directory",
  "openldap",
  "posix",
  "custom",
]);

export const ldapTransport = pgEnum("ldap_transport", ["ldaps", "starttls"]);

export const ldapReferralMode = pgEnum("ldap_referral_mode", [
  "disabled",
  "configured_endpoints",
]);

export const ldapNestedGroupMode = pgEnum("ldap_nested_group_mode", [
  "disabled",
  "active_directory",
  "reverse_search",
  "posix_member_uid",
]);

export const ldapAccountStatusMode = pgEnum("ldap_account_status_mode", [
  "none",
  "active_directory_uac",
  "attribute_equals",
]);

export const identitySubjectFormat = pgEnum("identity_subject_format", [
  "ad_object_guid",
  "entry_uuid",
  "utf8_exact",
  "utf8_casefold",
]);

export const identityJitMode = pgEnum("identity_jit_mode", [
  "disabled",
  "existing_identity",
  "create",
]);

export const identityNoMatchPolicy = pgEnum("identity_no_match_policy", [
  "deny",
  "provider_access_only",
]);

export const identityDeprovisionMode = pgEnum("identity_deprovision_mode", [
  "retain",
  "immediate",
  "grace",
]);

export const ldapProviderTestKind = pgEnum("ldap_provider_test_kind", [
  "connection",
  "bind",
]);

export const ldapProviderTestStatus = pgEnum("ldap_provider_test_status", [
  "started",
  "completed",
]);

export const ldapProviderTestOutcome = pgEnum("ldap_provider_test_outcome", [
  "success",
  "failure",
  "inconclusive",
]);

export const ldapProviderTestCategory = pgEnum("ldap_provider_test_category", [
  "success",
  "dns_failed",
  "destination_blocked",
  "connect_timeout",
  "connect_failed",
  "tls_failed",
  "certificate_rejected",
  "bind_rejected",
  "protocol_failed",
  "cancelled",
  "stale_configuration",
]);

export const ldapDirectoryOperationKind = pgEnum(
  "ldap_directory_operation_kind",
  ["search_user", "filter_user", "filter_group"],
);

export const ldapMappingMatcherType = pgEnum("ldap_mapping_matcher_type", [
  "exact_dn",
  "exact_cn",
  "regex",
]);

export const ldapMappingCaseMode = pgEnum("ldap_mapping_case_mode", [
  "sensitive",
  "insensitive",
]);

export const ldapMappingReconciliationMode = pgEnum(
  "ldap_mapping_reconciliation_mode",
  ["additive", "authoritative"],
);

export const ldapIdentityApplyMode = pgEnum("ldap_identity_apply_mode", [
  "jit",
  "sync",
]);

export const ldapIdentityApplyDecision = pgEnum(
  "ldap_identity_apply_decision",
  ["admitted", "denied"],
);

export const ldapJitRunStatus = pgEnum("ldap_jit_run_status", [
  "network_pending",
  "planning",
  "succeeded",
  "denied",
  "failed",
  "stale",
  "expired",
]);

export const ldapSyncTrigger = pgEnum("ldap_sync_trigger", [
  "scheduled",
  "manual",
]);

export const ldapSyncRunStatus = pgEnum("ldap_sync_run_status", [
  "queued",
  "enumerating",
  "applying",
  "succeeded",
  "failed",
  "cancelled",
  "stale",
]);

export const ldapSyncAbsenceStatus = pgEnum("ldap_sync_absence_status", [
  "pending",
  "cleared",
  "applied",
]);

export const ticketAggregateKind = pgEnum("ticket_aggregate_kind", [
  "alert",
  "case",
]);

export const ticketNumberingPeriod = pgEnum("ticket_numbering_period", [
  "annual",
  "lifetime",
]);

export const ticketCommentVisibility = pgEnum("ticket_comment_visibility", [
  "public",
  "private",
]);

export const ticketPrincipalKind = pgEnum("ticket_principal_kind", [
  "human",
  "service_account",
  "system",
]);

export const notificationEventType = pgEnum("notification_event_type", [
  "alert.created",
  "alert.assigned",
  "alert.claimed",
  "alert.status_changed",
  "alert.escalated",
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.created",
  "case.assigned",
  "case.claimed",
  "case.transferred",
  "case.status_changed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.public_added",
  "comment.private_added",
  "contact.changed",
  "sla.warning",
  "sla.breached",
  "task.assigned",
  "evidence.added",
  "webhook.custom",
]);

export const notificationObjectType = pgEnum("notification_object_type", [
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
]);

export const notificationAudience = pgEnum("notification_audience", [
  "operator",
  "customer",
]);

export const notificationChannel = pgEnum("notification_channel", [
  "email",
  "webhook",
]);

export const notificationSecretKind = pgEnum("notification_secret_kind", [
  "smtp_password",
  "smtp_dkim_private_key",
  "webhook_signing_key",
]);

export const notificationDeliveryStatus = pgEnum(
  "notification_delivery_status",
  [
    "queued",
    "leased",
    "reserved",
    "retry_scheduled",
    "delivered",
    "dead_lettered",
  ],
);

export const notificationFailureClass = pgEnum("notification_failure_class", [
  "authentication",
  "connectivity",
  "rate_limited",
  "render",
  "security",
  "timeout",
  "tls",
  "unknown",
  "submission_uncertain",
]);

export const notificationSmtpSecurity = pgEnum("notification_smtp_security", [
  "tls",
  "starttls",
  "plain_local",
]);
