-- name: ListTenantLDAPBindings :many
SELECT binding.id::uuid AS id,
       binding.provider_id::uuid AS provider_id,
       binding.key::text AS login_key,
       binding.enabled::boolean AS enabled,
       binding.profile_priority::integer AS profile_priority,
       binding.auth_revision::integer AS auth_revision,
       binding.current_access_epoch_id::uuid AS current_access_epoch_id,
       binding.archived_at::timestamptz AS archived_at,
       binding.version::integer AS version,
       binding.created_at::timestamptz AS created_at,
       binding.updated_at::timestamptz AS updated_at
FROM app.list_tenant_auth_provider_bindings_v1(
  sqlc.narg(after_binding_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS binding(
  id, provider_id, key, enabled, profile_priority, auth_revision,
  current_access_epoch_id, archived_at, version, created_at, updated_at
);

-- name: GetTenantLDAPBinding :one
SELECT binding.id::uuid AS id,
       binding.provider_id::uuid AS provider_id,
       binding.key::text AS login_key,
       binding.enabled::boolean AS enabled,
       binding.profile_priority::integer AS profile_priority,
       binding.auth_revision::integer AS auth_revision,
       binding.current_access_epoch_id::uuid AS current_access_epoch_id,
       binding.archived_at::timestamptz AS archived_at,
       binding.version::integer AS version,
       binding.created_at::timestamptz AS created_at,
       binding.updated_at::timestamptz AS updated_at
FROM app.get_tenant_auth_provider_binding_v1(
  sqlc.arg(binding_id)::uuid
) AS binding(
  id, provider_id, key, enabled, profile_priority, auth_revision,
  current_access_epoch_id, archived_at, version, created_at, updated_at
);

-- name: GetTenantLDAPBindingMutationResult :one
SELECT binding.id::uuid AS id,
       binding.provider_id::uuid AS provider_id,
       binding.key::text AS login_key,
       binding.enabled::boolean AS enabled,
       binding.profile_priority::integer AS profile_priority,
       binding.auth_revision::integer AS auth_revision,
       binding.current_access_epoch_id::uuid AS current_access_epoch_id,
       binding.archived_at::timestamptz AS archived_at,
       binding.version::integer AS version,
       binding.created_at::timestamptz AS created_at,
       binding.updated_at::timestamptz AS updated_at
FROM app.get_tenant_auth_provider_binding_mutation_result_v1(
  sqlc.arg(binding_id)::uuid
) AS binding(
  id, provider_id, key, enabled, profile_priority, auth_revision,
  current_access_epoch_id, archived_at, version, created_at, updated_at
);

-- name: CreateTenantLDAPBinding :one
SELECT result.result_resource_id::uuid AS binding_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_tenant_auth_provider_binding_v2(
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(login_key)::text,
  sqlc.arg(enabled)::boolean,
  sqlc.arg(profile_priority)::integer,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: UpdateTenantLDAPBinding :one
SELECT app.update_tenant_auth_provider_binding_v1(
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(login_key)::text,
  sqlc.arg(enabled)::boolean,
  sqlc.arg(profile_priority)::integer,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchiveTenantLDAPBinding :one
SELECT app.archive_tenant_auth_provider_binding_v1(
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantLDAPMappings :many
SELECT mapping.id::uuid AS id,
       mapping.binding_id::uuid AS binding_id,
       mapping.matcher_type::text AS matcher_type,
       mapping.matcher_value::text AS matcher_value,
       mapping.case_mode::text AS case_mode,
       mapping.priority::integer AS priority,
       mapping.security_group_id::uuid AS security_group_id,
       mapping.reconciliation_mode::text AS reconciliation_mode,
       mapping.role_ids::uuid[] AS role_ids,
       mapping.operator_team_id::uuid AS operator_team_id,
       mapping.operator_team_assignment_epoch_id::uuid AS operator_team_assignment_epoch_id,
       mapping.enabled::boolean AS enabled,
       mapping.current_source_epoch_id::uuid AS current_source_epoch_id,
       mapping.current_source_epoch_sequence::integer AS current_source_epoch_sequence,
       mapping.current_source_epoch_activated_at::timestamptz AS current_source_epoch_activated_at,
       mapping.notes::text AS notes,
       mapping.last_matched_at::timestamptz AS last_matched_at,
       mapping.archived_at::timestamptz AS archived_at,
       mapping.version::integer AS version,
       mapping.created_at::timestamptz AS created_at,
       mapping.updated_at::timestamptz AS updated_at
FROM app.list_tenant_ldap_mapping_rules_v1(
  sqlc.narg(binding_id)::uuid,
  sqlc.narg(after_priority)::integer,
  sqlc.narg(after_mapping_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS mapping(
  id, binding_id, matcher_type, matcher_value, case_mode, priority,
  security_group_id, reconciliation_mode, role_ids, operator_team_id,
  operator_team_assignment_epoch_id, enabled, current_source_epoch_id,
  current_source_epoch_sequence, current_source_epoch_activated_at,
  configuration_revision, notes, last_matched_at, archived_at, version,
  created_at, updated_at
);

-- name: GetTenantLDAPMapping :one
SELECT mapping.id::uuid AS id,
       mapping.binding_id::uuid AS binding_id,
       mapping.matcher_type::text AS matcher_type,
       mapping.matcher_value::text AS matcher_value,
       mapping.case_mode::text AS case_mode,
       mapping.priority::integer AS priority,
       mapping.security_group_id::uuid AS security_group_id,
       mapping.reconciliation_mode::text AS reconciliation_mode,
       mapping.role_ids::uuid[] AS role_ids,
       mapping.operator_team_id::uuid AS operator_team_id,
       mapping.operator_team_assignment_epoch_id::uuid AS operator_team_assignment_epoch_id,
       mapping.enabled::boolean AS enabled,
       mapping.current_source_epoch_id::uuid AS current_source_epoch_id,
       mapping.current_source_epoch_sequence::integer AS current_source_epoch_sequence,
       mapping.current_source_epoch_activated_at::timestamptz AS current_source_epoch_activated_at,
       mapping.notes::text AS notes,
       mapping.last_matched_at::timestamptz AS last_matched_at,
       mapping.archived_at::timestamptz AS archived_at,
       mapping.version::integer AS version,
       mapping.created_at::timestamptz AS created_at,
       mapping.updated_at::timestamptz AS updated_at
FROM app.get_tenant_ldap_mapping_rule_v1(
  sqlc.arg(mapping_id)::uuid
) AS mapping(
  id, binding_id, matcher_type, matcher_value, case_mode, priority,
  security_group_id, reconciliation_mode, role_ids, operator_team_id,
  operator_team_assignment_epoch_id, enabled, current_source_epoch_id,
  current_source_epoch_sequence, current_source_epoch_activated_at,
  configuration_revision, notes, last_matched_at, archived_at, version,
  created_at, updated_at
);

-- name: GetTenantLDAPMappingMutationResult :one
SELECT mapping.id::uuid AS id,
       mapping.binding_id::uuid AS binding_id,
       mapping.matcher_type::text AS matcher_type,
       mapping.matcher_value::text AS matcher_value,
       mapping.case_mode::text AS case_mode,
       mapping.priority::integer AS priority,
       mapping.security_group_id::uuid AS security_group_id,
       mapping.reconciliation_mode::text AS reconciliation_mode,
       mapping.role_ids::uuid[] AS role_ids,
       mapping.operator_team_id::uuid AS operator_team_id,
       mapping.operator_team_assignment_epoch_id::uuid AS operator_team_assignment_epoch_id,
       mapping.enabled::boolean AS enabled,
       mapping.current_source_epoch_id::uuid AS current_source_epoch_id,
       mapping.current_source_epoch_sequence::integer AS current_source_epoch_sequence,
       mapping.current_source_epoch_activated_at::timestamptz AS current_source_epoch_activated_at,
       mapping.notes::text AS notes,
       mapping.last_matched_at::timestamptz AS last_matched_at,
       mapping.archived_at::timestamptz AS archived_at,
       mapping.version::integer AS version,
       mapping.created_at::timestamptz AS created_at,
       mapping.updated_at::timestamptz AS updated_at
FROM app.get_tenant_ldap_mapping_rule_mutation_result_v1(
  sqlc.arg(mapping_id)::uuid
) AS mapping(
  id, binding_id, matcher_type, matcher_value, case_mode, priority,
  security_group_id, reconciliation_mode, role_ids, operator_team_id,
  operator_team_assignment_epoch_id, enabled, current_source_epoch_id,
  current_source_epoch_sequence, current_source_epoch_activated_at,
  configuration_revision, notes, last_matched_at, archived_at, version,
  created_at, updated_at
);

-- name: CreateTenantLDAPMapping :one
SELECT result.result_resource_id::uuid AS mapping_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_tenant_ldap_mapping_rule_v2(
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(matcher_type)::text::ldap_mapping_matcher_type,
  sqlc.arg(matcher_value)::text,
  sqlc.arg(case_mode)::text::ldap_mapping_case_mode,
  sqlc.arg(priority)::integer,
  sqlc.arg(security_group_id)::uuid,
  sqlc.arg(reconciliation_mode)::text::ldap_mapping_reconciliation_mode,
  sqlc.arg(role_ids)::uuid[],
  sqlc.narg(operator_team_id)::uuid,
  sqlc.narg(operator_team_assignment_epoch_id)::uuid,
  sqlc.arg(notes)::text,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(
  result_resource_id, binding_id, matcher_type, matcher_value, case_mode,
  priority, security_group_id, reconciliation_mode, role_ids,
  operator_team_id, operator_team_assignment_epoch_id, enabled,
  current_source_epoch_id, current_source_epoch_sequence,
  current_source_epoch_activated_at, configuration_revision, notes,
  last_matched_at, archived_at, result_version, created_at, updated_at,
  replayed
);

-- name: UpdateTenantLDAPMapping :one
SELECT app.update_tenant_ldap_mapping_rule_v1(
  sqlc.arg(mapping_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(matcher_type)::text::ldap_mapping_matcher_type,
  sqlc.arg(matcher_value)::text,
  sqlc.arg(case_mode)::text::ldap_mapping_case_mode,
  sqlc.arg(priority)::integer,
  sqlc.arg(security_group_id)::uuid,
  sqlc.arg(reconciliation_mode)::text::ldap_mapping_reconciliation_mode,
  sqlc.arg(role_ids)::uuid[],
  sqlc.narg(operator_team_id)::uuid,
  sqlc.narg(operator_team_assignment_epoch_id)::uuid,
  sqlc.arg(enabled)::boolean,
  sqlc.arg(notes)::text,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchiveTenantLDAPMapping :one
SELECT app.archive_tenant_ldap_mapping_rule_v1(
  sqlc.arg(mapping_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: GetTenantLDAPSyncStatus :one
SELECT projection.binding_id::uuid AS binding_id,
       projection.schedule_state::text AS schedule_state,
       coalesce(projection.sync_interval_seconds, 0)::integer AS sync_interval_seconds,
       projection.active_run_id::uuid AS active_run_id,
       projection.last_run_id::uuid AS last_run_id,
       coalesce(projection.last_run_state::text, '')::text AS last_run_state,
       projection.last_completed_at::timestamptz AS last_completed_at,
       projection.next_scheduled_at::timestamptz AS next_scheduled_at,
       projection.version::integer AS version,
       projection.updated_at::timestamptz AS updated_at
FROM app.get_tenant_ldap_sync_status_v1(
  sqlc.arg(binding_id)::uuid
) AS projection(
  binding_id, schedule_state, sync_interval_seconds, active_run_id,
  last_run_id, last_run_state, last_completed_at, next_scheduled_at,
  version, updated_at
);

-- name: ListTenantLDAPSyncRuns :many
SELECT projection.id::uuid AS id,
       projection.tenant_id::uuid AS tenant_id,
       projection.binding_id::uuid AS binding_id,
       projection.provider_id::uuid AS provider_id,
       projection.trigger::text AS trigger,
       coalesce(projection.manual_reason::text, '')::text AS manual_reason,
       projection.state::text AS state,
       projection.provider_version::integer AS provider_version,
       projection.binding_version::integer AS binding_version,
       projection.configuration_revision::integer AS configuration_revision,
       projection.access_epoch_id::uuid AS access_epoch_id,
       projection.mapping_revisions::jsonb AS mapping_revisions,
       projection.enumeration_state::text AS enumeration_state,
       projection.enumeration_complete::boolean AS enumeration_complete,
       projection.result_truncated::boolean AS result_truncated,
       projection.absence_allowed::boolean AS absence_allowed,
       projection.entry_count::integer AS entry_count,
       projection.page_count::integer AS page_count,
       projection.response_bytes::integer AS response_bytes,
       projection.cursor_state::text AS cursor_state,
       coalesce(projection.enumeration_error_category::text, '')::text AS enumeration_error_category,
       projection.observed::integer AS observed,
       projection.staged::integer AS staged,
       projection.identities_created::integer AS identities_created,
       projection.identities_linked::integer AS identities_linked,
       projection.provider_access_added::integer AS provider_access_added,
       projection.provider_access_suspended::integer AS provider_access_suspended,
       projection.group_edges_added::integer AS group_edges_added,
       projection.group_edges_refreshed::integer AS group_edges_refreshed,
       projection.group_edges_revoked::integer AS group_edges_revoked,
       projection.role_edges_added::integer AS role_edges_added,
       projection.role_edges_refreshed::integer AS role_edges_refreshed,
       projection.role_edges_revoked::integer AS role_edges_revoked,
       projection.roster_edges_added::integer AS roster_edges_added,
       projection.roster_edges_refreshed::integer AS roster_edges_refreshed,
       projection.roster_edges_revoked::integer AS roster_edges_revoked,
       projection.failed::integer AS failed,
       coalesce(projection.run_error_category::text, '')::text AS run_error_category,
       projection.created_at::timestamptz AS created_at,
       projection.started_at::timestamptz AS started_at,
       projection.completed_at::timestamptz AS completed_at,
       projection.version::integer AS version,
       projection.updated_at::timestamptz AS updated_at
FROM app.list_tenant_ldap_sync_runs_v1(
  sqlc.arg(binding_id)::uuid,
  sqlc.narg(after_run_id)::uuid,
  sqlc.arg(page_size)::integer
) AS projection(
  id, tenant_id, binding_id, provider_id, trigger, manual_reason, state,
  provider_version, binding_version, configuration_revision, access_epoch_id,
  mapping_revisions, enumeration_state, enumeration_complete,
  result_truncated, absence_allowed, entry_count, page_count, response_bytes,
  cursor_state, enumeration_error_category, observed, staged,
  identities_created, identities_linked, provider_access_added,
  provider_access_suspended, group_edges_added, group_edges_refreshed,
  group_edges_revoked, role_edges_added, role_edges_refreshed,
  role_edges_revoked, roster_edges_added, roster_edges_refreshed,
  roster_edges_revoked, failed, run_error_category, created_at, started_at,
  completed_at, version, updated_at
);

-- name: GetTenantLDAPSyncRun :one
SELECT projection.id::uuid AS id,
       projection.tenant_id::uuid AS tenant_id,
       projection.binding_id::uuid AS binding_id,
       projection.provider_id::uuid AS provider_id,
       projection.trigger::text AS trigger,
       coalesce(projection.manual_reason::text, '')::text AS manual_reason,
       projection.state::text AS state,
       projection.provider_version::integer AS provider_version,
       projection.binding_version::integer AS binding_version,
       projection.configuration_revision::integer AS configuration_revision,
       projection.access_epoch_id::uuid AS access_epoch_id,
       projection.mapping_revisions::jsonb AS mapping_revisions,
       projection.enumeration_state::text AS enumeration_state,
       projection.enumeration_complete::boolean AS enumeration_complete,
       projection.result_truncated::boolean AS result_truncated,
       projection.absence_allowed::boolean AS absence_allowed,
       projection.entry_count::integer AS entry_count,
       projection.page_count::integer AS page_count,
       projection.response_bytes::integer AS response_bytes,
       projection.cursor_state::text AS cursor_state,
       coalesce(projection.enumeration_error_category::text, '')::text AS enumeration_error_category,
       projection.observed::integer AS observed,
       projection.staged::integer AS staged,
       projection.identities_created::integer AS identities_created,
       projection.identities_linked::integer AS identities_linked,
       projection.provider_access_added::integer AS provider_access_added,
       projection.provider_access_suspended::integer AS provider_access_suspended,
       projection.group_edges_added::integer AS group_edges_added,
       projection.group_edges_refreshed::integer AS group_edges_refreshed,
       projection.group_edges_revoked::integer AS group_edges_revoked,
       projection.role_edges_added::integer AS role_edges_added,
       projection.role_edges_refreshed::integer AS role_edges_refreshed,
       projection.role_edges_revoked::integer AS role_edges_revoked,
       projection.roster_edges_added::integer AS roster_edges_added,
       projection.roster_edges_refreshed::integer AS roster_edges_refreshed,
       projection.roster_edges_revoked::integer AS roster_edges_revoked,
       projection.failed::integer AS failed,
       coalesce(projection.run_error_category::text, '')::text AS run_error_category,
       projection.created_at::timestamptz AS created_at,
       projection.started_at::timestamptz AS started_at,
       projection.completed_at::timestamptz AS completed_at,
       projection.version::integer AS version,
       projection.updated_at::timestamptz AS updated_at
FROM app.get_tenant_ldap_sync_run_v1(
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(sync_run_id)::uuid
) AS projection(
  id, tenant_id, binding_id, provider_id, trigger, manual_reason, state,
  provider_version, binding_version, configuration_revision, access_epoch_id,
  mapping_revisions, enumeration_state, enumeration_complete,
  result_truncated, absence_allowed, entry_count, page_count, response_bytes,
  cursor_state, enumeration_error_category, observed, staged,
  identities_created, identities_linked, provider_access_added,
  provider_access_suspended, group_edges_added, group_edges_refreshed,
  group_edges_revoked, role_edges_added, role_edges_refreshed,
  role_edges_revoked, roster_edges_added, roster_edges_refreshed,
  roster_edges_revoked, failed, run_error_category, created_at, started_at,
  completed_at, version, updated_at
);

-- name: BeginTenantLDAPManualSyncV2 :one
SELECT result.sync_run_id::uuid AS sync_run_id,
       result.replayed::boolean AS replayed
FROM app.begin_tenant_ldap_manual_sync_run_v2(
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(sync_run_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_binding_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(sync_run_id, replayed);
