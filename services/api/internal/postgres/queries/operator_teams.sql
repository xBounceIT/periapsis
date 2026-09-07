-- name: ResolveCurrentTenantOperatorTeams :many
SELECT relationship.operator_team_id::uuid AS operator_team_id,
       relationship.assignment_epoch_id::uuid AS assignment_epoch_id
FROM app.resolve_current_tenant_operator_teams(
  sqlc.arg(page_size)::integer
) AS relationship(operator_team_id, assignment_epoch_id);

-- name: ListPlatformOperatorTeams :many
SELECT team.operator_team_id::uuid AS operator_team_id,
       team.team_key::text AS team_key,
       team.display_name::text AS display_name,
       team.description::text AS description,
       team.version::integer AS version,
       team.created_by_user_id::uuid AS created_by_user_id,
       team.archived_at::timestamptz AS archived_at,
       team.archived_by_user_id::uuid AS archived_by_user_id,
       coalesce(team.archive_reason::text, '')::text AS archive_reason,
       team.active_assignment_count::bigint AS active_assignment_count,
       team.created_at::timestamptz AS created_at,
       team.updated_at::timestamptz AS updated_at
FROM app.list_platform_operator_teams(
  sqlc.narg(after_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS team(
  operator_team_id, team_key, display_name, description, version,
  created_by_user_id, archived_at, archived_by_user_id, archive_reason,
  active_assignment_count, created_at, updated_at
);

-- name: GetPlatformOperatorTeam :one
SELECT team.operator_team_id::uuid AS operator_team_id,
       team.team_key::text AS team_key,
       team.display_name::text AS display_name,
       team.description::text AS description,
       team.version::integer AS version,
       team.created_by_user_id::uuid AS created_by_user_id,
       team.archived_at::timestamptz AS archived_at,
       team.archived_by_user_id::uuid AS archived_by_user_id,
       coalesce(team.archive_reason::text, '')::text AS archive_reason,
       team.active_assignment_count::bigint AS active_assignment_count,
       team.created_at::timestamptz AS created_at,
       team.updated_at::timestamptz AS updated_at
FROM app.get_platform_operator_team(
  sqlc.arg(operator_team_id)::uuid
) AS team(
  operator_team_id, team_key, display_name, description, version,
  created_by_user_id, archived_at, archived_by_user_id, archive_reason,
  active_assignment_count, created_at, updated_at
);

-- name: CreatePlatformOperatorTeam :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_platform_operator_team(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(team_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: UpdatePlatformOperatorTeamMetadata :one
SELECT app.update_platform_operator_team_metadata(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.narg(display_name)::text,
  sqlc.narg(description)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchivePlatformOperatorTeam :one
SELECT app.archive_platform_operator_team(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantOperatorTeamAssignments :many
SELECT assignment.assignment_epoch_id::uuid AS assignment_epoch_id,
       assignment.operator_team_id::uuid AS operator_team_id,
       assignment.team_key::text AS team_key,
       assignment.team_display_name::text AS team_display_name,
       assignment.team_archived_at::timestamptz AS team_archived_at,
       assignment.assigned_by_membership_id::uuid AS assigned_by_membership_id,
       assignment.assigned_by_user_id::uuid AS assigned_by_user_id,
       assignment.assignment_reason::text AS assignment_reason,
       assignment.assigned_at::timestamptz AS assigned_at,
       assignment.ended_at::timestamptz AS ended_at,
       assignment.ended_by_membership_id::uuid AS ended_by_membership_id,
       assignment.ended_by_user_id::uuid AS ended_by_user_id,
       coalesce(assignment.end_reason::text, '')::text AS end_reason,
       assignment.version::integer AS version,
       assignment.updated_at::timestamptz AS updated_at
FROM app.list_tenant_operator_team_assignment_epochs(
  sqlc.narg(operator_team_id)::uuid,
  sqlc.narg(after_epoch_id)::uuid,
  sqlc.arg(include_ended)::boolean,
  sqlc.arg(page_size)::integer
) AS assignment(
  assignment_epoch_id, operator_team_id, team_key, team_display_name,
  team_archived_at, assigned_by_membership_id, assigned_by_user_id,
  assignment_reason, assigned_at, ended_at, ended_by_membership_id,
  ended_by_user_id, end_reason, version, updated_at
);

-- name: GetTenantOperatorTeamAssignment :one
SELECT assignment.assignment_epoch_id::uuid AS assignment_epoch_id,
       assignment.operator_team_id::uuid AS operator_team_id,
       assignment.team_key::text AS team_key,
       assignment.team_display_name::text AS team_display_name,
       assignment.team_archived_at::timestamptz AS team_archived_at,
       assignment.assigned_by_membership_id::uuid AS assigned_by_membership_id,
       assignment.assigned_by_user_id::uuid AS assigned_by_user_id,
       assignment.assignment_reason::text AS assignment_reason,
       assignment.assigned_at::timestamptz AS assigned_at,
       assignment.ended_at::timestamptz AS ended_at,
       assignment.ended_by_membership_id::uuid AS ended_by_membership_id,
       assignment.ended_by_user_id::uuid AS ended_by_user_id,
       coalesce(assignment.end_reason::text, '')::text AS end_reason,
       assignment.version::integer AS version,
       assignment.updated_at::timestamptz AS updated_at
FROM app.get_tenant_operator_team_assignment_epoch(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid
) AS assignment(
  assignment_epoch_id, operator_team_id, team_key, team_display_name,
  team_archived_at, assigned_by_membership_id, assigned_by_user_id,
  assignment_reason, assigned_at, ended_at, ended_by_membership_id,
  ended_by_user_id, end_reason, version, updated_at
);

-- name: StartTenantOperatorTeamAssignment :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.start_tenant_operator_team_assignment(
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.arg(tenant_audit_id)::uuid,
  sqlc.arg(platform_audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: EndTenantOperatorTeamAssignment :one
SELECT app.end_tenant_operator_team_assignment(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(tenant_audit_id)::uuid,
  sqlc.arg(platform_audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantOperatorTeamRosterEntries :many
SELECT roster.roster_entry_id::uuid AS roster_entry_id,
       roster.operator_team_id::uuid AS operator_team_id,
       roster.team_key::text AS team_key,
       roster.team_display_name::text AS team_display_name,
       roster.team_archived_at::timestamptz AS team_archived_at,
       roster.assignment_epoch_id::uuid AS assignment_epoch_id,
       roster.assignment_ended_at::timestamptz AS assignment_ended_at,
       roster.membership_id::uuid AS membership_id,
       roster.target_user_id::uuid AS target_user_id,
       coalesce(roster.email, '')::text AS email,
       roster.display_name::text AS display_name,
       roster.membership_status::text AS membership_status,
       roster.compatibility_role::text AS compatibility_role,
       roster.user_active::boolean AS user_active,
       roster.source_id::uuid AS source_id,
       roster.source_kind::text AS source_kind,
       roster.source_key::text AS source_key,
       roster.source_authoritative::boolean AS source_authoritative,
       roster.source_retired_at::timestamptz AS source_retired_at,
       roster.granted_by_membership_id::uuid AS granted_by_membership_id,
       roster.granted_by_user_id::uuid AS granted_by_user_id,
       roster.grant_reason::text AS grant_reason,
       roster.granted_at::timestamptz AS granted_at,
       roster.expires_at::timestamptz AS expires_at,
       roster.revoked_at::timestamptz AS revoked_at,
       roster.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       roster.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(roster.revoke_reason::text, '')::text AS revoke_reason,
       roster.roster_state::text AS roster_state,
       roster.version::integer AS version,
       roster.updated_at::timestamptz AS updated_at
FROM app.list_tenant_operator_team_roster_entries_v2(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.narg(after_entry_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS roster(
  roster_entry_id, operator_team_id, team_key, team_display_name,
  team_archived_at, assignment_epoch_id, assignment_ended_at, membership_id,
  target_user_id, email, display_name, membership_status, compatibility_role,
  user_active, source_id, source_kind, source_key, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at, revoked_by_membership_id,
  revoked_by_user_id, revoke_reason, roster_state, version, updated_at
);

-- name: GetTenantOperatorTeamRosterEntry :one
SELECT roster.roster_entry_id::uuid AS roster_entry_id,
       roster.operator_team_id::uuid AS operator_team_id,
       roster.team_key::text AS team_key,
       roster.team_display_name::text AS team_display_name,
       roster.team_archived_at::timestamptz AS team_archived_at,
       roster.assignment_epoch_id::uuid AS assignment_epoch_id,
       roster.assignment_ended_at::timestamptz AS assignment_ended_at,
       roster.membership_id::uuid AS membership_id,
       roster.target_user_id::uuid AS target_user_id,
       coalesce(roster.email, '')::text AS email,
       roster.display_name::text AS display_name,
       roster.membership_status::text AS membership_status,
       roster.compatibility_role::text AS compatibility_role,
       roster.user_active::boolean AS user_active,
       roster.source_id::uuid AS source_id,
       roster.source_kind::text AS source_kind,
       roster.source_key::text AS source_key,
       roster.source_authoritative::boolean AS source_authoritative,
       roster.source_retired_at::timestamptz AS source_retired_at,
       roster.granted_by_membership_id::uuid AS granted_by_membership_id,
       roster.granted_by_user_id::uuid AS granted_by_user_id,
       roster.grant_reason::text AS grant_reason,
       roster.granted_at::timestamptz AS granted_at,
       roster.expires_at::timestamptz AS expires_at,
       roster.revoked_at::timestamptz AS revoked_at,
       roster.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       roster.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(roster.revoke_reason::text, '')::text AS revoke_reason,
       roster.roster_state::text AS roster_state,
       roster.version::integer AS version,
       roster.updated_at::timestamptz AS updated_at
FROM app.get_tenant_operator_team_roster_entry_v2(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.arg(roster_entry_id)::uuid
) AS roster(
  roster_entry_id, operator_team_id, team_key, team_display_name,
  team_archived_at, assignment_epoch_id, assignment_ended_at, membership_id,
  target_user_id, email, display_name, membership_status, compatibility_role,
  user_active, source_id, source_kind, source_key, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at, revoked_by_membership_id,
  revoked_by_user_id, revoke_reason, roster_state, version, updated_at
);

-- name: AddTenantOperatorTeamRosterEntry :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.add_tenant_operator_team_roster_entry(
  sqlc.arg(roster_entry_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.arg(membership_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.narg(expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: RevokeTenantOperatorTeamRosterEntry :one
SELECT app.revoke_tenant_operator_team_roster_entry(
  sqlc.arg(operator_team_id)::uuid,
  sqlc.arg(assignment_epoch_id)::uuid,
  sqlc.arg(roster_entry_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;
