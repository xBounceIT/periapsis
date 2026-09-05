-- Audit operation mutations intentionally calculate their payload digests from
-- PostgreSQL's canonical jsonb representation. The database ABI verifies the
-- same representation before admitting an idempotency receipt.

-- name: CreateTenantAuditExportOperation :one
SELECT app.create_tenant_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'audit.export'::text,
  'audit.read'::text,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'filter',sqlc.arg(normalized_filter)::jsonb,
    'retentionSeconds',sqlc.arg(retention_seconds)::bigint,
    'projectionVersion',1,
    'format','jsonl',
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(job_id)::uuid,
  sqlc.arg(normalized_filter)::jsonb,
  sha256(convert_to(sqlc.arg(normalized_filter)::jsonb::text,'UTF8')),
  sqlc.arg(retention_seconds)::bigint,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: GetTenantAuditExportOperation :one
SELECT app.get_tenant_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'audit.export'::text,
  'audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: CancelTenantAuditExportOperation :one
SELECT app.cancel_tenant_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'audit.export'::text,
  'audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'exportId',sqlc.arg(export_id)::uuid,
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: AuthorizeTenantAuditExportDownload :one
SELECT result.artifact_id::uuid AS artifact_id,
       result.object_key::text AS object_key,
       result.digest::bytea AS digest,
       result.rows::bigint AS rows,
       result.bytes::bigint AS bytes,
       result.expires_at::timestamptz AS expires_at,
       result.filename::text AS filename
FROM app.authorize_tenant_audit_export_download_v1(
  sqlc.arg(session_id)::uuid,
  'audit.export'::text,
  'audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS result(artifact_id,object_key,digest,rows,bytes,expires_at,filename);

-- name: CreatePlatformAuditExportOperation :one
SELECT app.create_platform_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.export'::text,
  'platform.audit.read'::text,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'filter',sqlc.arg(normalized_filter)::jsonb,
    'retentionSeconds',sqlc.arg(retention_seconds)::bigint,
    'projectionVersion',1,
    'format','jsonl',
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(job_id)::uuid,
  sqlc.arg(normalized_filter)::jsonb,
  sha256(convert_to(sqlc.arg(normalized_filter)::jsonb::text,'UTF8')),
  sqlc.arg(retention_seconds)::bigint,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: GetPlatformAuditExportOperation :one
SELECT app.get_platform_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.export'::text,
  'platform.audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: CancelPlatformAuditExportOperation :one
SELECT app.cancel_platform_audit_export_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.export'::text,
  'platform.audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'exportId',sqlc.arg(export_id)::uuid,
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: AuthorizePlatformAuditExportDownload :one
SELECT result.artifact_id::uuid AS artifact_id,
       result.object_key::text AS object_key,
       result.digest::bytea AS digest,
       result.rows::bigint AS rows,
       result.bytes::bigint AS bytes,
       result.expires_at::timestamptz AS expires_at,
       result.filename::text AS filename
FROM app.authorize_platform_audit_export_download_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.export'::text,
  'platform.audit.read'::text,
  sqlc.arg(export_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS result(artifact_id,object_key,digest,rows,bytes,expires_at,filename);

-- name: GetTenantAuditRetentionOperation :one
SELECT app.get_tenant_audit_retention_v1(
  sqlc.arg(session_id)::uuid,
  'audit.retention.manage'::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: UpdateTenantAuditRetentionOperation :one
SELECT app.update_tenant_audit_retention_v1(
  sqlc.arg(session_id)::uuid,
  'audit.retention.manage'::text,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(retention_days)::integer,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'retentionDays',sqlc.arg(retention_days)::integer,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: PlaceTenantAuditLegalHoldOperation :one
SELECT app.place_tenant_audit_legal_hold_v1(
  sqlc.arg(session_id)::uuid,
  'audit.retention.manage'::text,
  sqlc.arg(hold_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object('reason',sqlc.arg(reason)::text)::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: ReleaseTenantAuditLegalHoldOperation :one
SELECT app.release_tenant_audit_legal_hold_v1(
  sqlc.arg(session_id)::uuid,
  'audit.retention.manage'::text,
  sqlc.arg(hold_id)::uuid,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'holdId',sqlc.arg(hold_id)::uuid,
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: GetPlatformAuditRetentionOperation :one
SELECT app.get_platform_audit_retention_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.retention.manage'::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: UpdatePlatformAuditRetentionOperation :one
SELECT app.update_platform_audit_retention_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.retention.manage'::text,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(retention_days)::integer,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'retentionDays',sqlc.arg(retention_days)::integer,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: PlacePlatformAuditLegalHoldOperation :one
SELECT app.place_platform_audit_legal_hold_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.retention.manage'::text,
  sqlc.arg(hold_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object('reason',sqlc.arg(reason)::text)::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: ReleasePlatformAuditLegalHoldOperation :one
SELECT app.release_platform_audit_legal_hold_v1(
  sqlc.arg(session_id)::uuid,
  'platform.audit.retention.manage'::text,
  sqlc.arg(hold_id)::uuid,
  sqlc.arg(expected_revision)::bigint,
  sqlc.arg(idempotency_key_digest)::bytea,
  sha256(convert_to(jsonb_build_object(
    'holdId',sqlc.arg(hold_id)::uuid,
    'expectedRevision',sqlc.arg(expected_revision)::bigint,
    'reason',sqlc.arg(reason)::text
  )::text,'UTF8')),
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;
