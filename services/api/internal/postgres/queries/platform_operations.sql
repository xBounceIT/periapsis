-- name: ListPlatformUsersOperation :one
SELECT app.list_platform_users_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.narg(after_user_id)::uuid,
  sqlc.arg(page_limit)::integer,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: GetPlatformGlobalSettingsOperation :one
SELECT settings.platform_name::text AS platform_name,
       settings.default_locale::text AS default_locale,
       settings.default_timezone::text AS default_timezone,
       coalesce(settings.support_url, '')::text AS support_url,
       settings.version::integer AS version,
       settings.updated_at::timestamptz AS updated_at
FROM app.get_platform_global_settings_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS settings(
  platform_name, default_locale, default_timezone, support_url, version, updated_at
);

-- name: UpdatePlatformGlobalSettingsOperation :one
SELECT settings.platform_name::text AS platform_name,
       settings.default_locale::text AS default_locale,
       settings.default_timezone::text AS default_timezone,
       coalesce(settings.support_url, '')::text AS support_url,
       settings.version::integer AS version,
       settings.updated_at::timestamptz AS updated_at
FROM app.update_platform_global_settings_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(platform_name)::text,
  sqlc.arg(default_locale)::text,
  sqlc.arg(default_timezone)::text,
  sqlc.narg(support_url)::text,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS settings(
  platform_name, default_locale, default_timezone, support_url, version, updated_at
);

-- name: GetPlatformOperationHealth :one
SELECT app.get_platform_operation_health_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: ListPlatformOperationQueues :one
SELECT app.list_platform_operation_queues_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: ListPlatformFailedNotifications :one
SELECT app.list_platform_failed_notifications_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.narg(after_failure_at)::timestamptz,
  sqlc.narg(after_delivery_id)::uuid,
  sqlc.arg(page_limit)::integer,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: ListPlatformFeatureFlags :one
SELECT app.list_platform_feature_flags_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
)::jsonb AS document;

-- name: UpdatePlatformFeatureFlag :one
SELECT flag.key::text AS key,
       flag.enabled::boolean AS enabled,
       flag.version::integer AS version,
       flag.updated_at::timestamptz AS updated_at
FROM app.update_platform_feature_flag_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(flag_key)::text,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(enabled)::boolean,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS flag(key, enabled, version, updated_at);
