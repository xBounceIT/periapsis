-- name: GetTenantSettings :one
SELECT settings.tenant_id::uuid AS tenant_id,
       settings.brand_name::text AS brand_name,
       settings.brand_mark::text AS brand_mark,
       settings.primary_color::text AS primary_color,
       settings.accent_color::text AS accent_color,
       settings.timezone::text AS timezone,
       settings.locale::text AS locale,
       settings.version::integer AS version,
       settings.updated_at::timestamptz AS updated_at
FROM app.get_tenant_settings_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text
) AS settings(
  tenant_id, brand_name, brand_mark, primary_color, accent_color,
  timezone, locale, version, updated_at
);

-- name: UpdateTenantSettings :one
SELECT settings.tenant_id::uuid AS tenant_id,
       settings.brand_name::text AS brand_name,
       settings.brand_mark::text AS brand_mark,
       settings.primary_color::text AS primary_color,
       settings.accent_color::text AS accent_color,
       settings.timezone::text AS timezone,
       settings.locale::text AS locale,
       settings.version::integer AS version,
       settings.updated_at::timestamptz AS updated_at
FROM app.update_tenant_settings_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(brand_name)::text,
  sqlc.arg(brand_mark)::text,
  sqlc.arg(primary_color)::text,
  sqlc.arg(accent_color)::text,
  sqlc.arg(timezone)::text,
  sqlc.arg(locale)::text,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS settings(
  tenant_id, brand_name, brand_mark, primary_color, accent_color,
  timezone, locale, version, updated_at
);
