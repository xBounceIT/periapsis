-- name: GetTenantTicketNumberingPolicy :one
SELECT policy.version_id::uuid AS version_id,
       policy.tenant_id::uuid AS tenant_id,
       policy.aggregate_kind::text AS aggregate_kind,
       policy.version::integer AS version,
       policy.prefix::text AS prefix,
       policy.separator::text AS separator,
       policy.period::text AS period,
       policy.width::integer AS width,
       policy.start::bigint AS start,
       policy.published_by_membership_id::uuid AS published_by_membership_id,
       policy.published_at::timestamptz AS published_at
FROM app.get_tenant_ticket_numbering_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(aggregate_kind)::public.ticket_aggregate_kind
) AS policy(
  version_id, tenant_id, aggregate_kind, version, prefix, separator,
  period, width, start, published_by_membership_id, published_at
);

-- name: PrepareReplaceTenantTicketNumberingPolicy :one
SELECT policy.replayed::boolean AS replayed,
       policy.version_id::uuid AS version_id,
       policy.tenant_id::uuid AS tenant_id,
       policy.aggregate_kind::text AS aggregate_kind,
       policy.version::integer AS version,
       policy.prefix::text AS prefix,
       policy.separator::text AS separator,
       policy.period::text AS period,
       policy.width::integer AS width,
       policy.start::bigint AS start,
       policy.published_by_membership_id::uuid AS published_by_membership_id,
       policy.published_at::timestamptz AS published_at
FROM app.prepare_replace_tenant_ticket_numbering_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(aggregate_kind)::public.ticket_aggregate_kind,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea
) AS policy(
  replayed, version_id, tenant_id, aggregate_kind, version, prefix,
  separator, period, width, start, published_by_membership_id, published_at
);

-- name: CommitReplaceTenantTicketNumberingPolicy :one
SELECT policy.version_id::uuid AS version_id,
       policy.tenant_id::uuid AS tenant_id,
       policy.aggregate_kind::text AS aggregate_kind,
       policy.version::integer AS version,
       policy.prefix::text AS prefix,
       policy.separator::text AS separator,
       policy.period::text AS period,
       policy.width::integer AS width,
       policy.start::bigint AS start,
       policy.published_by_membership_id::uuid AS published_by_membership_id,
       policy.published_at::timestamptz AS published_at
FROM app.commit_replace_tenant_ticket_numbering_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(aggregate_kind)::public.ticket_aggregate_kind,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(version_id)::uuid,
  sqlc.arg(result_version)::integer,
  sqlc.arg(prefix)::text,
  sqlc.arg(separator)::text,
  sqlc.arg(period)::public.ticket_numbering_period,
  sqlc.arg(width)::integer,
  sqlc.arg(start)::bigint,
  sqlc.arg(namespace_digest)::bytea,
  sqlc.arg(published_at)::timestamptz,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS policy(
  version_id, tenant_id, aggregate_kind, version, prefix, separator,
  period, width, start, published_by_membership_id, published_at
);
