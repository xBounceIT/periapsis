-- name: SetUserContext :one
SELECT set_config('app.user_id', sqlc.arg(user_id)::uuid::text, true)::text AS user_id;

-- name: VerifyProtectedConfiguration :one
SELECT app.verify_protected_configuration(
  sqlc.arg(authority_digest)::bytea,
  sqlc.arg(master_key_verifier)::bytea
) AS bootstrap_available;

-- name: ReserveBootstrap :one
SELECT app.reserve_platform_bootstrap(
  sqlc.arg(enrollment_id)::uuid,
  sqlc.arg(authority_digest)::bytea,
  sqlc.arg(enrollment_digest)::bytea,
  sqlc.arg(enrollment_rate_key_digest)::bytea,
  sqlc.arg(canonical_email)::text,
  sqlc.arg(totp_ciphertext)::bytea,
  sqlc.arg(totp_nonce)::bytea,
  sqlc.arg(totp_aad)::bytea,
  sqlc.arg(totp_key_version)::integer,
  sqlc.arg(expires_at)::timestamptz,
  sqlc.arg(max_attempts)::integer,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS enrollment_id;

-- name: GetBootstrapEnrollment :one
SELECT enrollment.enrollment_id::uuid AS enrollment_id,
       enrollment.canonical_email::text AS canonical_email,
       enrollment.totp_secret_ciphertext::bytea AS totp_secret_ciphertext,
       enrollment.totp_secret_nonce::bytea AS totp_secret_nonce,
       enrollment.totp_secret_aad::bytea AS totp_secret_aad,
       enrollment.totp_key_version::integer AS totp_key_version,
       enrollment.expires_at::timestamptz AS expires_at,
       enrollment.attempts::integer AS attempts,
       enrollment.max_attempts::integer AS max_attempts
FROM app.get_platform_bootstrap_enrollment(
  sqlc.arg(authority_digest)::bytea,
  sqlc.arg(enrollment_digest)::bytea
) AS enrollment(
  enrollment_id, canonical_email, totp_secret_ciphertext, totp_secret_nonce,
  totp_secret_aad, totp_key_version, expires_at, attempts, max_attempts
);

-- name: ConfirmBootstrap :one
SELECT app.confirm_platform_bootstrap(
  sqlc.arg(authority_digest)::bytea,
  sqlc.arg(enrollment_digest)::bytea,
  sqlc.arg(user_id)::uuid,
  sqlc.arg(local_credential_id)::uuid,
  sqlc.arg(totp_credential_id)::uuid,
  sqlc.arg(totp_ciphertext)::bytea,
  sqlc.arg(totp_nonce)::bytea,
  sqlc.arg(totp_aad)::bytea,
  sqlc.arg(totp_key_version)::integer,
  sqlc.arg(platform_role_grant_id)::uuid,
  sqlc.arg(canonical_email)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(password_phc)::text,
  1::integer,
  sqlc.arg(initial_totp_counter)::bigint,
  sqlc.arg(recovery_code_ids)::uuid[],
  sqlc.arg(recovery_code_digests)::bytea[],
  1::integer,
  sqlc.arg(session_id)::uuid,
  sqlc.arg(rotation_family_id)::uuid,
  sqlc.arg(session_token_digest)::bytea,
  sqlc.arg(csrf_digest)::bytea,
  sqlc.arg(idle_expires_at)::timestamptz,
  sqlc.arg(absolute_expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS session_id;

-- name: GetLocalCredential :one
SELECT credential.user_id::uuid AS user_id,
       credential.password_phc::text AS password_phc,
       credential.password_algorithm::text AS password_algorithm,
       credential.password_version::integer AS password_version,
       credential.must_rotate::boolean AS must_rotate
FROM app.get_local_break_glass_credential(sqlc.arg(canonical_email)::text)
  AS credential(user_id, password_phc, password_algorithm, password_version, must_rotate);

-- name: CreateMFAChallenge :one
SELECT app.create_auth_challenge(
  sqlc.arg(challenge_id)::uuid,
  sqlc.arg(user_id)::uuid,
  sqlc.arg(challenge_rate_key_digest)::bytea,
  sqlc.arg(mfa_rate_key_digest)::bytea,
  sqlc.arg(login_account_rate_key_digest)::bytea,
  sqlc.arg(token_digest)::bytea,
  'mfa_login'::auth_challenge_purpose,
  sqlc.arg(expires_at)::timestamptz,
  sqlc.arg(max_attempts)::integer,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  'local_password'::text
) AS challenge_id;

-- name: GetMFAChallenge :one
SELECT challenge.challenge_id::uuid AS challenge_id,
       challenge.user_id::uuid AS user_id,
       challenge.attempts::integer AS attempts,
       challenge.max_attempts::integer AS max_attempts,
       challenge.expires_at::timestamptz AS expires_at,
       credential.credential_id::uuid AS credential_id,
       credential.secret_ciphertext::bytea AS secret_ciphertext,
       credential.secret_nonce::bytea AS secret_nonce,
       credential.secret_aad::bytea AS secret_aad,
       credential.key_version::integer AS key_version,
       credential.last_accepted_counter::bigint AS last_accepted_counter
FROM app.get_auth_challenge(
  sqlc.arg(challenge_digest)::bytea,
  'mfa_login'::auth_challenge_purpose
) AS challenge(challenge_id, user_id, purpose, attempts, max_attempts, expires_at)
CROSS JOIN LATERAL app.get_totp_credential(challenge.user_id::uuid) AS credential(
  credential_id, secret_ciphertext, secret_nonce, secret_aad, key_version,
  encryption_algorithm, otp_algorithm, digits, period_seconds, last_accepted_counter
);

-- name: CompleteMFALogin :one
SELECT completion.session_id::uuid AS session_id,
       completion.failure_recorded::boolean AS failure_recorded,
       completion.blocked_until::timestamptz AS blocked_until
FROM app.complete_mfa_login(
  sqlc.arg(challenge_digest)::bytea,
  sqlc.arg(authentication_method)::text,
  sqlc.narg(totp_counter)::bigint,
  sqlc.narg(recovery_code_digest)::bytea,
  sqlc.arg(session_id)::uuid,
  sqlc.arg(rotation_family_id)::uuid,
  NULL::uuid,
  sqlc.arg(session_token_digest)::bytea,
  sqlc.arg(csrf_digest)::bytea,
  sqlc.arg(idle_expires_at)::timestamptz,
  sqlc.arg(absolute_expires_at)::timestamptz,
  sqlc.arg(failure_scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(failure_key_digests)::bytea[],
  sqlc.arg(failure_window_seconds)::integer[],
  sqlc.arg(failure_max_attempts)::integer[],
  sqlc.arg(failure_block_seconds)::integer[],
  sqlc.arg(clear_scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(clear_key_digests)::bytea[],
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS completion(session_id, failure_recorded, blocked_until);

-- name: ResolveSession :one
SELECT session.session_id::uuid AS session_id,
       session.user_id::uuid AS user_id,
       session.rotation_family_id::uuid AS rotation_family_id,
       COALESCE(session.email::text, '')::text AS email,
       session.display_name::text AS display_name,
       session.active_tenant_id::uuid AS active_tenant_id,
       session.csrf_secret_digest::bytea AS csrf_secret_digest,
       session.authentication_method::text AS authentication_method,
       session.created_at::timestamptz AS created_at,
       session.last_seen_at::timestamptz AS last_seen_at,
       session.idle_expires_at::timestamptz AS idle_expires_at,
       session.absolute_expires_at::timestamptz AS absolute_expires_at,
       session.platform_permissions::text[] AS platform_permissions
FROM app.get_auth_session_v3(sqlc.arg(token_digest)::bytea) AS session(
  session_id, user_id, rotation_family_id, email, display_name, active_tenant_id,
  csrf_secret_digest, authentication_method, mfa_satisfied_at, created_at,
  last_seen_at, idle_expires_at, absolute_expires_at, platform_permissions
);

-- name: TouchSession :one
SELECT app.touch_auth_session(
  sqlc.arg(token_digest)::bytea,
  sqlc.arg(idle_expires_at)::timestamptz
) AS touched;

-- name: RotateSession :one
SELECT app.rotate_auth_session(
  sqlc.arg(current_token_digest)::bytea,
  sqlc.arg(new_session_id)::uuid,
  sqlc.arg(new_token_digest)::bytea,
  sqlc.arg(new_csrf_digest)::bytea,
  sqlc.arg(idle_expires_at)::timestamptz,
  sqlc.arg(absolute_expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS session_id;

-- name: ListUserSessions :many
SELECT session.session_id::uuid AS session_id,
       session.current::boolean AS current,
       session.authentication_method::text AS authentication_method,
       session.last_seen_at::timestamptz AS last_seen_at,
       session.idle_expires_at::timestamptz AS idle_expires_at,
       session.absolute_expires_at::timestamptz AS absolute_expires_at,
       session.revoked_at::timestamptz AS revoked_at,
       session.created_at::timestamptz AS created_at
FROM app.list_user_sessions(
  sqlc.arg(current_session_id)::uuid,
  sqlc.narg(after_session_id)::uuid,
  sqlc.arg(page_size)::integer
) AS session(
  session_id, current, active_tenant_id, authentication_method, mfa_satisfied_at,
  last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoke_reason, created_at
);

-- name: RevokeUserSession :one
SELECT app.revoke_user_session(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS revoked;

-- name: ListUserTenantMemberships :many
SELECT membership.membership_id::uuid AS membership_id,
       membership.tenant_id::uuid AS tenant_id,
       membership.tenant_slug::text AS tenant_slug,
       membership.tenant_name::text AS tenant_name,
       membership.membership_role::text AS membership_role,
       membership.tenant_status::text AS tenant_status,
       membership.timezone::text AS timezone,
       membership.locale::text AS locale,
       membership.created_at::timestamptz AS created_at,
       membership.updated_at::timestamptz AS updated_at
FROM app.list_user_tenant_memberships(
  sqlc.narg(after_membership_id)::uuid,
  sqlc.arg(page_size)::integer
) AS membership(
  membership_id, tenant_id, tenant_slug, tenant_name, membership_role,
  membership_status, tenant_status, timezone, locale, created_at, updated_at
);

-- name: RotateSessionTenant :one
SELECT app.rotate_auth_session_tenant(
  sqlc.arg(current_token_digest)::bytea,
  sqlc.arg(new_session_id)::uuid,
  sqlc.arg(new_token_digest)::bytea,
  sqlc.arg(new_csrf_digest)::bytea,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(idle_expires_at)::timestamptz,
  sqlc.arg(absolute_expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS session_id;

-- name: GetAuthRateLimit :one
SELECT rate.attempt_count::integer AS attempt_count,
       rate.window_expires_at::timestamptz AS window_expires_at,
       rate.blocked_until::timestamptz AS blocked_until
FROM app.get_auth_rate_limit(
  sqlc.arg(scope)::auth_rate_limit_scope,
  sqlc.arg(key_digest)::bytea
) AS rate(attempt_count, window_expires_at, blocked_until);

-- name: AdmitAuthAttempts :one
SELECT admission.admitted::boolean AS admitted,
       admission.maximum_attempt_count::integer AS maximum_attempt_count,
       admission.blocked_until::timestamptz AS blocked_until
FROM app.admit_auth_attempts(
  sqlc.arg(scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(key_digests)::bytea[],
  sqlc.arg(window_seconds)::integer[],
  sqlc.arg(max_attempts)::integer[],
  sqlc.arg(block_seconds)::integer[]
) AS admission(admitted, maximum_attempt_count, blocked_until);

-- name: RecordAuthenticationFailure :one
SELECT app.record_authentication_failure(
  'local_login'::auth_rate_limit_scope,
  sqlc.arg(metered_key_digest)::bytea,
  sqlc.narg(user_id)::uuid,
  sqlc.arg(audit_id)::uuid,
  'invalid_credentials'::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  'local_password'::text
) AS recorded;

-- name: RecordAuthRateLimitFailure :one
SELECT failure.maximum_attempt_count::integer AS maximum_attempt_count,
       failure.blocked_until::timestamptz AS blocked_until
FROM app.record_auth_rate_limit_failure(
  sqlc.arg(scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(key_digests)::bytea[],
  sqlc.arg(window_seconds)::integer[],
  sqlc.arg(max_attempts)::integer[],
  sqlc.arg(block_seconds)::integer[],
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text
) AS failure(maximum_attempt_count, blocked_until);

-- name: RecordBootstrapFailure :one
SELECT failure.enrollment_attempts::integer AS enrollment_attempts,
       failure.enrollment_exhausted::boolean AS enrollment_exhausted,
       failure.maximum_rate_attempt_count::integer AS maximum_rate_attempt_count,
       failure.blocked_until::timestamptz AS blocked_until
FROM app.record_platform_bootstrap_failure(
  sqlc.arg(authority_digest)::bytea,
  sqlc.arg(enrollment_digest)::bytea,
  sqlc.arg(scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(key_digests)::bytea[],
  sqlc.arg(window_seconds)::integer[],
  sqlc.arg(max_attempts)::integer[],
  sqlc.arg(block_seconds)::integer[],
  sqlc.arg(audit_id)::uuid,
  'invalid_totp_proof'::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text
) AS failure(
  enrollment_attempts, enrollment_exhausted, maximum_rate_attempt_count, blocked_until
);

-- name: RecordMFAFailure :one
SELECT failure.challenge_attempts::integer AS challenge_attempts,
       failure.challenge_exhausted::boolean AS challenge_exhausted,
       failure.maximum_rate_attempt_count::integer AS maximum_rate_attempt_count,
       failure.blocked_until::timestamptz AS blocked_until
FROM app.record_mfa_challenge_failure(
  sqlc.arg(challenge_digest)::bytea,
  sqlc.arg(scopes)::text[]::auth_rate_limit_scope[],
  sqlc.arg(key_digests)::bytea[],
  sqlc.arg(window_seconds)::integer[],
  sqlc.arg(max_attempts)::integer[],
  sqlc.arg(block_seconds)::integer[],
  sqlc.arg(audit_id)::uuid,
  'invalid_mfa_proof'::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text
) AS failure(
  challenge_attempts, challenge_exhausted, maximum_rate_attempt_count, blocked_until
);
