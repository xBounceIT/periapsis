CREATE TABLE "platform_saml_tenant_switch_commands" (
	"source_session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"authentication_method" text DEFAULT 'saml' NOT NULL,
	"target_tenant_id" uuid NOT NULL,
	"target_tenant_version" bigint NOT NULL,
	"membership_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"binding_version" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_epoch_version" bigint NOT NULL,
	"access_source_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"access_grant_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"request_snapshot" jsonb NOT NULL,
	"decision" text NOT NULL,
	"rotated_session_id" uuid,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_saml_tenant_switch_commands_pkey" PRIMARY KEY("source_session_id","expected_version","target_tenant_id"),
	CONSTRAINT "platform_saml_tenant_switch_commands_value_check" CHECK ("platform_saml_tenant_switch_commands"."expected_version" between 1 and 2147483647
        and "platform_saml_tenant_switch_commands"."authentication_method" = 'saml'
        and "platform_saml_tenant_switch_commands"."target_tenant_version" between 1 and 2147483647
        and "platform_saml_tenant_switch_commands"."binding_version" between 1 and 2147483647
        and "platform_saml_tenant_switch_commands"."mapping_revision" between 1 and 9007199254740991
        and "platform_saml_tenant_switch_commands"."authorization_revision" between 1 and 9007199254740991
        and "platform_saml_tenant_switch_commands"."access_epoch_version" between 1 and 2147483647
        and "platform_saml_tenant_switch_commands"."access_grant_version" between 1 and 2147483647
        and octet_length("platform_saml_tenant_switch_commands"."request_digest") = 32
        and jsonb_typeof("platform_saml_tenant_switch_commands"."request_snapshot") = 'object'
        and pg_column_size("platform_saml_tenant_switch_commands"."request_snapshot") between 2 and 262144
        and "platform_saml_tenant_switch_commands"."decision" in ('rotated','stale','denied')
        and ("platform_saml_tenant_switch_commands"."decision" = 'rotated') = ("platform_saml_tenant_switch_commands"."rotated_session_id" is not null)
        and jsonb_typeof("platform_saml_tenant_switch_commands"."result_snapshot") = 'object'
        and pg_column_size("platform_saml_tenant_switch_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "platform_saml_tenant_switch_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TRIGGER platform_saml_tenant_switch_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_tenant_switch_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
--> statement-breakpoint
ALTER TABLE "platform_post_primary_totp_challenges" DROP CONSTRAINT "platform_post_primary_totp_challenges_continuation_key";--> statement-breakpoint
ALTER TABLE "platform_saml_tenant_switch_commands" ADD CONSTRAINT "platform_saml_tenant_switch_commands_target_tenant_id_tenants_id_fk" FOREIGN KEY ("target_tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_tenant_switch_commands" ADD CONSTRAINT "platform_saml_tenant_switch_commands_rotated_session_id_auth_sessions_id_fk" FOREIGN KEY ("rotated_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_tenant_switch_commands" ADD CONSTRAINT "platform_saml_tenant_switch_commands_source_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_session_platform_saml_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_post_primary_totp_challenges_live_continuation_key" ON "platform_post_primary_totp_challenges" USING btree ("continuation_id") WHERE "platform_post_primary_totp_challenges"."state" = 'pending';
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_tenant_switch_assurance_v1(
  p_session_id uuid,p_observed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE provider_count integer;
DECLARE totp_count integer;
DECLARE assurance_level text;
DECLARE assurance_authenticated_at timestamptz;
DECLARE assurance_expires_at timestamptz;
BEGIN
  SELECT count(*) FILTER (WHERE evidence.kind='platform_provider')::integer,
         count(*) FILTER (WHERE evidence.kind='totp')::integer
    INTO provider_count,totp_count
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  WHERE evidence.session_id=p_session_id;
  IF provider_count<>1 OR totp_count NOT BETWEEN 0 AND 1 THEN RETURN NULL; END IF;
  SELECT ranked.level,ranked.authenticated_at,ranked.expires_at
    INTO STRICT assurance_level,assurance_authenticated_at,assurance_expires_at
  FROM (
    SELECT evidence.level,evidence.authenticated_at,evidence.expires_at,
      CASE evidence.level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
        WHEN 'phishing_resistant' THEN 3 ELSE 0 END AS level_rank,evidence.id
    FROM ONLY public.auth_session_platform_saml_evidence AS evidence
    WHERE evidence.session_id=p_session_id
      AND (evidence.expires_at IS NULL OR evidence.expires_at>p_observed_at)
    ORDER BY level_rank DESC,evidence.authenticated_at DESC,evidence.id LIMIT 1
  ) AS ranked;
  RETURN jsonb_build_object(
    'level',assurance_level,'authenticatedAt',to_jsonb(assurance_authenticated_at),
    'expiresAt',to_jsonb(assurance_expires_at),'localSatisfied',totp_count=1
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RETURN NULL;
END;
$function$;
--> statement-breakpoint

-- Completing the SAML-only local step-up moves the encrypted SAML session
-- material to the exact successor and, for a revalidation continuation,
-- revokes the exact source in the same transaction. Any missing or ambiguous
-- material/provenance aborts the whole apply.
CREATE FUNCTION app.private_platform_saml_totp_completion_fence_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  continuation public.platform_saml_post_primary_continuations%ROWTYPE;
  successor_id uuid;
  moved_count integer;
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.state <> 'pending' OR NEW.state <> 'completed' THEN
    RETURN NEW;
  END IF;
  IF current_setting('app.platform_saml_direct_runtime_write_v1',true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'direct platform SAML TOTP completion requires runtime capability'
      USING ERRCODE='42501';
  END IF;
  successor_id := app.private_mfa_require_uuidv7_v1(
    NEW.result_snapshot ->> 'sessionId'
  );
  SELECT parent.* INTO STRICT continuation
  FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=NEW.continuation_id AND parent.user_id=NEW.user_id
    AND parent.authority='direct_platform_saml'
    AND parent.authentication_method='saml'
  FOR UPDATE;
  IF continuation.state<>'consumed' OR continuation.consumed_at<>NEW.completed_at THEN
    RAISE EXCEPTION 'direct platform SAML TOTP continuation completion is not exact'
      USING ERRCODE='40001';
  END IF;
  IF continuation.origin='initial_login' THEN
    UPDATE ONLY public.platform_saml_session_materials AS material
    SET session_id=successor_id,continuation_id=NULL
    WHERE material.continuation_id=continuation.id;
    GET DIAGNOSTICS moved_count=ROW_COUNT;
  ELSIF continuation.origin='session_revalidation' THEN
    IF continuation.source_session_id IS NULL
       OR continuation.source_session_family_id IS NULL
       OR continuation.source_session_version IS NULL
       OR continuation.source_absolute_expires_at IS NULL
       OR NOT EXISTS (
         SELECT 1
         FROM ONLY public.auth_sessions AS source
         JOIN ONLY public.auth_session_platform_saml_states AS state
           ON state.session_id=source.id AND state.user_id=source.user_id
          AND state.authority='direct_platform_saml'
          AND state.authentication_method='saml'
          AND state.primary_kind='platform_provider'
         JOIN ONLY public.auth_session_platform_saml_provenance AS provenance
           ON provenance.session_id=state.session_id
          AND provenance.user_id=state.user_id
          AND provenance.platform_provider_id=continuation.platform_provider_id
          AND provenance.external_identity_id=continuation.external_identity_id
         WHERE source.id=continuation.source_session_id
           AND source.user_id=continuation.user_id
           AND source.rotation_family_id=continuation.source_session_family_id
           AND source.active_tenant_id IS NULL
           AND source.authentication_method='saml'
           AND source.revoked_at IS NULL
           AND source.absolute_expires_at=continuation.source_absolute_expires_at
           AND state.session_version=continuation.source_session_version
         FOR UPDATE OF source,state,provenance
       ) THEN
      RAISE EXCEPTION 'direct platform SAML TOTP source session is stale'
        USING ERRCODE='40001';
    END IF;
    UPDATE ONLY public.platform_saml_session_materials AS material
    SET session_id=successor_id,continuation_id=NULL
    WHERE material.session_id=continuation.source_session_id;
    GET DIAGNOSTICS moved_count=ROW_COUNT;
    UPDATE ONLY public.auth_sessions AS source
    SET revoked_at=NEW.completed_at,
        revoke_reason='session_revalidation_totp_completed'
    WHERE source.id=continuation.source_session_id
      AND source.user_id=continuation.user_id
      AND source.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform SAML TOTP source revocation lost CAS'
        USING ERRCODE='40001';
    END IF;
  ELSE
    RAISE EXCEPTION 'direct platform SAML TOTP continuation origin is invalid'
      USING ERRCODE='22023';
  END IF;
  IF moved_count<>1 THEN
    RAISE EXCEPTION 'direct platform SAML TOTP session material is ambiguous'
      USING ERRCODE='40001';
  END IF;
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'direct platform SAML TOTP completion authority is ambiguous'
    USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER platform_saml_totp_completion_fence_v1
AFTER UPDATE ON public.platform_saml_post_primary_totp_challenges
FOR EACH ROW EXECUTE FUNCTION app.private_platform_saml_totp_completion_fence_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.cleanup_platform_saml_post_primary_totp_apply_v1(
  p_request jsonb
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
  result jsonb;
  original jsonb;
  cleaned_at timestamptz;
  provider_id uuid;
  result_session_id uuid;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['request','result','reason','cleanedUpAt','audit'],
    ARRAY['request','result','reason','cleanedUpAt','audit'],262144
  );
  result:=p_request->'result';
  original:=p_request->'request';
  cleaned_at:=(p_request->>'cleanedUpAt')::timestamptz;
  IF p_request->>'reason'<>'delivery_failed'
     OR result->>'category' NOT IN ('success','already_applied')
     OR cleaned_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                           AND statement_timestamp()+interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform SAML TOTP cleanup request'
      USING ERRCODE='22023';
  END IF;
  result_session_id:=app.private_mfa_require_uuidv7_v1(result->>'sessionId');
  SELECT existing.* INTO challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(original->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(
      original->>'continuationId')
  FOR UPDATE;
  IF NOT FOUND THEN RETURN true; END IF;
  SELECT parent.platform_provider_id INTO STRICT provider_id
  FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=challenge.continuation_id
    AND parent.authority='direct_platform_saml'
    AND parent.authentication_method='saml';
  IF challenge.state<>'completed'
     OR challenge.completion_request_digest<>app.private_mfa_decode_base64_v1(
       original->>'completionRequestDigest',32,32)
     OR challenge.completion_request_snapshot IS DISTINCT FROM original-'audit'
     OR jsonb_set(challenge.result_snapshot,'{category}',result->'category')
       IS DISTINCT FROM result
     OR challenge.result_snapshot->>'sessionId'<>result_session_id::text THEN
    RAISE EXCEPTION 'direct platform SAML TOTP cleanup proof mismatch'
      USING ERRCODE='23505';
  END IF;
  IF challenge.cleaned_up_at IS NOT NULL THEN
    IF challenge.cleanup_reason<>'delivery_failed'
       OR challenge.cleaned_up_at<>cleaned_at THEN
      RAISE EXCEPTION 'direct platform SAML TOTP cleanup replay collision'
        USING ERRCODE='23505';
    END IF;
    RETURN true;
  END IF;
  UPDATE ONLY public.auth_sessions AS session
  SET revoked_at=coalesce(session.revoked_at,cleaned_at),
      revoke_reason=coalesce(session.revoke_reason,'saml_totp_delivery_failed')
  WHERE session.id=result_session_id
    AND session.user_id=challenge.user_id
    AND session.authentication_method='saml';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform SAML TOTP cleanup session is unavailable'
      USING ERRCODE='40001';
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS changed
  SET cleanup_reason='delivery_failed',cleaned_up_at=cleaned_at,
      version=changed.version+1
  WHERE changed.id=challenge.id AND changed.state='completed'
    AND changed.cleaned_up_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform SAML TOTP cleanup lost CAS'
      USING ERRCODE='40001';
  END IF;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request->'audit',uuidv7(),'platform.saml.totp.delivery_failed',
    'platform_identity_provider',provider_id,'failure',
    jsonb_build_object('sessionId',result_session_id)
  );
  RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML TOTP cleanup request'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

-- V42 replaces the OIDC TOTP begin boundary without rewriting the sealed v1
-- source. A new browser ceremony supersedes the one active challenge under the
-- already locked continuation; exact retries of the current challenge remain
-- read-only.
CREATE FUNCTION app.begin_platform_post_primary_totp_v2(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge jsonb;
  continuation_id uuid;
  receipt_digest bytea;
  expected_version bigint;
  challenge_id bytea;
  browser_digest bytea;
  created_at timestamptz;
  expires_at timestamptz;
  observed_at timestamptz;
  continuation_record public.platform_post_primary_continuations%ROWTYPE;
  factor_record public.totp_credentials%ROWTYPE;
  challenge_record public.platform_post_primary_totp_challenges%ROWTYPE;
  superseded boolean := false;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['continuationId','receiptDigest','expectedVersion','challenge',
      'observedAt','audit'],
    ARRAY['continuationId','receiptDigest','expectedVersion','challenge',
      'observedAt','audit'],32768
  );
  challenge := p_request -> 'challenge';
  PERFORM app.private_platform_oidc_direct_json_v1(
    challenge,ARRAY['id','browserDigest','createdAt','expiresAt'],
    ARRAY['id','browserDigest','createdAt','expiresAt'],8192
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_request ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'receiptDigest',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  challenge_id := app.private_mfa_decode_base64_v1(challenge ->> 'id',32,32);
  browser_digest := app.private_mfa_decode_base64_v1(
    challenge ->> 'browserDigest',32,32
  );
  created_at := (challenge ->> 'createdAt')::timestamptz;
  expires_at := (challenge ->> 'expiresAt')::timestamptz;
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  IF expected_version <> 1
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR created_at <> observed_at
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds'
     OR expires_at NOT BETWEEN created_at + interval '1 minute'
                           AND created_at + interval '10 minutes' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP begin request'
      USING ERRCODE = '22023';
  END IF;
  SELECT continuation.* INTO STRICT continuation_record
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE continuation.id = continuation_id
    AND continuation.receipt_digest = receipt_digest
  FOR UPDATE;
  IF continuation_record.state <> 'pending'
     OR continuation_record.version <> expected_version
     OR continuation_record.expires_at <= observed_at
     OR expires_at > continuation_record.expires_at
     OR NOT app.private_platform_oidc_direct_continuation_source_live_v1(
       continuation_record,observed_at
     )
     OR NOT app.private_platform_oidc_direct_authority_live_v1(
       continuation_record.platform_provider_id,continuation_record.user_id,
       continuation_record.external_identity_id,
       continuation_record.provider_revision,
       continuation_record.security_revision,
       continuation_record.login_policy_revision,
       continuation_record.user_authentication_revision,
       continuation_record.identity_version,
       continuation_record.alias_key_version,
       continuation_record.assurance_policy_revision,
       continuation_record.platform_floor_policy_id,
       continuation_record.platform_floor_policy_revision,
       continuation_record.trust_rule_id,continuation_record.trust_rule_revision
     ) THEN
    RETURN NULL;
  END IF;
  SELECT factor.* INTO STRICT factor_record
  FROM ONLY public.totp_credentials AS factor
  WHERE factor.id = continuation_record.selected_totp_credential_id
    AND factor.user_id = continuation_record.user_id
    AND factor.security_revision =
      continuation_record.selected_totp_security_revision
    AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
  FOR SHARE;

  SELECT existing.* INTO challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS existing
  WHERE existing.id = challenge_id
  FOR UPDATE;
  IF FOUND THEN
    IF challenge_record.continuation_id <> continuation_id
       OR challenge_record.browser_digest <> browser_digest
       OR challenge_record.expected_continuation_version <> expected_version
       OR challenge_record.created_at <> created_at
       OR challenge_record.expires_at <> expires_at
       OR challenge_record.state <> 'pending' THEN
      RAISE EXCEPTION 'direct platform OIDC TOTP begin replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
  END IF;

  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  SELECT existing.* INTO challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS existing
  WHERE existing.continuation_id = continuation_id
    AND existing.state = 'pending'
  FOR UPDATE;
  IF FOUND THEN
    IF challenge_record.version >= 2147483647 THEN
      RAISE EXCEPTION 'direct platform OIDC TOTP challenge revision is exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE ONLY public.platform_post_primary_totp_challenges AS old_challenge
    SET state = 'abandoned', version = old_challenge.version + 1,
        abandoned_at = observed_at
    WHERE old_challenge.id = challenge_record.id
      AND old_challenge.state = 'pending';
    superseded := true;
  END IF;
  INSERT INTO public.platform_post_primary_totp_challenges (
    id,continuation_id,user_id,totp_credential_id,browser_digest,
    expected_continuation_version,user_authentication_revision,
    totp_security_revision,failure_count,state,version,created_at,expires_at
  ) VALUES (
    challenge_id,continuation_id,continuation_record.user_id,factor_record.id,
    browser_digest,expected_version,
    continuation_record.user_authentication_revision,
    factor_record.security_revision,0,'pending',1,created_at,expires_at
  ) RETURNING * INTO challenge_record;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.totp_started',
    'platform_identity_account',continuation_record.external_identity_id,
    'success',jsonb_build_object(
      'provider_id',continuation_record.platform_provider_id,
      'user_id',continuation_record.user_id,
      'totp_security_revision',factor_record.security_revision,
      'superseded_previous_challenge',superseded
    )
  );
  RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP begin request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.lookup_platform_saml_tenant_switch_replay_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  target_tenant_id uuid;
  new_session_id uuid;
  rotation_family_id uuid;
  source_token_digest bytea;
  new_token_digest bytea;
  csrf_secret_digest bytea;
  occurred_at timestamptz;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  audit jsonb;
  audit_event_id uuid;
  audit_request_id uuid;
  audit_correlation_id uuid;
  audit_ip_address inet;
  matched_result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,
    ARRAY['sourceSessionId','targetTenantId','newSessionId',
      'rotationFamilyId','sourceTokenDigest','newTokenDigest',
      'csrfSecretDigest','occurredAt','idleExpiresAt','absoluteExpiresAt',
      'audit'],
    ARRAY['sourceSessionId','targetTenantId','newSessionId',
      'rotationFamilyId','sourceTokenDigest','newTokenDigest',
      'csrfSecretDigest','occurredAt','idleExpiresAt','absoluteExpiresAt',
      'audit'],32768
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sourceSessionId'
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'targetTenantId'
  );
  new_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'newSessionId'
  );
  rotation_family_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'rotationFamilyId'
  );
  source_token_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'sourceTokenDigest',32,32
  );
  new_token_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'newTokenDigest',32,32
  );
  csrf_secret_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'csrfSecretDigest',32,32
  );
  occurred_at := (p_lookup ->> 'occurredAt')::timestamptz;
  idle_expires_at := (p_lookup ->> 'idleExpiresAt')::timestamptz;
  absolute_expires_at := (p_lookup ->> 'absoluteExpiresAt')::timestamptz;
  audit := p_lookup -> 'audit';
  PERFORM app.private_platform_saml_direct_json_v1(
    audit,
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod','reason'],
    ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
  );
  audit_event_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'eventId'
  );
  audit_request_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'requestId'
  );
  audit_correlation_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'correlationId'
  );
  IF audit ? 'ipAddress' AND audit ->> 'ipAddress' <> '' THEN
    audit_ip_address := (audit ->> 'ipAddress')::inet;
  END IF;
  IF source_session_id = new_session_id
     OR source_token_digest IN (new_token_digest,csrf_secret_digest)
     OR new_token_digest = csrf_secret_digest
     OR pg_catalog.encode(source_token_digest,'hex') = pg_catalog.repeat('00',32)
     OR pg_catalog.encode(new_token_digest,'hex') = pg_catalog.repeat('00',32)
     OR pg_catalog.encode(csrf_secret_digest,'hex') = pg_catalog.repeat('00',32)
     OR audit ->> 'authenticationMethod' <> 'saml'
     OR idle_expires_at <= occurred_at
     OR absolute_expires_at < idle_expires_at THEN
    RAISE EXCEPTION 'invalid direct platform SAML tenant switch replay lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT command.result_snapshot INTO matched_result
  FROM ONLY public.platform_saml_tenant_switch_commands AS command
  JOIN ONLY public.auth_sessions AS source_session
    ON source_session.id = command.source_session_id
  JOIN ONLY public.auth_session_platform_saml_states AS source_state
    ON source_state.session_id = source_session.id
   AND source_state.user_id = source_session.user_id
  JOIN ONLY public.auth_session_platform_saml_provenance AS source_provenance
    ON source_provenance.session_id = source_session.id
   AND source_provenance.user_id = source_session.user_id
   AND source_provenance.primary_kind = source_state.primary_kind
  JOIN ONLY public.auth_sessions AS rotated_session
    ON rotated_session.id = command.rotated_session_id
   AND rotated_session.rotated_from_session_id = source_session.id
   AND rotated_session.user_id = source_session.user_id
  JOIN ONLY public.auth_session_mfa_states AS rotated_state
    ON rotated_state.session_id = rotated_session.id
   AND rotated_state.tenant_id = command.target_tenant_id
   AND rotated_state.user_id = rotated_session.user_id
  JOIN ONLY public.auth_session_tenant_platform_federated_provenance
    AS rotated_provenance
    ON rotated_provenance.session_id = rotated_session.id
   AND rotated_provenance.tenant_id = command.target_tenant_id
   AND rotated_provenance.user_id = rotated_session.user_id
   AND rotated_provenance.primary_kind = 'tenant_platform_provider'
   AND rotated_provenance.authentication_method = 'saml'
   AND rotated_provenance.platform_provider_id =
     source_provenance.platform_provider_id
   AND rotated_provenance.external_identity_id =
     source_provenance.external_identity_id
   AND rotated_provenance.membership_id = command.membership_id
   AND rotated_provenance.binding_id = command.binding_id
   AND rotated_provenance.access_epoch_id = command.access_epoch_id
   AND rotated_provenance.access_source_id = command.access_source_id
   AND rotated_provenance.access_grant_id = command.access_grant_id
  JOIN ONLY public.platform_audit_events AS audit_event
    ON audit_event.id = audit_event_id
  WHERE command.source_session_id = source_session_id
    AND command.target_tenant_id = target_tenant_id
    AND command.rotated_session_id = new_session_id
    AND command.decision = 'rotated'
    AND command.applied_at = occurred_at
    AND command.expected_version = rotated_state.session_version - 1
    AND command.result_snapshot = jsonb_build_object(
      'applied',true,'decision','rotated',
      'sourceSessionId',source_session_id::text,
      'sessionId',new_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'sessionVersion',rotated_state.session_version
    )
    AND source_session.rotation_family_id = rotation_family_id
    AND source_session.token_digest = source_token_digest
    AND source_session.revoked_at = occurred_at
    AND source_session.revoke_reason =
      'platform_saml_tenant_switch_rotated'
    AND source_session.absolute_expires_at = absolute_expires_at
    AND source_state.session_version = command.expected_version
    AND rotated_session.rotation_family_id = rotation_family_id
    AND rotated_session.active_tenant_id = target_tenant_id
    AND rotated_session.token_digest = new_token_digest
    AND rotated_session.csrf_secret_digest = csrf_secret_digest
    AND rotated_session.authentication_method = 'saml'
    AND rotated_session.revoked_at IS NULL
    AND rotated_session.revoke_reason IS NULL
    AND rotated_session.last_seen_at = occurred_at
    AND rotated_session.idle_expires_at = idle_expires_at
    AND rotated_session.absolute_expires_at = absolute_expires_at
    AND rotated_session.created_at = occurred_at
    AND rotated_state.session_version = command.expected_version + 1
    AND rotated_state.issued_at = occurred_at
    AND rotated_state.audience = 'api'
    AND NOT rotated_state.recovery_restricted
    AND rotated_state.primary_kind = 'tenant_platform_provider'
    AND audit_event.actor_type = 'system'
    AND audit_event.actor_user_id IS NULL
    AND audit_event.action = 'platform.saml.session.tenant_switched'
    AND audit_event.resource_type = 'auth_session'
    AND audit_event.resource_id = source_session_id
    AND audit_event.request_id = audit_request_id
    AND audit_event.correlation_id = audit_correlation_id
    AND audit_event.ip_address IS NOT DISTINCT FROM audit_ip_address
    AND audit_event.user_agent IS NOT DISTINCT FROM
      nullif(audit ->> 'userAgent','')
    AND audit_event.authentication_method = 'saml'
    AND audit_event.outcome = 'success'
    AND audit_event.reason IS NOT DISTINCT FROM audit ->> 'reason'
    AND audit_event.metadata = jsonb_build_object(
      'provider_id',source_provenance.platform_provider_id,
      'user_id',source_session.user_id,
      'target_tenant_id',target_tenant_id,
      'decision','rotated',
      'expected_version',command.expected_version
    );
  IF NOT FOUND THEN
    RETURN jsonb_build_object('matched',false);
  END IF;
  RETURN jsonb_build_object('matched',true,'result',matched_result);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML tenant switch replay lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_saml_tenant_switch_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  expected_version bigint;
  target jsonb;
  target_tenant_id uuid;
  request_digest bytea;
  requested_decision text;
  observed_at timestamptz;
  live_snapshot jsonb;
  source_snapshot jsonb;
  assurance_snapshot jsonb;
  session_request jsonb;
  source_session public.auth_sessions%ROWTYPE;
  source_state public.auth_session_platform_saml_states%ROWTYPE;
  existing public.platform_saml_tenant_switch_commands%ROWTYPE;
  new_session_id uuid;
  rotation_family_id uuid;
  token_digest bytea;
  csrf_digest bytea;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  audience text;
  recovery_restricted boolean;
  required_level text;
  source_level text;
  local_required boolean;
  freshness_nanoseconds bigint;
  source_authenticated_at timestamptz;
  source_expires_at timestamptz;
  user_id uuid;
  provider_id uuid;
  external_identity_id uuid;
  policy_entry jsonb;
  result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_command,
    ARRAY['sourceSessionId','expectedVersion','authenticationMethod','target',
      'requestDigest','decision','session','observedAt','audit'],
    ARRAY['sourceSessionId','expectedVersion','authenticationMethod','target',
      'requestDigest','decision','observedAt','audit'],262144
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    p_command->'audit',
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod'],
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod'],8192
  );
  PERFORM app.private_mfa_require_uuidv7_v1(
    p_command#>>'{audit,eventId}'
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_command ->> 'sourceSessionId'
  );
  expected_version := (p_command ->> 'expectedVersion')::bigint;
  target := p_command -> 'target';
  PERFORM app.private_platform_saml_direct_json_v1(
    target,
    ARRAY['tenantId','tenantVersion','membershipId','mfaSubjectVersion',
      'identityEpoch','sessionInvalidationEpoch','bindingId','bindingVersion',
      'mappingRevision','authorizationRevision','accessEpochId',
      'accessEpochVersion','accessSourceId','accessGrantId',
      'accessGrantVersion','platformProviderId','providerRevision',
      'securityRevision','externalIdentityId','identityVersion',
      'aliasKeyVersion','policySnapshot'],
    ARRAY['tenantId','tenantVersion','membershipId','mfaSubjectVersion',
      'identityEpoch','sessionInvalidationEpoch','bindingId','bindingVersion',
      'mappingRevision','authorizationRevision','accessEpochId',
      'accessEpochVersion','accessSourceId','accessGrantId',
      'accessGrantVersion','platformProviderId','providerRevision',
      'securityRevision','externalIdentityId','identityVersion',
      'aliasKeyVersion','policySnapshot'],196608
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'tenantId'
  );
  request_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'requestDigest',32,32
  );
  requested_decision := p_command ->> 'decision';
  observed_at := (p_command ->> 'observedAt')::timestamptz;
  IF p_command->>'authenticationMethod'<>'saml'
     OR requested_decision NOT IN ('rotate','deny')
     OR expected_version NOT BETWEEN 1 AND 2147483647
     OR request_digest = decode(repeat('00',32),'hex')
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds'
     OR (requested_decision = 'rotate' AND NOT p_command ? 'session')
     OR (requested_decision = 'deny' AND p_command ? 'session') THEN
    RAISE EXCEPTION 'invalid direct platform SAML tenant switch command'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO existing
  FROM ONLY public.platform_saml_tenant_switch_commands AS command
  WHERE command.source_session_id = source_session_id
    AND command.expected_version = expected_version
    AND command.target_tenant_id = target_tenant_id;
  IF FOUND THEN
    IF existing.request_digest <> request_digest
       OR existing.authentication_method<>'saml'
       OR existing.request_snapshot IS DISTINCT FROM p_command
       OR existing.decision <> (CASE requested_decision
         WHEN 'rotate' THEN 'rotated' ELSE 'denied' END) THEN
      RAISE EXCEPTION 'direct platform SAML tenant switch replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN existing.result_snapshot;
  END IF;

  SELECT session.* INTO STRICT source_session
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = source_session_id FOR UPDATE;
  SELECT state.* INTO STRICT source_state
  FROM ONLY public.auth_session_platform_saml_states AS state
  WHERE state.session_id = source_session_id FOR UPDATE;
  PERFORM 1
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  WHERE evidence.session_id = source_session_id FOR SHARE;
  PERFORM 1
  FROM ONLY public.totp_credentials AS factor
  JOIN ONLY public.auth_session_platform_saml_evidence AS evidence
    ON evidence.session_id = source_session_id
   AND evidence.kind = 'totp' AND evidence.totp_credential_id = factor.id
  WHERE factor.user_id = source_state.user_id FOR SHARE OF factor;

  -- Hold every source and target authority row through rotation. Recomputing
  -- the graph without these locks would leave a disable/retirement TOCTOU
  -- window between the live snapshot and the tenant-session inserts.
  PERFORM 1
  FROM ONLY public.users AS local_user
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'platformProviderId'
    )
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'saml'
  JOIN ONLY public.auth_session_platform_saml_provenance AS provenance
    ON provenance.session_id = source_session_id
   AND provenance.user_id = local_user.id
   AND provenance.platform_provider_id = provider.id
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'externalIdentityId'
    )
   AND identity.platform_provider_id = provider.id
   AND identity.user_id = local_user.id
  JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provider.id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = (target ->> 'aliasKeyVersion')::integer
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.id = provenance.platform_floor_policy_id
   AND platform_floor.revision = provenance.platform_floor_policy_revision
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = target_tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'membershipId'
    )
   AND membership.tenant_id = tenant.id
   AND membership.user_id = local_user.id
  JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = tenant.id AND subject.user_id = local_user.id
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.id = app.private_mfa_require_uuidv7_v1(target ->> 'bindingId')
   AND binding.tenant_id = tenant.id
   AND binding.platform_provider_id = provider.id
  JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessEpochId'
    )
   AND epoch.tenant_id = tenant.id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = provider.id
  JOIN ONLY public.tenant_authorization_sources AS authorization_source
    ON authorization_source.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessSourceId'
    )
   AND authorization_source.tenant_id = tenant.id
  JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    ON grant_row.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessGrantId'
    )
   AND grant_row.tenant_id = tenant.id
   AND grant_row.platform_provider_id = provider.id
   AND grant_row.binding_id = binding.id
   AND grant_row.access_epoch_id = epoch.id
   AND grant_row.source_id = authorization_source.id
   AND grant_row.external_identity_id = identity.id
   AND grant_row.membership_id = membership.id
   AND grant_row.user_id = local_user.id
  WHERE local_user.id = source_state.user_id
  FOR SHARE OF local_user,provider,runtime_policy,login_policy,provenance,
    identity,alias,platform_floor,tenant,membership,subject,binding,epoch,
    authorization_source,grant_row;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  PERFORM 1
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  JOIN ONLY public.platform_federated_trust_rules AS trust
    ON trust.id = evidence.trust_rule_id
  WHERE evidence.session_id = source_session_id
    AND evidence.kind = 'platform_provider'
  FOR SHARE OF trust;

  live_snapshot := app.load_platform_saml_tenant_switch_v1(
    jsonb_build_object(
      'sourceSessionId',source_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'observedAt',to_jsonb(observed_at)
    )
  );
  IF live_snapshot IS NULL
     OR live_snapshot -> 'commandPins' IS DISTINCT FROM target
     OR live_snapshot -> 'assurance' IS NULL
     OR source_state.session_version <> expected_version
     OR source_session.revoked_at IS NOT NULL
     OR source_session.active_tenant_id IS NOT NULL
     OR source_session.authentication_method <> 'saml' THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  source_snapshot := live_snapshot -> 'source';
  assurance_snapshot := live_snapshot -> 'assurance';
  required_level := target #>> '{policySnapshot,requirement,level}';
  local_required :=
    (target #>> '{policySnapshot,requirement,localRequired}')::boolean;
  freshness_nanoseconds :=
    (target #>> '{policySnapshot,requirement,freshnessNanoseconds}')::bigint;
  -- A direct global TOTP cannot be represented by the tenant-local factor
  -- evidence family.  Select the one exact provider proof and transfer only
  -- its level and temporal bounds.  Target policies that require a local
  -- proof fail closed and must use the tenant-local step-up flow instead.
  SELECT evidence.level,evidence.authenticated_at,evidence.expires_at
    INTO STRICT source_level,source_authenticated_at,source_expires_at
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  WHERE evidence.session_id = source_session_id
    AND evidence.kind = 'platform_provider';
  IF required_level NOT IN ('primary','mfa','phishing_resistant')
     OR source_level NOT IN ('primary','mfa','phishing_resistant')
     OR (CASE source_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
       WHEN 'phishing_resistant' THEN 3 END) <
       (CASE required_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
       WHEN 'phishing_resistant' THEN 3 END)
     OR local_required
     OR (freshness_nanoseconds > 0 AND source_authenticated_at +
       (freshness_nanoseconds::numeric / 1000000000) * interval '1 second'
       <= observed_at)
     OR (source_expires_at IS NOT NULL AND source_expires_at <= observed_at) THEN
    RETURN jsonb_build_object('applied',false,'category','denied');
  END IF;
  user_id := app.private_mfa_require_uuidv7_v1(
    source_snapshot ->> 'userId'
  );
  provider_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'platformProviderId'
  );
  external_identity_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'externalIdentityId'
  );
  IF requested_decision = 'deny' THEN
    result := jsonb_build_object(
      'applied',true,'decision','denied',
      'sourceSessionId',source_session_id::text,
      'targetTenantId',target_tenant_id::text
    );
  ELSE
    session_request := p_command -> 'session';
    PERFORM app.private_platform_saml_direct_json_v1(
      session_request,
      ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
        'idleExpiresAt','absoluteExpiresAt','sessionVersion',
        'recoveryRestricted'],
      ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
        'idleExpiresAt','absoluteExpiresAt','sessionVersion',
        'recoveryRestricted'],32768
    );
    new_session_id := app.private_mfa_require_uuidv7_v1(
      session_request ->> 'id'
    );
    rotation_family_id := app.private_mfa_require_uuidv7_v1(
      session_request ->> 'rotationFamilyId'
    );
    token_digest := app.private_mfa_decode_base64_v1(
      session_request ->> 'tokenDigest',32,32
    );
    csrf_digest := app.private_mfa_decode_base64_v1(
      session_request ->> 'csrfSecretDigest',32,32
    );
    audience := session_request ->> 'audience';
    idle_expires_at := (session_request ->> 'idleExpiresAt')::timestamptz;
    absolute_expires_at :=
      (session_request ->> 'absoluteExpiresAt')::timestamptz;
    recovery_restricted :=
      (session_request ->> 'recoveryRestricted')::boolean;
    IF new_session_id = source_session_id
       OR rotation_family_id <> source_session.rotation_family_id
       OR absolute_expires_at <> source_session.absolute_expires_at
       OR (session_request ->> 'sessionVersion')::bigint <>
         expected_version + 1
       OR token_digest = csrf_digest
       OR encode(token_digest,'hex') = repeat('00',32)
       OR encode(csrf_digest,'hex') = repeat('00',32)
       OR idle_expires_at <= observed_at
       OR idle_expires_at > absolute_expires_at
       OR absolute_expires_at <= observed_at
       OR audience <> 'api'
       OR audience <> source_state.audience
       OR recovery_restricted <> source_state.recovery_restricted
       OR recovery_restricted THEN
      RAISE EXCEPTION 'invalid direct platform SAML tenant session envelope'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'platform-saml-switch:token:' || encode(token_digest,'hex'),3900186
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'platform-saml-switch:csrf:' || encode(csrf_digest,'hex'),3900186
    ));
    IF EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS collision
      WHERE collision.token_digest IN (token_digest,csrf_digest)
         OR collision.csrf_secret_digest IN (token_digest,csrf_digest)
    ) THEN
      RAISE EXCEPTION 'direct platform SAML tenant session digest collision'
        USING ERRCODE = '23505';
    END IF;
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at = observed_at,
        revoke_reason = 'platform_saml_tenant_switch_rotated'
    WHERE session.id = source_session_id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform SAML tenant switch lost source CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      new_session_id,user_id,rotation_family_id,target_tenant_id,token_digest,
      csrf_digest,'saml',CASE WHEN source_level = 'primary' THEN NULL
        ELSE source_authenticated_at END,observed_at,idle_expires_at,
      absolute_expires_at,source_session_id,observed_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,
      session_invalidation_epoch,issued_at
    ) VALUES (
      new_session_id,target_tenant_id,user_id,expected_version + 1,
      (target ->> 'identityEpoch')::bigint,recovery_restricted,audience,
      'tenant_platform_provider',
      (target ->> 'sessionInvalidationEpoch')::bigint,observed_at
    );
    INSERT INTO public.auth_session_tenant_platform_federated_provenance (
      tenant_id,session_id,user_id,primary_kind,authentication_method,
      platform_provider_id,binding_id,access_epoch_id,access_source_id,
      access_grant_id,membership_id,external_identity_id,
      external_identity_revision,provider_revision,binding_revision,
      security_revision,mapping_revision,authorization_revision,
      subject_alias_key_version,trust_rule_revision,authenticated_at
    ) VALUES (
      target_tenant_id,new_session_id,user_id,'tenant_platform_provider','saml',
      provider_id,app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessEpochId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessSourceId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessGrantId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'membershipId'),
      external_identity_id,(target ->> 'identityVersion')::bigint,
      (target ->> 'providerRevision')::bigint,
      (target ->> 'bindingVersion')::bigint,
      (target ->> 'securityRevision')::bigint,
      (target ->> 'mappingRevision')::bigint,
      (target ->> 'authorizationRevision')::bigint,
      (target ->> 'aliasKeyVersion')::integer,
      (target ->> 'securityRevision')::bigint,source_authenticated_at
    );
    FOR policy_entry IN
      SELECT entry.value
      FROM jsonb_array_elements(target #> '{policySnapshot,policies}')
        AS entry(value)
    LOOP
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES (
        target_tenant_id,new_session_id,
        app.private_mfa_require_uuidv7_v1(
          policy_entry #>> '{policy,id}'
        ),
        (policy_entry #>> '{policy,revision}')::bigint
      );
    END LOOP;
    INSERT INTO public.auth_session_tenant_platform_federated_evidence (
      id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,
      trust_rule_revision
    ) VALUES (
      uuidv7(),target_tenant_id,new_session_id,user_id,provider_id,
      app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
      external_identity_id,source_level,source_authenticated_at,
      source_expires_at,(target ->> 'securityRevision')::bigint
    );
    result := jsonb_build_object(
      'applied',true,'decision','rotated',
      'sourceSessionId',source_session_id::text,
      'sessionId',new_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'sessionVersion',expected_version + 1
    );
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  INSERT INTO public.platform_saml_tenant_switch_commands (
    source_session_id,expected_version,authentication_method,target_tenant_id,target_tenant_version,
    membership_id,binding_id,binding_version,mapping_revision,
    authorization_revision,access_epoch_id,access_epoch_version,
    access_source_id,access_grant_id,access_grant_version,request_digest,
    request_snapshot,decision,rotated_session_id,result_snapshot,applied_at
  ) VALUES (
    source_session_id,expected_version,'saml',target_tenant_id,
    (target ->> 'tenantVersion')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'membershipId'),
    app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
    (target ->> 'bindingVersion')::bigint,
    (target ->> 'mappingRevision')::bigint,
    (target ->> 'authorizationRevision')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'accessEpochId'),
    (target ->> 'accessEpochVersion')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'accessSourceId'),
    app.private_mfa_require_uuidv7_v1(target ->> 'accessGrantId'),
    (target ->> 'accessGrantVersion')::bigint,request_digest,p_command,
    CASE requested_decision WHEN 'rotate' THEN 'rotated' ELSE 'denied' END,
    CASE WHEN requested_decision = 'rotate' THEN new_session_id END,
    result,observed_at
  );
  PERFORM app.private_platform_saml_direct_audit_v1(
    (p_command -> 'audit') - 'eventId' - 'authenticationMethod',
    app.private_mfa_require_uuidv7_v1(p_command#>>'{audit,eventId}'),
    'platform.saml.session.tenant_switched',
    'auth_session',source_session_id,'success',jsonb_build_object(
      'provider_id',provider_id,'user_id',user_id,
      'target_tenant_id',target_tenant_id,
      'decision',CASE requested_decision
        WHEN 'rotate' THEN 'rotated' ELSE 'denied' END,
      'expected_version',expected_version
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_build_object('applied',false,'category','stale');
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML tenant switch command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- This projection translates the SAML-only raw authority into the compact
-- tenant-switch planner vocabulary without ever consulting OIDC state.
CREATE FUNCTION app.load_platform_saml_tenant_switch_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE raw jsonb;
BEGIN
  raw:=app.load_platform_saml_session_revalidation_v1(p_lookup);
  IF raw IS NULL THEN RETURN NULL; END IF;
  RETURN jsonb_build_object(
    'session',jsonb_build_object(
      'activeTenantId',raw#>'{session,activeTenantId}',
      'authenticationMethod',raw#>>'{session,authenticationMethod}',
      'audience',raw#>>'{session,audience}',
      'primaryKind',raw#>>'{session,primaryKind}',
      'recoveryRestricted',(raw#>>'{session,recoveryRestricted}')::boolean,
      'directStateCount',(raw#>>'{session,samlStateCount}')::integer,
      'directProvenanceCount',(raw#>>'{session,samlProvenanceCount}')::integer,
      'tenantProvenanceCount',(raw#>>'{session,tenantProvenanceCount}')::integer,
      'providerEvidenceCount',(raw#>>'{session,providerEvidenceCount}')::integer,
      'totpEvidenceCount',(raw#>>'{session,totpEvidenceCount}')::integer,
      'active',(raw#>>'{session,active}')::boolean,
      'rotationFamilyLive',(raw#>>'{session,rotationFamilyLive}')::boolean
    ),
    'authority',jsonb_build_object(
      'providerKind',raw#>>'{authority,providerKind}',
      'runtimePolicyEnabled',(raw#>>'{authority,configurationLive}')::boolean,
      'legacyPlatformLoginEnabled',false,
      'loginPolicyEnabled',(raw#>>'{authority,platformLoginLive}')::boolean,
      'accountMode',raw#>>'{authority,accountMode}',
      'providerRevision',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedProviderRevision}')::bigint,
        'current',(raw#>>'{authority,currentProviderRevision}')::bigint),
      'securityRevision',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedSecurityRevision}')::bigint,
        'current',(raw#>>'{authority,currentSecurityRevision}')::bigint),
      'loginPolicyRevision',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedLoginPolicyRevision}')::bigint,
        'current',(raw#>>'{authority,currentLoginPolicyRevision}')::bigint),
      'userAuthenticationRevision',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedUserAuthenticationRevision}')::bigint,
        'current',(raw#>>'{authority,currentUserAuthenticationRevision}')::bigint),
      'identityVersion',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedIdentityRevision}')::bigint,
        'current',(raw#>>'{authority,currentIdentityRevision}')::bigint),
      'aliasKeyVersion',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedAliasKeyVersion}')::integer,
        'current',(raw#>>'{authority,currentAliasKeyVersion}')::integer),
      'assurancePolicyRevision',jsonb_build_object(
        'pinned',(raw#>>'{authority,pinnedAssurancePolicyRevision}')::bigint,
        'current',(raw#>>'{authority,currentAssurancePolicyRevision}')::bigint),
      'platformFloor',jsonb_build_object(
        'pinnedId',raw#>>'{authority,pinnedPlatformFloorId}',
        'currentId',raw#>>'{authority,currentPlatformFloorId}',
        'pinnedRevision',(raw#>>'{authority,pinnedPlatformFloorRevision}')::bigint,
        'currentRevision',(raw#>>'{authority,currentPlatformFloorRevision}')::bigint,
        'currentScope','platform_floor','currentTenantId',NULL,
        'currentRetiredAt',NULL,
        'currentCount',CASE WHEN (raw#>>'{authority,platformFloorLive}')::boolean THEN 1 ELSE 0 END),
      'providerEnabled',(raw#>>'{authority,providerEnabled}')::boolean,
      'platformLoginLive',(raw#>>'{authority,platformLoginLive}')::boolean,
      'userActive',(raw#>>'{authority,userActive}')::boolean,
      'identityLive',(raw#>>'{authority,identityLive}')::boolean,
      'subjectAliasLive',(raw#>>'{authority,subjectAliasLive}')::boolean,
      'factorEvidenceLive',(raw#>>'{authority,factorEvidenceLive}')::boolean,
      'trustEvidenceLive',(raw#>>'{authority,trustEvidenceLive}')::boolean,
      'evidenceFresh',(raw#>>'{authority,evidenceFresh}')::boolean,
      'policyPinsExact',(raw#>>'{authority,policyPinsExact}')::boolean
    ),
    'evidence',raw->'evidence','factorAuthorities',raw->'factorAuthorities',
    'trustAuthorities',raw->'trustAuthorities','policyPins',raw->'policyPins'
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_tenant_switch_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  target_tenant_id uuid;
  observed_at timestamptz;
  source_snapshot jsonb;
  target_snapshot jsonb;
  command_pins jsonb;
  policy_snapshot jsonb;
  assurance_snapshot jsonb;
  revalidation_snapshot jsonb;
  source_ready boolean;
  revalidation_ready boolean;
  user_id uuid;
  provider_id uuid;
  external_identity_id uuid;
  alias_key_version integer;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,
    ARRAY['sourceSessionId','targetTenantId','observedAt'],
    ARRAY['sourceSessionId','targetTenantId','observedAt'],8192
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sourceSessionId'
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'targetTenantId'
  );
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform SAML tenant switch lookup'
      USING ERRCODE = '22023';
  END IF;

  -- Project the complete source facts even when they deny. The application
  -- planner must never need an adapter to invent a live edge.
  SELECT jsonb_build_object(
    'sessionId',session.id::text,
    'rotationFamilyId',session.rotation_family_id::text,
    'userId',session.user_id::text,
    'providerId',provenance.platform_provider_id::text,
    'externalIdentityId',provenance.external_identity_id::text,
    'activeTenantId',session.active_tenant_id,
    'authenticationMethod',session.authentication_method,
    'primaryKind',state.primary_kind,
    'directStateCount',(
      SELECT count(*)::integer
      FROM ONLY public.auth_session_platform_saml_states AS counted_state
      WHERE counted_state.session_id = session.id
    ),
    'directProvenanceCount',(
      SELECT count(*)::integer
      FROM ONLY public.auth_session_platform_saml_provenance AS counted_provenance
      WHERE counted_provenance.session_id = session.id
    ),
    'tenantProvenanceCount',(
      (SELECT count(*) FROM ONLY public.auth_session_mfa_states AS tenant_state
       WHERE tenant_state.session_id = session.id) +
      (SELECT count(*) FROM ONLY public.auth_session_federated_provenance
         AS tenant_provenance
       WHERE tenant_provenance.session_id = session.id) +
      (SELECT count(*)
       FROM ONLY public.auth_session_tenant_platform_federated_provenance
         AS tenant_platform_provenance
       WHERE tenant_platform_provenance.session_id = session.id)
    )::integer,
    'expectedVersion',state.session_version,
    'currentVersion',state.session_version,
    'idleExpiresAt',to_jsonb(session.idle_expires_at),
    'absoluteExpiresAt',to_jsonb(session.absolute_expires_at),
    'sessionActive',session.revoked_at IS NULL
      AND session.idle_expires_at > observed_at
      AND session.absolute_expires_at > observed_at,
    'rotationFamilyLive',EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS family_session
      WHERE family_session.user_id = session.user_id
        AND family_session.rotation_family_id = session.rotation_family_id
        AND family_session.revoked_at IS NULL
        AND family_session.idle_expires_at > observed_at
        AND family_session.absolute_expires_at > observed_at
    ),
    'userActive',coalesce(local_user.active,false),
    'providerEnabled',coalesce(
      provider.kind = 'saml' AND provider.enabled
        AND provider.archived_at IS NULL,false
    ),
    'platformLoginLive',coalesce(
      runtime_policy.provider_kind = 'saml' AND runtime_policy.enabled
        AND NOT runtime_policy.platform_login_enabled
        AND login_policy.provider_kind = 'saml' AND login_policy.enabled,false
    ),
    'accountMode',login_policy.account_mode,
    'identityLive',coalesce(
      identity.provider_kind = 'saml'
        AND identity.platform_provider_id = provenance.platform_provider_id
        AND identity.user_id = session.user_id
        AND identity.retired_at IS NULL,false
    ),
    'subjectAliasLive',coalesce(
      alias.platform_provider_id = provenance.platform_provider_id
        AND alias.external_identity_id = provenance.external_identity_id
        AND alias.retired_at IS NULL,false
    ),
    'revisions',jsonb_build_object(
      'provider',jsonb_build_object(
        'pinned',provenance.provider_revision,'current',provider.version
      ),
      'security',jsonb_build_object(
        'pinned',provenance.security_revision,
        'current',runtime_policy.security_revision
      ),
      'platformLogin',jsonb_build_object(
        'pinned',provenance.login_policy_revision,
        'current',login_policy.revision
      ),
      'externalIdentity',jsonb_build_object(
        'pinned',provenance.identity_version,'current',identity.version
      ),
      'subjectAliasKey',jsonb_build_object(
        'pinned',provenance.alias_key_version,'current',alias.key_version
      )
    )
  ) INTO source_snapshot
  FROM ONLY public.auth_sessions AS session
  LEFT JOIN ONLY public.auth_session_platform_saml_states AS state
    ON state.session_id = session.id AND state.user_id = session.user_id
  LEFT JOIN ONLY public.auth_session_platform_saml_provenance AS provenance
    ON provenance.session_id = session.id
   AND provenance.user_id = session.user_id
   AND provenance.primary_kind = state.primary_kind
  LEFT JOIN ONLY public.users AS local_user ON local_user.id = session.user_id
  LEFT JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = provenance.platform_provider_id
  LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'saml'
  LEFT JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'saml'
  LEFT JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = provenance.external_identity_id
   AND identity.platform_provider_id = provenance.platform_provider_id
   AND identity.user_id = session.user_id
  LEFT JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provenance.platform_provider_id
   AND alias.external_identity_id = provenance.external_identity_id
   AND alias.key_version = provenance.alias_key_version
  WHERE session.id = source_session_id;
  IF source_snapshot IS NULL THEN RETURN NULL; END IF;

  revalidation_snapshot := app.load_platform_saml_tenant_switch_revalidation_v1(
    jsonb_build_object(
      'sessionId',source_session_id::text,
      'observedAt',to_jsonb(observed_at)
    )
  );
  revalidation_ready := coalesce(
    revalidation_snapshot IS NOT NULL
    AND revalidation_snapshot #>> '{session,activeTenantId}' IS NULL
    AND revalidation_snapshot #>> '{session,authenticationMethod}' = 'saml'
    AND revalidation_snapshot #>> '{session,audience}' = 'api'
    AND revalidation_snapshot #>> '{session,primaryKind}' =
      'platform_provider'
    AND NOT (revalidation_snapshot #>>
      '{session,recoveryRestricted}')::boolean
    AND (revalidation_snapshot #>>
      '{session,directStateCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,directProvenanceCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,tenantProvenanceCount}')::integer = 0
    AND (revalidation_snapshot #>>
      '{session,providerEvidenceCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,totpEvidenceCount}')::integer BETWEEN 0 AND 1
    AND (revalidation_snapshot #>> '{session,active}')::boolean
    AND (revalidation_snapshot #>>
      '{session,rotationFamilyLive}')::boolean
    AND revalidation_snapshot #>> '{authority,providerKind}' = 'saml'
    AND (revalidation_snapshot #>>
      '{authority,runtimePolicyEnabled}')::boolean
    AND NOT (revalidation_snapshot #>>
      '{authority,legacyPlatformLoginEnabled}')::boolean
    AND (revalidation_snapshot #>>
      '{authority,loginPolicyEnabled}')::boolean
    AND revalidation_snapshot #>> '{authority,accountMode}' =
      'existing_identity'
    AND (revalidation_snapshot #>>
      '{authority,providerRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,providerRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,securityRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,securityRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,loginPolicyRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,loginPolicyRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,userAuthenticationRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,userAuthenticationRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,identityVersion,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,identityVersion,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,aliasKeyVersion,pinned}')::integer =
      (revalidation_snapshot #>>
      '{authority,aliasKeyVersion,current}')::integer
    AND (revalidation_snapshot #>>
      '{authority,assurancePolicyRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,assurancePolicyRevision,current}')::bigint
    AND revalidation_snapshot #>> '{authority,platformFloor,pinnedId}' =
      revalidation_snapshot #>> '{authority,platformFloor,currentId}'
    AND (revalidation_snapshot #>>
      '{authority,platformFloor,pinnedRevision}')::bigint =
      (revalidation_snapshot #>>
      '{authority,platformFloor,currentRevision}')::bigint
    AND revalidation_snapshot #>>
      '{authority,platformFloor,currentScope}' = 'platform_floor'
    AND revalidation_snapshot #>
      '{authority,platformFloor,currentTenantId}' = 'null'::jsonb
    AND revalidation_snapshot #>
      '{authority,platformFloor,currentRetiredAt}' = 'null'::jsonb
    AND (revalidation_snapshot #>>
      '{authority,platformFloor,currentCount}')::integer = 1
    AND (revalidation_snapshot #>> '{authority,providerEnabled}')::boolean
    AND (revalidation_snapshot #>> '{authority,platformLoginLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,userActive}')::boolean
    AND (revalidation_snapshot #>> '{authority,identityLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,subjectAliasLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,factorEvidenceLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,trustEvidenceLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,evidenceFresh}')::boolean
    AND (revalidation_snapshot #>> '{authority,policyPinsExact}')::boolean
    AND jsonb_array_length(
      revalidation_snapshot -> 'factorAuthorities'
    ) = (revalidation_snapshot #>> '{session,totpEvidenceCount}')::integer
    AND jsonb_array_length(
      revalidation_snapshot -> 'trustAuthorities'
    ) BETWEEN 0 AND 1,
    false
  );
  source_ready := coalesce(
    revalidation_ready
    AND source_snapshot ->> 'activeTenantId' IS NULL
    AND source_snapshot ->> 'authenticationMethod' = 'saml'
    AND source_snapshot ->> 'primaryKind' = 'platform_provider'
    AND (source_snapshot ->> 'directStateCount')::integer = 1
    AND (source_snapshot ->> 'directProvenanceCount')::integer = 1
    AND (source_snapshot ->> 'tenantProvenanceCount')::integer = 0
    AND (source_snapshot ->> 'expectedVersion')::bigint BETWEEN 1 AND 2147483647
    AND (source_snapshot ->> 'expectedVersion')::bigint =
      (source_snapshot ->> 'currentVersion')::bigint
    AND (source_snapshot ->> 'sessionActive')::boolean
    AND (source_snapshot ->> 'rotationFamilyLive')::boolean
    AND (source_snapshot ->> 'userActive')::boolean
    AND (source_snapshot ->> 'providerEnabled')::boolean
    AND (source_snapshot ->> 'platformLoginLive')::boolean
    AND source_snapshot ->> 'accountMode' = 'existing_identity'
    AND (source_snapshot ->> 'identityLive')::boolean
    AND (source_snapshot ->> 'subjectAliasLive')::boolean
    AND (source_snapshot #>> '{revisions,provider,pinned}')::bigint =
      (source_snapshot #>> '{revisions,provider,current}')::bigint
    AND (source_snapshot #>> '{revisions,security,pinned}')::bigint =
      (source_snapshot #>> '{revisions,security,current}')::bigint
    AND (source_snapshot #>> '{revisions,platformLogin,pinned}')::bigint =
      (source_snapshot #>> '{revisions,platformLogin,current}')::bigint
    AND (source_snapshot #>> '{revisions,externalIdentity,pinned}')::bigint =
      (source_snapshot #>> '{revisions,externalIdentity,current}')::bigint
    AND (source_snapshot #>> '{revisions,subjectAliasKey,pinned}')::integer =
      (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer,
    false
  );

  user_id := (source_snapshot ->> 'userId')::uuid;
  provider_id := nullif(source_snapshot ->> 'providerId','')::uuid;
  external_identity_id :=
    nullif(source_snapshot ->> 'externalIdentityId','')::uuid;
  alias_key_version :=
    (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer;
  assurance_snapshot := app.private_platform_saml_tenant_switch_assurance_v1(
    source_session_id,observed_at
  );
  IF assurance_snapshot IS NOT NULL AND revalidation_snapshot IS NOT NULL THEN
    -- The aggregate remains a compact diagnostic, but callers evaluate the
    -- exact normalized rows.  In particular, a trusted upstream level and an
    -- unrelated local TOTP must never be combined into one synthetic proof.
    assurance_snapshot := assurance_snapshot || jsonb_build_object(
      'evidence',revalidation_snapshot -> 'evidence'
    );
  END IF;

  SELECT jsonb_build_object(
    'tenantExecutionLive',coalesce(
      runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled,
      false
    ),
    'tenant',jsonb_build_object(
      'id',tenant.id::text,'version',tenant.version,
      'active',tenant.status = 'active'
    ),
    'membership',jsonb_build_object(
      'id',membership.id::text,'tenantId',membership.tenant_id::text,
      'userId',membership.user_id::text,
      'active',coalesce(membership.status = 'active',false)
    ),
    'binding',jsonb_build_object(
      'id',binding.id::text,'tenantId',binding.tenant_id::text,
      'providerId',binding.platform_provider_id::text,
      'version',binding.version,'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'currentAccessEpochId',binding.current_access_epoch_id::text,
      'enabled',coalesce(
        binding.enabled AND binding.archived_at IS NULL,false
      )
    ),
    'accessEpoch',jsonb_build_object(
      'id',epoch.id::text,'tenantId',epoch.tenant_id::text,
      'bindingId',epoch.binding_id::text,
      'providerId',epoch.platform_provider_id::text,
      'sourceId',epoch.source_id::text,'version',epoch.version,
      'live',coalesce(
        epoch.started_at <= observed_at AND epoch.ended_at IS NULL,false
      )
    ),
    'accessSource',jsonb_build_object(
      'id',authorization_source.id::text,
      'tenantId',authorization_source.tenant_id::text,
      'platformProvider',coalesce(
        authorization_source.kind = 'identity_provider_access'
        AND authorization_source.key = format(
          'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
        ),false
      ),
      'authoritative',coalesce(authorization_source.authoritative,false),
      'live',coalesce(
        NOT authorization_source.protected
        AND authorization_source.retired_at IS NULL,false
      )
    ),
    'externalIdentity',jsonb_build_object(
      'id',identity.id::text,
      'providerId',identity.platform_provider_id::text,
      'userId',identity.user_id::text,'version',identity.version,
      'live',coalesce(
        identity.provider_kind = 'saml' AND identity.retired_at IS NULL,false
      )
    ),
    'subjectAlias',jsonb_build_object(
      'externalIdentityId',alias.external_identity_id::text,
      'keyVersion',alias.key_version,
      'live',coalesce(alias.retired_at IS NULL,false)
    ),
    'accessGrant',jsonb_build_object(
      'id',grant_row.id::text,'tenantId',grant_row.tenant_id::text,
      'providerId',grant_row.platform_provider_id::text,
      'bindingId',grant_row.binding_id::text,
      'accessEpochId',grant_row.access_epoch_id::text,
      'accessSourceId',grant_row.source_id::text,
      'externalIdentityId',grant_row.external_identity_id::text,
      'membershipId',grant_row.membership_id::text,
      'userId',grant_row.user_id::text,'version',grant_row.version,
      'live',coalesce(
        grant_row.started_at <= observed_at AND grant_row.ended_at IS NULL,
        false
      )
    ),
    'mfaSubject',jsonb_build_object(
      'version',subject.version,'identityEpoch',subject.identity_epoch,
      'sessionInvalidationEpoch',subject.session_invalidation_epoch
    )
  ) INTO target_snapshot
  FROM ONLY public.tenants AS tenant
  LEFT JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = tenant.id AND membership.user_id = user_id
  LEFT JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = tenant.id AND subject.user_id = user_id
  LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider_id
   AND runtime_policy.provider_kind = 'saml'
  LEFT JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant.id
   AND binding.platform_provider_id = provider_id
  LEFT JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = provider_id
  LEFT JOIN ONLY public.tenant_authorization_sources AS authorization_source
    ON authorization_source.tenant_id = epoch.tenant_id
   AND authorization_source.id = epoch.source_id
  LEFT JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id = provider_id
   AND identity.id = external_identity_id
   AND identity.user_id = user_id
  LEFT JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = identity.platform_provider_id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = alias_key_version
  LEFT JOIN LATERAL (
    SELECT candidate.*
    FROM ONLY public.tenant_platform_federated_provider_access_grants
      AS candidate
    WHERE candidate.tenant_id = tenant.id
      AND candidate.platform_provider_id = provider_id
      AND candidate.binding_id = binding.id
      AND candidate.access_epoch_id = epoch.id
      AND candidate.source_id = authorization_source.id
      AND candidate.external_identity_id = external_identity_id
      AND candidate.membership_id = membership.id
      AND candidate.user_id = user_id
    ORDER BY (candidate.ended_at IS NULL) DESC,
      candidate.started_at DESC,candidate.id
    LIMIT 1
  ) AS grant_row ON true
  WHERE tenant.id = target_tenant_id;

  -- commandPins are a capability, unlike the raw planner projection. They are
  -- emitted only for a completely revalidated source and exact live target.
  IF source_ready THEN
    SELECT jsonb_build_object(
      'tenantId',tenant.id::text,'tenantVersion',tenant.version,
      'membershipId',membership.id::text,
      'mfaSubjectVersion',subject.version,
      'identityEpoch',subject.identity_epoch,
      'sessionInvalidationEpoch',subject.session_invalidation_epoch,
      'bindingId',binding.id::text,'bindingVersion',binding.version,
      'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'accessEpochId',epoch.id::text,'accessEpochVersion',epoch.version,
      'accessSourceId',authorization_source.id::text,
      'accessGrantId',grant_row.id::text,
      'accessGrantVersion',grant_row.version,
      'platformProviderId',provider.id::text,
      'providerRevision',provider.version,
      'securityRevision',runtime_policy.security_revision,
      'externalIdentityId',identity.id::text,
      'identityVersion',identity.version,
      'aliasKeyVersion',alias.key_version
    ) INTO command_pins
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = tenant.id AND membership.user_id = user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = tenant.id AND subject.user_id = user_id
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = provider_id AND provider.kind = 'saml'
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'saml'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = tenant.id
     AND binding.platform_provider_id = provider.id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.platform_provider_id = provider.id
     AND epoch.started_at <= observed_at AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS authorization_source
      ON authorization_source.tenant_id = epoch.tenant_id
     AND authorization_source.id = epoch.source_id
     AND authorization_source.kind = 'identity_provider_access'
     AND authorization_source.authoritative
     AND NOT authorization_source.protected
     AND authorization_source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     ) AND authorization_source.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = provider.id
     AND identity.id = external_identity_id
     AND identity.user_id = user_id
     AND identity.version =
       (source_snapshot #>> '{revisions,externalIdentity,current}')::bigint
     AND identity.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = identity.platform_provider_id
     AND alias.external_identity_id = identity.id
     AND alias.key_version =
       (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer
     AND alias.retired_at IS NULL
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.tenant_id = tenant.id
     AND grant_row.platform_provider_id = provider.id
     AND grant_row.binding_id = binding.id
     AND grant_row.access_epoch_id = epoch.id
     AND grant_row.source_id = authorization_source.id
     AND grant_row.external_identity_id = identity.id
     AND grant_row.membership_id = membership.id
     AND grant_row.user_id = user_id
     AND grant_row.started_at <= observed_at AND grant_row.ended_at IS NULL
    WHERE tenant.id = target_tenant_id AND tenant.status = 'active'
      AND provider.version =
        (source_snapshot #>> '{revisions,provider,current}')::bigint
      AND runtime_policy.security_revision =
        (source_snapshot #>> '{revisions,security,current}')::bigint;
    IF command_pins IS NOT NULL THEN
      policy_snapshot := app.private_mfa_policy_snapshot_v1(
        target_tenant_id,user_id,'session.create',observed_at
      );
      IF policy_snapshot IS NULL THEN
        command_pins := NULL;
      ELSE
        command_pins := command_pins || jsonb_build_object(
          'policySnapshot',policy_snapshot
        );
      END IF;
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'source',source_snapshot,
    'assurance',assurance_snapshot,
    'target',target_snapshot,
    'commandPins',command_pins
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML tenant switch lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- Same-transaction ACL closure: an interrupted upgrade after 0186 exposes no
-- SECURITY DEFINER entry point through PostgreSQL's default PUBLIC grant.
ALTER TABLE public.platform_saml_tenant_switch_commands
  OWNER TO periapsis_migrator;
REVOKE ALL PRIVILEGES ON TABLE public.platform_saml_tenant_switch_commands
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier;
--> statement-breakpoint

DO $platform_saml_successor_acl_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity,procedure.proname
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'private_platform_saml_tenant_switch_assurance_v1',
      'private_platform_saml_totp_completion_fence_v1',
      'cleanup_platform_saml_post_primary_totp_apply_v1',
      'begin_platform_post_primary_totp_v2',
      'lookup_platform_saml_tenant_switch_replay_v1',
      'apply_platform_saml_tenant_switch_v1',
      'load_platform_saml_tenant_switch_revalidation_v1',
      'load_platform_saml_tenant_switch_v1'
    ]::name[])
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',object_record.identity);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.identity
    );
    IF object_record.proname=ANY(ARRAY[
      'cleanup_platform_saml_post_primary_totp_apply_v1',
      'begin_platform_post_primary_totp_v2',
      'lookup_platform_saml_tenant_switch_replay_v1',
      'apply_platform_saml_tenant_switch_v1',
      'load_platform_saml_tenant_switch_v1'
    ]::name[]) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO periapsis_api',object_record.identity);
    END IF;
  END LOOP;
END;
$platform_saml_successor_acl_v1$;
--> statement-breakpoint
