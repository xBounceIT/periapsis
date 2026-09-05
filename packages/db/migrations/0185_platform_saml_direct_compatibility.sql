-- The generated 0184 checkpoint still described the pre-review absolute
-- uniqueness constraint although the runtime SQL had already emitted the
-- stronger pending-only index.  Accept either exact journal-184 catalogue.
ALTER TABLE "platform_saml_post_primary_totp_challenges" DROP CONSTRAINT IF EXISTS "platform_saml_post_primary_totp_challenges_continuation_key";--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" DROP CONSTRAINT "platform_saml_post_primary_continuations_value_check";--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" DROP CONSTRAINT "platform_saml_post_primary_totp_challenges_value_check";--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" DROP CONSTRAINT "platform_saml_session_revalidation_commands_value_check";--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD COLUMN "origin" text DEFAULT 'initial_login' NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD COLUMN "source_session_id" uuid;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD COLUMN "source_session_family_id" uuid;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD COLUMN "source_session_version" bigint;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD COLUMN "source_absolute_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ADD COLUMN "cleanup_reason" text;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ADD COLUMN "cleaned_up_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ADD COLUMN "request_snapshot" jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ADD COLUMN "cleanup_reason" text;--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ADD COLUMN "cleaned_up_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_source_session_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "platform_saml_post_primary_totp_challenges_live_continuation_key" ON "platform_saml_post_primary_totp_challenges" USING btree ("continuation_id") WHERE "platform_saml_post_primary_totp_challenges"."state" = 'pending';--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_value_check" CHECK ((uuid_extract_version("platform_saml_post_primary_continuations"."id") = 7) is true
        and octet_length("platform_saml_post_primary_continuations"."receipt_digest") = 32
        and "platform_saml_post_primary_continuations"."authority" = 'direct_platform_saml'
        and "platform_saml_post_primary_continuations"."authentication_method" = 'saml'
        and "platform_saml_post_primary_continuations"."provider_revision" between 1 and 2147483647
        and "platform_saml_post_primary_continuations"."login_policy_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."configuration_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."security_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."plan_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."assurance_policy_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."metadata_revision" between 1 and 9007199254740991
        and octet_length("platform_saml_post_primary_continuations"."metadata_digest") = 32
        and "platform_saml_post_primary_continuations"."sp_key_revision" between 1 and 9007199254740991
        and octet_length("platform_saml_post_primary_continuations"."configuration_digest") = 32
        and "platform_saml_post_primary_continuations"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."identity_version" between 1 and 2147483647
        and "platform_saml_post_primary_continuations"."alias_key_version" between 1 and 32767
        and (uuid_extract_version("platform_saml_post_primary_continuations"."platform_authority_id") = 7) is true
        and "platform_saml_post_primary_continuations"."platform_authority_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_saml_post_primary_continuations"."platform_floor_policy_id") = 7) is true
        and "platform_saml_post_primary_continuations"."platform_floor_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_saml_post_primary_continuations"."selected_totp_credential_id") = 7) is true
        and "platform_saml_post_primary_continuations"."selected_totp_security_revision" between 1 and 9007199254740991
        and (("platform_saml_post_primary_continuations"."trust_rule_id" is null and "platform_saml_post_primary_continuations"."trust_rule_revision" is null)
          or ((uuid_extract_version("platform_saml_post_primary_continuations"."trust_rule_id") = 7) is true
            and "platform_saml_post_primary_continuations"."trust_rule_revision" between 1 and 9007199254740991))
        and (("platform_saml_post_primary_continuations"."origin" = 'initial_login'
          and "platform_saml_post_primary_continuations"."source_session_id" is null and "platform_saml_post_primary_continuations"."source_session_family_id" is null
          and "platform_saml_post_primary_continuations"."source_session_version" is null and "platform_saml_post_primary_continuations"."source_absolute_expires_at" is null)
        or ("platform_saml_post_primary_continuations"."origin" = 'session_revalidation'
          and (uuid_extract_version("platform_saml_post_primary_continuations"."source_session_id") = 7) is true
          and (uuid_extract_version("platform_saml_post_primary_continuations"."source_session_family_id") = 7) is true
          and "platform_saml_post_primary_continuations"."source_session_id" <> "platform_saml_post_primary_continuations"."source_session_family_id"
          and "platform_saml_post_primary_continuations"."source_session_version" between 1 and 2147483647
          and "platform_saml_post_primary_continuations"."source_absolute_expires_at" > "platform_saml_post_primary_continuations"."created_at"))
        and btrim("platform_saml_post_primary_continuations"."action") = "platform_saml_post_primary_continuations"."action"
        and char_length("platform_saml_post_primary_continuations"."action") between 1 and 256
        and "platform_saml_post_primary_continuations"."action" !~ '[[:cntrl:]]'
        and btrim("platform_saml_post_primary_continuations"."audience") = "platform_saml_post_primary_continuations"."audience"
        and char_length("platform_saml_post_primary_continuations"."audience") between 1 and 256
        and "platform_saml_post_primary_continuations"."audience" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ADD CONSTRAINT "platform_saml_post_primary_totp_challenges_value_check" CHECK (octet_length("platform_saml_post_primary_totp_challenges"."id") = 32 and octet_length("platform_saml_post_primary_totp_challenges"."browser_digest") = 32
        and "platform_saml_post_primary_totp_challenges"."expected_continuation_version" between 1 and 2147483647
        and "platform_saml_post_primary_totp_challenges"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_totp_challenges"."totp_security_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_totp_challenges"."failure_count" between 0 and 5
        and "platform_saml_post_primary_totp_challenges"."version" between 1 and 2147483647
        and "platform_saml_post_primary_totp_challenges"."expires_at" between "platform_saml_post_primary_totp_challenges"."created_at" + interval '1 minute'
          and "platform_saml_post_primary_totp_challenges"."created_at" + interval '10 minutes'
        and (("platform_saml_post_primary_totp_challenges"."state" = 'pending' and "platform_saml_post_primary_totp_challenges"."completed_at" is null
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" is null and "platform_saml_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_saml_post_primary_totp_challenges"."completion_request_snapshot" is null
          and "platform_saml_post_primary_totp_challenges"."result_snapshot" is null and "platform_saml_post_primary_totp_challenges"."cleanup_reason" is null
          and "platform_saml_post_primary_totp_challenges"."cleaned_up_at" is null)
        or ("platform_saml_post_primary_totp_challenges"."state" = 'completed' and "platform_saml_post_primary_totp_challenges"."completed_at" >= "platform_saml_post_primary_totp_challenges"."created_at"
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" is null and octet_length("platform_saml_post_primary_totp_challenges"."completion_request_digest") = 32
          and jsonb_typeof("platform_saml_post_primary_totp_challenges"."completion_request_snapshot") = 'object'
          and pg_column_size("platform_saml_post_primary_totp_challenges"."completion_request_snapshot") between 2 and 131072
          and jsonb_typeof("platform_saml_post_primary_totp_challenges"."result_snapshot") = 'object'
          and pg_column_size("platform_saml_post_primary_totp_challenges"."result_snapshot") between 2 and 65536
          and (("platform_saml_post_primary_totp_challenges"."cleanup_reason" is null and "platform_saml_post_primary_totp_challenges"."cleaned_up_at" is null)
            or ("platform_saml_post_primary_totp_challenges"."cleanup_reason" = 'delivery_failed'
              and "platform_saml_post_primary_totp_challenges"."cleaned_up_at" >= "platform_saml_post_primary_totp_challenges"."completed_at")))
        or ("platform_saml_post_primary_totp_challenges"."state" in ('abandoned','expired','failed') and "platform_saml_post_primary_totp_challenges"."completed_at" is null
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" >= "platform_saml_post_primary_totp_challenges"."created_at"
          and "platform_saml_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_saml_post_primary_totp_challenges"."completion_request_snapshot" is null and "platform_saml_post_primary_totp_challenges"."result_snapshot" is null
          and "platform_saml_post_primary_totp_challenges"."cleanup_reason" is null and "platform_saml_post_primary_totp_challenges"."cleaned_up_at" is null)));--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ADD CONSTRAINT "platform_saml_session_revalidation_commands_value_check" CHECK ("platform_saml_session_revalidation_commands"."expected_version" between 1 and 2147483647
        and octet_length("platform_saml_session_revalidation_commands"."request_digest") = 32
        and "platform_saml_session_revalidation_commands"."decision" in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof("platform_saml_session_revalidation_commands"."request_snapshot") = 'object'
        and pg_column_size("platform_saml_session_revalidation_commands"."request_snapshot") between 2 and 131072
        and jsonb_typeof("platform_saml_session_revalidation_commands"."result_snapshot") = 'object'
        and pg_column_size("platform_saml_session_revalidation_commands"."result_snapshot") between 2 and 65536
        and (("platform_saml_session_revalidation_commands"."cleanup_reason" is null and "platform_saml_session_revalidation_commands"."cleaned_up_at" is null)
          or ("platform_saml_session_revalidation_commands"."cleanup_reason" = 'delivery_failed' and "platform_saml_session_revalidation_commands"."cleaned_up_at" >= "platform_saml_session_revalidation_commands"."applied_at")));
--> statement-breakpoint

-- Direct-platform SAML session revalidation is an independent authority
-- family.  The digest transcript mirrors the constructor-only Go command
-- exactly: uint64 big-endian length prefixes, raw UUID/IP bytes and Unix
-- microseconds.  A caller cannot relabel an OIDC or tenant command as SAML.
CREATE FUNCTION app.private_platform_saml_revalidation_field_v1(
  p_transcript bytea,p_value bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_transcript || int8send(octet_length(p_value)::bigint) || p_value
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_saml_session_revalidation_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE session_id uuid;
DECLARE expected_version bigint;
DECLARE request_digest bytea;
DECLARE decision text;
DECLARE reason text;
DECLARE observed_at timestamptz;
DECLARE command_record public.platform_saml_session_revalidation_commands%ROWTYPE;
DECLARE session_record public.auth_sessions%ROWTYPE;
DECLARE state_record public.auth_session_platform_saml_states%ROWTYPE;
DECLARE provenance_record public.auth_session_platform_saml_provenance%ROWTYPE;
DECLARE provider_evidence public.auth_session_platform_saml_evidence%ROWTYPE;
DECLARE totp_evidence public.auth_session_platform_saml_evidence%ROWTYPE;
DECLARE authority jsonb;
DECLARE plan jsonb;
DECLARE result jsonb;
DECLARE floor_satisfied boolean:=false;
DECLARE lifecycle_live boolean:=false;
DECLARE primary_exact boolean:=false;
DECLARE policy_exact boolean:=false;
DECLARE continuation_id uuid;
DECLARE new_session_id uuid;
DECLARE factor_id uuid;
DECLARE factor_revision bigint;
DECLARE continuation_expires_at timestamptz;
DECLARE receipt_digest bytea;
BEGIN
  session_id:=app.private_mfa_require_uuidv7_v1(p_command->>'sessionId');
  expected_version:=(p_command->>'expectedVersion')::bigint;
  request_digest:=app.private_mfa_decode_base64_v1(p_command->>'requestDigest',32,32);
  decision:=p_command->>'decision';
  reason:=p_command->>'reason';
  observed_at:=(p_command->>'observedAt')::timestamptz;
  IF request_digest<>app.private_platform_saml_revalidation_digest_v1(p_command)
     OR request_digest=decode(repeat('00',32),'hex')
     OR observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                            AND statement_timestamp()+interval '30 seconds'
     OR (decision='usable' AND reason<>'current')
     OR (decision='rotate' AND reason<>'policy_refresh')
     OR (decision='step_up' AND reason NOT IN ('assurance_insufficient','recovery_restricted'))
     OR (decision='revoke' AND reason NOT IN ('expired','lifecycle','identity_epoch',
       'primary_drift','factor_drift','trust_drift'))
     OR (decision='deny' AND reason NOT IN ('malformed','assurance_insufficient','recovery_restricted'))
     OR (decision='rotate')<>(p_command ? 'session')
     OR (decision='step_up')<>(p_command ? 'continuation') THEN
    RAISE EXCEPTION 'invalid direct platform SAML session revalidation command'
      USING ERRCODE='22023';
  END IF;
  SELECT command.* INTO command_record
  FROM ONLY public.platform_saml_session_revalidation_commands AS command
  WHERE command.session_id=session_id AND command.expected_version=expected_version;
  IF FOUND THEN
    IF command_record.request_digest<>request_digest
       OR command_record.decision<>decision
       OR command_record.request_snapshot IS DISTINCT FROM p_command THEN
      RAISE EXCEPTION 'direct platform SAML revalidation replay collision'
        USING ERRCODE='23505';
    END IF;
    RETURN jsonb_set(command_record.result_snapshot,'{category}','"already_applied"'::jsonb);
  END IF;
  SELECT source.* INTO STRICT session_record
  FROM ONLY public.auth_sessions AS source WHERE source.id=session_id FOR UPDATE;
  SELECT source.* INTO STRICT state_record
  FROM ONLY public.auth_session_platform_saml_states AS source
  WHERE source.session_id=session_id FOR UPDATE;
  SELECT source.* INTO STRICT provenance_record
  FROM ONLY public.auth_session_platform_saml_provenance AS source
  WHERE source.session_id=session_id FOR SHARE;
  SELECT evidence.* INTO STRICT provider_evidence
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  WHERE evidence.session_id=session_id AND evidence.kind='platform_provider' FOR SHARE;
  SELECT evidence.* INTO totp_evidence
  FROM ONLY public.auth_session_platform_saml_evidence AS evidence
  WHERE evidence.session_id=session_id AND evidence.kind='totp' FOR SHARE;
  authority:=app.load_platform_saml_session_revalidation_v1(jsonb_build_object(
    'sessionId',session_id::text,'observedAt',to_jsonb(observed_at)
  ));
  IF authority IS NULL OR state_record.session_version<>expected_version
     OR authority#>>'{session,authority}'<>'direct_platform_saml'
     OR authority#>>'{session,authenticationMethod}'<>'saml'
     OR authority#>>'{session,audience}'<>'api'
     OR authority#>>'{session,primaryKind}'<>'platform_provider'
     OR authority#>'{session,activeTenantId}'<>'null'::jsonb
     OR (authority#>>'{session,samlStateCount}')::integer<>1
     OR (authority#>>'{session,samlProvenanceCount}')::integer<>1
     OR (authority#>>'{session,oidcStateCount}')::integer<>0
     OR (authority#>>'{session,tenantProvenanceCount}')::integer<>0
     OR (authority#>>'{session,providerEvidenceCount}')::integer<>1
     OR (authority#>>'{session,totpEvidenceCount}')::integer NOT BETWEEN 0 AND 1 THEN
    RETURN jsonb_build_object(
      'applied',false,'category','stale','decision',decision,
      'sessionId',session_id::text,'userId',state_record.user_id::text,
      'expectedVersion',expected_version,'newVersion',0
    );
  END IF;
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(authority->'evidence') AS evidence(value)
    WHERE (CASE evidence.value->>'level' WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
      WHEN 'phishing_resistant' THEN 3 ELSE 0 END) >=
      (CASE authority#>>'{authority,platformFloor,level}' WHEN 'primary' THEN 1
        WHEN 'mfa' THEN 2 WHEN 'phishing_resistant' THEN 3 ELSE 4 END)
      AND (NOT (authority#>>'{authority,platformFloor,localRequired}')::boolean
        OR evidence.value->>'kind'='totp')
      AND (authority#>>'{authority,platformFloor,freshnessNanoseconds}')::bigint>=0
      AND ((authority#>>'{authority,platformFloor,freshnessNanoseconds}')::bigint=0
        OR (evidence.value->>'authenticatedAt')::timestamptz
          + ((authority#>>'{authority,platformFloor,freshnessNanoseconds}')::numeric/1000000000)
            * interval '1 second'>observed_at)
      AND (evidence.value->>'authenticatedAt')::timestamptz<=observed_at
      AND (NOT evidence.value ? 'expiresAt'
        OR evidence.value->'expiresAt'='null'::jsonb
        OR (evidence.value->>'expiresAt')::timestamptz>observed_at)
  ) INTO floor_satisfied;
  lifecycle_live:=coalesce(
    (authority#>>'{session,active}')::boolean
    AND (authority#>>'{session,rotationFamilyLive}')::boolean
    AND (authority#>>'{authority,providerEnabled}')::boolean
    AND (authority#>>'{authority,platformLoginLive}')::boolean
    AND (authority#>>'{authority,userActive}')::boolean
    AND (authority#>>'{authority,identityLive}')::boolean
    AND (authority#>>'{authority,subjectAliasLive}')::boolean
    AND (authority#>>'{authority,factorEvidenceLive}')::boolean
    AND (authority#>>'{authority,trustEvidenceLive}')::boolean
    AND (authority#>>'{authority,configurationLive}')::boolean
    AND (authority#>>'{authority,metadataLive}')::boolean
    AND (authority#>>'{authority,spKeyLive}')::boolean
    AND (authority#>>'{authority,platformAuthorityLive}')::boolean
    AND (authority#>>'{authority,platformFloorLive}')::boolean
    AND authority#>>'{authority,accountMode}'='existing_identity',false);
  primary_exact:=coalesce(
    (authority#>>'{authority,pinnedProviderRevision}')::bigint=(authority#>>'{authority,currentProviderRevision}')::bigint
    AND (authority#>>'{authority,pinnedLoginPolicyRevision}')::bigint=(authority#>>'{authority,currentLoginPolicyRevision}')::bigint
    AND (authority#>>'{authority,pinnedConfigurationRevision}')::bigint=(authority#>>'{authority,currentConfigurationRevision}')::bigint
    AND (authority#>>'{authority,pinnedSecurityRevision}')::bigint=(authority#>>'{authority,currentSecurityRevision}')::bigint
    AND (authority#>>'{authority,pinnedPlanRevision}')::bigint=(authority#>>'{authority,currentPlanRevision}')::bigint
    AND (authority#>>'{authority,pinnedMetadataRevision}')::bigint=(authority#>>'{authority,currentMetadataRevision}')::bigint
    AND (authority#>>'{authority,pinnedSpKeyRevision}')::bigint=(authority#>>'{authority,currentSpKeyRevision}')::bigint
    AND (authority#>>'{authority,pinnedUserAuthenticationRevision}')::bigint=(authority#>>'{authority,currentUserAuthenticationRevision}')::bigint
    AND (authority#>>'{authority,pinnedIdentityRevision}')::bigint=(authority#>>'{authority,currentIdentityRevision}')::bigint
    AND (authority#>>'{authority,pinnedAliasKeyVersion}')::integer=(authority#>>'{authority,currentAliasKeyVersion}')::integer
    AND authority#>>'{authority,pinnedMetadataDigest}'=authority#>>'{authority,currentMetadataDigest}'
    AND authority#>>'{authority,pinnedConfigurationDigest}'=authority#>>'{authority,currentConfigurationDigest}'
    AND authority#>>'{authority,identityCurrentProviderId}'=provenance_record.platform_provider_id::text
    AND authority#>>'{authority,identityCurrentUserId}'=state_record.user_id::text
    AND authority#>>'{authority,aliasCurrentProviderId}'=provenance_record.platform_provider_id::text
    AND authority#>>'{authority,aliasCurrentIdentityId}'=provenance_record.external_identity_id::text
    AND provider_evidence.expires_at>observed_at,false);
  policy_exact:=coalesce(
    (authority#>>'{authority,policyPinsExact}')::boolean
    AND (authority#>>'{authority,pinnedAssurancePolicyRevision}')::bigint=(authority#>>'{authority,currentAssurancePolicyRevision}')::bigint
    AND authority#>>'{authority,pinnedPlatformFloorId}'=authority#>>'{authority,currentPlatformFloorId}'
    AND (authority#>>'{authority,pinnedPlatformFloorRevision}')::bigint=(authority#>>'{authority,currentPlatformFloorRevision}')::bigint,false);
  IF decision='usable' AND NOT (lifecycle_live AND primary_exact AND policy_exact
      AND floor_satisfied AND (authority#>>'{authority,evidenceFresh}')::boolean
      AND NOT state_record.recovery_restricted)
     OR decision='rotate' AND NOT (lifecycle_live AND primary_exact AND NOT policy_exact
      AND floor_satisfied AND (authority#>>'{authority,evidenceFresh}')::boolean
      AND NOT state_record.recovery_restricted)
     OR decision='step_up' AND NOT (lifecycle_live AND primary_exact
      AND provider_evidence.expires_at>observed_at AND authority#>'{authority,stepUpTotp}'<>'null'::jsonb
      AND (state_record.recovery_restricted OR NOT floor_satisfied
        OR NOT (authority#>>'{authority,evidenceFresh}')::boolean)) THEN
    RETURN jsonb_build_object(
      'applied',false,'category','stale','decision',decision,
      'sessionId',session_id::text,'userId',state_record.user_id::text,
      'expectedVersion',expected_version,'newVersion',0
    );
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF decision='usable' THEN
    UPDATE ONLY public.auth_session_platform_saml_states AS changed
    SET session_version=changed.session_version+1
    WHERE changed.session_id=session_id AND changed.session_version=expected_version;
    IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML revalidation lost session CAS' USING ERRCODE='40001'; END IF;
    result:=jsonb_build_object(
      'applied',true,'category','success','decision',decision,'sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'newVersion',expected_version+1,'appliedAt',to_jsonb(observed_at));
  ELSIF decision='rotate' THEN
    plan:=jsonb_build_object(
      'pins',jsonb_build_object(
        'protocol',app.private_platform_saml_direct_pins_v1(
          provenance_record.platform_provider_id,(authority#>>'{authority,currentProviderRevision}')::bigint,
          (authority#>>'{authority,currentLoginPolicyRevision}')::bigint,
          (authority#>>'{authority,currentConfigurationRevision}')::bigint,
          (authority#>>'{authority,currentSecurityRevision}')::bigint,
          (authority#>>'{authority,currentPlanRevision}')::bigint,
          (authority#>>'{authority,currentAssurancePolicyRevision}')::bigint,
          (authority#>>'{authority,currentMetadataRevision}')::bigint,
          app.private_mfa_decode_base64_v1(authority#>>'{authority,currentMetadataDigest}',32,32),
          (authority#>>'{authority,currentSpKeyRevision}')::bigint,
          app.private_mfa_decode_base64_v1(authority#>>'{authority,currentConfigurationDigest}',32,32)),
        'platformFloorPolicyId',authority#>>'{authority,currentPlatformFloorId}',
        'platformFloorPolicyRevision',(authority#>>'{authority,currentPlatformFloorRevision}')::bigint),
      'provenance',jsonb_build_object(
        'provider',jsonb_build_object('scope','platform','providerId',provenance_record.platform_provider_id::text),
        'externalIdentityId',provenance_record.external_identity_id::text,
        'userId',state_record.user_id::text,
        'identityRevision',(authority#>>'{authority,currentIdentityRevision}')::bigint,
        'userAuthenticationRevision',(authority#>>'{authority,currentUserAuthenticationRevision}')::bigint,
        'platformAuthorityId',authority#>>'{authority,currentPlatformAuthorityId}',
        'platformAuthorityRevision',(authority#>>'{authority,currentPlatformAuthorityRevision}')::bigint,
        'matchedAliasKeyVersion',(authority#>>'{authority,currentAliasKeyVersion}')::integer,
        'authenticatedAt',to_jsonb(provider_evidence.authenticated_at),
        'validUntil',to_jsonb(provider_evidence.expires_at),
        'selectedAssurance',jsonb_strip_nulls(jsonb_build_object(
          'level',provider_evidence.level,'authenticatedAt',to_jsonb(provider_evidence.authenticated_at),
          'trustRuleId',provider_evidence.trust_rule_id,
          'trustRuleRevision',provider_evidence.trust_rule_revision))),
      'platformFloor',authority#>'{authority,platformFloor}');
    IF app.private_mfa_require_uuidv7_v1(p_command#>>'{session,rotationFamilyId}')<>session_record.rotation_family_id
       OR (p_command#>>'{session,absoluteExpiresAt}')::timestamptz<>session_record.absolute_expires_at THEN
      RAISE EXCEPTION 'direct platform SAML rotation anchor changed' USING ERRCODE='22023';
    END IF;
    new_session_id:=app.private_platform_saml_create_session_v1(
      p_command->'session',plan,'api',observed_at,
      totp_evidence.totp_credential_id,totp_evidence.factor_revision,
      totp_evidence.authenticated_at,session_id);
    UPDATE ONLY public.platform_saml_session_materials AS material
    SET session_id=new_session_id,continuation_id=NULL
    WHERE material.session_id=session_id;
    UPDATE ONLY public.auth_sessions AS source
    SET revoked_at=observed_at,revoke_reason='session_revalidation_rotated'
    WHERE source.id=session_id AND source.revoked_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML rotation lost source CAS' USING ERRCODE='40001'; END IF;
    result:=jsonb_build_object(
      'applied',true,'category','success','decision',decision,'sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,'newVersion',0,
      'newSessionId',new_session_id::text,'appliedAt',to_jsonb(observed_at));
  ELSIF decision='step_up' THEN
    continuation_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{continuation,id}');
    factor_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{continuation,factorId}');
    factor_revision:=(p_command#>>'{continuation,factorRevision}')::bigint;
    receipt_digest:=app.private_mfa_decode_base64_v1(p_command#>>'{continuation,receiptDigest}',32,32);
    continuation_expires_at:=(p_command#>>'{continuation,expiresAt}')::timestamptz;
    IF factor_id::text<>authority#>>'{authority,stepUpTotp,factorId}'
       OR factor_revision<>(authority#>>'{authority,stepUpTotp,revision}')::bigint
       OR receipt_digest=decode(repeat('00',32),'hex')
       OR continuation_expires_at NOT BETWEEN observed_at+interval '1 minute' AND observed_at+interval '15 minutes'
       OR continuation_expires_at>session_record.absolute_expires_at THEN
      RAISE EXCEPTION 'invalid direct platform SAML revalidation continuation' USING ERRCODE='22023';
    END IF;
    INSERT INTO public.platform_saml_post_primary_continuations(
      id,user_id,receipt_digest,authority,authentication_method,action,audience,
      platform_provider_id,external_identity_id,provider_revision,login_policy_revision,
      configuration_revision,security_revision,plan_revision,assurance_policy_revision,
      metadata_revision,metadata_digest,sp_key_revision,configuration_digest,
      user_authentication_revision,identity_version,alias_key_version,
      platform_authority_id,platform_authority_revision,platform_floor_policy_id,
      platform_floor_policy_revision,selected_totp_credential_id,
      selected_totp_security_revision,trust_rule_id,trust_rule_revision,
      origin,source_session_id,source_session_family_id,source_session_version,
      source_absolute_expires_at,state,version,created_at,expires_at
    ) VALUES (
      continuation_id,state_record.user_id,receipt_digest,'direct_platform_saml','saml',
      'session.revalidate','api',provenance_record.platform_provider_id,
      provenance_record.external_identity_id,
      (authority#>>'{authority,currentProviderRevision}')::bigint,
      (authority#>>'{authority,currentLoginPolicyRevision}')::bigint,
      (authority#>>'{authority,currentConfigurationRevision}')::bigint,
      (authority#>>'{authority,currentSecurityRevision}')::bigint,
      (authority#>>'{authority,currentPlanRevision}')::bigint,
      (authority#>>'{authority,currentAssurancePolicyRevision}')::bigint,
      (authority#>>'{authority,currentMetadataRevision}')::bigint,
      app.private_mfa_decode_base64_v1(authority#>>'{authority,currentMetadataDigest}',32,32),
      (authority#>>'{authority,currentSpKeyRevision}')::bigint,
      app.private_mfa_decode_base64_v1(authority#>>'{authority,currentConfigurationDigest}',32,32),
      (authority#>>'{authority,currentUserAuthenticationRevision}')::bigint,
      (authority#>>'{authority,currentIdentityRevision}')::bigint,
      (authority#>>'{authority,currentAliasKeyVersion}')::integer,
      app.private_mfa_require_uuidv7_v1(authority#>>'{authority,currentPlatformAuthorityId}'),
      (authority#>>'{authority,currentPlatformAuthorityRevision}')::bigint,
      app.private_mfa_require_uuidv7_v1(authority#>>'{authority,currentPlatformFloorId}'),
      (authority#>>'{authority,currentPlatformFloorRevision}')::bigint,
      factor_id,factor_revision,provider_evidence.trust_rule_id,provider_evidence.trust_rule_revision,
      'session_revalidation',session_id,session_record.rotation_family_id,expected_version+1,
      session_record.absolute_expires_at,'pending',1,observed_at,continuation_expires_at
    );
    INSERT INTO public.platform_saml_post_primary_continuation_evidence(
      id,continuation_id,user_id,kind,level,platform_provider_id,external_identity_id,
      trust_rule_id,trust_rule_revision,authenticated_at,expires_at
    ) VALUES (
      uuidv7(),continuation_id,state_record.user_id,'platform_provider',provider_evidence.level,
      provenance_record.platform_provider_id,provenance_record.external_identity_id,
      provider_evidence.trust_rule_id,provider_evidence.trust_rule_revision,
      provider_evidence.authenticated_at,provider_evidence.expires_at
    );
    INSERT INTO public.platform_saml_post_primary_continuation_policy_pins(
      continuation_id,policy_kind,policy_id,policy_revision
    ) VALUES
      (continuation_id,'login',provenance_record.platform_provider_id,
        (authority#>>'{authority,currentLoginPolicyRevision}')::bigint),
      (continuation_id,'assurance',provenance_record.platform_provider_id,
        (authority#>>'{authority,currentAssurancePolicyRevision}')::bigint),
      (continuation_id,'platform_floor',
        app.private_mfa_require_uuidv7_v1(authority#>>'{authority,currentPlatformFloorId}'),
        (authority#>>'{authority,currentPlatformFloorRevision}')::bigint);
    UPDATE ONLY public.auth_session_platform_saml_states AS changed
    SET session_version=changed.session_version+1
    WHERE changed.session_id=session_id AND changed.session_version=expected_version;
    IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML revalidation lost session CAS' USING ERRCODE='40001'; END IF;
    result:=jsonb_build_object(
      'applied',true,'category','success','decision',decision,'sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'newVersion',expected_version+1,'continuationId',continuation_id::text,
      'appliedAt',to_jsonb(observed_at));
  ELSE
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS challenge
    SET state='failed',version=challenge.version+1,abandoned_at=observed_at
    FROM ONLY public.platform_saml_post_primary_continuations AS continuation
    WHERE challenge.continuation_id=continuation.id AND challenge.state='pending'
      AND continuation.user_id=state_record.user_id
      AND continuation.platform_provider_id=provenance_record.platform_provider_id;
    UPDATE ONLY public.platform_saml_post_primary_continuations AS continuation
    SET state='revoked',version=continuation.version+1,revoked_at=observed_at,
      revoke_reason=left('session_revalidation_'||reason,500)
    WHERE continuation.user_id=state_record.user_id
      AND continuation.platform_provider_id=provenance_record.platform_provider_id
      AND continuation.external_identity_id=provenance_record.external_identity_id
      AND continuation.state='pending';
    UPDATE ONLY public.auth_sessions AS family
    SET revoked_at=observed_at,revoke_reason=left('platform_saml_revalidation_'||reason,500)
    WHERE family.user_id=session_record.user_id
      AND family.rotation_family_id=session_record.rotation_family_id
      AND family.revoked_at IS NULL;
    result:=jsonb_build_object(
      'applied',true,'category','success','decision',decision,'sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'newVersion',0,'appliedAt',to_jsonb(observed_at));
  END IF;
  INSERT INTO public.platform_saml_session_revalidation_commands(
    session_id,expected_version,request_digest,decision,request_snapshot,
    result_snapshot,applied_at
  ) VALUES (session_id,expected_version,request_digest,decision,p_command,result,observed_at);
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_command->'audit',uuidv7(),'platform.saml.session.revalidated','auth_session',
    session_id,'success',jsonb_build_object(
      'decision',decision,'reason',reason,'expectedVersion',expected_version,
      'newVersion',(result->>'newVersion')::bigint
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'applied',false,'category','stale','decision',decision,'sessionId',session_id::text,
    'userId',coalesce(state_record.user_id,session_record.user_id)::text,
    'expectedVersion',expected_version,'newVersion',0));
WHEN invalid_text_representation OR numeric_value_out_of_range OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML session revalidation command'
    USING ERRCODE='22023';
END;
$function$;

-- Compatibility functions are sealed in the same transaction that creates
-- them; there is no PUBLIC-executable migration-to-seal interval.
DO $platform_saml_revalidation_acl_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity,procedure.proname
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'private_platform_saml_revalidation_field_v1',
      'apply_platform_saml_session_revalidation_v1',
      'recover_platform_saml_session_revalidation_apply_v1',
      'cleanup_platform_saml_session_revalidation_delivery_v1',
      'private_platform_saml_revalidation_digest_v1',
      'load_platform_saml_session_revalidation_v1'
    ]::name[])
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',object_record.identity);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.identity
    );
    IF object_record.proname=ANY(ARRAY[
      'apply_platform_saml_session_revalidation_v1',
      'recover_platform_saml_session_revalidation_apply_v1',
      'cleanup_platform_saml_session_revalidation_delivery_v1',
      'load_platform_saml_session_revalidation_v1'
    ]::name[]) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO periapsis_api',object_record.identity);
    END IF;
  END LOOP;
END;
$platform_saml_revalidation_acl_v1$;
--> statement-breakpoint
--> statement-breakpoint

CREATE FUNCTION app.recover_platform_saml_session_revalidation_apply_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE command_value jsonb;
DECLARE command_record public.platform_saml_session_revalidation_commands%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['command'],ARRAY['command'],131072
  );
  command_value:=p_lookup->'command';
  SELECT command.* INTO command_record
  FROM ONLY public.platform_saml_session_revalidation_commands AS command
  WHERE command.session_id=app.private_mfa_require_uuidv7_v1(command_value->>'sessionId')
    AND command.expected_version=(command_value->>'expectedVersion')::bigint
    AND command.request_digest=app.private_mfa_decode_base64_v1(command_value->>'requestDigest',32,32)
    AND command.request_digest=app.private_platform_saml_revalidation_digest_v1(command_value)
    AND command.decision=command_value->>'decision'
    AND command.request_snapshot IS NOT DISTINCT FROM command_value;
  IF NOT FOUND THEN RETURN jsonb_build_object('matched',false); END IF;
  RETURN jsonb_build_object(
    'matched',true,
    'result',jsonb_set(command_record.result_snapshot,'{category}','"already_applied"'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.cleanup_platform_saml_session_revalidation_delivery_v1(p_cleanup jsonb)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE command_value jsonb;
DECLARE result_value jsonb;
DECLARE cleaned_at timestamptz;
DECLARE command_record public.platform_saml_session_revalidation_commands%ROWTYPE;
DECLARE target_id uuid;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_cleanup,ARRAY['command','result','reason','cleanedUpAt','audit'],
    ARRAY['command','result','reason','cleanedUpAt','audit'],262144
  );
  command_value:=p_cleanup->'command';
  result_value:=p_cleanup->'result';
  cleaned_at:=(p_cleanup->>'cleanedUpAt')::timestamptz;
  IF p_cleanup->>'reason'<>'delivery_failed'
     OR command_value->>'decision' NOT IN ('rotate','step_up')
     OR result_value->>'category' NOT IN ('success','already_applied')
     OR NOT (result_value->>'applied')::boolean
     OR cleaned_at<(command_value->>'observedAt')::timestamptz
     OR cleaned_at>statement_timestamp()+interval '30 seconds'
     OR app.private_platform_saml_revalidation_digest_v1(command_value)<>
       app.private_mfa_decode_base64_v1(command_value->>'requestDigest',32,32) THEN
    RAISE EXCEPTION 'invalid direct platform SAML revalidation cleanup'
      USING ERRCODE='22023';
  END IF;
  SELECT command.* INTO STRICT command_record
  FROM ONLY public.platform_saml_session_revalidation_commands AS command
  WHERE command.session_id=app.private_mfa_require_uuidv7_v1(command_value->>'sessionId')
    AND command.expected_version=(command_value->>'expectedVersion')::bigint
  FOR UPDATE;
  IF command_record.request_snapshot IS DISTINCT FROM command_value
     OR command_record.request_digest<>
       app.private_mfa_decode_base64_v1(command_value->>'requestDigest',32,32)
     OR command_record.result_snapshot-'category' IS DISTINCT FROM result_value-'category' THEN
    RAISE EXCEPTION 'direct platform SAML revalidation cleanup mismatch'
      USING ERRCODE='23505';
  END IF;
  IF command_record.cleaned_up_at IS NOT NULL THEN
    IF command_record.cleanup_reason<>'delivery_failed'
       OR command_record.cleaned_up_at<>cleaned_at THEN
      RAISE EXCEPTION 'direct platform SAML revalidation cleanup collision'
        USING ERRCODE='23505';
    END IF;
    RETURN;
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF command_record.decision='rotate' THEN
    target_id:=app.private_mfa_require_uuidv7_v1(result_value->>'newSessionId');
    UPDATE ONLY public.auth_sessions AS successor
    SET revoked_at=cleaned_at,revoke_reason='platform_saml_revalidation_delivery_failed'
    WHERE successor.id=target_id
      AND successor.rotated_from_session_id=command_record.session_id
      AND successor.revoked_at IS NULL;
    IF NOT FOUND AND NOT EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS successor
      WHERE successor.id=target_id
        AND successor.rotated_from_session_id=command_record.session_id
        AND successor.revoked_at=cleaned_at
        AND successor.revoke_reason='platform_saml_revalidation_delivery_failed'
    ) THEN RAISE EXCEPTION 'direct platform SAML revalidation cleanup target mismatch' USING ERRCODE='23505'; END IF;
  ELSE
    target_id:=app.private_mfa_require_uuidv7_v1(result_value->>'continuationId');
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS challenge
    SET state='failed',version=challenge.version+1,abandoned_at=cleaned_at
    WHERE challenge.continuation_id=target_id AND challenge.state='pending';
    UPDATE ONLY public.platform_saml_post_primary_continuations AS continuation
    SET state='revoked',version=continuation.version+1,revoked_at=cleaned_at,
      revoke_reason='session_revalidation_delivery_failed'
    WHERE continuation.id=target_id AND continuation.origin='session_revalidation'
      AND continuation.source_session_id=command_record.session_id
      AND continuation.state='pending';
    IF NOT FOUND AND NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_saml_post_primary_continuations AS continuation
      WHERE continuation.id=target_id AND continuation.origin='session_revalidation'
        AND continuation.source_session_id=command_record.session_id
        AND continuation.state='revoked' AND continuation.revoked_at=cleaned_at
        AND continuation.revoke_reason='session_revalidation_delivery_failed'
    ) THEN RAISE EXCEPTION 'direct platform SAML revalidation cleanup target mismatch' USING ERRCODE='23505'; END IF;
  END IF;
  UPDATE ONLY public.platform_saml_session_revalidation_commands AS command
  SET cleanup_reason='delivery_failed',cleaned_up_at=cleaned_at
  WHERE command.session_id=command_record.session_id
    AND command.expected_version=command_record.expected_version
    AND command.cleaned_up_at IS NULL;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_cleanup->'audit',uuidv7(),'platform.saml.session.revalidation_delivery_failed',
    'auth_session',command_record.session_id,'failure',
    jsonb_build_object('decision',command_record.decision,
      'expectedVersion',command_record.expected_version)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_revalidation_digest_v1(p_command jsonb)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE transcript bytea:=decode('','hex');
DECLARE session_id uuid;
DECLARE expected_version bigint;
DECLARE observed_at timestamptz;
DECLARE audit jsonb;
DECLARE session_value jsonb;
DECLARE continuation_value jsonb;
DECLARE address inet;
DECLARE field bytea;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_command,
    ARRAY['sessionId','expectedVersion','requestDigest','decision','reason',
      'observedAt','session','continuation','audit'],
    ARRAY['sessionId','expectedVersion','requestDigest','decision','reason',
      'observedAt','audit'],131072
  );
  session_id:=app.private_mfa_require_uuidv7_v1(p_command->>'sessionId');
  expected_version:=(p_command->>'expectedVersion')::bigint;
  observed_at:=(p_command->>'observedAt')::timestamptz;
  audit:=p_command->'audit';
  PERFORM app.private_platform_saml_direct_json_v1(
    audit,ARRAY['requestId','correlationId','ipAddress','userAgent'],
    ARRAY['requestId','correlationId','ipAddress','userAgent'],8192
  );
  address:=(audit->>'ipAddress')::inet;
  IF expected_version NOT BETWEEN 1 AND 2147483647
     OR p_command->>'decision' NOT IN ('usable','rotate','step_up','revoke','deny')
     OR p_command->>'reason' NOT IN ('current','policy_refresh','assurance_insufficient',
       'lifecycle','identity_epoch','primary_drift','factor_drift','trust_drift',
       'recovery_restricted','expired','malformed')
     OR octet_length(convert_to(audit->>'userAgent','UTF8')) NOT BETWEEN 1 AND 512
     OR audit->>'userAgent' ~ '[[:cntrl:]]'
     OR observed_at IS NULL OR date_trunc('microseconds',observed_at)<>observed_at THEN
    RAISE EXCEPTION 'invalid direct platform SAML revalidation digest command'
      USING ERRCODE='22023';
  END IF;
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,convert_to('periapsis/platform-saml/session-revalidation/v1','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,convert_to('direct_platform_saml','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(transcript,convert_to('saml','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(transcript,convert_to('api','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(transcript,uuid_send(session_id));
  transcript:=app.private_platform_saml_revalidation_field_v1(transcript,int8send(expected_version));
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,convert_to(p_command->>'decision','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,convert_to(p_command->>'reason','UTF8'));
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,int8send((extract(epoch FROM observed_at)*1000000)::bigint));

  IF p_command ? 'session' THEN
    transcript:=app.private_platform_saml_revalidation_field_v1(transcript,decode('01','hex'));
    session_value:=p_command->'session';
    PERFORM app.private_platform_saml_direct_json_v1(
      session_value,ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],32768
    );
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,uuid_send(app.private_mfa_require_uuidv7_v1(session_value->>'id')));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,uuid_send(app.private_mfa_require_uuidv7_v1(session_value->>'rotationFamilyId')));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,app.private_mfa_decode_base64_v1(session_value->>'tokenDigest',32,32));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,app.private_mfa_decode_base64_v1(session_value->>'csrfSecretDigest',32,32));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,convert_to(session_value->>'authenticationMethod','UTF8'));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,int8send((extract(epoch FROM (session_value->>'idleExpiresAt')::timestamptz)*1000000)::bigint));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,int8send((extract(epoch FROM (session_value->>'absoluteExpiresAt')::timestamptz)*1000000)::bigint));
  ELSE
    transcript:=app.private_platform_saml_revalidation_field_v1(transcript,decode('00','hex'));
  END IF;

  IF p_command ? 'continuation' THEN
    transcript:=app.private_platform_saml_revalidation_field_v1(transcript,decode('01','hex'));
    continuation_value:=p_command->'continuation';
    PERFORM app.private_platform_saml_direct_json_v1(
      continuation_value,ARRAY['id','factorId','factorRevision','receiptDigest','expiresAt'],
      ARRAY['id','factorId','factorRevision','receiptDigest','expiresAt'],16384
    );
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,uuid_send(app.private_mfa_require_uuidv7_v1(continuation_value->>'id')));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,uuid_send(app.private_mfa_require_uuidv7_v1(continuation_value->>'factorId')));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,int8send((continuation_value->>'factorRevision')::bigint));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,app.private_mfa_decode_base64_v1(continuation_value->>'receiptDigest',32,32));
    transcript:=app.private_platform_saml_revalidation_field_v1(
      transcript,int8send((extract(epoch FROM (continuation_value->>'expiresAt')::timestamptz)*1000000)::bigint));
  ELSE
    transcript:=app.private_platform_saml_revalidation_field_v1(transcript,decode('00','hex'));
  END IF;
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,uuid_send(app.private_mfa_require_uuidv7_v1(audit->>'requestId')));
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,uuid_send(app.private_mfa_require_uuidv7_v1(audit->>'correlationId')));
  field:=substring(inet_send(address) FROM 5);
  transcript:=app.private_platform_saml_revalidation_field_v1(transcript,field);
  transcript:=app.private_platform_saml_revalidation_field_v1(
    transcript,convert_to(audit->>'userAgent','UTF8'));
  RETURN sha256(transcript);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML revalidation digest command'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE session_id uuid;
DECLARE observed_at timestamptz;
DECLARE result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['sessionId','observedAt'],ARRAY['sessionId','observedAt'],8192
  );
  session_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'sessionId');
  observed_at:=(p_lookup->>'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                         AND statement_timestamp()+interval '30 seconds'
     OR date_trunc('microseconds',observed_at)<>observed_at THEN
    RAISE EXCEPTION 'invalid direct platform SAML session revalidation lookup'
      USING ERRCODE='22023';
  END IF;
  WITH source AS (
    SELECT session.id,session.rotation_family_id,session.user_id,
      session.active_tenant_id,session.idle_expires_at,session.absolute_expires_at,
      session.revoked_at,state.authority,state.authentication_method,state.audience,
      state.primary_kind,state.session_version,state.user_authentication_revision,
      state.recovery_restricted,state.issued_at,
      provenance.platform_provider_id,provenance.external_identity_id,
      provenance.provider_revision,provenance.login_policy_revision,
      provenance.configuration_revision,provenance.security_revision,
      provenance.plan_revision,provenance.assurance_policy_revision,
      provenance.metadata_revision,provenance.metadata_digest,
      provenance.sp_key_revision,provenance.configuration_digest,
      provenance.identity_version,provenance.alias_key_version,
      provenance.platform_authority_id,provenance.platform_authority_revision,
      provenance.platform_floor_policy_id,provenance.platform_floor_policy_revision
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_platform_saml_states AS state
      ON state.session_id=session.id
    JOIN ONLY public.auth_session_platform_saml_provenance AS provenance
      ON provenance.session_id=session.id
    WHERE session.id=session_id
  ), current_floor_candidates AS (
    SELECT floor.*
    FROM ONLY public.mfa_policy_revisions AS floor
    WHERE floor.scope='platform_floor' AND floor.tenant_id IS NULL
      AND floor.retired_at IS NULL
    ORDER BY floor.id,floor.revision
  ), current_floor AS (
    SELECT floor.* FROM current_floor_candidates AS floor
    ORDER BY floor.id,floor.revision LIMIT 1
  )
  SELECT jsonb_build_object(
    'session',jsonb_build_object(
      'sessionId',source.id::text,'rotationFamilyId',source.rotation_family_id::text,
      'userId',source.user_id::text,'activeTenantId',source.active_tenant_id,
      'authority',source.authority,'authenticationMethod',source.authentication_method,
      'audience',source.audience,'primaryKind',source.primary_kind,
      'samlStateCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_states AS s WHERE s.session_id=source.id),
      'samlProvenanceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_provenance AS p WHERE p.session_id=source.id),
      'oidcStateCount',(SELECT count(*) FROM ONLY public.auth_session_platform_oidc_states AS s WHERE s.session_id=source.id),
      'tenantProvenanceCount',(SELECT count(*) FROM ONLY public.auth_session_federated_provenance AS p WHERE p.session_id=source.id),
      'providerEvidenceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_evidence AS e WHERE e.session_id=source.id AND e.kind='platform_provider'),
      'totpEvidenceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_evidence AS e WHERE e.session_id=source.id AND e.kind='totp'),
      'currentVersion',source.session_version,
      'userAuthenticationRevision',source.user_authentication_revision,
      'recoveryRestricted',source.recovery_restricted,
      'issuedAt',to_jsonb(source.issued_at),'idleExpiresAt',to_jsonb(source.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(source.absolute_expires_at),
      'active',source.revoked_at IS NULL AND source.idle_expires_at>observed_at
        AND source.absolute_expires_at>observed_at,
      'rotationFamilyLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_sessions AS family
        WHERE family.user_id=source.user_id AND family.rotation_family_id=source.rotation_family_id
          AND family.revoked_at IS NOT NULL AND family.id=source.id
      )
    ),
    'authority',jsonb_build_object(
      'providerId',source.platform_provider_id::text,
      'externalIdentityId',source.external_identity_id::text,'providerKind','saml',
      'accountMode',coalesce(login_policy.account_mode,'disabled'),
      'pinnedProviderRevision',source.provider_revision,'currentProviderRevision',provider.version,
      'pinnedLoginPolicyRevision',source.login_policy_revision,'currentLoginPolicyRevision',login_policy.revision,
      'pinnedConfigurationRevision',source.configuration_revision,'currentConfigurationRevision',runtime_policy.configuration_revision,
      'pinnedSecurityRevision',source.security_revision,'currentSecurityRevision',runtime_policy.security_revision,
      'pinnedPlanRevision',source.plan_revision,'currentPlanRevision',runtime_policy.plan_revision,
      'pinnedAssurancePolicyRevision',source.assurance_policy_revision,'currentAssurancePolicyRevision',runtime_policy.assurance_policy_revision,
      'pinnedMetadataRevision',source.metadata_revision,'currentMetadataRevision',configuration.metadata_revision,
      'pinnedSpKeyRevision',source.sp_key_revision,'currentSpKeyRevision',configuration.sp_key_revision,
      'pinnedUserAuthenticationRevision',source.user_authentication_revision,
      'currentUserAuthenticationRevision',local_user.authentication_revision,
      'pinnedIdentityRevision',source.identity_version,'currentIdentityRevision',identity_record.version,
      'pinnedAliasKeyVersion',source.alias_key_version,
      'currentAliasKeyVersion',coalesce(current_alias.key_version,source.alias_key_version),
      'pinnedMetadataDigest',replace(encode(source.metadata_digest,'base64'),E'\n',''),
      'currentMetadataDigest',replace(encode(metadata.document_digest,'base64'),E'\n',''),
      'pinnedConfigurationDigest',replace(encode(source.configuration_digest,'base64'),E'\n',''),
      'currentConfigurationDigest',replace(encode(
        CASE WHEN source.configuration_revision=runtime_policy.configuration_revision
          AND source.security_revision=runtime_policy.security_revision
          AND source.plan_revision=runtime_policy.plan_revision
          AND source.metadata_revision=configuration.metadata_revision
          AND source.sp_key_revision=configuration.sp_key_revision
        THEN source.configuration_digest
        ELSE sha256(source.configuration_digest || int8send(runtime_policy.configuration_revision)
          || int8send(runtime_policy.security_revision) || int8send(runtime_policy.plan_revision)
          || int8send(configuration.metadata_revision) || int8send(configuration.sp_key_revision)) END,
        'base64'),E'\n',''),
      'identityCurrentProviderId',identity_record.platform_provider_id::text,
      'identityCurrentUserId',identity_record.user_id::text,
      'aliasCurrentProviderId',coalesce(current_alias.platform_provider_id,source.platform_provider_id)::text,
      'aliasCurrentIdentityId',coalesce(current_alias.external_identity_id,source.external_identity_id)::text,
      'pinnedPlatformAuthorityId',source.platform_authority_id::text,
      'currentPlatformAuthorityId',coalesce(current_grant.id,source.platform_authority_id)::text,
      'pinnedPlatformAuthorityRevision',source.platform_authority_revision,
      'currentPlatformAuthorityRevision',1,
      'pinnedPlatformFloorId',source.platform_floor_policy_id::text,
      'currentPlatformFloorId',coalesce(floor.id,pinned_floor.id)::text,
      'pinnedPlatformFloorRevision',source.platform_floor_policy_revision,
      'currentPlatformFloorRevision',coalesce(floor.revision,pinned_floor.revision),
      'providerEnabled',provider.enabled AND provider.archived_at IS NULL,
      'platformLoginLive',login_policy.enabled AND login_policy.account_mode='existing_identity',
      'userActive',local_user.active,
      'identityLive',identity_record.provider_kind='saml' AND identity_record.retired_at IS NULL,
      'subjectAliasLive',current_alias.id IS NOT NULL,
      'factorEvidenceLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        LEFT JOIN ONLY public.totp_credentials AS factor
          ON factor.id=evidence.totp_credential_id AND factor.user_id=evidence.user_id
        WHERE evidence.session_id=source.id AND evidence.kind='totp'
          AND (factor.id IS NULL OR factor.security_revision<>evidence.factor_revision
            OR factor.confirmed_at IS NULL OR factor.disabled_at IS NOT NULL)
      ),
      'evidenceFresh',coalesce((
        SELECT bool_and(evidence.authenticated_at<=observed_at
          AND (evidence.expires_at IS NULL OR evidence.expires_at>observed_at))
        FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        WHERE evidence.session_id=source.id
      ),false),
      'policyPinsExact',(SELECT count(*)=3 AND bool_and(
          (pin.policy_kind='login' AND pin.policy_id=source.platform_provider_id AND pin.policy_revision=source.login_policy_revision)
          OR (pin.policy_kind='assurance' AND pin.policy_id=source.platform_provider_id AND pin.policy_revision=source.assurance_policy_revision)
          OR (pin.policy_kind='platform_floor' AND pin.policy_id=source.platform_floor_policy_id AND pin.policy_revision=source.platform_floor_policy_revision)
        ) FROM ONLY public.auth_session_platform_saml_policy_pins AS pin WHERE pin.session_id=source.id),
      'trustEvidenceLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
          ON trust.id=evidence.trust_rule_id AND trust.revision=evidence.trust_rule_revision
        WHERE evidence.session_id=source.id AND evidence.kind='platform_provider'
          AND evidence.trust_rule_id IS NOT NULL
          AND (trust.id IS NULL OR trust.provider_id<>source.platform_provider_id
            OR trust.provider_kind<>'saml' OR NOT trust.enabled OR trust.retired_at IS NOT NULL
            OR trust.level<>evidence.level)
      ),
      'configurationLive',configuration.provider_kind='saml'
        AND configuration.encryption_policy='disabled'
        AND cardinality(configuration.decryption_key_versions)=0,
      'metadataLive',metadata.document_digest=sha256(metadata.document)
        AND metadata.maximum_valid_until>observed_at,
      'spKeyLive',active_key.id IS NOT NULL,
      'platformAuthorityLive',current_grant.id IS NOT NULL,
      'platformFloorLive',floor.id IS NOT NULL AND (SELECT count(*) FROM current_floor_candidates)=1,
      'platformFloor',jsonb_build_object(
        'level',coalesce(floor.level,pinned_floor.level),
        'localRequired',coalesce(floor.local_required,pinned_floor.local_required),
        'freshnessNanoseconds',coalesce(floor.freshness_nanoseconds,pinned_floor.freshness_nanoseconds),
        'enrollmentDeadline',to_jsonb(coalesce(floor.enrollment_deadline,pinned_floor.enrollment_deadline)),
        'policyRevisions',jsonb_build_array(jsonb_build_object(
          'policyId',coalesce(floor.id,pinned_floor.id)::text,
          'revision',coalesce(floor.revision,pinned_floor.revision)
        ))
      ),
      'stepUpTotp',CASE WHEN factor_choice.factor_count=1 THEN jsonb_build_object(
        'factorId',factor_choice.factor_id::text,'revision',factor_choice.security_revision
      ) ELSE NULL END
    ),
    'evidence',coalesce((
      SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'id',evidence.id::text,'userId',evidence.user_id::text,'kind',evidence.kind,
        'level',evidence.level,'platformProviderId',evidence.platform_provider_id,
        'externalIdentityId',evidence.external_identity_id,
        'totpCredentialId',evidence.totp_credential_id,'factorRevision',evidence.factor_revision,
        'trustRuleId',evidence.trust_rule_id,'trustRuleRevision',evidence.trust_rule_revision,
        'authenticatedAt',to_jsonb(evidence.authenticated_at),'expiresAt',to_jsonb(evidence.expires_at)
      )) ORDER BY evidence.kind,evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      WHERE evidence.session_id=source.id
    ),'[]'::jsonb),
    'factorAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,'evidenceUserId',evidence.user_id::text,
        'totpCredentialId',evidence.totp_credential_id::text,
        'pinnedSecurityRevision',evidence.factor_revision,
        'currentUserId',factor.user_id::text,'currentSecurityRevision',factor.security_revision,
        'confirmedAt',to_jsonb(factor.confirmed_at),'disabledAt',to_jsonb(factor.disabled_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      JOIN ONLY public.totp_credentials AS factor ON factor.id=evidence.totp_credential_id
      WHERE evidence.session_id=source.id AND evidence.kind='totp'
    ),'[]'::jsonb),
    'trustAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,'trustRuleId',evidence.trust_rule_id::text,
        'pinnedRevision',evidence.trust_rule_revision,
        'currentProviderId',coalesce(trust.provider_id,source.platform_provider_id)::text,
        'currentProviderKind',coalesce(trust.provider_kind,'saml'),
        'currentRevision',coalesce(trust.revision,evidence.trust_rule_revision),
        'currentLevel',coalesce(trust.level,evidence.level),
        'enabled',coalesce(trust.enabled,false),'retiredAt',to_jsonb(trust.retired_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
        ON trust.id=evidence.trust_rule_id AND trust.revision=evidence.trust_rule_revision
      WHERE evidence.session_id=source.id AND evidence.kind='platform_provider'
        AND evidence.trust_rule_id IS NOT NULL
    ),'[]'::jsonb),
    'policyPins',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'kind',pin.policy_kind,'id',pin.policy_id::text,'revision',pin.policy_revision
      ) ORDER BY CASE pin.policy_kind WHEN 'login' THEN 1 WHEN 'assurance' THEN 2 ELSE 3 END,pin.policy_id)
      FROM ONLY public.auth_session_platform_saml_policy_pins AS pin
      WHERE pin.session_id=source.id
    ),'[]'::jsonb)
  ) INTO result
  FROM source
  JOIN ONLY public.platform_auth_providers AS provider ON provider.id=source.platform_provider_id
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_saml_provider_configurations AS configuration ON configuration.provider_id=provider.id
  JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
    ON metadata.provider_id=provider.id AND metadata.revision=configuration.metadata_revision
  JOIN ONLY public.platform_federated_external_identities AS identity_record
    ON identity_record.id=source.external_identity_id AND identity_record.platform_provider_id=provider.id
  JOIN ONLY public.users AS local_user ON local_user.id=source.user_id
  JOIN ONLY public.mfa_policy_revisions AS pinned_floor
    ON pinned_floor.id=source.platform_floor_policy_id AND pinned_floor.revision=source.platform_floor_policy_revision
  LEFT JOIN current_floor AS floor ON true
  LEFT JOIN LATERAL (
    SELECT alias.* FROM ONLY public.platform_federated_external_identity_aliases AS alias
    WHERE alias.platform_provider_id=provider.id AND alias.external_identity_id=identity_record.id
      AND alias.retired_at IS NULL ORDER BY alias.key_version DESC LIMIT 1
  ) AS current_alias ON true
  LEFT JOIN LATERAL (
    SELECT role_grant.* FROM ONLY public.user_platform_roles AS role_grant
    JOIN ONLY public.platform_roles AS role ON role.id=role_grant.role_id
    WHERE role_grant.user_id=source.user_id AND role_grant.revoked_at IS NULL
      AND role.key='platform_super_admin' ORDER BY role_grant.id LIMIT 1
  ) AS current_grant ON true
  LEFT JOIN LATERAL (
    SELECT sp_key.id
    FROM ONLY public.platform_saml_sp_keys AS sp_key
    JOIN ONLY public.identity_keyring_versions AS root
      ON root.key_version=sp_key.key_version AND root.is_active AND root.retired_at IS NULL
    WHERE sp_key.provider_id=provider.id AND sp_key.revision=configuration.sp_key_revision
      AND sp_key.retired_at IS NULL
      AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
           WHERE certificate.key_id=sp_key.id) BETWEEN 1 AND 8
  ) AS active_key ON true
  LEFT JOIN LATERAL (
    SELECT count(*)::integer AS factor_count,
      (array_agg(factor.id ORDER BY factor.id))[1] AS factor_id,
      (array_agg(factor.security_revision ORDER BY factor.id))[1] AS security_revision
    FROM ONLY public.totp_credentials AS factor
    WHERE factor.user_id=source.user_id AND factor.confirmed_at IS NOT NULL
      AND factor.disabled_at IS NULL
  ) AS factor_choice ON true;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML session revalidation lookup'
    USING ERRCODE='22023';
END;
$function$;

DO $platform_saml_revalidation_final_acl_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity,procedure.proname
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'private_platform_saml_revalidation_field_v1',
      'apply_platform_saml_session_revalidation_v1',
      'recover_platform_saml_session_revalidation_apply_v1',
      'cleanup_platform_saml_session_revalidation_delivery_v1',
      'private_platform_saml_revalidation_digest_v1',
      'load_platform_saml_session_revalidation_v1'
    ]::name[])
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',object_record.identity);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.identity
    );
    IF object_record.proname=ANY(ARRAY[
      'apply_platform_saml_session_revalidation_v1',
      'recover_platform_saml_session_revalidation_apply_v1',
      'cleanup_platform_saml_session_revalidation_delivery_v1',
      'load_platform_saml_session_revalidation_v1'
    ]::name[]) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO periapsis_api',object_record.identity);
    END IF;
  END LOOP;
END;
$platform_saml_revalidation_final_acl_v1$;
--> statement-breakpoint
