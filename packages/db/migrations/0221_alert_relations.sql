-- Explicit Alert-to-Alert duplicate/correlation evidence. Relations never
-- merge aggregates; retraction is terminal append-only evidence.
CREATE TABLE "alert_relation_retractions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"relation_id" uuid NOT NULL,
	"source_alert_id" uuid NOT NULL,
	"target_alert_id" uuid NOT NULL,
	"retracted_by_membership_id" uuid NOT NULL,
	"retracted_by_user_id" uuid NOT NULL,
	"reason" text NOT NULL,
	"prior_source_version" integer NOT NULL,
	"result_source_version" integer NOT NULL,
	"prior_target_version" integer NOT NULL,
	"result_target_version" integer NOT NULL,
	"retracted_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_relation_retractions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "alert_relation_retractions_relation_key" UNIQUE("tenant_id","relation_id"),
	CONSTRAINT "alert_relation_retractions_id_uuidv7_check" CHECK ((uuid_extract_version("alert_relation_retractions"."id") = 7) is true),
	CONSTRAINT "alert_relation_retractions_reason_check" CHECK (btrim("alert_relation_retractions"."reason") <> '' and char_length("alert_relation_retractions"."reason") <= 2000 and "alert_relation_retractions"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "alert_relation_retractions_version_check" CHECK ("alert_relation_retractions"."prior_source_version" between 1 and 2147483646
        and "alert_relation_retractions"."result_source_version" = "alert_relation_retractions"."prior_source_version" + 1
        and "alert_relation_retractions"."prior_target_version" between 1 and 2147483646
        and "alert_relation_retractions"."result_target_version" = "alert_relation_retractions"."prior_target_version" + 1)
);
--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "alert_relations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"source_alert_id" uuid NOT NULL,
	"target_alert_id" uuid NOT NULL,
	"canonical_first_alert_id" uuid NOT NULL,
	"canonical_second_alert_id" uuid NOT NULL,
	"relation_type" text NOT NULL,
	"reason" text NOT NULL,
	"linked_by_membership_id" uuid NOT NULL,
	"linked_by_user_id" uuid NOT NULL,
	"prior_source_version" integer NOT NULL,
	"result_source_version" integer NOT NULL,
	"prior_target_version" integer NOT NULL,
	"result_target_version" integer NOT NULL,
	"linked_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_relations_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "alert_relations_identity_key" UNIQUE("tenant_id","id","source_alert_id","target_alert_id"),
	CONSTRAINT "alert_relations_pair_key" UNIQUE("tenant_id","canonical_first_alert_id","canonical_second_alert_id"),
	CONSTRAINT "alert_relations_id_uuidv7_check" CHECK ((uuid_extract_version("alert_relations"."id") = 7) is true),
	CONSTRAINT "alert_relations_pair_check" CHECK ("alert_relations"."source_alert_id" <> "alert_relations"."target_alert_id"
        and "alert_relations"."canonical_first_alert_id" < "alert_relations"."canonical_second_alert_id"
        and "alert_relations"."canonical_first_alert_id" = least("alert_relations"."source_alert_id", "alert_relations"."target_alert_id")
        and "alert_relations"."canonical_second_alert_id" = greatest("alert_relations"."source_alert_id", "alert_relations"."target_alert_id")),
	CONSTRAINT "alert_relations_type_check" CHECK ("alert_relations"."relation_type" in ('duplicate_of', 'correlation')),
	CONSTRAINT "alert_relations_reason_check" CHECK (btrim("alert_relations"."reason") <> '' and char_length("alert_relations"."reason") <= 2000 and "alert_relations"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "alert_relations_version_check" CHECK ("alert_relations"."prior_source_version" between 1 and 2147483646
        and "alert_relations"."result_source_version" = "alert_relations"."prior_source_version" + 1
        and "alert_relations"."prior_target_version" between 1 and 2147483646
        and "alert_relations"."result_target_version" = "alert_relations"."prior_target_version" + 1)
);
--> statement-breakpoint
ALTER TABLE "alert_relations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ADD CONSTRAINT "alert_relation_retractions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ADD CONSTRAINT "alert_relation_retractions_relation_identity_fk" FOREIGN KEY ("tenant_id","relation_id","source_alert_id","target_alert_id") REFERENCES "public"."alert_relations"("tenant_id","id","source_alert_id","target_alert_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ADD CONSTRAINT "alert_relation_retractions_actor_membership_fk" FOREIGN KEY ("tenant_id","retracted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ADD CONSTRAINT "alert_relation_retractions_actor_user_fk" FOREIGN KEY ("tenant_id","retracted_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_source_alert_fk" FOREIGN KEY ("tenant_id","source_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_target_alert_fk" FOREIGN KEY ("tenant_id","target_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_actor_membership_fk" FOREIGN KEY ("tenant_id","linked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_actor_user_fk" FOREIGN KEY ("tenant_id","linked_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "alert_relation_retractions_source_idx" ON "alert_relation_retractions" USING btree ("tenant_id","source_alert_id","id");--> statement-breakpoint
CREATE INDEX "alert_relation_retractions_target_idx" ON "alert_relation_retractions" USING btree ("tenant_id","target_alert_id","id");--> statement-breakpoint
CREATE INDEX "alert_relations_source_idx" ON "alert_relations" USING btree ("tenant_id","source_alert_id","id");--> statement-breakpoint
CREATE INDEX "alert_relations_target_idx" ON "alert_relations" USING btree ("tenant_id","target_alert_id","id");--> statement-breakpoint
CREATE POLICY "alert_relation_retractions_api_tenant" ON "alert_relation_retractions" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "alert_relation_retractions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alert_relation_retractions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alert_relation_retractions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "alert_relations_api_tenant" ON "alert_relations" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "alert_relations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alert_relations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alert_relations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint

-- Alert-to-Alert mutations admit the same creator-owned scope as reads. The
-- historical alert.update catalog predates this explicit relation workflow and
-- did not expose own, so make that supported scope assignable before the ABI
-- evaluates it. Existing tenant roles are left unchanged.
INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'own'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key = 'alert.update'
ON CONFLICT DO NOTHING;--> statement-breakpoint

ALTER TABLE public.alert_relations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.alert_relation_retractions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.alert_relations OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.alert_relation_retractions OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON TABLE public.alert_relations, public.alert_relation_retractions
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_ticket_runtime_owner,
       periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT ON TABLE public.alert_relations, public.alert_relation_retractions
  TO periapsis_api;--> statement-breakpoint

CREATE TRIGGER alert_relations_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_relations
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER alert_relation_retractions_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_relation_retractions
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint

-- Return the one exact permission scope that authorizes both permissions over
-- both Alert resources. This deliberately rejects a request that would splice
-- read/update grants or two different resource scopes together.
CREATE FUNCTION app.private_current_alert_relation_scope_v1(
  p_source_assigned_team_id uuid,
  p_source_owner_user_id uuid,
  p_source_assignee_user_id uuid,
  p_source_claimed_by_user_id uuid,
  p_target_assigned_team_id uuid,
  p_target_owner_user_id uuid,
  p_target_assignee_user_id uuid,
  p_target_claimed_by_user_id uuid
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF app.current_tenant_human_has_exact_permission_v3('alert.read', 'tenant')
     AND app.current_tenant_human_has_exact_permission_v3('alert.update', 'tenant') THEN
    RETURN 'tenant';
  END IF;

  IF app.current_tenant_human_has_exact_permission_v3('alert.read', 'own')
     AND app.current_tenant_human_has_exact_permission_v3('alert.update', 'own')
     AND actor_user = p_source_owner_user_id
     AND actor_user = p_target_owner_user_id THEN
    RETURN 'own';
  END IF;

  IF app.current_tenant_human_has_exact_permission_v3('alert.read', 'assigned')
     AND app.current_tenant_human_has_exact_permission_v3('alert.update', 'assigned')
     AND actor_user IN (
       p_source_assignee_user_id, p_source_claimed_by_user_id
     )
     AND actor_user IN (
       p_target_assignee_user_id, p_target_claimed_by_user_id
     ) THEN
    RETURN 'assigned';
  END IF;

  IF p_source_assigned_team_id IS NOT NULL
     AND p_target_assigned_team_id IS NOT NULL
     AND app.current_tenant_human_has_exact_permission_v3(
       'alert.read', 'operator_team'
     )
     AND app.current_tenant_human_has_exact_permission_v3(
       'alert.update', 'operator_team'
     )
     AND EXISTS (
       SELECT 1
       FROM public.operator_team_assignment_epochs AS assignment
       JOIN public.operator_team_roster_entries AS roster
         ON roster.tenant_id = assignment.tenant_id
        AND roster.assignment_epoch_id = assignment.id
       JOIN public.tenant_authorization_sources AS source
         ON source.tenant_id = roster.tenant_id
        AND source.id = roster.source_id
       WHERE assignment.tenant_id = context_tenant
         AND assignment.operator_team_id = p_source_assigned_team_id
         AND assignment.ended_at IS NULL
         AND roster.membership_id = actor_membership
         AND roster.revoked_at IS NULL
         AND (roster.expires_at IS NULL
           OR roster.expires_at > transaction_timestamp())
         AND source.retired_at IS NULL
     )
     AND EXISTS (
       SELECT 1
       FROM public.operator_team_assignment_epochs AS assignment
       JOIN public.operator_team_roster_entries AS roster
         ON roster.tenant_id = assignment.tenant_id
        AND roster.assignment_epoch_id = assignment.id
       JOIN public.tenant_authorization_sources AS source
         ON source.tenant_id = roster.tenant_id
        AND source.id = roster.source_id
       WHERE assignment.tenant_id = context_tenant
         AND assignment.operator_team_id = p_target_assigned_team_id
         AND assignment.ended_at IS NULL
         AND roster.membership_id = actor_membership
         AND roster.revoked_at IS NULL
         AND (roster.expires_at IS NULL
           OR roster.expires_at > transaction_timestamp())
         AND source.retired_at IS NULL
     ) THEN
    RETURN 'operator_team';
  END IF;
  RETURN NULL;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_current_alert_relation_scope_v1(
  uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_alert_relation_scope_v1(
  uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_alert_relation_create_replay_v1(
  p_source_alert_id uuid,
  p_target_alert_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (
  result_relation_id uuid,
  relation_type text,
  previous_source_version integer,
  result_source_version integer,
  previous_target_version integer,
  result_target_version integer,
  linked_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay_command public.ticket_commands%ROWTYPE;
  source_alert public.alerts%ROWTYPE;
  target_alert public.alerts%ROWTYPE;
  source_relation public.alert_relations%ROWTYPE;
BEGIN
  IF p_source_alert_id IS NULL
        OR (uuid_extract_version(p_source_alert_id) = 7) IS NOT TRUE
     OR p_target_alert_id IS NULL
        OR (uuid_extract_version(p_target_alert_id) = 7) IS NOT TRUE
     OR p_source_alert_id = p_target_alert_id
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_digest = decode(repeat('00', 32), 'hex') THEN
    RAISE EXCEPTION 'Alert relation replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  SELECT command.* INTO replay_command
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'alert.relation.create'
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay_command.request_digest IS DISTINCT FROM p_request_digest
     OR replay_command.result_alert_id IS DISTINCT FROM p_source_alert_id
     OR replay_command.result_case_id IS NOT NULL THEN
    RAISE EXCEPTION 'Alert relation idempotency key conflicts'
      USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
  END IF;

  SELECT alert.* INTO source_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_source_alert_id
    AND alert.deleted_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT alert.* INTO target_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_target_alert_id
    AND alert.deleted_at IS NULL
  FOR SHARE;
  IF NOT FOUND OR app.private_current_alert_relation_scope_v1(
       source_alert.assigned_team_id, source_alert.created_by,
       source_alert.assignee_user_id, source_alert.claimed_by_user_id,
       target_alert.assigned_team_id, target_alert.created_by,
       target_alert.assignee_user_id, target_alert.claimed_by_user_id
     ) IS NULL THEN
    RAISE EXCEPTION 'Alert relation replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT relation.* INTO source_relation
  FROM public.alert_relations AS relation
  WHERE relation.tenant_id = context_tenant
    AND relation.source_alert_id = p_source_alert_id
    AND relation.target_alert_id = p_target_alert_id
    AND relation.linked_by_membership_id = actor_membership
    AND relation.linked_by_user_id = app.context_user_id()
  FOR SHARE;
  IF NOT FOUND
     OR source_alert.version < source_relation.result_source_version
     OR target_alert.version < source_relation.result_target_version
     OR replay_command.result_version <> source_relation.result_source_version
     OR replay_command.created_at <> source_relation.linked_at
     OR replay_command.result_metadata IS DISTINCT FROM jsonb_build_object(
       'relationId', source_relation.id,
       'relationType', source_relation.relation_type,
       'targetAlertId', source_relation.target_alert_id,
       'previousSourceVersion', source_relation.prior_source_version,
       'sourceVersion', source_relation.result_source_version,
       'previousTargetVersion', source_relation.prior_target_version,
       'targetVersion', source_relation.result_target_version,
       'linkedAt', source_relation.linked_at
     ) THEN
    RAISE EXCEPTION 'Alert relation replay provenance drifted'
      USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT source_relation.id, source_relation.relation_type,
    source_relation.prior_source_version,
    source_relation.result_source_version,
    source_relation.prior_target_version,
    source_relation.result_target_version, source_relation.linked_at;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_alert_relation_create_replay_v1(
  uuid, uuid, bytea, bytea
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_alert_relation_create_replay_v1(
  uuid, uuid, bytea, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_alert_relation_create_replay_v1(
  uuid, uuid, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_tenant_alert_relation_create_v1(
  p_source_alert_id uuid,
  p_target_alert_id uuid,
  p_relation_type text,
  p_expected_source_version integer,
  p_expected_target_version integer,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_relation_id uuid,
  result_relation_type text,
  previous_source_version integer,
  result_source_version integer,
  previous_target_version integer,
  result_target_version integer,
  linked_at timestamp with time zone,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  source_alert public.alerts%ROWTYPE;
  target_alert public.alerts%ROWTYPE;
  replay_result record;
  relation_id uuid := uuidv7();
  operation_at timestamp with time zone := transaction_timestamp();
  affected_rows integer;
BEGIN
  IF p_source_alert_id IS NULL
        OR (uuid_extract_version(p_source_alert_id) = 7) IS NOT TRUE
     OR p_target_alert_id IS NULL
        OR (uuid_extract_version(p_target_alert_id) = 7) IS NOT TRUE
     OR p_source_alert_id = p_target_alert_id
     OR p_relation_type NOT IN ('duplicate_of', 'correlation')
     OR p_expected_source_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_target_version NOT BETWEEN 1 AND 2147483646
     OR p_reason IS NULL OR btrim(p_reason) = '' OR btrim(p_reason) <> p_reason
        OR char_length(p_reason) > 2000 OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
        OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
        OR p_request_digest = decode(repeat('00', 32), 'hex')
     OR p_request_id IS NULL OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR p_correlation_id IS NULL OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR btrim(p_user_agent) = ''
        OR octet_length(p_user_agent) > 512 OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
        OR p_authentication_method !~ '^[a-z][a-z0-9_.-]{0,63}$' THEN
    RAISE EXCEPTION 'Alert relation request is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':alert.relation.create:' || encode(p_key_digest, 'hex'), 0
  ));

  SELECT replay.* INTO replay_result
  FROM app.lookup_tenant_alert_relation_create_replay_v1(
    p_source_alert_id, p_target_alert_id, p_key_digest, p_request_digest
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_result.result_relation_id,
      replay_result.relation_type, replay_result.previous_source_version,
      replay_result.result_source_version,
      replay_result.previous_target_version,
      replay_result.result_target_version, replay_result.linked_at, true;
    RETURN;
  END IF;

  -- Lock the pair in canonical UUID order so reverse requests cannot deadlock.
  PERFORM 1 FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id IN (p_source_alert_id, p_target_alert_id)
    AND alert.deleted_at IS NULL
  ORDER BY alert.id
  FOR UPDATE;

  SELECT alert.* INTO source_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_source_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation source is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT alert.* INTO target_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_target_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation target is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF source_alert.version <> p_expected_source_version
     OR target_alert.version <> p_expected_target_version THEN
    RAISE EXCEPTION 'Alert relation version pin is stale'
      USING ERRCODE = '40001';
  END IF;
  IF app.private_current_alert_relation_scope_v1(
       source_alert.assigned_team_id, source_alert.created_by,
       source_alert.assignee_user_id, source_alert.claimed_by_user_id,
       target_alert.assigned_team_id, target_alert.created_by,
       target_alert.assignee_user_id, target_alert.claimed_by_user_id
     ) IS NULL THEN
    RAISE EXCEPTION 'Alert relation authority is required'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.alert_relations (
    id, tenant_id, source_alert_id, target_alert_id,
    canonical_first_alert_id, canonical_second_alert_id,
    relation_type, reason, linked_by_membership_id, linked_by_user_id,
    prior_source_version, result_source_version,
    prior_target_version, result_target_version, linked_at
  ) VALUES (
    relation_id, context_tenant, p_source_alert_id, p_target_alert_id,
    least(p_source_alert_id, p_target_alert_id),
    greatest(p_source_alert_id, p_target_alert_id),
    p_relation_type, p_reason, actor_membership, actor_user,
    p_expected_source_version, p_expected_source_version + 1,
    p_expected_target_version, p_expected_target_version + 1, operation_at
  );

  UPDATE public.alerts AS alert
  SET version = p_expected_source_version + 1, updated_at = operation_at
  WHERE alert.tenant_id = context_tenant AND alert.id = p_source_alert_id
    AND alert.version = p_expected_source_version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Alert relation source compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.alerts AS alert
  SET version = p_expected_target_version + 1, updated_at = operation_at
  WHERE alert.tenant_id = context_tenant AND alert.id = p_target_alert_id
    AND alert.version = p_expected_target_version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Alert relation target compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;

  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_source_alert_id, 'relation_added',
    p_expected_source_version + 1, ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object('version', p_expected_source_version),
    jsonb_build_object('version', p_expected_source_version + 1),
    jsonb_build_object(
      'relation_id', relation_id, 'relation_type', p_relation_type,
      'related_alert_id', p_target_alert_id,
      'relation_source_alert_id', p_source_alert_id,
      'relation_target_alert_id', p_target_alert_id,
      'reason', p_reason, 'content_redacted', true
    )
  );
  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_target_alert_id, 'relation_added',
    p_expected_target_version + 1, ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object('version', p_expected_target_version),
    jsonb_build_object('version', p_expected_target_version + 1),
    jsonb_build_object(
      'relation_id', relation_id, 'relation_type', p_relation_type,
      'related_alert_id', p_source_alert_id,
      'relation_source_alert_id', p_source_alert_id,
      'relation_target_alert_id', p_target_alert_id,
      'reason', p_reason, 'content_redacted', true
    )
  );

  INSERT INTO public.ticket_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_alert_id, result_case_id,
    result_version, result_metadata, created_at
  ) VALUES (
    context_tenant, 'alert.relation.create', actor_membership, actor_user,
    p_key_digest, p_request_digest, p_source_alert_id, NULL,
    p_expected_source_version + 1,
    jsonb_build_object(
      'relationId', relation_id, 'relationType', p_relation_type,
      'targetAlertId', p_target_alert_id,
      'previousSourceVersion', p_expected_source_version,
      'sourceVersion', p_expected_source_version + 1,
      'previousTargetVersion', p_expected_target_version,
      'targetVersion', p_expected_target_version + 1,
      'linkedAt', operation_at
    ), operation_at
  );

  RETURN QUERY SELECT relation_id, p_relation_type,
    p_expected_source_version, p_expected_source_version + 1,
    p_expected_target_version, p_expected_target_version + 1,
    operation_at, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_alert_relation_create_v1(
  uuid, uuid, text, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_alert_relation_create_v1(
  uuid, uuid, text, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_alert_relation_create_v1(
  uuid, uuid, text, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_alert_relation_retract_replay_v1(
  p_alert_id uuid,
  p_related_alert_id uuid,
  p_relation_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (
  result_relation_id uuid,
  relation_type text,
  previous_alert_version integer,
  result_alert_version integer,
  previous_related_alert_version integer,
  result_related_alert_version integer,
  retracted_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay_command public.ticket_commands%ROWTYPE;
  path_alert public.alerts%ROWTYPE;
  related_alert public.alerts%ROWTYPE;
  source_relation public.alert_relations%ROWTYPE;
  retraction public.alert_relation_retractions%ROWTYPE;
  prior_path integer;
  result_path integer;
  prior_related integer;
  result_related integer;
BEGIN
  IF p_alert_id IS NULL OR (uuid_extract_version(p_alert_id) = 7) IS NOT TRUE
     OR p_related_alert_id IS NULL
        OR (uuid_extract_version(p_related_alert_id) = 7) IS NOT TRUE
     OR p_relation_id IS NULL
        OR (uuid_extract_version(p_relation_id) = 7) IS NOT TRUE
     OR p_alert_id = p_related_alert_id
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_digest = decode(repeat('00', 32), 'hex') THEN
    RAISE EXCEPTION 'Alert relation retraction replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  SELECT command.* INTO replay_command
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'alert.relation.retract'
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay_command.request_digest IS DISTINCT FROM p_request_digest
     OR replay_command.result_alert_id IS DISTINCT FROM p_alert_id
     OR replay_command.result_case_id IS NOT NULL THEN
    RAISE EXCEPTION 'Alert relation retraction idempotency key conflicts'
      USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
  END IF;

  SELECT relation.* INTO source_relation
  FROM public.alert_relations AS relation
  WHERE relation.tenant_id = context_tenant AND relation.id = p_relation_id
    AND (
      relation.source_alert_id = p_alert_id
        AND relation.target_alert_id = p_related_alert_id
      OR relation.source_alert_id = p_related_alert_id
        AND relation.target_alert_id = p_alert_id
    )
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation retraction replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT alert.* INTO path_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation retraction replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT alert.* INTO related_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_related_alert_id
    AND alert.deleted_at IS NULL
  FOR SHARE;
  IF NOT FOUND OR app.private_current_alert_relation_scope_v1(
       path_alert.assigned_team_id, path_alert.created_by,
       path_alert.assignee_user_id, path_alert.claimed_by_user_id,
       related_alert.assigned_team_id, related_alert.created_by,
       related_alert.assignee_user_id, related_alert.claimed_by_user_id
     ) IS NULL THEN
    RAISE EXCEPTION 'Alert relation retraction replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT withdrawn.* INTO retraction
  FROM public.alert_relation_retractions AS withdrawn
  WHERE withdrawn.tenant_id = context_tenant
    AND withdrawn.relation_id = p_relation_id
    AND withdrawn.retracted_by_membership_id = actor_membership
    AND withdrawn.retracted_by_user_id = app.context_user_id()
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation retraction replay provenance drifted'
      USING ERRCODE = '55000';
  END IF;
  IF source_relation.source_alert_id = p_alert_id THEN
    prior_path := retraction.prior_source_version;
    result_path := retraction.result_source_version;
    prior_related := retraction.prior_target_version;
    result_related := retraction.result_target_version;
  ELSE
    prior_path := retraction.prior_target_version;
    result_path := retraction.result_target_version;
    prior_related := retraction.prior_source_version;
    result_related := retraction.result_source_version;
  END IF;
  IF path_alert.version < result_path
     OR related_alert.version < result_related
     OR replay_command.result_version <> result_path
     OR replay_command.created_at <> retraction.retracted_at
     OR replay_command.result_metadata IS DISTINCT FROM jsonb_build_object(
       'relationId', source_relation.id,
       'relationType', source_relation.relation_type,
       'relatedAlertId', p_related_alert_id,
       'previousAlertVersion', prior_path,
       'alertVersion', result_path,
       'previousRelatedAlertVersion', prior_related,
       'relatedAlertVersion', result_related,
       'retractedAt', retraction.retracted_at
     ) THEN
    RAISE EXCEPTION 'Alert relation retraction replay provenance drifted'
      USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT source_relation.id, source_relation.relation_type,
    prior_path, result_path, prior_related, result_related,
    retraction.retracted_at;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_alert_relation_retract_replay_v1(
  uuid, uuid, uuid, bytea, bytea
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_alert_relation_retract_replay_v1(
  uuid, uuid, uuid, bytea, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_alert_relation_retract_replay_v1(
  uuid, uuid, uuid, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_tenant_alert_relation_retract_v1(
  p_alert_id uuid,
  p_related_alert_id uuid,
  p_relation_id uuid,
  p_expected_alert_version integer,
  p_expected_related_alert_version integer,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_relation_id uuid,
  result_relation_type text,
  previous_alert_version integer,
  result_alert_version integer,
  previous_related_alert_version integer,
  result_related_alert_version integer,
  retracted_at timestamp with time zone,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  path_alert public.alerts%ROWTYPE;
  related_alert public.alerts%ROWTYPE;
  source_relation public.alert_relations%ROWTYPE;
  replay_result record;
  operation_at timestamp with time zone := transaction_timestamp();
  prior_source integer;
  result_source integer;
  prior_target integer;
  result_target integer;
  affected_rows integer;
BEGIN
  IF p_alert_id IS NULL OR (uuid_extract_version(p_alert_id) = 7) IS NOT TRUE
     OR p_related_alert_id IS NULL
        OR (uuid_extract_version(p_related_alert_id) = 7) IS NOT TRUE
     OR p_relation_id IS NULL
        OR (uuid_extract_version(p_relation_id) = 7) IS NOT TRUE
     OR p_alert_id = p_related_alert_id
     OR p_expected_alert_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_related_alert_version NOT BETWEEN 1 AND 2147483646
     OR p_reason IS NULL OR btrim(p_reason) = '' OR btrim(p_reason) <> p_reason
        OR char_length(p_reason) > 2000 OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
        OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
        OR p_request_digest = decode(repeat('00', 32), 'hex')
     OR p_request_id IS NULL OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR p_correlation_id IS NULL OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR btrim(p_user_agent) = ''
        OR octet_length(p_user_agent) > 512 OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
        OR p_authentication_method !~ '^[a-z][a-z0-9_.-]{0,63}$' THEN
    RAISE EXCEPTION 'Alert relation retraction request is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':alert.relation.retract:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT replay.* INTO replay_result
  FROM app.lookup_tenant_alert_relation_retract_replay_v1(
    p_alert_id, p_related_alert_id, p_relation_id,
    p_key_digest, p_request_digest
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_result.result_relation_id,
      replay_result.relation_type, replay_result.previous_alert_version,
      replay_result.result_alert_version,
      replay_result.previous_related_alert_version,
      replay_result.result_related_alert_version,
      replay_result.retracted_at, true;
    RETURN;
  END IF;

  PERFORM 1 FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id IN (p_alert_id, p_related_alert_id)
    AND alert.deleted_at IS NULL
  ORDER BY alert.id
  FOR UPDATE;
  SELECT alert.* INTO path_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation retraction source is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT alert.* INTO related_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_related_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation retraction target is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF path_alert.version <> p_expected_alert_version
     OR related_alert.version <> p_expected_related_alert_version THEN
    RAISE EXCEPTION 'Alert relation retraction version pin is stale'
      USING ERRCODE = '40001';
  END IF;
  IF app.private_current_alert_relation_scope_v1(
       path_alert.assigned_team_id, path_alert.created_by,
       path_alert.assignee_user_id, path_alert.claimed_by_user_id,
       related_alert.assigned_team_id, related_alert.created_by,
       related_alert.assignee_user_id, related_alert.claimed_by_user_id
     ) IS NULL THEN
    RAISE EXCEPTION 'Alert relation retraction authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT relation.* INTO source_relation
  FROM public.alert_relations AS relation
  WHERE relation.tenant_id = context_tenant AND relation.id = p_relation_id
    AND (
      relation.source_alert_id = p_alert_id
        AND relation.target_alert_id = p_related_alert_id
      OR relation.source_alert_id = p_related_alert_id
        AND relation.target_alert_id = p_alert_id
    )
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert relation is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.alert_relation_retractions AS retraction
    WHERE retraction.tenant_id = context_tenant
      AND retraction.relation_id = p_relation_id
  ) THEN
    RAISE EXCEPTION 'Alert relation retraction is terminal'
      USING ERRCODE = '23505',
            CONSTRAINT = 'alert_relation_retractions_relation_key';
  END IF;

  IF source_relation.source_alert_id = p_alert_id THEN
    prior_source := p_expected_alert_version;
    result_source := p_expected_alert_version + 1;
    prior_target := p_expected_related_alert_version;
    result_target := p_expected_related_alert_version + 1;
  ELSE
    prior_source := p_expected_related_alert_version;
    result_source := p_expected_related_alert_version + 1;
    prior_target := p_expected_alert_version;
    result_target := p_expected_alert_version + 1;
  END IF;

  UPDATE public.alerts AS alert
  SET version = p_expected_alert_version + 1, updated_at = operation_at
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.version = p_expected_alert_version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Alert relation retraction source compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.alerts AS alert
  SET version = p_expected_related_alert_version + 1,
      updated_at = operation_at
  WHERE alert.tenant_id = context_tenant AND alert.id = p_related_alert_id
    AND alert.version = p_expected_related_alert_version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Alert relation retraction target compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.alert_relation_retractions (
    tenant_id, relation_id, source_alert_id, target_alert_id,
    retracted_by_membership_id, retracted_by_user_id, reason,
    prior_source_version, result_source_version,
    prior_target_version, result_target_version, retracted_at
  ) VALUES (
    context_tenant, p_relation_id, source_relation.source_alert_id,
    source_relation.target_alert_id, actor_membership, actor_user, p_reason,
    prior_source, result_source, prior_target, result_target, operation_at
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_alert_id, 'relation_retracted',
    p_expected_alert_version + 1, ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object('version', p_expected_alert_version),
    jsonb_build_object('version', p_expected_alert_version + 1),
    jsonb_build_object(
      'relation_id', p_relation_id,
      'relation_type', source_relation.relation_type,
      'related_alert_id', p_related_alert_id,
      'relation_source_alert_id', source_relation.source_alert_id,
      'relation_target_alert_id', source_relation.target_alert_id,
      'reason', p_reason, 'content_redacted', true
    )
  );
  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_related_alert_id, 'relation_retracted',
    p_expected_related_alert_version + 1,
    ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object('version', p_expected_related_alert_version),
    jsonb_build_object('version', p_expected_related_alert_version + 1),
    jsonb_build_object(
      'relation_id', p_relation_id,
      'relation_type', source_relation.relation_type,
      'related_alert_id', p_alert_id,
      'relation_source_alert_id', source_relation.source_alert_id,
      'relation_target_alert_id', source_relation.target_alert_id,
      'reason', p_reason, 'content_redacted', true
    )
  );

  INSERT INTO public.ticket_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_alert_id, result_case_id,
    result_version, result_metadata, created_at
  ) VALUES (
    context_tenant, 'alert.relation.retract', actor_membership, actor_user,
    p_key_digest, p_request_digest, p_alert_id, NULL,
    p_expected_alert_version + 1,
    jsonb_build_object(
      'relationId', p_relation_id,
      'relationType', source_relation.relation_type,
      'relatedAlertId', p_related_alert_id,
      'previousAlertVersion', p_expected_alert_version,
      'alertVersion', p_expected_alert_version + 1,
      'previousRelatedAlertVersion', p_expected_related_alert_version,
      'relatedAlertVersion', p_expected_related_alert_version + 1,
      'retractedAt', operation_at
    ), operation_at
  );

  RETURN QUERY SELECT p_relation_id, source_relation.relation_type,
    p_expected_alert_version, p_expected_alert_version + 1,
    p_expected_related_alert_version,
    p_expected_related_alert_version + 1, operation_at, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_alert_relation_retract_v1(
  uuid, uuid, uuid, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_alert_relation_retract_v1(
  uuid, uuid, uuid, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_alert_relation_retract_v1(
  uuid, uuid, uuid, integer, integer, text, bytea, bytea,
  uuid, uuid, inet, text, text
) TO periapsis_api;
