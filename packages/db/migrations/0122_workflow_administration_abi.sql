-- Workflow administration is exposed through a narrow, migration-owned ABI.
-- Runtime roles can read authorized projections, but all writes, replay state,
-- audit evidence, and outbox publication remain transactionally coupled here.

ALTER TABLE public.ticket_workflows OWNER TO periapsis_migrator;
ALTER TABLE public.ticket_workflow_versions OWNER TO periapsis_migrator;
ALTER TABLE public.ticket_workflow_commands OWNER TO periapsis_migrator;
ALTER TABLE public.ticket_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_workflows FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_workflow_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_workflow_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_workflow_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_workflow_commands FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.ticket_workflows,
  public.ticket_workflow_versions, public.ticket_workflow_commands
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.ticket_workflows, public.ticket_workflow_versions
FROM periapsis_api;
REVOKE ALL ON TABLE public.ticket_workflow_commands FROM periapsis_api;
GRANT SELECT ON TABLE public.ticket_workflows,
  public.ticket_workflow_versions TO periapsis_api;
--> statement-breakpoint

DROP POLICY IF EXISTS ticket_workflows_api_tenant
ON public.ticket_workflows;
DROP POLICY IF EXISTS ticket_workflow_versions_api_tenant
ON public.ticket_workflow_versions;
CREATE POLICY ticket_workflows_api_tenant
ON public.ticket_workflows AS PERMISSIVE FOR SELECT TO periapsis_api
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND (
    app.current_tenant_human_has_exact_permission_v3(
      'workflow.read', 'tenant'
    )
    OR app.current_tenant_human_has_exact_permission_v3(
      'workflow.manage', 'tenant'
    )
  )
);
CREATE POLICY ticket_workflow_versions_api_tenant
ON public.ticket_workflow_versions AS PERMISSIVE FOR SELECT TO periapsis_api
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND (
    app.current_tenant_human_has_exact_permission_v3(
      'workflow.read', 'tenant'
    )
    OR app.current_tenant_human_has_exact_permission_v3(
      'workflow.manage', 'tenant'
    )
  )
);
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'workflow.read', 'Read workflows',
   'Read tenant Alert and Case workflow definitions and versions.', false),
  (uuidv7(), 'workflow.manage', 'Manage workflows',
   'Create, publish, configure, default, archive, and restore tenant workflows.', false)
ON CONFLICT (key) DO UPDATE
SET service_account_allowed = false;
--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN ('workflow.read', 'workflow.manage')
ON CONFLICT DO NOTHING;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_workflow_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  changed_role_ids uuid[] := ARRAY[]::uuid[];
  permission_role_ids uuid[] := ARRAY[]::uuid[];
  ceiling_role_ids uuid[] := ARRAY[]::uuid[];
  changed_role record;
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'workflow authorization tenant is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope,
      created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'tenant'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission
      ON permission.key IN ('workflow.read', 'workflow.manage')
    WHERE role.tenant_id = p_tenant_id
      AND role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT role_id), ARRAY[]::uuid[])
  INTO permission_role_ids FROM inserted;

  WITH inserted AS (
    INSERT INTO public.tenant_role_delegation_ceilings (
      tenant_id, role_id, permission_id, scope,
      created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'tenant'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission
      ON permission.key IN ('workflow.read', 'workflow.manage')
    WHERE role.tenant_id = p_tenant_id
      AND role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT role_id), ARRAY[]::uuid[])
  INTO ceiling_role_ids FROM inserted;

  SELECT coalesce(array_agg(DISTINCT changed.role_id), ARRAY[]::uuid[])
  INTO changed_role_ids
  FROM unnest(permission_role_ids || ceiling_role_ids) AS changed(role_id);

  FOR changed_role IN
    SELECT role.id, role.version
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.id = ANY(changed_role_ids)
    ORDER BY role.id
    FOR UPDATE
  LOOP
    IF changed_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'workflow authorization role version is exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = changed_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = changed_role.id;
  END LOOP;

  IF cardinality(changed_role_ids) > 0 THEN
    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, outcome, before, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.workflow_seeded', 'tenant_authorization',
      p_tenant_id, 'success', NULL,
      jsonb_build_object('workflow_permissions', true),
      jsonb_build_object(
        'migration', '0122_workflow_administration_abi',
        'role_count', cardinality(changed_role_ids),
        'content_redacted', true
      )
    );
  END IF;
END;
$function$;
ALTER FUNCTION app.private_seed_tenant_workflow_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_seed_tenant_workflow_authorization_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

SELECT app.private_seed_tenant_workflow_authorization_v1(tenant.id)
FROM public.tenants AS tenant
ORDER BY tenant.id;
--> statement-breakpoint

-- Keep a static successor name so migration parsers never need to resolve an
-- overloaded function that has just been renamed in the same source file.
CREATE FUNCTION app.seed_tenant_authorization_workflow_successor(
  p_tenant_id uuid,
  p_bootstrap_user_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_workflow_compatibility_impl(
    p_tenant_id, p_bootstrap_user_id
  );
  PERFORM app.private_seed_tenant_workflow_authorization_v1(p_tenant_id);
END;
$function$;
--> statement-breakpoint
DO $workflow_seed_successor$
BEGIN
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) RENAME TO seed_tenant_authorization_workflow_compatibility_impl';
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization_workflow_successor(uuid, uuid) RENAME TO seed_tenant_authorization';
END
$workflow_seed_successor$;
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION
  app.seed_tenant_authorization_workflow_compatibility_impl(uuid, uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid),
  app.seed_tenant_authorization_workflow_compatibility_impl(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_workflow_json_exact_keys_v1(
  p_document jsonb,
  p_keys text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT CASE WHEN jsonb_typeof(p_document) <> 'object' THEN false
    ELSE p_document ?& p_keys
      AND (SELECT count(*) FROM jsonb_object_keys(p_document))
        = cardinality(p_keys)
  END
$function$;
ALTER FUNCTION app.private_workflow_json_exact_keys_v1(jsonb, text[])
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_workflow_json_exact_keys_v1(jsonb, text[])
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_workflow_effect_plan_valid_v1(
  p_effects jsonb
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT p_effects IN (
    '["activity","audit"]'::jsonb,
    '["activity","audit","sla"]'::jsonb,
    '["activity","audit","notification"]'::jsonb,
    '["activity","audit","sla","notification"]'::jsonb
  )
$function$;
ALTER FUNCTION app.private_workflow_effect_plan_valid_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_workflow_effect_plan_valid_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_workflow_string_array_valid_v1(
  p_values jsonb,
  p_kind text,
  p_aggregate_kind public.ticket_aggregate_kind
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  item record;
  current_value text;
  previous_value text;
  current_rank integer;
  previous_rank integer := 0;
BEGIN
  IF jsonb_typeof(p_values) <> 'array'
     OR jsonb_array_length(p_values) > 64
     OR p_kind NOT IN ('key', 'permission') THEN
    RETURN false;
  END IF;
  FOR item IN
    SELECT value, ordinality
    FROM jsonb_array_elements(p_values) WITH ORDINALITY
  LOOP
    IF jsonb_typeof(item.value) <> 'string' THEN
      RETURN false;
    END IF;
    current_value := item.value #>> '{}';
    IF p_kind = 'key' THEN
      IF current_value !~ '^[a-z][a-z0-9_.-]{0,63}$'
         OR previous_value IS NOT NULL
           AND previous_value COLLATE "C" >= current_value COLLATE "C" THEN
        RETURN false;
      END IF;
      previous_value := current_value;
    ELSE
      current_rank := CASE current_value
        WHEN 'alert.create' THEN 1
        WHEN 'alert.update' THEN 2
        WHEN 'alert.assign' THEN 3
        WHEN 'alert.claim' THEN 4
        WHEN 'alert.escalate' THEN 5
        WHEN 'alert.comment.public' THEN 6
        WHEN 'alert.comment.private' THEN 7
        WHEN 'case.create' THEN 8
        WHEN 'case.update' THEN 9
        WHEN 'case.claim' THEN 10
        WHEN 'case.transfer' THEN 11
        WHEN 'case.transition' THEN 12
        WHEN 'case.comment.public' THEN 13
        WHEN 'case.comment.private' THEN 14
        ELSE 0
      END;
      IF current_rank = 0 OR current_rank <= previous_rank
         OR p_aggregate_kind = 'alert'
           AND current_value NOT LIKE 'alert.%'
         OR p_aggregate_kind = 'case'
           AND current_value NOT LIKE 'case.%' THEN
        RETURN false;
      END IF;
      previous_rank := current_rank;
    END IF;
  END LOOP;
  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_workflow_string_array_valid_v1(
  jsonb, text, public.ticket_aggregate_kind
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_workflow_string_array_valid_v1(
  jsonb, text, public.ticket_aggregate_kind
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_workflow_condition_node_count_v1(
  p_node jsonb,
  p_depth integer DEFAULT 1
)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE
  node_kind text;
  field_name text;
  operator_name text;
  values_json jsonb;
  value_item record;
  value_type text;
  first_value_type text;
  expected_type text;
  previous_text text;
  current_text text;
  previous_number numeric;
  current_number numeric;
  previous_boolean boolean;
  current_boolean boolean;
  previous_instant timestamp with time zone;
  current_instant timestamp with time zone;
  child_item record;
  child_count integer;
  total_count integer := 1;
  value_count integer;
BEGIN
  IF p_depth NOT BETWEEN 1 AND 8
     OR jsonb_typeof(p_node) <> 'object'
     OR jsonb_typeof(p_node -> 'kind') <> 'string' THEN
    RETURN 0;
  END IF;
  node_kind := p_node ->> 'kind';
  IF node_kind = 'predicate' THEN
    IF NOT app.private_workflow_json_exact_keys_v1(
      p_node, ARRAY['kind', 'field', 'operator', 'values']
    ) OR jsonb_typeof(p_node -> 'field') <> 'string'
      OR jsonb_typeof(p_node -> 'operator') <> 'string'
      OR jsonb_typeof(p_node -> 'values') <> 'array' THEN
      RETURN 0;
    END IF;
    field_name := p_node ->> 'field';
    operator_name := p_node ->> 'operator';
    values_json := p_node -> 'values';
    value_count := jsonb_array_length(values_json);
    IF field_name !~ '^(aggregate_kind|state|severity|priority|category|classification|source|source_type|customer_visible|assigned|assignee_present|claimed|comment_present|detected_at|received_at|opened_at|created_at|updated_at|(custom|tag)\.[a-z][a-z0-9_.-]{0,63})$'
       OR operator_name NOT IN (
         'equal', 'not_equal', 'in', 'not_in', 'less_than',
         'less_than_or_equal', 'greater_than',
         'greater_than_or_equal', 'exists', 'not_exists'
       ) OR value_count > 32
       OR operator_name IN ('exists', 'not_exists') AND value_count <> 0
       OR operator_name IN (
         'equal', 'not_equal', 'less_than', 'less_than_or_equal',
         'greater_than', 'greater_than_or_equal'
       ) AND value_count <> 1
       OR operator_name IN ('in', 'not_in') AND value_count NOT BETWEEN 1 AND 32 THEN
      RETURN 0;
    END IF;
    expected_type := CASE
      WHEN field_name IN (
        'aggregate_kind', 'state', 'severity', 'priority', 'category',
        'classification', 'source', 'source_type'
      ) THEN 'text'
      WHEN field_name IN (
        'customer_visible', 'assigned', 'assignee_present', 'claimed',
        'comment_present'
      ) OR field_name LIKE 'tag.%' THEN 'boolean'
      WHEN field_name IN (
        'detected_at', 'received_at', 'opened_at', 'created_at',
        'updated_at'
      ) THEN 'instant'
      ELSE NULL
    END;
    FOR value_item IN
      SELECT value, ordinality
      FROM jsonb_array_elements(values_json) WITH ORDINALITY
    LOOP
      IF NOT app.private_workflow_json_exact_keys_v1(
        value_item.value, ARRAY['type', 'value']
      ) OR jsonb_typeof(value_item.value -> 'type') <> 'string' THEN
        RETURN 0;
      END IF;
      value_type := value_item.value ->> 'type';
      IF first_value_type IS NULL THEN
        first_value_type := value_type;
      ELSIF first_value_type <> value_type THEN
        RETURN 0;
      END IF;
      IF expected_type IS NOT NULL AND expected_type <> value_type THEN
        RETURN 0;
      END IF;
      IF value_type = 'text' THEN
        IF jsonb_typeof(value_item.value -> 'value') <> 'string' THEN
          RETURN 0;
        END IF;
        current_text := value_item.value ->> 'value';
        IF octet_length(current_text) NOT BETWEEN 1 AND 2048
           OR btrim(current_text) <> current_text
           OR current_text ~ '[[:cntrl:]]' THEN
          RETURN 0;
        END IF;
        IF operator_name IN ('in', 'not_in')
           AND previous_text IS NOT NULL
           AND previous_text COLLATE "C" >= current_text COLLATE "C" THEN
          RETURN 0;
        END IF;
        previous_text := current_text;
      ELSIF value_type = 'number' THEN
        IF jsonb_typeof(value_item.value -> 'value') <> 'number'
           OR length(value_item.value ->> 'value') > 320 THEN
          RETURN 0;
        END IF;
        current_number := (value_item.value ->> 'value')::numeric;
        IF abs(current_number) > 1.7976931348623157e308::numeric
           OR operator_name IN ('in', 'not_in')
             AND previous_number IS NOT NULL
             AND previous_number >= current_number THEN
          RETURN 0;
        END IF;
        previous_number := current_number;
      ELSIF value_type = 'boolean' THEN
        IF jsonb_typeof(value_item.value -> 'value') <> 'boolean' THEN
          RETURN 0;
        END IF;
        current_boolean := (value_item.value ->> 'value')::boolean;
        IF operator_name IN ('in', 'not_in')
           AND previous_boolean IS NOT NULL
           AND previous_boolean >= current_boolean THEN
          RETURN 0;
        END IF;
        previous_boolean := current_boolean;
      ELSIF value_type = 'instant' THEN
        IF jsonb_typeof(value_item.value -> 'value') <> 'string' THEN
          RETURN 0;
        END IF;
        current_text := value_item.value ->> 'value';
        IF current_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN
          RETURN 0;
        END IF;
        current_instant := current_text::timestamp with time zone;
        IF operator_name IN ('in', 'not_in')
           AND previous_instant IS NOT NULL
           AND previous_instant >= current_instant THEN
          RETURN 0;
        END IF;
        previous_instant := current_instant;
      ELSE
        RETURN 0;
      END IF;
    END LOOP;
    IF operator_name IN (
      'less_than', 'less_than_or_equal', 'greater_than',
      'greater_than_or_equal'
    ) AND first_value_type NOT IN ('number', 'instant') THEN
      RETURN 0;
    END IF;
    RETURN 1;
  ELSIF node_kind IN ('all', 'any', 'not') THEN
    IF NOT app.private_workflow_json_exact_keys_v1(
      p_node, ARRAY['kind', 'children']
    ) OR jsonb_typeof(p_node -> 'children') <> 'array'
      OR node_kind IN ('all', 'any')
        AND jsonb_array_length(p_node -> 'children') NOT BETWEEN 2 AND 32
      OR node_kind = 'not'
        AND jsonb_array_length(p_node -> 'children') <> 1 THEN
      RETURN 0;
    END IF;
    FOR child_item IN
      SELECT value FROM jsonb_array_elements(p_node -> 'children')
    LOOP
      child_count := app.private_workflow_condition_node_count_v1(
        child_item.value, p_depth + 1
      );
      IF child_count = 0 THEN
        RETURN 0;
      END IF;
      total_count := total_count + child_count;
      IF total_count > 128 THEN
        RETURN 0;
      END IF;
    END LOOP;
    RETURN total_count;
  END IF;
  RETURN 0;
EXCEPTION WHEN OTHERS THEN
  RETURN 0;
END;
$function$;
ALTER FUNCTION app.private_workflow_condition_node_count_v1(jsonb, integer)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_workflow_condition_node_count_v1(jsonb, integer)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_workflow_definition_valid_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_states jsonb,
  p_transitions jsonb
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE
  state_item record;
  action_item record;
  transition_item record;
  state_key text;
  previous_state_key text;
  action_name text;
  previous_action_rank integer;
  action_rank integer;
  initial_state text;
  initial_count integer := 0;
  terminal_count integer := 0;
  state_keys text[] := ARRAY[]::text[];
  terminal_keys text[] := ARRAY[]::text[];
  outgoing_keys text[] := ARRAY[]::text[];
  edge_keys text[] := ARRAY[]::text[];
  transition_key text;
  previous_transition_key text;
  from_key text;
  to_key text;
  seen_keys text[] := ARRAY[]::text[];
  changed boolean;
BEGIN
  IF p_aggregate_kind NOT IN ('alert', 'case')
     OR jsonb_typeof(p_states) <> 'array'
     OR jsonb_array_length(p_states) NOT BETWEEN 2 AND 64
     OR jsonb_typeof(p_transitions) <> 'array'
     OR jsonb_array_length(p_transitions) NOT BETWEEN 1 AND 256
     OR octet_length(p_states::text) + octet_length(p_transitions::text)
       > 491520 THEN
    RETURN false;
  END IF;

  FOR state_item IN
    SELECT value, ordinality
    FROM jsonb_array_elements(p_states) WITH ORDINALITY
  LOOP
    IF NOT app.private_workflow_json_exact_keys_v1(
      state_item.value,
      ARRAY['key', 'initial', 'terminal', 'visibility', 'actions']
    ) OR jsonb_typeof(state_item.value -> 'key') <> 'string'
      OR jsonb_typeof(state_item.value -> 'initial') <> 'boolean'
      OR jsonb_typeof(state_item.value -> 'terminal') <> 'boolean'
      OR jsonb_typeof(state_item.value -> 'visibility') <> 'string'
      OR jsonb_typeof(state_item.value -> 'actions') <> 'array'
      OR jsonb_array_length(state_item.value -> 'actions') > 7 THEN
      RETURN false;
    END IF;
    state_key := state_item.value ->> 'key';
    IF state_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
       OR previous_state_key IS NOT NULL
         AND previous_state_key COLLATE "C" >= state_key COLLATE "C"
       OR state_item.value ->> 'visibility' NOT IN ('internal', 'customer')
       OR (state_item.value ->> 'initial')::boolean
          AND (state_item.value ->> 'terminal')::boolean THEN
      RETURN false;
    END IF;
    previous_state_key := state_key;
    state_keys := array_append(state_keys, state_key);
    IF (state_item.value ->> 'initial')::boolean THEN
      initial_count := initial_count + 1;
      initial_state := state_key;
    END IF;
    IF (state_item.value ->> 'terminal')::boolean THEN
      terminal_count := terminal_count + 1;
      terminal_keys := array_append(terminal_keys, state_key);
    END IF;

    previous_action_rank := 0;
    FOR action_item IN
      SELECT value, ordinality
      FROM jsonb_array_elements(state_item.value -> 'actions')
           WITH ORDINALITY
    LOOP
      IF NOT app.private_workflow_json_exact_keys_v1(
        action_item.value, ARRAY['action', 'effects']
      ) OR jsonb_typeof(action_item.value -> 'action') <> 'string'
        OR NOT app.private_workflow_effect_plan_valid_v1(
          action_item.value -> 'effects'
        ) THEN
        RETURN false;
      END IF;
      action_name := action_item.value ->> 'action';
      action_rank := CASE action_name
        WHEN 'create' THEN 1
        WHEN 'assign' THEN 2
        WHEN 'claim' THEN 3
        WHEN 'release' THEN 4
        WHEN 'transfer' THEN 5
        WHEN 'escalate' THEN 6
        WHEN 'link' THEN 7
        ELSE 0
      END;
      IF action_rank = 0 OR action_rank <= previous_action_rank
         OR p_aggregate_kind = 'alert' AND action_name = 'link'
         OR p_aggregate_kind = 'case' AND action_name = 'escalate' THEN
        RETURN false;
      END IF;
      previous_action_rank := action_rank;
    END LOOP;
    IF ((state_item.value ->> 'initial')::boolean)
       IS DISTINCT FROM EXISTS (
         SELECT 1
         FROM jsonb_array_elements(state_item.value -> 'actions') AS action
         WHERE action ->> 'action' = 'create'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF initial_count <> 1 OR terminal_count = 0 THEN
    RETURN false;
  END IF;

  FOR transition_item IN
    SELECT value, ordinality
    FROM jsonb_array_elements(p_transitions) WITH ORDINALITY
  LOOP
    IF NOT app.private_workflow_json_exact_keys_v1(
      transition_item.value,
      CASE WHEN transition_item.value ? 'condition'
        THEN ARRAY[
          'key', 'from', 'to', 'requiredComment', 'reopen',
          'requiredRoles', 'requiredPermissions',
          'requiredCustomFields', 'condition', 'effects'
        ]
        ELSE ARRAY[
          'key', 'from', 'to', 'requiredComment', 'reopen',
          'requiredRoles', 'requiredPermissions',
          'requiredCustomFields', 'effects'
        ]
      END
    ) OR jsonb_typeof(transition_item.value -> 'key') <> 'string'
      OR jsonb_typeof(transition_item.value -> 'from') <> 'string'
      OR jsonb_typeof(transition_item.value -> 'to') <> 'string'
      OR jsonb_typeof(transition_item.value -> 'requiredComment') <> 'boolean'
      OR jsonb_typeof(transition_item.value -> 'reopen') <> 'boolean'
      OR NOT app.private_workflow_string_array_valid_v1(
        transition_item.value -> 'requiredRoles', 'key', p_aggregate_kind
      ) OR NOT app.private_workflow_string_array_valid_v1(
        transition_item.value -> 'requiredPermissions',
        'permission', p_aggregate_kind
      ) OR NOT app.private_workflow_string_array_valid_v1(
        transition_item.value -> 'requiredCustomFields',
        'key', p_aggregate_kind
      ) OR NOT app.private_workflow_effect_plan_valid_v1(
        transition_item.value -> 'effects'
      ) OR transition_item.value ? 'condition'
        AND app.private_workflow_condition_node_count_v1(
          transition_item.value -> 'condition', 1
        ) = 0 THEN
      RETURN false;
    END IF;
    transition_key := transition_item.value ->> 'key';
    from_key := transition_item.value ->> 'from';
    to_key := transition_item.value ->> 'to';
    IF transition_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
       OR previous_transition_key IS NOT NULL
         AND previous_transition_key COLLATE "C"
           >= transition_key COLLATE "C"
       OR from_key = to_key
       OR NOT from_key = ANY(state_keys)
       OR NOT to_key = ANY(state_keys)
       OR from_key || chr(31) || to_key = ANY(edge_keys)
       OR ((transition_item.value ->> 'reopen')::boolean)
          IS DISTINCT FROM (from_key = ANY(terminal_keys))
       OR (transition_item.value ->> 'reopen')::boolean
          AND to_key = ANY(terminal_keys)
       OR NOT (transition_item.value ->> 'reopen')::boolean
          AND to_key = initial_state THEN
      RETURN false;
    END IF;
    previous_transition_key := transition_key;
    edge_keys := array_append(edge_keys, from_key || chr(31) || to_key);
    outgoing_keys := array_append(outgoing_keys, from_key);
  END LOOP;

  IF EXISTS (
    SELECT 1 FROM unnest(state_keys) AS state(key)
    WHERE NOT state.key = ANY(terminal_keys)
      AND NOT state.key = ANY(outgoing_keys)
  ) THEN
    RETURN false;
  END IF;

  seen_keys := ARRAY[initial_state];
  LOOP
    changed := false;
    FOR transition_item IN
      SELECT value FROM jsonb_array_elements(p_transitions)
    LOOP
      from_key := transition_item.value ->> 'from';
      to_key := transition_item.value ->> 'to';
      IF from_key = ANY(seen_keys) AND NOT to_key = ANY(seen_keys) THEN
        seen_keys := array_append(seen_keys, to_key);
        changed := true;
      END IF;
    END LOOP;
    EXIT WHEN NOT changed;
  END LOOP;
  RETURN cardinality(seen_keys) = cardinality(state_keys);
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_ticket_workflow_definition_valid_v1(
  public.ticket_aggregate_kind, jsonb, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_workflow_definition_valid_v1(
  public.ticket_aggregate_kind, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.lookup_ticket_workflow_admin_replay_v1(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_action text,
  p_key_digest bytea
)
RETURNS TABLE (
  workflow_id uuid,
  request_fingerprint bytea,
  result_revision bigint,
  result_snapshot jsonb
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid;
BEGIN
  IF p_tenant_id IS NULL OR p_actor_user_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_actor_user_id) = 7) IS NOT TRUE
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_actor_user_id IS DISTINCT FROM app.context_user_id()
     OR p_action NOT IN (
       'create', 'publish', 'update_metadata',
       'set_default', 'archive', 'restore'
     ) OR p_key_digest IS NULL
     OR octet_length(p_key_digest) <> 32 THEN
    RAISE EXCEPTION 'workflow replay context is forbidden'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  IF actor_membership IS NULL
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'workflow.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'workflow management is forbidden'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT command.result_workflow_id,
         command.request_digest,
         command.result_revision::bigint,
         command.result_snapshot
  FROM public.ticket_workflow_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_user_id = p_actor_user_id
    AND command.actor_membership_id = actor_membership
    AND command.action = p_action
    AND command.key_digest = p_key_digest
    AND command.expires_at > transaction_timestamp();
END;
$function$;
ALTER FUNCTION app.lookup_ticket_workflow_admin_replay_v1(
  uuid, uuid, text, bytea
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.lookup_ticket_workflow_admin_replay_v1(
  uuid, uuid, text, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.lookup_ticket_workflow_admin_replay_v1(
  uuid, uuid, text, bytea
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_workflow_admin_v1(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_action text,
  p_workflow_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_key text,
  p_display_name text,
  p_description text,
  p_is_default boolean,
  p_status text,
  p_next_revision bigint,
  p_current_version bigint,
  p_states jsonb,
  p_transitions jsonb,
  p_expected_revision bigint,
  p_publishes_definition boolean,
  p_displaced_workflow_id uuid,
  p_displaced_expected_revision bigint,
  p_displaced_next_revision bigint,
  p_key_digest bytea,
  p_request_fingerprint bytea,
  p_command_id uuid,
  p_version_id uuid,
  p_audit_id uuid,
  p_outbox_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  workflow_id uuid,
  revision bigint,
  replayed boolean,
  result_snapshot jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET statement_timeout = '5s'
SET lock_timeout = '3s'
AS $function$
DECLARE
  actor_membership uuid;
  command_record public.ticket_workflow_commands%ROWTYPE;
  locked_workflow public.ticket_workflows%ROWTYPE;
  locked_version public.ticket_workflow_versions%ROWTYPE;
  current_default public.ticket_workflows%ROWTYPE;
  changed_at timestamp with time zone := transaction_timestamp();
  archived_at timestamp with time zone;
  snapshot jsonb;
  before_state jsonb;
  after_state jsonb;
  outbox_payload jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_actor_user_id IS NULL
     OR p_workflow_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_actor_user_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_workflow_id) = 7) IS NOT TRUE
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_actor_user_id IS DISTINCT FROM app.context_user_id() THEN
    RAISE EXCEPTION 'workflow command context is forbidden'
      USING ERRCODE = '42501';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF actor_membership IS NULL
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'workflow.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'workflow management is forbidden'
      USING ERRCODE = '42501';
  END IF;

  IF p_action NOT IN (
       'create', 'publish', 'update_metadata',
       'set_default', 'archive', 'restore'
     ) OR p_aggregate_kind NOT IN ('alert', 'case')
     OR p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_]{2,63}$'
     OR p_display_name IS NULL
     OR octet_length(p_display_name) NOT BETWEEN 1 AND 120
     OR btrim(p_display_name) <> p_display_name
     OR p_display_name ~ '[[:cntrl:]]'
     OR p_description IS NULL OR octet_length(p_description) > 1000
     OR p_description <> '' AND btrim(p_description) <> p_description
     OR p_description ~ '[[:cntrl:]]'
     OR p_is_default IS NULL OR p_status NOT IN ('active', 'archived')
     OR p_status = 'archived' AND p_is_default
     OR p_next_revision NOT BETWEEN 1 AND 2147483647
     OR p_current_version NOT BETWEEN 1 AND 2147483647
     OR p_expected_revision NOT BETWEEN 0 AND 2147483647
     OR p_publishes_definition IS DISTINCT FROM
       (p_action IN ('create', 'publish'))
     OR NOT app.private_ticket_workflow_definition_valid_v1(
       p_aggregate_kind, p_states, p_transitions
     ) OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_fingerprint IS NULL
       OR octet_length(p_request_fingerprint) <> 32
     OR p_command_id IS NULL OR p_version_id IS NULL
     OR p_audit_id IS NULL OR p_outbox_id IS NULL
     OR (uuid_extract_version(p_command_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_version_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_audit_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_outbox_id) = 7) IS NOT TRUE
     OR (SELECT count(DISTINCT identifier)
         FROM unnest(ARRAY[
           p_workflow_id, p_command_id, p_version_id,
           p_audit_id, p_outbox_id
         ]) AS supplied(identifier)) <> 5
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
       OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) OR p_action = 'create' AND p_expected_revision <> 0
     OR p_action <> 'create' AND p_expected_revision = 0
     OR p_displaced_workflow_id IS NULL AND (
       p_displaced_expected_revision <> 0
       OR p_displaced_next_revision <> 0
     ) OR p_displaced_workflow_id IS NOT NULL AND (
       p_action <> 'set_default'
       OR (uuid_extract_version(p_displaced_workflow_id) = 7) IS NOT TRUE
       OR p_displaced_workflow_id = p_workflow_id
       OR p_displaced_expected_revision NOT BETWEEN 1 AND 2147483646
       OR p_displaced_next_revision <> p_displaced_expected_revision + 1
     ) THEN
    RAISE EXCEPTION 'workflow command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Serialize the exact tenant/user/action/key lineage before inspecting its
  -- immutable result. READ COMMITTED callers can then observe a concurrent
  -- winner after this wait without manufacturing a serialization failure.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_actor_user_id::text || ':' ||
    p_action || ':' || encode(p_key_digest, 'hex'), 0
  ));

  DELETE FROM public.ticket_workflow_commands AS expired
  WHERE expired.tenant_id = p_tenant_id
    AND expired.actor_user_id = p_actor_user_id
    AND expired.action = p_action
    AND expired.key_digest = p_key_digest
    AND expired.expires_at <= transaction_timestamp();

  SELECT command.* INTO command_record
  FROM public.ticket_workflow_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_user_id = p_actor_user_id
    AND command.action = p_action
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF command_record.actor_membership_id IS DISTINCT FROM actor_membership
       OR command_record.request_digest
          IS DISTINCT FROM p_request_fingerprint
       OR p_action <> 'create'
          AND command_record.result_workflow_id
            IS DISTINCT FROM p_workflow_id THEN
      RAISE EXCEPTION 'workflow idempotency lineage conflicts'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT command_record.result_workflow_id,
      command_record.result_revision::bigint, true,
      command_record.result_snapshot;
    RETURN;
  END IF;

  IF p_action = 'set_default' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(
      p_tenant_id::text || ':workflow-default:' || p_aggregate_kind::text,
      0
    ));
  END IF;

  IF p_action = 'create' THEN
    IF p_next_revision <> 1 OR p_current_version <> 1
       OR p_status <> 'active' OR p_is_default
       OR p_displaced_workflow_id IS NOT NULL THEN
      RAISE EXCEPTION 'workflow create projection is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.ticket_workflows (
      id, tenant_id, aggregate_kind, key, display_name, description,
      is_default, revision, current_version, archived_at,
      created_at, updated_at
    ) VALUES (
      p_workflow_id, p_tenant_id, p_aggregate_kind, p_key,
      p_display_name, p_description, false, 1, 1, NULL,
      changed_at, changed_at
    );
    INSERT INTO public.ticket_workflow_versions (
      id, tenant_id, workflow_id, aggregate_kind, version,
      states, transitions, published_by_membership_id,
      published_at, created_at
    ) VALUES (
      p_version_id, p_tenant_id, p_workflow_id, p_aggregate_kind, 1,
      p_states, p_transitions, actor_membership, changed_at, changed_at
    );
    before_state := NULL;
  ELSE
    SELECT workflow.* INTO locked_workflow
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = p_tenant_id
      AND workflow.id = p_workflow_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'workflow not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT version.* INTO locked_version
    FROM public.ticket_workflow_versions AS version
    WHERE version.tenant_id = p_tenant_id
      AND version.workflow_id = p_workflow_id
      AND version.aggregate_kind = locked_workflow.aggregate_kind
      AND version.version = locked_workflow.current_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'workflow publication is unavailable'
        USING ERRCODE = '55000';
    END IF;
    IF locked_workflow.aggregate_kind IS DISTINCT FROM p_aggregate_kind
       OR locked_workflow.key IS DISTINCT FROM p_key
       OR locked_workflow.revision IS DISTINCT FROM p_expected_revision
       OR p_next_revision <> p_expected_revision + 1 THEN
      RAISE EXCEPTION 'workflow revision precondition failed'
        USING ERRCODE = '40001';
    END IF;
    before_state := jsonb_build_object(
      'revision', locked_workflow.revision,
      'current_version', locked_workflow.current_version,
      'is_default', locked_workflow.is_default,
      'status', CASE WHEN locked_workflow.archived_at IS NULL
        THEN 'active' ELSE 'archived' END
    );

    IF p_action = 'publish' THEN
      IF locked_workflow.archived_at IS NOT NULL
         OR p_status <> 'active'
         OR p_display_name IS DISTINCT FROM locked_workflow.display_name
         OR p_description IS DISTINCT FROM locked_workflow.description
         OR p_is_default IS DISTINCT FROM locked_workflow.is_default
         OR p_current_version <> locked_workflow.current_version + 1
         OR p_states = locked_version.states
            AND p_transitions = locked_version.transitions THEN
        RAISE EXCEPTION 'workflow publication projection is invalid'
          USING ERRCODE = '22023';
      END IF;
      INSERT INTO public.ticket_workflow_versions (
        id, tenant_id, workflow_id, aggregate_kind, version,
        states, transitions, published_by_membership_id,
        published_at, created_at
      ) VALUES (
        p_version_id, p_tenant_id, p_workflow_id, p_aggregate_kind,
        p_current_version, p_states, p_transitions, actor_membership,
        changed_at, changed_at
      );
      UPDATE public.ticket_workflows
      SET revision = p_next_revision::integer,
          current_version = p_current_version::integer,
          updated_at = changed_at
      WHERE tenant_id = p_tenant_id AND id = p_workflow_id;
    ELSIF p_action = 'update_metadata' THEN
      IF p_status <> (CASE WHEN locked_workflow.archived_at IS NULL
           THEN 'active' ELSE 'archived' END)
         OR p_is_default IS DISTINCT FROM locked_workflow.is_default
         OR p_current_version <> locked_workflow.current_version
         OR p_states IS DISTINCT FROM locked_version.states
         OR p_transitions IS DISTINCT FROM locked_version.transitions
         OR p_display_name IS NOT DISTINCT FROM locked_workflow.display_name
            AND p_description IS NOT DISTINCT FROM locked_workflow.description
         OR p_displaced_workflow_id IS NOT NULL THEN
        RAISE EXCEPTION 'workflow metadata projection is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.ticket_workflows
      SET display_name = p_display_name, description = p_description,
          revision = p_next_revision::integer, updated_at = changed_at
      WHERE tenant_id = p_tenant_id AND id = p_workflow_id;
    ELSIF p_action = 'set_default' THEN
      IF locked_workflow.archived_at IS NOT NULL
         OR locked_workflow.is_default OR NOT p_is_default
         OR p_status <> 'active'
         OR p_display_name IS DISTINCT FROM locked_workflow.display_name
         OR p_description IS DISTINCT FROM locked_workflow.description
         OR p_current_version <> locked_workflow.current_version
         OR p_states IS DISTINCT FROM locked_version.states
         OR p_transitions IS DISTINCT FROM locked_version.transitions THEN
        RAISE EXCEPTION 'workflow default projection is invalid'
          USING ERRCODE = '22023';
      END IF;
      SELECT workflow.* INTO current_default
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id = p_tenant_id
        AND workflow.aggregate_kind = p_aggregate_kind
        AND workflow.is_default AND workflow.archived_at IS NULL
      FOR UPDATE;
      IF FOUND THEN
        IF current_default.id = p_workflow_id
           OR p_displaced_workflow_id IS DISTINCT FROM current_default.id
           OR p_displaced_expected_revision
             IS DISTINCT FROM current_default.revision
           OR p_displaced_next_revision <> current_default.revision + 1 THEN
          RAISE EXCEPTION 'workflow default precondition failed'
            USING ERRCODE = '40001';
        END IF;
        UPDATE public.ticket_workflows
        SET is_default = false,
            revision = p_displaced_next_revision::integer,
            updated_at = changed_at
        WHERE tenant_id = p_tenant_id AND id = current_default.id;
      ELSIF p_displaced_workflow_id IS NOT NULL THEN
        RAISE EXCEPTION 'workflow default precondition failed'
          USING ERRCODE = '40001';
      END IF;
      UPDATE public.ticket_workflows
      SET is_default = true, revision = p_next_revision::integer,
          updated_at = changed_at
      WHERE tenant_id = p_tenant_id AND id = p_workflow_id;
    ELSIF p_action = 'archive' THEN
      IF locked_workflow.archived_at IS NOT NULL
         OR locked_workflow.is_default OR p_is_default
         OR p_status <> 'archived'
         OR p_display_name IS DISTINCT FROM locked_workflow.display_name
         OR p_description IS DISTINCT FROM locked_workflow.description
         OR p_current_version <> locked_workflow.current_version
         OR p_states IS DISTINCT FROM locked_version.states
         OR p_transitions IS DISTINCT FROM locked_version.transitions
         OR p_displaced_workflow_id IS NOT NULL THEN
        RAISE EXCEPTION 'workflow archive projection is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.ticket_workflows
      SET archived_at = changed_at, revision = p_next_revision::integer,
          updated_at = changed_at
      WHERE tenant_id = p_tenant_id AND id = p_workflow_id;
    ELSIF p_action = 'restore' THEN
      IF locked_workflow.archived_at IS NULL
         OR locked_workflow.is_default OR p_is_default
         OR p_status <> 'active'
         OR p_display_name IS DISTINCT FROM locked_workflow.display_name
         OR p_description IS DISTINCT FROM locked_workflow.description
         OR p_current_version <> locked_workflow.current_version
         OR p_states IS DISTINCT FROM locked_version.states
         OR p_transitions IS DISTINCT FROM locked_version.transitions
         OR p_displaced_workflow_id IS NOT NULL THEN
        RAISE EXCEPTION 'workflow restore projection is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.ticket_workflows
      SET archived_at = NULL, revision = p_next_revision::integer,
          updated_at = changed_at
      WHERE tenant_id = p_tenant_id AND id = p_workflow_id;
    ELSE
      RAISE EXCEPTION 'workflow action is unsupported'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  SELECT workflow.* INTO locked_workflow
  FROM public.ticket_workflows AS workflow
  WHERE workflow.tenant_id = p_tenant_id
    AND workflow.id = p_workflow_id;
  IF NOT FOUND OR locked_workflow.revision <> p_next_revision
     OR locked_workflow.current_version <> p_current_version THEN
    RAISE EXCEPTION 'workflow committed projection is unavailable'
      USING ERRCODE = '55000';
  END IF;
  SELECT version.* INTO locked_version
  FROM public.ticket_workflow_versions AS version
  WHERE version.tenant_id = p_tenant_id
    AND version.workflow_id = p_workflow_id
    AND version.aggregate_kind = locked_workflow.aggregate_kind
    AND version.version = locked_workflow.current_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'workflow committed publication is unavailable'
      USING ERRCODE = '55000';
  END IF;
  archived_at := locked_workflow.archived_at;
  snapshot := jsonb_build_object(
    'schemaVersion', 1,
    'action', p_action,
    'workflowId', locked_workflow.id,
    'aggregateKind', locked_workflow.aggregate_kind,
    'key', locked_workflow.key,
    'displayName', locked_workflow.display_name,
    'description', locked_workflow.description,
    'isDefault', locked_workflow.is_default,
    'status', CASE WHEN archived_at IS NULL THEN 'active' ELSE 'archived' END,
    'revision', locked_workflow.revision,
    'currentVersion', locked_workflow.current_version,
    'states', locked_version.states,
    'transitions', locked_version.transitions,
    'createdAt', to_char(
      locked_workflow.created_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'updatedAt', to_char(
      locked_workflow.updated_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'archivedAt', CASE WHEN archived_at IS NULL THEN NULL ELSE to_char(
      archived_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ) END
  );
  IF pg_column_size(snapshot) > 524288 THEN
    RAISE EXCEPTION 'workflow result snapshot exceeds its bound'
      USING ERRCODE = '22023';
  END IF;

  after_state := jsonb_build_object(
    'revision', locked_workflow.revision,
    'current_version', locked_workflow.current_version,
    'is_default', locked_workflow.is_default,
    'status', CASE WHEN archived_at IS NULL THEN 'active' ELSE 'archived' END
  );
  PERFORM app.append_tenant_authorization_audit(
    p_audit_id, 'tenant.workflow.' || p_action, 'ticket_workflow',
    p_workflow_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, before_state, after_state,
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'aggregate_kind', p_aggregate_kind,
      'published_definition', p_publishes_definition,
      'displaced_workflow_id', p_displaced_workflow_id,
      'content_redacted', true
    )
  );

  outbox_payload := jsonb_strip_nulls(jsonb_build_object(
    'workflow_id', p_workflow_id,
    'aggregate_kind', p_aggregate_kind,
    'action', p_action,
    'revision', locked_workflow.revision,
    'current_version', locked_workflow.current_version,
    'displaced_workflow_id', p_displaced_workflow_id
  ));
  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, occurred_at, available_at
  ) VALUES (
    p_outbox_id, p_tenant_id, 'ticket_workflow', p_workflow_id,
    locked_workflow.revision, 'workflow.' || p_action, 1,
    outbox_payload,
    'workflow.' || p_action || ':' || p_command_id::text,
    p_correlation_id, p_request_id, 'human', p_actor_user_id,
    'api.workflow', 'operator', changed_at, changed_at
  );

  INSERT INTO public.ticket_workflow_commands (
    id, tenant_id, actor_membership_id, actor_user_id, action,
    key_digest, request_digest, result_workflow_id, result_revision,
    result_snapshot, created_at, expires_at
  ) VALUES (
    p_command_id, p_tenant_id, actor_membership, p_actor_user_id,
    p_action, p_key_digest, p_request_fingerprint, p_workflow_id,
    locked_workflow.revision, snapshot, changed_at,
    changed_at + interval '24 hours'
  );
  RETURN QUERY SELECT p_workflow_id, locked_workflow.revision::bigint,
    false, snapshot;
END;
$function$;
ALTER FUNCTION app.commit_ticket_workflow_admin_v1(
  uuid, uuid, text, uuid, public.ticket_aggregate_kind,
  text, text, text, boolean, text, bigint, bigint,
  jsonb, jsonb, bigint, boolean, uuid, bigint, bigint,
  bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_workflow_admin_v1(
  uuid, uuid, text, uuid, public.ticket_aggregate_kind,
  text, text, text, boolean, text, bigint, bigint,
  jsonb, jsonb, bigint, boolean, uuid, bigint, bigint,
  bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.commit_ticket_workflow_admin_v1(
  uuid, uuid, text, uuid, public.ticket_aggregate_kind,
  text, text, text, boolean, text, bigint, bigint,
  jsonb, jsonb, bigint, boolean, uuid, bigint, bigint,
  bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid,
  inet, text, text
) TO periapsis_api;
--> statement-breakpoint

-- Command results are immutable. Expired rows can only be removed through the
-- commit ABI, whose owner is the sole role with table write authority.
CREATE FUNCTION app.guard_ticket_workflow_command_update_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION 'workflow command evidence is immutable'
    USING ERRCODE = '55000';
END;
$function$;
ALTER FUNCTION app.guard_ticket_workflow_command_update_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_workflow_command_update_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
CREATE TRIGGER ticket_workflow_commands_immutable_v1
BEFORE UPDATE ON public.ticket_workflow_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_workflow_command_update_v1();
