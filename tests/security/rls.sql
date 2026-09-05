\set ON_ERROR_STOP on

-- Run after packages/db migrations as a PostgreSQL superuser or a bootstrap login that
-- can SET ROLE to the NOLOGIN group roles. Every fixture change is rolled back.
BEGIN;

SET LOCAL ROLE "periapsis_migrator";

-- A CHECK must reject uuid_extract_version(...) UNKNOWN, not only non-v7 FALSE values.
DO $test$
DECLARE
  rejected boolean := false;
BEGIN
  BEGIN
    INSERT INTO public.tenants (id, slug, name)
    VALUES ('00000000-0000-0000-0000-000000000000', 'nil-uuid', 'Must be rejected');
  EXCEPTION
    WHEN check_violation THEN rejected := true;
  END;

  IF NOT rejected THEN
    RAISE EXCEPTION 'non-RFC UUID bypassed the UUIDv7 CHECK';
  END IF;
END
$test$;

INSERT INTO public.tenants (id, slug, name)
VALUES
  ('01993ea0-1000-7000-8000-000000000001', 'rls-acme', 'RLS Acme'),
  ('01993ea0-1000-7000-8000-000000000002', 'rls-globex', 'RLS Globex');

INSERT INTO public.users (id, email, display_name)
VALUES
  ('01993ea0-1000-7000-8000-000000000101', 'rls.acme@example.invalid', 'RLS Acme Analyst'),
  ('01993ea0-1000-7000-8000-000000000102', 'rls.globex@example.invalid', 'RLS Globex Analyst'),
  ('01993ea0-1000-7000-8000-000000000103', 'rls.acme.peer@example.invalid', 'RLS Acme Peer');

INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
VALUES
  (
    '01993ea0-1000-7000-8000-000000000201',
    '01993ea0-1000-7000-8000-000000000001',
    '01993ea0-1000-7000-8000-000000000101',
    'analyst',
    'active'
  ),
  (
    '01993ea0-1000-7000-8000-000000000202',
    '01993ea0-1000-7000-8000-000000000002',
    '01993ea0-1000-7000-8000-000000000102',
    'analyst',
    'active'
  ),
  (
    '01993ea0-1000-7000-8000-000000000203',
    '01993ea0-1000-7000-8000-000000000001',
    '01993ea0-1000-7000-8000-000000000103',
    'analyst',
    'active'
  );

-- Use the same tenant-initialization path as production. Ticket writes are
-- deliberately rejected for tenants whose authorization state has not been
-- initialized, so bypassing this function would make the RLS fixture test an
-- impossible lifecycle state rather than a live tenant boundary.
SELECT app.seed_tenant_authorization(
  '01993ea0-1000-7000-8000-000000000001',
  '01993ea0-1000-7000-8000-000000000201'
);
SELECT app.seed_tenant_authorization(
  '01993ea0-1000-7000-8000-000000000002',
  '01993ea0-1000-7000-8000-000000000202'
);

-- Ticket defaulting allocates a tenant-local number and therefore requires the
-- same explicit tenant/actor context as the production mutation boundary.
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
INSERT INTO public.alerts (
  id,
  tenant_id,
  external_id,
  title,
  severity,
  created_by,
  created_by_membership_id
)
VALUES (
    '01993ea0-1000-7000-8000-000000000301',
    '01993ea0-1000-7000-8000-000000000001',
    'rls-acme-alert',
    'Acme searchable canary',
    'high',
    '01993ea0-1000-7000-8000-000000000101',
    '01993ea0-1000-7000-8000-000000000201'
  );

SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000002', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000102', true);
INSERT INTO public.alerts (
  id,
  tenant_id,
  external_id,
  title,
  severity,
  created_by,
  created_by_membership_id
)
VALUES (
    '01993ea0-1000-7000-8000-000000000302',
    '01993ea0-1000-7000-8000-000000000002',
    'rls-globex-alert',
    'Globex searchable canary',
    'critical',
    '01993ea0-1000-7000-8000-000000000102',
    '01993ea0-1000-7000-8000-000000000202'
  );

INSERT INTO public.outbox_events (
  id,
  tenant_id,
  aggregate_type,
  aggregate_id,
  event_type,
  payload
)
VALUES
  (
    '01993ea0-1000-7000-8000-000000000501',
    '01993ea0-1000-7000-8000-000000000001',
    'alert',
    '01993ea0-1000-7000-8000-000000000301',
    'alert.created',
    '{"fixture":true}'::jsonb
  ),
  (
    '01993ea0-1000-7000-8000-000000000502',
    '01993ea0-1000-7000-8000-000000000002',
    'alert',
    '01993ea0-1000-7000-8000-000000000302',
    'alert.created',
    '{"fixture":true}'::jsonb
  ),
  (
    '01993ea0-1000-7000-8000-000000000503',
    '01993ea0-1000-7000-8000-000000000001',
    'notification',
    '01993ea0-1000-7000-8000-000000000301',
    'notification.dispatch.v1',
    '{"fixture":true}'::jsonb
  ),
  (
    '01993ea0-1000-7000-8000-000000000504',
    '01993ea0-1000-7000-8000-000000000002',
    'notification',
    '01993ea0-1000-7000-8000-000000000302',
    'notification.dispatch.v1',
    '{"fixture":true}'::jsonb
  );

RESET ROLE;
SET LOCAL ROLE "periapsis_api";

-- Missing tenant and actor context fails closed.
SELECT set_config('app.tenant_id', '', true);
SELECT set_config('app.user_id', '', true);
DO $test$
DECLARE
  visible_count integer;
BEGIN
  SELECT count(*) INTO visible_count FROM public.alerts;
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'RLS exposed % alerts without context', visible_count;
  END IF;
END
$test$;

-- Correct Acme context allows Acme direct reads/search/export-style scans only.
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
DECLARE
  visible_count integer;
  globex_direct_count integer;
  search_count integer;
  visible_user_count integer;
BEGIN
  SELECT count(*) INTO visible_count
    FROM public.alerts
    WHERE id IN (
      '01993ea0-1000-7000-8000-000000000301',
      '01993ea0-1000-7000-8000-000000000302'
    );
  IF visible_count <> 1 THEN
    RAISE EXCEPTION 'Acme context expected 1 test alert, saw %', visible_count;
  END IF;

  SELECT count(*) INTO globex_direct_count
    FROM public.alerts
    WHERE id = '01993ea0-1000-7000-8000-000000000302';
  IF globex_direct_count <> 0 THEN
    RAISE EXCEPTION 'direct-ID cross-tenant read escaped RLS';
  END IF;

  SELECT count(*) INTO search_count
    FROM public.alerts
    WHERE title ILIKE '%searchable canary%'
      AND id IN (
        '01993ea0-1000-7000-8000-000000000301',
        '01993ea0-1000-7000-8000-000000000302'
      );
  IF search_count <> 1 THEN
    RAISE EXCEPTION 'tenant-filtered search/export scan expected 1 row, saw %', search_count;
  END IF;

  SELECT count(*) INTO visible_user_count
    FROM public.users
    WHERE id IN (
      '01993ea0-1000-7000-8000-000000000101',
      '01993ea0-1000-7000-8000-000000000102',
      '01993ea0-1000-7000-8000-000000000103'
    );
  IF visible_user_count <> 1 THEN
    RAISE EXCEPTION 'user visibility expected self only, saw %', visible_user_count;
  END IF;
END
$test$;

-- A cross-tenant write is either filtered to zero rows or rejected by WITH CHECK.
DO $test$
DECLARE
  changed_count integer := 0;
BEGIN
  BEGIN
    UPDATE public.alerts
      SET title = 'must not change'
      WHERE id = '01993ea0-1000-7000-8000-000000000302';
    GET DIAGNOSTICS changed_count = ROW_COUNT;
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  IF changed_count <> 0 THEN
    RAISE EXCEPTION 'cross-tenant update changed % rows', changed_count;
  END IF;

  BEGIN
    INSERT INTO public.alerts (
      id,
      tenant_id,
      external_id,
      title,
      severity,
      created_by,
      created_by_membership_id
    ) VALUES (
      '01993ea0-1000-7000-8000-000000000399',
      '01993ea0-1000-7000-8000-000000000002',
      'cross-tenant-insert',
      'must be rejected',
      'low',
      '01993ea0-1000-7000-8000-000000000102',
      '01993ea0-1000-7000-8000-000000000202'
    );
    RAISE EXCEPTION 'cross-tenant insert unexpectedly succeeded';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Even a wrong tenant context remains closed because the actor lacks that membership.
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000002', true);
DO $test$
DECLARE
  visible_count integer;
BEGIN
  SELECT count(*) INTO visible_count
    FROM public.alerts
    WHERE id = '01993ea0-1000-7000-8000-000000000302';
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'wrong tenant context exposed Globex data to the Acme actor';
  END IF;
END
$test$;

-- Background roles must also choose a tenant explicitly; they never receive USING (true).
RESET ROLE;
SET LOCAL ROLE "periapsis_worker";
SELECT set_config('app.tenant_id', '', true);
DO $test$
DECLARE
  visible_count integer := 0;
  direct_read_allowed boolean := true;
BEGIN
  BEGIN
    SELECT count(*) INTO visible_count FROM public.outbox_events;
  EXCEPTION
    WHEN insufficient_privilege THEN direct_read_allowed := false;
  END;
  IF direct_read_allowed AND visible_count <> 0 THEN
    RAISE EXCEPTION 'worker saw % outbox rows without tenant context', visible_count;
  END IF;
END
$test$;

SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
DO $test$
DECLARE
  visible_count integer := 0;
  direct_read_allowed boolean := true;
BEGIN
  BEGIN
    SELECT count(*) INTO visible_count
      FROM public.outbox_events
      WHERE id IN (
        '01993ea0-1000-7000-8000-000000000501',
        '01993ea0-1000-7000-8000-000000000502',
        '01993ea0-1000-7000-8000-000000000503',
        '01993ea0-1000-7000-8000-000000000504'
      );
  EXCEPTION
    WHEN insufficient_privilege THEN direct_read_allowed := false;
  END;
  IF direct_read_allowed AND visible_count <> 2 THEN
    RAISE EXCEPTION 'tenant-scoped worker expected 2 outbox rows, saw %', visible_count;
  END IF;
END
$test$;

-- The notifier is tenant-bound and can consume notification events, not generic domain events.
RESET ROLE;
SET LOCAL ROLE "periapsis_notifier";
SELECT set_config('app.tenant_id', '', true);
DO $test$
DECLARE
  visible_count integer := 0;
  direct_read_allowed boolean := true;
BEGIN
  BEGIN
    SELECT count(*) INTO visible_count FROM public.outbox_events;
  EXCEPTION
    WHEN insufficient_privilege THEN direct_read_allowed := false;
  END;
  IF direct_read_allowed AND visible_count <> 0 THEN
    RAISE EXCEPTION 'notifier saw % outbox rows without tenant context', visible_count;
  END IF;
END
$test$;

SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
DO $test$
DECLARE
  notification_count integer := 0;
  generic_count integer := 0;
  direct_read_allowed boolean := true;
BEGIN
  BEGIN
    SELECT count(*) INTO notification_count
      FROM public.outbox_events
      WHERE id IN (
        '01993ea0-1000-7000-8000-000000000503',
        '01993ea0-1000-7000-8000-000000000504'
      );
    SELECT count(*) INTO generic_count
      FROM public.outbox_events
      WHERE id = '01993ea0-1000-7000-8000-000000000501';
  EXCEPTION
    WHEN insufficient_privilege THEN direct_read_allowed := false;
  END;

  IF direct_read_allowed AND (notification_count <> 1 OR generic_count <> 0) THEN
    RAISE EXCEPTION 'notifier visibility was notification=% generic=%', notification_count, generic_count;
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000002', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
BEGIN
  BEGIN
    PERFORM 1
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000002');
    RAISE EXCEPTION 'API verified a tenant chain without active membership';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);

-- Audit inserts are sealed by the database and the chain verifies.
-- Runtime roles append through narrow SECURITY DEFINER mutation functions;
-- only the migrator may seed raw rows for this chain-integrity fixture.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.audit_events (
  id,
  tenant_id,
  actor_type,
  actor_user_id,
  action,
  resource_type,
  resource_id,
  outcome,
  metadata
) VALUES
  (
    '01993ea0-1000-7000-8000-000000000401',
    '01993ea0-1000-7000-8000-000000000001',
    'user',
    '01993ea0-1000-7000-8000-000000000101',
    'rls.test.first',
    'alert',
    '01993ea0-1000-7000-8000-000000000301',
    'success',
    '{"fixture":true}'::jsonb
  ),
  (
    '01993ea0-1000-7000-8000-000000000402',
    '01993ea0-1000-7000-8000-000000000001',
    'user',
    '01993ea0-1000-7000-8000-000000000101',
    'rls.test.second',
    'alert',
    '01993ea0-1000-7000-8000-000000000301',
    'success',
    '{"fixture":true}'::jsonb
  );

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);

-- An API actor cannot attribute an unmarked event to another same-tenant user.
DO $test$
BEGIN
  BEGIN
    INSERT INTO public.audit_events (
      id,
      tenant_id,
      actor_type,
      actor_user_id,
      action,
      resource_type,
      outcome
    ) VALUES (
      '01993ea0-1000-7000-8000-000000000490',
      '01993ea0-1000-7000-8000-000000000001',
      'user',
      '01993ea0-1000-7000-8000-000000000103',
      'rls.test.false-attribution',
      'alert',
      'success'
    );
    RAISE EXCEPTION 'unmarked false audit attribution unexpectedly succeeded';
  EXCEPTION
    WHEN check_violation OR insufficient_privilege THEN NULL;
  END;

  BEGIN
    INSERT INTO public.audit_events (
      id,
      tenant_id,
      actor_type,
      actor_user_id,
      impersonated_by_user_id,
      action,
      resource_type,
      outcome
    ) VALUES (
      '01993ea0-1000-7000-8000-000000000491',
      '01993ea0-1000-7000-8000-000000000001',
      'user',
      '01993ea0-1000-7000-8000-000000000103',
      '01993ea0-1000-7000-8000-000000000103',
      'rls.test.false-impersonator',
      'alert',
      'success'
    );
    RAISE EXCEPTION 'audit attribution accepted an impersonator other than app.user_id';
  EXCEPTION
    WHEN check_violation OR insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Explicit impersonation records the effective actor and binds the marker to app.user_id.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.audit_events (
  id,
  tenant_id,
  actor_type,
  actor_user_id,
  impersonated_by_user_id,
  action,
  resource_type,
  resource_id,
  outcome,
  metadata
) VALUES (
  '01993ea0-1000-7000-8000-000000000403',
  '01993ea0-1000-7000-8000-000000000001',
  'user',
  '01993ea0-1000-7000-8000-000000000103',
  '01993ea0-1000-7000-8000-000000000101',
  'rls.test.impersonated',
  'alert',
  '01993ea0-1000-7000-8000-000000000301',
  'success',
  '{"fixture":true}'::jsonb
);

-- Background roles cannot forge a user actor even if they install an app.user_id GUC.
RESET ROLE;
SET LOCAL ROLE "periapsis_worker";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
BEGIN
  BEGIN
    INSERT INTO public.audit_events (
      id,
      tenant_id,
      actor_type,
      actor_user_id,
      action,
      resource_type,
      outcome
    ) VALUES (
      '01993ea0-1000-7000-8000-000000000492',
      '01993ea0-1000-7000-8000-000000000001',
      'user',
      '01993ea0-1000-7000-8000-000000000101',
      'rls.test.worker-forgery',
      'alert',
      'success'
    );
    RAISE EXCEPTION 'worker forged a user-attributed audit event';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_notifier";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
BEGIN
  BEGIN
    INSERT INTO public.audit_events (
      id,
      tenant_id,
      actor_type,
      actor_user_id,
      action,
      resource_type,
      outcome
    ) VALUES (
      '01993ea0-1000-7000-8000-000000000493',
      '01993ea0-1000-7000-8000-000000000001',
      'user',
      '01993ea0-1000-7000-8000-000000000101',
      'rls.test.notifier-forgery',
      'alert',
      'success'
    );
    RAISE EXCEPTION 'notifier forged a user-attributed audit event';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- The read-only auditor also fails closed without an explicit tenant GUC. Its
-- verifier reaches the protected head through a narrow SECURITY DEFINER
-- projection; it never receives direct tenant, head, or customer-table access.
RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '', true);
DO $test$
DECLARE
  visible_count integer;
BEGIN
  SELECT count(*) INTO visible_count
  FROM public.audit_events
  WHERE id IN (
    '01993ea0-1000-7000-8000-000000000401',
    '01993ea0-1000-7000-8000-000000000402',
    '01993ea0-1000-7000-8000-000000000403'
  );
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'auditor saw % audit rows without tenant context', visible_count;
  END IF;

  BEGIN
    PERFORM 1
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000001');
    RAISE EXCEPTION 'auditor verified a tenant chain without tenant context';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM count(*) FROM public.tenants;
    RAISE EXCEPTION 'auditor read tenant rows directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM count(*) FROM public.audit_chain_heads;
    RAISE EXCEPTION 'auditor read protected audit heads directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM count(*) FROM public.alerts;
    RAISE EXCEPTION 'auditor read customer alert rows directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
DO $test$
DECLARE
  visible_count integer;
  verifier_row_count integer;
  invalid_count integer;
BEGIN
  SELECT count(*) INTO visible_count
  FROM public.audit_events
  WHERE id IN (
    '01993ea0-1000-7000-8000-000000000401',
    '01993ea0-1000-7000-8000-000000000402',
    '01993ea0-1000-7000-8000-000000000403'
  );
  IF visible_count <> 3 THEN
    RAISE EXCEPTION 'tenant-scoped auditor expected 3 audit rows, saw %', visible_count;
  END IF;

  SELECT count(*), count(*) FILTER (WHERE NOT valid)
    INTO verifier_row_count, invalid_count
  FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000001');
  IF verifier_row_count < 4 OR invalid_count <> 0 THEN
    RAISE EXCEPTION 'tenant-scoped auditor verification failed: rows=% invalid=%',
      verifier_row_count, invalid_count;
  END IF;

  BEGIN
    PERFORM 1
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000002');
    RAISE EXCEPTION 'auditor verified a cross-tenant chain under Acme context';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);

DO $test$
DECLARE
  invalid_count integer;
  impersonation_count integer;
  stored_sequences bigint[];
BEGIN
  SELECT count(*) INTO invalid_count
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000001')
    WHERE NOT valid;
  IF invalid_count <> 0 THEN
    RAISE EXCEPTION 'audit chain contains % invalid events', invalid_count;
  END IF;

  SELECT array_agg(sequence ORDER BY sequence) INTO stored_sequences
    FROM public.audit_events
    WHERE id IN (
      '01993ea0-1000-7000-8000-000000000401',
      '01993ea0-1000-7000-8000-000000000402',
      '01993ea0-1000-7000-8000-000000000403'
    );
  IF cardinality(stored_sequences) <> 3
     OR stored_sequences[2] <> stored_sequences[1] + 1
     OR stored_sequences[3] <> stored_sequences[2] + 1 THEN
    RAISE EXCEPTION 'fixture audit sequence is not contiguous: %', stored_sequences;
  END IF;

  SELECT count(*) INTO impersonation_count
    FROM public.audit_events
    WHERE id = '01993ea0-1000-7000-8000-000000000403'
      AND actor_user_id = '01993ea0-1000-7000-8000-000000000103'
      AND impersonated_by_user_id = '01993ea0-1000-7000-8000-000000000101';
  IF impersonation_count <> 1 THEN
    RAISE EXCEPTION 'explicit audit impersonation was not stored correctly';
  END IF;

  BEGIN
    UPDATE public.audit_events
      SET reason = 'tamper attempt'
      WHERE id = '01993ea0-1000-7000-8000-000000000401';
    RAISE EXCEPTION 'auditor role unexpectedly mutated an audit event';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- The API role likewise has no direct mutation path to the append-only stream.
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
BEGIN
  BEGIN
    UPDATE public.audit_events
      SET reason = 'API tamper attempt'
      WHERE id = '01993ea0-1000-7000-8000-000000000401';
    RAISE EXCEPTION 'API role unexpectedly mutated an audit event';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Losing the head itself is also detectable even when every remaining event hash is valid.
SAVEPOINT audit_head_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DELETE FROM public.audit_chain_heads
  WHERE tenant_id = '01993ea0-1000-7000-8000-000000000001';
RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
DECLARE
  invalid_count integer;
BEGIN
  SELECT count(*) INTO invalid_count
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000001')
    WHERE NOT valid;
  IF invalid_count = 0 THEN
    RAISE EXCEPTION 'audit verifier did not detect a missing chain head';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT audit_head_probe;
RELEASE SAVEPOINT audit_head_probe;

-- The trigger also protects against accidental mutation by the schema owner.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  BEGIN
    UPDATE public.audit_events
      SET reason = 'owner tamper attempt'
      WHERE id = '01993ea0-1000-7000-8000-000000000401';
    RAISE EXCEPTION 'audit append-only trigger did not fire';
  EXCEPTION
    WHEN object_not_in_prerequisite_state THEN NULL;
  END;
END
$test$;

-- A privileged tail deletion leaves the separately protected head mismatched and detectable.
ALTER TABLE public.audit_events DISABLE TRIGGER audit_events_reject_update_delete;
DELETE FROM public.audit_events
  WHERE id = '01993ea0-1000-7000-8000-000000000403';
ALTER TABLE public.audit_events ENABLE TRIGGER audit_events_reject_update_delete;

RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
DECLARE
  invalid_count integer;
BEGIN
  SELECT count(*) INTO invalid_count
    FROM app.verify_audit_chain('01993ea0-1000-7000-8000-000000000001')
    WHERE NOT valid;
  IF invalid_count = 0 THEN
    RAISE EXCEPTION 'audit verifier did not detect a deleted tail event';
  END IF;
END
$test$;

-- Phase 2A authentication and platform authority are reachable only through narrow
-- SECURITY DEFINER functions. PUBLIC and the API role have no direct table path.
RESET ROLE;
CREATE ROLE "periapsis_rls_anonymous" NOLOGIN;
SET LOCAL ROLE "periapsis_rls_anonymous";
DO $test$
BEGIN
  BEGIN
    PERFORM count(*) FROM public.auth_sessions;
    RAISE EXCEPTION 'PUBLIC unexpectedly read authentication sessions';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.get_local_break_glass_credential('nobody@example.invalid');
    RAISE EXCEPTION 'PUBLIC unexpectedly called a credential definer';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
    );
    RAISE EXCEPTION 'PUBLIC unexpectedly called the protected-configuration verifier';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM count(*) FROM public.local_break_glass_credentials;
    RAISE EXCEPTION 'API unexpectedly read credential storage directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO public.platform_audit_events (
      id, sequence, actor_type, action, resource_type, outcome
    ) VALUES (
      '01993ea0-2000-7000-8000-000000000001', 1, 'system',
      'forged', 'authentication', 'failure'
    );
    RAISE EXCEPTION 'API unexpectedly inserted platform audit directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM master_key_verifier FROM public.platform_bootstrap_state;
    RAISE EXCEPTION 'API unexpectedly read the stored master-key verifier';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- No legacy single-secret operation remains reachable: an API replica can only
-- bind/check the authority digest and HKDF master-key verifier together.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  IF to_regprocedure('app.configure_platform_bootstrap_authority(bytea)') IS NOT NULL
     OR to_regprocedure('app.platform_bootstrap_status(bytea)') IS NOT NULL
     OR to_regprocedure('app.verify_or_bind_master_key(bytea,bytea)') IS NOT NULL THEN
    RAISE EXCEPTION 'legacy partial bootstrap configuration function still exists';
  END IF;
  IF NOT has_function_privilege(
    'periapsis_api',
    'app.verify_protected_configuration(bytea,bytea)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'API cannot execute the atomic protected-configuration verifier';
  END IF;
END
$test$;

-- A failed or rolled-back first verification cannot persist either half of the
-- protected configuration. The canonical CHECK also rejects authority-only state.
SAVEPOINT protected_configuration_rollback_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  is_available boolean;
BEGIN
  is_available := app.verify_protected_configuration(
    decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
  );
  IF NOT is_available THEN
    RAISE EXCEPTION 'fresh protected configuration was not reported available';
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  configured_count integer;
BEGIN
  SELECT count(*) INTO configured_count
  FROM public.platform_bootstrap_state
  WHERE authority_token_digest = decode(repeat('a1', 32), 'hex')
    AND authority_configured_at IS NOT NULL
    AND master_key_verifier = decode(repeat('f1', 32), 'hex')
    AND master_key_verifier_bound_at IS NOT NULL;
  IF configured_count <> 1 THEN
    RAISE EXCEPTION 'atomic verifier did not bind both protected values';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT protected_configuration_rollback_probe;
RELEASE SAVEPOINT protected_configuration_rollback_probe;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  unconfigured_count integer;
BEGIN
  SELECT count(*) INTO unconfigured_count
  FROM public.platform_bootstrap_state
  WHERE authority_token_digest IS NULL
    AND authority_configured_at IS NULL
    AND master_key_verifier IS NULL
    AND master_key_verifier_bound_at IS NULL;
  IF unconfigured_count <> 1 THEN
    RAISE EXCEPTION 'rolled-back verification left protected configuration state';
  END IF;

  BEGIN
    UPDATE public.platform_bootstrap_state
    SET authority_token_digest = decode(repeat('a1', 32), 'hex'),
        authority_configured_at = transaction_timestamp()
    WHERE singleton = true;
    RAISE EXCEPTION 'bootstrap state accepted an authority-only binding';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END
$test$;

-- The one atomic operation validates both inputs, installs both bindings once,
-- compares both thereafter, and never lets a mismatched replica rewrite state.
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  is_available boolean;
BEGIN
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 32), 'hex'), NULL
    );
    RAISE EXCEPTION 'protected verifier accepted a NULL verifier';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 31), 'hex'), decode(repeat('f1', 32), 'hex')
    );
    RAISE EXCEPTION 'protected verifier accepted a malformed authority digest';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;

  is_available := app.verify_protected_configuration(
    decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
  );
  IF NOT is_available OR NOT app.verify_protected_configuration(
    decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
  ) THEN
    RAISE EXCEPTION 'protected configuration did not bind idempotently';
  END IF;
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a2', 32), 'hex'), decode(repeat('f1', 32), 'hex')
    );
    RAISE EXCEPTION 'protected verifier accepted the wrong authority';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 32), 'hex'), decode(repeat('f2', 32), 'hex')
    );
    RAISE EXCEPTION 'protected verifier accepted the wrong master-key verifier';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  IF NOT app.verify_protected_configuration(
    decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
  ) THEN
    RAISE EXCEPTION 'mismatch attempt mutated protected configuration';
  END IF;
END
$test$;

SELECT app.reserve_platform_bootstrap(
  '01993ea0-2000-7000-8000-000000000101',
  decode(repeat('a1', 32), 'hex'),
  decode(repeat('b1', 32), 'hex'),
  decode(repeat('52', 32), 'hex'),
  'bootstrap.admin@example.invalid',
  decode(repeat('c1', 32), 'hex'),
  decode(repeat('d1', 12), 'hex'),
  convert_to(
    'bootstrap_enrollment:01993ea0-2000-7000-8000-000000000101:email:bootstrap.admin@example.invalid',
    'UTF8'
  ),
  1,
  date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
  5,
  '01993ea0-2000-7000-8000-000000000111',
  '01993ea0-2000-7000-8000-000000000112',
  '192.0.2.10'::inet,
  'rls-security-test/1.0'
);

DO $test$
BEGIN
  BEGIN
    PERFORM app.reserve_platform_bootstrap(
      '01993ea0-2000-7000-8000-000000000102',
      decode(repeat('a1', 32), 'hex'),
      decode(repeat('b2', 32), 'hex'),
      decode(repeat('53', 32), 'hex'),
      'other.admin@example.invalid',
      decode(repeat('c2', 32), 'hex'),
      decode(repeat('d2', 12), 'hex'),
      convert_to(
        'bootstrap_enrollment:01993ea0-2000-7000-8000-000000000102:email:other.admin@example.invalid',
        'UTF8'
      ),
      1,
      date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
      5,
      '01993ea0-2000-7000-8000-000000000113',
      '01993ea0-2000-7000-8000-000000000114',
      '192.0.2.10'::inet,
      'rls-security-test/1.0'
    );
    RAISE EXCEPTION 'a second live bootstrap reservation succeeded';
  EXCEPTION
    WHEN object_not_in_prerequisite_state THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.tenants (id, slug, name, status)
VALUES
  ('01993ea0-2000-7000-8000-000000000761', 'suspended-membership', 'Suspended Membership', 'active'),
  ('01993ea0-2000-7000-8000-000000000762', 'suspended-tenant', 'Suspended Tenant', 'suspended');
INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
VALUES
  (
    '01993ea0-2000-7000-8000-000000000771',
    '01993ea0-2000-7000-8000-000000000761',
    '01993ea0-1000-7000-8000-000000000101', 'analyst', 'suspended'
  ),
  (
    '01993ea0-2000-7000-8000-000000000772',
    '01993ea0-2000-7000-8000-000000000762',
    '01993ea0-1000-7000-8000-000000000101', 'analyst', 'active'
  );
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
DECLARE
  leaked_count integer;
BEGIN
  SELECT count(*) INTO leaked_count
  FROM app.list_user_tenant_memberships(NULL, 101) AS membership
  WHERE membership.tenant_id IN (
    '01993ea0-2000-7000-8000-000000000761',
    '01993ea0-2000-7000-8000-000000000762'
  );
  IF leaked_count <> 0 THEN
    RAISE EXCEPTION 'inactive membership or tenant leaked through membership projection';
  END IF;
END
$test$;

DO $test$
DECLARE
  enrollment_attempts integer;
  enrollment_exhausted boolean;
  rate_attempts integer;
  blocked timestamp with time zone;
BEGIN
  SELECT failure.enrollment_attempts, failure.enrollment_exhausted,
         failure.maximum_rate_attempt_count, failure.blocked_until
    INTO enrollment_attempts, enrollment_exhausted, rate_attempts, blocked
  FROM app.record_platform_bootstrap_failure(
    decode(repeat('a1', 32), 'hex'), decode(repeat('b1', 32), 'hex'),
    ARRAY['bootstrap_totp'::public.auth_rate_limit_scope, 'bootstrap_totp'],
    ARRAY[decode(repeat('51', 32), 'hex'), decode(repeat('52', 32), 'hex')],
    ARRAY[60, 60], ARRAY[3, 20], ARRAY[120, 120],
    '01993ea0-2000-7000-8000-000000000522',
    'invalid_totp', NULL, NULL, '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS failure;
  IF enrollment_attempts <> 1 OR enrollment_exhausted OR rate_attempts <> 1
     OR blocked IS NOT NULL THEN
    RAISE EXCEPTION 'bootstrap failure counters were not updated atomically';
  END IF;
END
$test$;

-- Confirmation must bind the reserved email; a failed attempt is fully rolled back and
-- leaves the enrollment available for a correctly bound confirmation.
DO $test$
BEGIN
  BEGIN
    PERFORM app.confirm_platform_bootstrap(
      p_authority_token_digest => decode(repeat('a1', 32), 'hex'),
      p_enrollment_token_digest => decode(repeat('b1', 32), 'hex'),
      p_user_id => '01993ea0-2000-7000-8000-000000000201',
      p_credential_id => '01993ea0-2000-7000-8000-000000000202',
      p_totp_credential_id => '01993ea0-2000-7000-8000-000000000203',
      p_final_totp_secret_ciphertext => decode(repeat('e1', 32), 'hex'),
      p_final_totp_secret_nonce => decode(repeat('e2', 12), 'hex'),
      p_final_totp_secret_aad => convert_to(
        'totp_credential:01993ea0-2000-7000-8000-000000000203:user:01993ea0-2000-7000-8000-000000000201',
        'UTF8'
      ),
      p_final_totp_key_version => 1,
      p_platform_role_grant_id => '01993ea0-2000-7000-8000-000000000204',
      p_canonical_email => 'identity.drift@example.invalid',
      p_display_name => 'Bootstrap Administrator',
      p_password_phc => '$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$ZmFrZWJ1dGZvcm1hdHZhbGlkaGFzaA',
      p_password_version => 1,
      p_initial_totp_counter => 100,
      p_recovery_code_ids => ARRAY[
        '01993ea0-2000-7000-8000-000000000301'::uuid,
        '01993ea0-2000-7000-8000-000000000302'::uuid,
        '01993ea0-2000-7000-8000-000000000303'::uuid,
        '01993ea0-2000-7000-8000-000000000304'::uuid,
        '01993ea0-2000-7000-8000-000000000305'::uuid,
        '01993ea0-2000-7000-8000-000000000306'::uuid,
        '01993ea0-2000-7000-8000-000000000307'::uuid,
        '01993ea0-2000-7000-8000-000000000308'::uuid,
        '01993ea0-2000-7000-8000-000000000309'::uuid,
        '01993ea0-2000-7000-8000-000000000310'::uuid
      ],
      p_recovery_code_digests => ARRAY[
        decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'),
        decode(repeat('03', 32), 'hex'), decode(repeat('04', 32), 'hex'),
        decode(repeat('05', 32), 'hex'), decode(repeat('06', 32), 'hex'),
        decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'),
        decode(repeat('09', 32), 'hex'), decode(repeat('0a', 32), 'hex')
      ],
      p_recovery_code_key_version => 1,
      p_session_id => '01993ea0-2000-7000-8000-000000000401',
      p_rotation_family_id => '01993ea0-2000-7000-8000-000000000491',
      p_session_token_digest => decode(repeat('f1', 32), 'hex'),
      p_csrf_secret_digest => decode(repeat('f2', 32), 'hex'),
      p_idle_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '30 minutes',
      p_absolute_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '60 minutes',
      p_platform_audit_event_id => '01993ea0-2000-7000-8000-000000000501',
      p_request_id => '01993ea0-2000-7000-8000-000000000502',
      p_correlation_id => '01993ea0-2000-7000-8000-000000000503',
      p_ip_address => '192.0.2.10',
      p_user_agent => 'rls-security-test/1.0'
    );
    RAISE EXCEPTION 'bootstrap confirmation accepted identity drift';
  EXCEPTION
    WHEN check_violation THEN NULL;
  END;
END
$test$;

SELECT app.confirm_platform_bootstrap(
  p_authority_token_digest => decode(repeat('a1', 32), 'hex'),
  p_enrollment_token_digest => decode(repeat('b1', 32), 'hex'),
  p_user_id => '01993ea0-2000-7000-8000-000000000201',
  p_credential_id => '01993ea0-2000-7000-8000-000000000202',
  p_totp_credential_id => '01993ea0-2000-7000-8000-000000000203',
  p_final_totp_secret_ciphertext => decode(repeat('e1', 32), 'hex'),
  p_final_totp_secret_nonce => decode(repeat('e2', 12), 'hex'),
  p_final_totp_secret_aad => convert_to(
    'totp_credential:01993ea0-2000-7000-8000-000000000203:user:01993ea0-2000-7000-8000-000000000201',
    'UTF8'
  ),
  p_final_totp_key_version => 1,
  p_platform_role_grant_id => '01993ea0-2000-7000-8000-000000000204',
  p_canonical_email => 'bootstrap.admin@example.invalid',
  p_display_name => 'Bootstrap Administrator',
  p_password_phc => '$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$ZmFrZWJ1dGZvcm1hdHZhbGlkaGFzaA',
  p_password_version => 1,
  p_initial_totp_counter => 100,
  p_recovery_code_ids => ARRAY[
    '01993ea0-2000-7000-8000-000000000301'::uuid,
    '01993ea0-2000-7000-8000-000000000302'::uuid,
    '01993ea0-2000-7000-8000-000000000303'::uuid,
    '01993ea0-2000-7000-8000-000000000304'::uuid,
    '01993ea0-2000-7000-8000-000000000305'::uuid,
    '01993ea0-2000-7000-8000-000000000306'::uuid,
    '01993ea0-2000-7000-8000-000000000307'::uuid,
    '01993ea0-2000-7000-8000-000000000308'::uuid,
    '01993ea0-2000-7000-8000-000000000309'::uuid,
    '01993ea0-2000-7000-8000-000000000310'::uuid
  ],
  p_recovery_code_digests => ARRAY[
    decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'),
    decode(repeat('03', 32), 'hex'), decode(repeat('04', 32), 'hex'),
    decode(repeat('05', 32), 'hex'), decode(repeat('06', 32), 'hex'),
    decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'),
    decode(repeat('09', 32), 'hex'), decode(repeat('0a', 32), 'hex')
  ],
  p_recovery_code_key_version => 1,
  p_session_id => '01993ea0-2000-7000-8000-000000000401',
  p_rotation_family_id => '01993ea0-2000-7000-8000-000000000491',
  p_session_token_digest => decode(repeat('f1', 32), 'hex'),
  p_csrf_secret_digest => decode(repeat('f2', 32), 'hex'),
  p_idle_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '30 minutes',
  p_absolute_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '60 minutes',
  p_platform_audit_event_id => '01993ea0-2000-7000-8000-000000000501',
  p_request_id => '01993ea0-2000-7000-8000-000000000502',
  p_correlation_id => '01993ea0-2000-7000-8000-000000000503',
  p_ip_address => '192.0.2.10',
  p_user_agent => 'rls-security-test/1.0'
);

DO $test$
DECLARE
  enrollment_meter_count integer;
  network_attempts integer;
BEGIN
  SELECT count(*) INTO enrollment_meter_count
  FROM app.get_auth_rate_limit(
    'bootstrap_totp', decode(repeat('52', 32), 'hex')
  );
  SELECT rate.attempt_count INTO network_attempts
  FROM app.get_auth_rate_limit(
    'bootstrap_totp', decode(repeat('51', 32), 'hex')
  ) AS rate;
  IF enrollment_meter_count <> 0 OR network_attempts <> 1 THEN
    RAISE EXCEPTION 'bootstrap success did not clear only its enrollment meter';
  END IF;
END
$test$;

DO $test$
BEGIN
  BEGIN
    PERFORM app.get_platform_bootstrap_enrollment(
      decode(repeat('a1', 32), 'hex'), decode(repeat('b1', 32), 'hex')
    );
    RAISE EXCEPTION 'completed bootstrap lookup did not surface conflict';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;
  END;
  BEGIN
    PERFORM app.get_platform_bootstrap_enrollment(
      decode(repeat('a2', 32), 'hex'), decode(repeat('b1', 32), 'hex')
    );
    RAISE EXCEPTION 'completed bootstrap lookup accepted a wrong authority';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

DO $test$
BEGIN
  IF app.verify_protected_configuration(
    decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
  ) THEN
    RAISE EXCEPTION 'completed bootstrap was reported available';
  END IF;
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 32), 'hex'), decode(repeat('f2', 32), 'hex')
    );
    RAISE EXCEPTION 'completed bootstrap accepted another master-key verifier';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

SAVEPOINT completed_master_key_missing_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  BEGIN
    UPDATE public.platform_bootstrap_state
    SET master_key_verifier = NULL, master_key_verifier_bound_at = NULL
    WHERE singleton = true;
    RAISE EXCEPTION 'completed bootstrap state accepted a missing master-key verifier';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END
$test$;

ALTER TABLE public.platform_bootstrap_state
  DROP CONSTRAINT platform_bootstrap_state_completion_check;
ALTER TABLE public.platform_bootstrap_state
  DROP CONSTRAINT platform_bootstrap_state_protected_configuration_check;
UPDATE public.platform_bootstrap_state
SET master_key_verifier = NULL, master_key_verifier_bound_at = NULL
WHERE singleton = true;

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM app.verify_protected_configuration(
      decode(repeat('a1', 32), 'hex'), decode(repeat('f1', 32), 'hex')
    );
    RAISE EXCEPTION 'completed bootstrap with a missing verifier reported ready';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;
  END;
END
$test$;

ROLLBACK TO SAVEPOINT completed_master_key_missing_probe;
RELEASE SAVEPOINT completed_master_key_missing_probe;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  grant_count integer;
BEGIN
  SELECT count(*) INTO grant_count
  FROM public.user_platform_roles AS user_role
  JOIN public.platform_roles AS role ON role.id = user_role.role_id
  WHERE user_role.revoked_at IS NULL AND role.key = 'platform_super_admin';
  IF grant_count <> 1 THEN
    RAISE EXCEPTION 'bootstrap expected exactly one initial super-admin grant, saw %', grant_count;
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM app.confirm_platform_bootstrap(
      p_authority_token_digest => decode(repeat('a1', 32), 'hex'),
      p_enrollment_token_digest => decode(repeat('b1', 32), 'hex'),
      p_user_id => '01993ea0-2000-7000-8000-000000000211',
      p_credential_id => '01993ea0-2000-7000-8000-000000000212',
      p_totp_credential_id => '01993ea0-2000-7000-8000-000000000213',
      p_final_totp_secret_ciphertext => decode(repeat('e3', 32), 'hex'),
      p_final_totp_secret_nonce => decode(repeat('e4', 12), 'hex'),
      p_final_totp_secret_aad => convert_to(
        'totp_credential:01993ea0-2000-7000-8000-000000000213:user:01993ea0-2000-7000-8000-000000000211', 'UTF8'
      ),
      p_final_totp_key_version => 1,
      p_platform_role_grant_id => '01993ea0-2000-7000-8000-000000000214',
      p_canonical_email => 'bootstrap.admin@example.invalid',
      p_display_name => 'Second Administrator',
      p_password_phc => '$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$ZmFrZWJ1dGZvcm1hdHZhbGlkaGFzaA',
      p_password_version => 1,
      p_initial_totp_counter => 101,
      p_recovery_code_ids => ARRAY[
        '01993ea0-2000-7000-8000-000000000311'::uuid,
        '01993ea0-2000-7000-8000-000000000312'::uuid,
        '01993ea0-2000-7000-8000-000000000313'::uuid,
        '01993ea0-2000-7000-8000-000000000314'::uuid,
        '01993ea0-2000-7000-8000-000000000315'::uuid,
        '01993ea0-2000-7000-8000-000000000316'::uuid,
        '01993ea0-2000-7000-8000-000000000317'::uuid,
        '01993ea0-2000-7000-8000-000000000318'::uuid,
        '01993ea0-2000-7000-8000-000000000319'::uuid,
        '01993ea0-2000-7000-8000-000000000320'::uuid
      ],
      p_recovery_code_digests => ARRAY[
        decode(repeat('11', 32), 'hex'), decode(repeat('12', 32), 'hex'),
        decode(repeat('13', 32), 'hex'), decode(repeat('14', 32), 'hex'),
        decode(repeat('15', 32), 'hex'), decode(repeat('16', 32), 'hex'),
        decode(repeat('17', 32), 'hex'), decode(repeat('18', 32), 'hex'),
        decode(repeat('19', 32), 'hex'), decode(repeat('1a', 32), 'hex')
      ],
      p_recovery_code_key_version => 1,
      p_session_id => '01993ea0-2000-7000-8000-000000000411',
      p_rotation_family_id => '01993ea0-2000-7000-8000-000000000492',
      p_session_token_digest => decode(repeat('f3', 32), 'hex'),
      p_csrf_secret_digest => decode(repeat('f4', 32), 'hex'),
      p_idle_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '30 minutes',
      p_absolute_expires_at => date_trunc('milliseconds', transaction_timestamp()) + interval '60 minutes',
      p_platform_audit_event_id => '01993ea0-2000-7000-8000-000000000511',
      p_request_id => NULL,
      p_correlation_id => NULL,
      p_ip_address => '192.0.2.10',
      p_user_agent => 'rls-security-test/1.0'
    );
    RAISE EXCEPTION 'bootstrap confirmation succeeded twice';
  EXCEPTION
    WHEN object_not_in_prerequisite_state THEN NULL;
  END;
END
$test$;

-- Bootstrap completion created the principal used by the remaining authenticated
-- function tests; bind that live user explicitly instead of relying on fixture order.
SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);

-- Password KDF admission updates account and shared-network meters atomically with
-- their distinct policies. A denied aggregate cannot persist a new rotating sibling.
DO $test$
DECLARE
  was_admitted boolean;
  attempts integer;
  account_attempts integer;
  network_attempts integer;
  visible_count integer;
BEGIN
  SELECT admission.admitted INTO was_admitted
  FROM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  ) AS admission;
  IF NOT was_admitted THEN
    RAISE EXCEPTION 'first account/network admission was denied';
  END IF;

  PERFORM app.record_authentication_failure(
    'local_login', decode(repeat('41', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000201',
    '01993ea0-2000-7000-8000-000000000615', 'invalid_credentials',
    '01993ea0-2000-7000-8000-000000000616',
    '01993ea0-2000-7000-8000-000000000617',
    '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
  );
  SELECT rate.attempt_count INTO account_attempts
  FROM app.get_auth_rate_limit('local_login', decode(repeat('41', 32), 'hex')) AS rate;
  SELECT rate.attempt_count INTO network_attempts
  FROM app.get_auth_rate_limit('local_login', decode(repeat('42', 32), 'hex')) AS rate;
  IF account_attempts <> 1 OR network_attempts <> 1 THEN
    RAISE EXCEPTION 'audit-only password failure mutated admission meters: %, %',
      account_attempts, network_attempts;
  END IF;

  PERFORM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  );
  SELECT admission.admitted INTO was_admitted
  FROM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  ) AS admission;
  IF was_admitted THEN
    RAISE EXCEPTION 'account policy allowed an attempt beyond its limit';
  END IF;
  SELECT rate.attempt_count INTO account_attempts
  FROM app.get_auth_rate_limit('local_login', decode(repeat('41', 32), 'hex')) AS rate;
  SELECT rate.attempt_count INTO network_attempts
  FROM app.get_auth_rate_limit('local_login', decode(repeat('42', 32), 'hex')) AS rate;
  IF account_attempts <> 3 OR network_attempts <> 3 THEN
    RAISE EXCEPTION 'denied aggregate did not update both existing meters: %, %',
      account_attempts, network_attempts;
  END IF;

  -- The fourth network attempt is still admitted under its independent policy.
  SELECT admission.admitted INTO was_admitted
  FROM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('43', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  ) AS admission;
  IF NOT was_admitted THEN
    RAISE EXCEPTION 'network policy did not preserve its distinct fourth allowance';
  END IF;

  -- Crossing the shared-network limit must retain that block but remove the new
  -- rotating account row. A subsequent blocked probe has the same invariant.
  SELECT admission.admitted INTO was_admitted
  FROM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('44', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  ) AS admission;
  IF was_admitted THEN
    RAISE EXCEPTION 'network policy allowed an attempt beyond its limit';
  END IF;
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('44', 32), 'hex'));
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'denied network admission persisted a rotating account sibling';
  END IF;

  PERFORM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('45', 32), 'hex'), decode(repeat('42', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 4], ARRAY[900, 900]
  );
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('45', 32), 'hex'));
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'blocked network persisted another rotating account sibling';
  END IF;

  -- The symmetric blocked-account case cannot persist a rotating network row.
  PERFORM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('41', 32), 'hex'), decode(repeat('46', 32), 'hex')],
    ARRAY[900, 900], ARRAY[2, 20], ARRAY[900, 900]
  );
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('46', 32), 'hex'));
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'blocked account persisted a rotating network sibling';
  END IF;
END
$test$;

-- A block remains visible and enforceable when its duration outlives the
-- counting window. Denial must not retain a newly introduced sibling key.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.auth_rate_limits (
  id, scope, key_digest, attempt_count, window_started_at,
  window_expires_at, blocked_until, updated_at
) VALUES (
  '01993ea0-2000-7000-8000-000000000807', 'local_login',
  decode(repeat('47', 32), 'hex'), 5,
  transaction_timestamp() - interval '20 minutes',
  transaction_timestamp() - interval '10 minutes',
  date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes',
  transaction_timestamp() - interval '10 minutes'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  visible_count integer;
  was_admitted boolean;
BEGIN
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('47', 32), 'hex'));
  IF visible_count <> 1 THEN
    RAISE EXCEPTION 'a live block disappeared when its counting window expired';
  END IF;

  SELECT admission.admitted INTO was_admitted
  FROM app.admit_auth_attempts(
    ARRAY['local_login'::public.auth_rate_limit_scope, 'local_login'],
    ARRAY[decode(repeat('47', 32), 'hex'), decode(repeat('48', 32), 'hex')],
    ARRAY[600, 600], ARRAY[5, 20], ARRAY[900, 900]
  ) AS admission;
  IF was_admitted THEN
    RAISE EXCEPTION 'an unexpired block was bypassed after its window expired';
  END IF;
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('48', 32), 'hex'));
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'expired-window block persisted a denied sibling meter';
  END IF;
END
$test$;

-- Atomic anti-replay primitives: TOTP counters, recovery codes, challenges, and
-- rotated session tokens can each transition only once.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.auth_challenges (
  id, user_id, challenge_rate_key_digest, mfa_rate_key_digest,
  login_account_rate_key_digest, token_digest, purpose, attempts,
  max_attempts, expires_at, created_at
) VALUES (
  '01993ea0-2000-7000-8000-00000000059f',
  '01993ea0-2000-7000-8000-000000000201',
  decode(repeat('60', 32), 'hex'), decode(repeat('61', 32), 'hex'),
  decode(repeat('41', 32), 'hex'), decode(repeat('19', 32), 'hex'),
  'mfa_login', 0, 3, transaction_timestamp() - interval '5 minutes',
  transaction_timestamp() - interval '10 minutes'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  completed_session uuid;
  replayed_session uuid;
  failure_was_recorded boolean;
  replay_failure_was_recorded boolean;
  rotated_id uuid;
  visible_count integer;
  failed_attempts integer;
  mfa_rate_attempts integer;
  mfa_network_attempts integer;
  network_rate_attempts integer;
  rotation_family uuid;
  original_idle_expires_at timestamp with time zone;
  touched_idle_expires_at timestamp with time zone;
  session_absolute_expires_at timestamp with time zone;
BEGIN
  PERFORM app.create_auth_challenge(
    '01993ea0-2000-7000-8000-000000000600',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex'),
    decode(repeat('41', 32), 'hex'),
    decode(repeat('20', 32), 'hex'), 'mfa_login',
    date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
    '01993ea0-2000-7000-8000-000000000604',
    '01993ea0-2000-7000-8000-000000000610',
    '01993ea0-2000-7000-8000-000000000611',
    '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
  );
  PERFORM app.create_auth_challenge(
    '01993ea0-2000-7000-8000-000000000601',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex'),
    decode(repeat('41', 32), 'hex'),
    decode(repeat('21', 32), 'hex'), 'mfa_login',
    date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
    '01993ea0-2000-7000-8000-000000000605',
    '01993ea0-2000-7000-8000-000000000612',
    '01993ea0-2000-7000-8000-000000000613',
    '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
  );
  SELECT count(*) INTO visible_count
  FROM app.get_auth_challenge(decode(repeat('20', 32), 'hex'), 'mfa_login');
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'replacement left two live MFA challenges for one user';
  END IF;

  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('21', 32), 'hex'), 'totp', 100, NULL,
    '01993ea0-2000-7000-8000-000000000418',
    '01993ea0-2000-7000-8000-000000000498', NULL,
    decode(repeat('68', 32), 'hex'), decode(repeat('69', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000630',
    '01993ea0-2000-7000-8000-000000000618',
    '01993ea0-2000-7000-8000-000000000619',
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  SELECT challenge.attempts INTO failed_attempts
  FROM app.get_auth_challenge(decode(repeat('21', 32), 'hex'), 'mfa_login') AS challenge;
  SELECT rate.attempt_count INTO mfa_rate_attempts
  FROM app.get_auth_rate_limit('mfa_challenge', decode(repeat('61', 32), 'hex')) AS rate;
  IF completed_session IS NOT NULL OR NOT failure_was_recorded
     OR failed_attempts <> 1 OR mfa_rate_attempts <> 1 THEN
    RAISE EXCEPTION 'invalid MFA proof did not update challenge/rate/audit atomically';
  END IF;

  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('21', 32), 'hex'), 'totp', 101, NULL,
    '01993ea0-2000-7000-8000-000000000421',
    '01993ea0-2000-7000-8000-000000000493', NULL,
    decode(repeat('71', 32), 'hex'), decode(repeat('72', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000631', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  IF completed_session IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000421'::uuid
     OR failure_was_recorded THEN
    RAISE EXCEPTION 'atomic TOTP login completion failed';
  END IF;
  SELECT session.rotation_family_id INTO rotation_family
  FROM app.get_auth_session(decode(repeat('71', 32), 'hex')) AS session;
  IF rotation_family IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000493'::uuid THEN
    RAISE EXCEPTION 'MFA login did not persist its rotation family';
  END IF;
  SELECT count(*) INTO visible_count
  FROM app.get_auth_rate_limit('local_login', decode(repeat('41', 32), 'hex'));
  SELECT rate.attempt_count INTO network_rate_attempts
  FROM app.get_auth_rate_limit('local_login', decode(repeat('42', 32), 'hex')) AS rate;
  SELECT count(*) INTO visible_count
  FROM (
    SELECT * FROM app.get_auth_rate_limit(
      'mfa_challenge', decode(repeat('61', 32), 'hex')
    )
    UNION ALL
    SELECT * FROM app.get_auth_rate_limit(
      'mfa_challenge', decode(repeat('62', 32), 'hex')
    )
  ) AS proof_meter;
  SELECT rate.attempt_count INTO mfa_network_attempts
  FROM app.get_auth_rate_limit(
    'mfa_challenge', decode(repeat('63', 32), 'hex')
  ) AS rate;
  IF visible_count <> 0 OR network_rate_attempts < 5 OR mfa_network_attempts < 1 THEN
    RAISE EXCEPTION 'MFA success did not clear proof-bound meters while retaining networks';
  END IF;
  SELECT completion.session_id, completion.failure_recorded
    INTO replayed_session, replay_failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('21', 32), 'hex'), 'totp', 102, NULL,
    '01993ea0-2000-7000-8000-000000000424',
    '01993ea0-2000-7000-8000-000000000496', NULL,
    decode(repeat('73', 32), 'hex'), decode(repeat('74', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000634', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  IF replayed_session IS NOT NULL OR replay_failure_was_recorded THEN
    RAISE EXCEPTION 'consumed TOTP challenge completed twice';
  END IF;

  PERFORM app.create_auth_challenge(
    '01993ea0-2000-7000-8000-000000000602',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex'),
    decode(repeat('41', 32), 'hex'),
    decode(repeat('22', 32), 'hex'), 'mfa_login',
    date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
    '01993ea0-2000-7000-8000-000000000606',
    '01993ea0-2000-7000-8000-000000000622',
    '01993ea0-2000-7000-8000-000000000623',
    '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
  );
  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('22', 32), 'hex'), 'recovery_code', NULL,
    decode(repeat('01', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000422',
    '01993ea0-2000-7000-8000-000000000494', NULL,
    decode(repeat('75', 32), 'hex'), decode(repeat('76', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000632', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  SELECT completion.session_id, completion.failure_recorded
    INTO replayed_session, replay_failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('22', 32), 'hex'), 'recovery_code', NULL,
    decode(repeat('01', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000425',
    '01993ea0-2000-7000-8000-000000000497', NULL,
    decode(repeat('77', 32), 'hex'), decode(repeat('78', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000635', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  IF completed_session IS NULL OR failure_was_recorded
     OR replayed_session IS NOT NULL OR replay_failure_was_recorded THEN
    RAISE EXCEPTION 'recovery code or its challenge was not one-use';
  END IF;

  -- A tenant-bound session failure must roll back challenge and recovery consumption.
  PERFORM app.create_auth_challenge(
    '01993ea0-2000-7000-8000-000000000603',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex'),
    decode(repeat('41', 32), 'hex'),
    decode(repeat('23', 32), 'hex'), 'mfa_login',
    date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
    '01993ea0-2000-7000-8000-000000000607',
    '01993ea0-2000-7000-8000-000000000624',
    '01993ea0-2000-7000-8000-000000000625',
    '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
  );
  BEGIN
    PERFORM app.complete_mfa_login(
      decode(repeat('23', 32), 'hex'), 'recovery_code', NULL,
      decode(repeat('02', 32), 'hex'),
      '01993ea0-2000-7000-8000-000000000423',
      '01993ea0-2000-7000-8000-000000000495',
      '01993ea0-1000-7000-8000-000000000002',
      decode(repeat('79', 32), 'hex'), decode(repeat('7a', 32), 'hex'),
      date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
      date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
      ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
      ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
      ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
      ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
      ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
      '01993ea0-2000-7000-8000-000000000633', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0'
    );
    RAISE EXCEPTION 'session selected a tenant without membership';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('23', 32), 'hex'), 'recovery_code', NULL,
    decode(repeat('02', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000423',
    '01993ea0-2000-7000-8000-000000000495', NULL,
    decode(repeat('79', 32), 'hex'), decode(repeat('7a', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('61', 32), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('62', 32), 'hex'), decode(repeat('61', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000633', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  IF completed_session IS NULL OR failure_was_recorded THEN
    RAISE EXCEPTION 'failed tenant selection partially consumed MFA state';
  END IF;

  SELECT session.idle_expires_at, session.absolute_expires_at
    INTO original_idle_expires_at, session_absolute_expires_at
  FROM app.get_auth_session(decode(repeat('f1', 32), 'hex')) AS session;
  IF NOT app.touch_auth_session(
    decode(repeat('f1', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes'
  ) THEN
    RAISE EXCEPTION 'live session touch failed';
  END IF;
  SELECT session.idle_expires_at INTO touched_idle_expires_at
  FROM app.get_auth_session(decode(repeat('f1', 32), 'hex')) AS session;
  IF touched_idle_expires_at IS DISTINCT FROM original_idle_expires_at THEN
    RAISE EXCEPTION 'overlapping touch shortened the idle expiry';
  END IF;
  PERFORM app.touch_auth_session(
    decode(repeat('f1', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '90 minutes'
  );
  SELECT session.idle_expires_at INTO touched_idle_expires_at
  FROM app.get_auth_session(decode(repeat('f1', 32), 'hex')) AS session;
  IF touched_idle_expires_at IS DISTINCT FROM session_absolute_expires_at THEN
    RAISE EXCEPTION 'session touch exceeded or failed to reach absolute expiry cap';
  END IF;

  rotated_id := app.rotate_auth_session(
    decode(repeat('f1', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000402',
    decode(repeat('f5', 32), 'hex'), decode(repeat('f6', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '20 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '50 minutes',
    '01993ea0-2000-7000-8000-000000000640', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  );
  IF rotated_id IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000402'::uuid THEN
    RAISE EXCEPTION 'session rotation failed';
  END IF;
  IF app.rotate_auth_session(
    decode(repeat('f1', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000403',
    decode(repeat('f7', 32), 'hex'), decode(repeat('f8', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '20 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '50 minutes',
    '01993ea0-2000-7000-8000-000000000641', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'retired session token rotated twice';
  END IF;

  SELECT count(*) INTO visible_count
  FROM app.get_auth_session(decode(repeat('f1', 32), 'hex'));
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'rotated source session remained active';
  END IF;
  SELECT count(*) INTO visible_count
  FROM app.get_auth_session(decode(repeat('f5', 32), 'hex'));
  IF visible_count <> 1 THEN
    RAISE EXCEPTION 'rotated target session was not active';
  END IF;
  SELECT session.rotation_family_id INTO rotation_family
  FROM app.get_auth_session(decode(repeat('f5', 32), 'hex')) AS session;
  IF rotation_family IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000491'::uuid THEN
    RAISE EXCEPTION 'session rotation changed its rotation family';
  END IF;
END
$test$;

-- MFA continuation is revoked with its identity, local password credential, or
-- parent TOTP factor. Revocation after challenge issuance must meter one generic
-- failure without consuming a recovery proof or creating a session.
SAVEPOINT mfa_disabled_issuance_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
UPDATE public.local_break_glass_credentials
SET disabled_at = transaction_timestamp()
WHERE user_id = '01993ea0-2000-7000-8000-000000000201';
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM app.create_auth_challenge(
      '01993ea0-2000-7000-8000-000000000608',
      '01993ea0-2000-7000-8000-000000000201',
      decode(repeat('65', 32), 'hex'), decode(repeat('64', 32), 'hex'),
      decode(repeat('49', 32), 'hex'),
      decode(repeat('24', 32), 'hex'), 'mfa_login',
      date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
      '01993ea0-2000-7000-8000-000000000650', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
    );
    RAISE EXCEPTION 'disabled local credential issued an MFA challenge';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;
ROLLBACK TO SAVEPOINT mfa_disabled_issuance_probe;
RELEASE SAVEPOINT mfa_disabled_issuance_probe;

SAVEPOINT mfa_disabled_local_completion_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT app.create_auth_challenge(
  '01993ea0-2000-7000-8000-000000000608',
  '01993ea0-2000-7000-8000-000000000201',
  decode(repeat('65', 32), 'hex'), decode(repeat('64', 32), 'hex'),
  decode(repeat('49', 32), 'hex'),
  decode(repeat('24', 32), 'hex'), 'mfa_login',
  date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
  '01993ea0-2000-7000-8000-000000000650', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
UPDATE public.local_break_glass_credentials
SET disabled_at = transaction_timestamp()
WHERE user_id = '01993ea0-2000-7000-8000-000000000201';
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  completed_session uuid;
  failure_was_recorded boolean;
  failed_attempts integer;
BEGIN
  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('24', 32), 'hex'), 'totp', 102, NULL,
    '01993ea0-2000-7000-8000-000000000426',
    '01993ea0-2000-7000-8000-000000000499', NULL,
    decode(repeat('7b', 32), 'hex'), decode(repeat('7c', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('64', 32), 'hex'), decode(repeat('65', 32), 'hex'), decode(repeat('66', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('65', 32), 'hex'), decode(repeat('64', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000651', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  SELECT challenge.attempts INTO failed_attempts
  FROM app.get_auth_challenge(decode(repeat('24', 32), 'hex'), 'mfa_login') AS challenge;
  IF completed_session IS NOT NULL OR NOT failure_was_recorded OR failed_attempts <> 1 THEN
    RAISE EXCEPTION 'disabled local credential did not fail and meter MFA atomically';
  END IF;
END
$test$;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions
    WHERE id = '01993ea0-2000-7000-8000-000000000426'
  ) THEN
    RAISE EXCEPTION 'disabled local credential created an MFA session';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT mfa_disabled_local_completion_probe;
RELEASE SAVEPOINT mfa_disabled_local_completion_probe;

SAVEPOINT mfa_disabled_totp_completion_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT app.create_auth_challenge(
  '01993ea0-2000-7000-8000-000000000609',
  '01993ea0-2000-7000-8000-000000000201',
  decode(repeat('68', 32), 'hex'), decode(repeat('67', 32), 'hex'),
  decode(repeat('49', 32), 'hex'),
  decode(repeat('25', 32), 'hex'), 'mfa_login',
  date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
  '01993ea0-2000-7000-8000-000000000652', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
UPDATE public.totp_credentials
SET disabled_at = transaction_timestamp()
WHERE id = '01993ea0-2000-7000-8000-000000000203';
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  completed_session uuid;
  failure_was_recorded boolean;
  failed_attempts integer;
BEGIN
  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('25', 32), 'hex'), 'recovery_code', NULL,
    decode(repeat('03', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000427',
    '01993ea0-2000-7000-8000-00000000049a', NULL,
    decode(repeat('7d', 32), 'hex'), decode(repeat('7e', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('67', 32), 'hex'), decode(repeat('68', 32), 'hex'), decode(repeat('69', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('68', 32), 'hex'), decode(repeat('67', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000653', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  SELECT challenge.attempts INTO failed_attempts
  FROM app.get_auth_challenge(decode(repeat('25', 32), 'hex'), 'mfa_login') AS challenge;
  IF completed_session IS NOT NULL OR NOT failure_was_recorded OR failed_attempts <> 1 THEN
    RAISE EXCEPTION 'disabled TOTP parent did not fail and meter recovery MFA atomically';
  END IF;
END
$test$;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions
    WHERE id = '01993ea0-2000-7000-8000-000000000427'
  ) OR EXISTS (
    SELECT 1 FROM public.recovery_codes
    WHERE user_id = '01993ea0-2000-7000-8000-000000000201'
      AND code_digest = decode(repeat('03', 32), 'hex')
      AND consumed_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'disabled TOTP parent consumed recovery proof or created a session';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT mfa_disabled_totp_completion_probe;
RELEASE SAVEPOINT mfa_disabled_totp_completion_probe;

SAVEPOINT mfa_inactive_user_completion_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT app.create_auth_challenge(
  '01993ea0-2000-7000-8000-00000000060a',
  '01993ea0-2000-7000-8000-000000000201',
  decode(repeat('6b', 32), 'hex'), decode(repeat('6a', 32), 'hex'),
  decode(repeat('49', 32), 'hex'),
  decode(repeat('26', 32), 'hex'), 'mfa_login',
  date_trunc('milliseconds', transaction_timestamp()) + interval '5 minutes', 3,
  '01993ea0-2000-7000-8000-000000000654', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
UPDATE public.users SET active = false
WHERE id = '01993ea0-2000-7000-8000-000000000201';
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
DECLARE
  completed_session uuid;
  failure_was_recorded boolean;
  failed_attempts integer;
BEGIN
  SELECT completion.session_id, completion.failure_recorded
    INTO completed_session, failure_was_recorded
  FROM app.complete_mfa_login(
    decode(repeat('26', 32), 'hex'), 'totp', 102, NULL,
    '01993ea0-2000-7000-8000-000000000428',
    '01993ea0-2000-7000-8000-00000000049b', NULL,
    decode(repeat('7f', 32), 'hex'), decode(repeat('80', 32), 'hex'),
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '10 minutes',
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge', 'mfa_challenge'],
    ARRAY[decode(repeat('6a', 32), 'hex'), decode(repeat('6b', 32), 'hex'), decode(repeat('6c', 32), 'hex')],
    ARRAY[60, 60, 60], ARRAY[3, 5, 20], ARRAY[120, 120, 120],
    ARRAY['mfa_challenge'::public.auth_rate_limit_scope, 'mfa_challenge'],
    ARRAY[decode(repeat('6b', 32), 'hex'), decode(repeat('6a', 32), 'hex')],
    '01993ea0-2000-7000-8000-000000000655', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) AS completion;
  SELECT challenge.attempts INTO failed_attempts
  FROM app.get_auth_challenge(decode(repeat('26', 32), 'hex'), 'mfa_login') AS challenge;
  IF completed_session IS NOT NULL OR NOT failure_was_recorded OR failed_attempts <> 1 THEN
    RAISE EXCEPTION 'inactive user did not fail and meter MFA atomically';
  END IF;
END
$test$;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions
    WHERE id = '01993ea0-2000-7000-8000-000000000428'
  ) OR EXISTS (
    SELECT 1 FROM public.totp_credentials
    WHERE id = '01993ea0-2000-7000-8000-000000000203'
      AND last_accepted_counter >= 102
  ) THEN
    RAISE EXCEPTION 'inactive user advanced MFA proof or created a session';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT mfa_inactive_user_completion_probe;
RELEASE SAVEPOINT mfa_inactive_user_completion_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";

SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);
SELECT app.create_platform_tenant(
  '01993ea0-2000-7000-8000-000000000701',
  '01993ea0-2000-7000-8000-000000000702',
  'bootstrap-created', 'Bootstrap Created Tenant', 'UTC', 'en',
  '01993ea0-2000-7000-8000-000000000703',
  '01993ea0-2000-7000-8000-000000000704',
  '01993ea0-2000-7000-8000-000000000705',
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
);

-- Tenant provisioning creates its audit head and initialization event atomically.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  head_count integer;
BEGIN
  SELECT count(*) INTO head_count
  FROM public.audit_chain_heads AS head
  WHERE head.tenant_id = '01993ea0-2000-7000-8000-000000000701'
    AND head.last_sequence > 0
    AND head.last_sequence = (
      SELECT count(*)
      FROM public.audit_events AS event
      WHERE event.tenant_id = head.tenant_id
    )
    AND EXISTS (
      SELECT 1
      FROM public.audit_events AS tail
      WHERE tail.tenant_id = head.tenant_id
        AND tail.sequence = head.last_sequence
        AND tail.event_hash = head.last_event_hash
        AND tail.action = 'tenant.authorization.initialized'
    );
  IF head_count <> 1 THEN
    RAISE EXCEPTION 'platform tenant creation omitted its initialization audit tail';
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '01993ea0-2000-7000-8000-000000000701', true);
SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);
DO $test$
DECLARE
  row_count integer;
  invalid_count integer;
  event_count integer;
BEGIN
  SELECT count(*) INTO event_count
  FROM public.audit_events
  WHERE tenant_id = '01993ea0-2000-7000-8000-000000000701';
  SELECT count(*), count(*) FILTER (WHERE NOT valid)
    INTO row_count, invalid_count
  FROM app.verify_audit_chain('01993ea0-2000-7000-8000-000000000701');
  IF row_count <> event_count + 1 OR invalid_count <> 0 THEN
    RAISE EXCEPTION 'initialized tenant audit head did not verify: %, %',
      row_count, invalid_count;
  END IF;
END
$test$;

SAVEPOINT empty_tenant_head_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DELETE FROM public.audit_chain_heads
WHERE tenant_id = '01993ea0-2000-7000-8000-000000000701';
RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
SELECT set_config('app.tenant_id', '01993ea0-2000-7000-8000-000000000701', true);
SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);
DO $test$
DECLARE
  invalid_count integer;
BEGIN
  SELECT count(*) INTO invalid_count
  FROM app.verify_audit_chain('01993ea0-2000-7000-8000-000000000701')
  WHERE NOT valid;
  IF invalid_count = 0 THEN
    RAISE EXCEPTION 'tenant verifier treated a missing empty-chain head as pristine';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT empty_tenant_head_probe;
RELEASE SAVEPOINT empty_tenant_head_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);

DO $test$
DECLARE
  membership_count integer;
  tenant_count integer;
  bounded_count integer;
BEGIN
  SELECT count(*) INTO membership_count
  FROM app.list_user_tenant_memberships(NULL, 101) AS membership
  WHERE tenant_id = '01993ea0-2000-7000-8000-000000000701'
    AND membership_role = 'tenant_admin'
    AND membership_status = 'active';
  IF membership_count <> 1 THEN
    RAISE EXCEPTION 'platform tenant creation omitted creator membership';
  END IF;

  SELECT count(*) INTO tenant_count
  FROM app.list_platform_tenants(NULL, 100)
  WHERE id = '01993ea0-2000-7000-8000-000000000701';
  IF tenant_count <> 1 THEN
    RAISE EXCEPTION 'platform tenant list omitted the created tenant';
  END IF;

  SELECT count(*) INTO bounded_count
  FROM app.list_platform_tenants(NULL, 1);
  IF bounded_count <> 1 THEN
    RAISE EXCEPTION 'platform tenant list did not honor the repository-supplied limit';
  END IF;
  BEGIN
    PERFORM app.list_platform_tenants(NULL, NULL);
    RAISE EXCEPTION 'platform tenant list accepted an unbounded NULL page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.list_platform_tenants(NULL, 102);
    RAISE EXCEPTION 'platform tenant list accepted an oversized page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END
$test$;

-- Active memberships are keyset-paginated by their UUIDv7 identifier. The
-- repository may request one sentinel row, so the database accepts at most
-- 101 rows and every active membership remains reachable across pages.
SAVEPOINT membership_pagination_probe;
DO $test$
DECLARE
  cursor_id uuid;
  last_id uuid;
  expected_id uuid;
  membership_row record;
  seen_ids uuid[] := ARRAY[]::uuid[];
  page_count integer;
  page_number integer := 0;
BEGIN
  FOR fixture_number IN 1..105 LOOP
    PERFORM *
    FROM app.create_platform_tenant(
      (
        '01993ea0-5000-7000-8000-'
        || lpad(to_hex(fixture_number), 12, '0')
      )::uuid,
      (
        '01993ea0-5001-7000-8000-'
        || lpad(to_hex(fixture_number), 12, '0')
      )::uuid,
      'membership-page-' || lpad(fixture_number::text, 3, '0'),
      'Membership Page ' || fixture_number,
      'UTC', 'en',
      (
        '01993ea0-5002-7000-8000-'
        || lpad(to_hex(fixture_number), 12, '0')
      )::uuid,
      NULL, NULL, '192.0.2.10'::inet,
      'rls-security-test/1.0', 'bootstrap_totp'
    );
  END LOOP;

  LOOP
    page_number := page_number + 1;
    page_count := 0;
    last_id := NULL;
    FOR membership_row IN
      SELECT * FROM app.list_user_tenant_memberships(cursor_id, 100)
    LOOP
      page_count := page_count + 1;
      IF membership_row.membership_id = ANY(seen_ids) THEN
        RAISE EXCEPTION 'membership keyset returned duplicate %',
          membership_row.membership_id;
      END IF;
      seen_ids := array_append(seen_ids, membership_row.membership_id);
      last_id := membership_row.membership_id;
    END LOOP;

    EXIT WHEN page_count < 100;
    IF last_id IS NULL OR page_number > 10 THEN
      RAISE EXCEPTION 'membership keyset pagination did not make progress';
    END IF;
    cursor_id := last_id;
  END LOOP;

  FOR fixture_number IN 1..105 LOOP
    expected_id := (
      '01993ea0-5001-7000-8000-'
      || lpad(to_hex(fixture_number), 12, '0')
    )::uuid;
    IF NOT expected_id = ANY(seen_ids) THEN
      RAISE EXCEPTION 'active membership % was stranded between pages', expected_id;
    END IF;
  END LOOP;
  IF page_number < 2 THEN
    RAISE EXCEPTION 'membership keyset fixture did not cross a page boundary';
  END IF;

  BEGIN
    PERFORM app.list_user_tenant_memberships(
      '01993ea0-5fff-7000-8000-000000000001', 100
    );
    RAISE EXCEPTION 'membership keyset accepted a missing or foreign cursor';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.list_user_tenant_memberships(NULL, 102);
    RAISE EXCEPTION 'membership keyset accepted an oversized page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.list_user_tenant_memberships(NULL, NULL);
    RAISE EXCEPTION 'membership keyset accepted an unbounded NULL page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END
$test$;
ROLLBACK TO SAVEPOINT membership_pagination_probe;
RELEASE SAVEPOINT membership_pagination_probe;

DO $test$
BEGIN
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000731',
      '01993ea0-2000-7000-8000-000000000741',
      'Invalid_Slug', 'Valid Name', 'UTC', 'en',
      '01993ea0-2000-7000-8000-000000000751', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant function accepted an invalid slug';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000732',
      '01993ea0-2000-7000-8000-000000000742',
      'valid-name', E'Invalid\nName', 'UTC', 'en',
      '01993ea0-2000-7000-8000-000000000752', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant function accepted a control character in name';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000733',
      '01993ea0-2000-7000-8000-000000000743',
      'valid-zone', 'Valid Name', 'Not/AZone', 'en',
      '01993ea0-2000-7000-8000-000000000753', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant function accepted a non-IANA timezone';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000734',
      '01993ea0-2000-7000-8000-000000000744',
      'valid-locale', 'Valid Name', 'UTC', 'en_US',
      '01993ea0-2000-7000-8000-000000000754', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant function accepted an invalid locale';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000736',
      '01993ea0-2000-7000-8000-000000000746',
      'undefined-locale', 'Undefined Locale', 'UTC', 'und-US',
      '01993ea0-2000-7000-8000-000000000756', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant function accepted an undefined locale base';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000735',
      '01993ea0-2000-7000-8000-000000000745',
      'bounded-context', 'Bounded Context', 'UTC', 'en',
      '01993ea0-2000-7000-8000-000000000755', NULL, NULL,
      '192.0.2.10'::inet, repeat('x', 1025), 'bootstrap_totp'
    );
    RAISE EXCEPTION 'tenant mutation accepted an oversized audit user agent';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END
$test$;

DO $test$
DECLARE
  switched_session uuid;
  active_tenant uuid;
  active_memberships integer;
  rotation_family uuid;
  session_count_before integer;
  session_count_after integer;
  switch_admitted boolean;
BEGIN
  SELECT admission.admitted INTO switch_admitted
  FROM app.admit_auth_attempts(
    ARRAY['tenant_switch'::public.auth_rate_limit_scope],
    ARRAY[decode(repeat('91', 32), 'hex')],
    ARRAY[60], ARRAY[10], ARRAY[60]
  ) AS admission;
  IF NOT switch_admitted THEN
    RAISE EXCEPTION 'first real tenant switch was not admitted';
  END IF;

  switched_session := app.rotate_auth_session_tenant(
    decode(repeat('f5', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000405',
    decode(repeat('81', 32), 'hex'), decode(repeat('82', 32), 'hex'),
    '01993ea0-2000-7000-8000-000000000701',
    date_trunc('milliseconds', transaction_timestamp()) + interval '15 minutes',
    date_trunc('milliseconds', transaction_timestamp()) + interval '40 minutes',
    '01993ea0-2000-7000-8000-000000000706', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  );
  IF switched_session IS NULL THEN
    RAISE EXCEPTION 'session tenant rotation failed';
  END IF;

  SELECT session.active_tenant_id, session.rotation_family_id
    INTO active_tenant, rotation_family
  FROM app.get_auth_session(decode(repeat('81', 32), 'hex')) AS session;
  IF active_tenant IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000701'::uuid THEN
    RAISE EXCEPTION 'rotated session did not bind the selected tenant';
  END IF;
  IF rotation_family IS DISTINCT FROM '01993ea0-2000-7000-8000-000000000491'::uuid THEN
    RAISE EXCEPTION 'tenant rotation changed the session family';
  END IF;

  SELECT count(*) INTO session_count_before
  FROM app.list_user_sessions(
    '01993ea0-2000-7000-8000-000000000405', NULL, 101
  );
  BEGIN
    PERFORM app.rotate_auth_session_tenant(
      decode(repeat('81', 32), 'hex'),
      '01993ea0-2000-7000-8000-000000000406',
      decode(repeat('83', 32), 'hex'), decode(repeat('84', 32), 'hex'),
      '01993ea0-2000-7000-8000-000000000701',
      date_trunc('milliseconds', transaction_timestamp()) + interval '15 minutes',
      date_trunc('milliseconds', transaction_timestamp()) + interval '35 minutes',
      '01993ea0-2000-7000-8000-000000000709',
      '01993ea0-2000-7000-8000-000000000710',
      '01993ea0-2000-7000-8000-000000000711',
      '192.0.2.10'::inet, 'rls-security-test/1.0'
    );
    RAISE EXCEPTION 'same-tenant rotation created another session';
  EXCEPTION
    WHEN invalid_parameter_value THEN NULL;
  END;
  SELECT count(*) INTO session_count_after
  FROM app.list_user_sessions(
    '01993ea0-2000-7000-8000-000000000405', NULL, 101
  );
  IF session_count_after <> session_count_before THEN
    RAISE EXCEPTION 'same-tenant rotation changed session history';
  END IF;

  SELECT count(*) INTO active_memberships
  FROM app.list_user_tenant_memberships(NULL, 101) AS membership
  WHERE membership.membership_status = 'active';
  IF active_memberships <> 1 THEN
    RAISE EXCEPTION 'bootstrap administrator expected one active membership, saw %', active_memberships;
  END IF;

  IF NOT app.revoke_user_session(
    '01993ea0-2000-7000-8000-000000000422', 'user_logout',
    '01993ea0-2000-7000-8000-000000000707', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) THEN
    RAISE EXCEPTION 'own-session revocation failed';
  END IF;
  IF app.revoke_user_session(
    '01993ea0-2000-7000-8000-000000000422', 'user_logout',
    '01993ea0-2000-7000-8000-000000000708', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) THEN
    RAISE EXCEPTION 'own-session revocation was not one-use';
  END IF;
END
$test$;

-- Removing only the independently protected platform tail head is itself
-- detectable even though all surviving event hashes remain internally valid.
SAVEPOINT platform_audit_head_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DELETE FROM public.platform_audit_chain_head WHERE singleton = true;
RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
DO $test$
DECLARE
  invalid_count integer;
BEGIN
  SELECT count(*) INTO invalid_count
  FROM app.verify_platform_audit_chain()
  WHERE NOT valid;
  IF invalid_count = 0 THEN
    RAISE EXCEPTION 'platform verifier did not detect its missing chain head';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT platform_audit_head_probe;
RELEASE SAVEPOINT platform_audit_head_probe;

-- Session history uses an ownership-bound keyset rather than a hard cap. More
-- than one page of live sessions remains reachable exactly once, the current
-- session appears only at the head of page one, and an older target remains
-- revocable after pagination.
SAVEPOINT session_pagination_probe;
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.auth_sessions (
  id, user_id, rotation_family_id, active_tenant_id, token_digest,
  csrf_secret_digest, authentication_method, mfa_satisfied_at,
  last_seen_at, idle_expires_at, absolute_expires_at, created_at
)
SELECT (
         '01993ea0-4000-7000-8000-' || lpad(to_hex(series.value), 12, '0')
       )::uuid,
       '01993ea0-2000-7000-8000-000000000201'::uuid,
       '01993ea0-4001-7000-8000-000000000001'::uuid,
       NULL,
       decode(lpad(to_hex(100000 + series.value), 64, '0'), 'hex'),
       decode(lpad(to_hex(200000 + series.value), 64, '0'), 'hex'),
       'totp', transaction_timestamp(), transaction_timestamp(),
       date_trunc('milliseconds', transaction_timestamp()) + interval '2 hours',
       date_trunc('milliseconds', transaction_timestamp()) + interval '3 hours', transaction_timestamp()
FROM generate_series(1, 110) AS series(value);

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.user_id', '01993ea0-2000-7000-8000-000000000201', true);
DO $test$
DECLARE
  cursor_id uuid;
  last_id uuid;
  fixture_id uuid;
  session_row record;
  seen_ids uuid[] := ARRAY[]::uuid[];
  page_count integer;
  page_number integer := 0;
  current_count integer := 0;
BEGIN
  LOOP
    page_number := page_number + 1;
    page_count := 0;
    last_id := NULL;
    FOR session_row IN
      SELECT *
      FROM app.list_user_sessions(
        '01993ea0-2000-7000-8000-000000000405', cursor_id, 100
      )
    LOOP
      page_count := page_count + 1;
      IF session_row.session_id = ANY(seen_ids) THEN
        RAISE EXCEPTION 'session keyset returned duplicate %', session_row.session_id;
      END IF;
      IF page_number = 1 AND page_count = 1 AND NOT session_row.current THEN
        RAISE EXCEPTION 'current session was not the first row of page one';
      END IF;
      IF session_row.current THEN
        current_count := current_count + 1;
      END IF;
      seen_ids := array_append(seen_ids, session_row.session_id);
      last_id := session_row.session_id;
    END LOOP;

    EXIT WHEN page_count < 100;
    IF last_id IS NULL OR page_number > 10 THEN
      RAISE EXCEPTION 'session keyset pagination did not make progress';
    END IF;
    cursor_id := last_id;
  END LOOP;

  FOR fixture_number IN 1..110 LOOP
    fixture_id := (
      '01993ea0-4000-7000-8000-' || lpad(to_hex(fixture_number), 12, '0')
    )::uuid;
    IF NOT fixture_id = ANY(seen_ids) THEN
      RAISE EXCEPTION 'live session % was stranded behind the first page', fixture_id;
    END IF;
  END LOOP;
  IF current_count <> 1 OR page_number < 2 THEN
    RAISE EXCEPTION 'session keyset current/page invariant failed: %, %',
      current_count, page_number;
  END IF;

  BEGIN
    PERFORM app.list_user_sessions(
      '01993ea0-2000-7000-8000-000000000405',
      '01993ea0-4fff-7000-8000-000000000001', 100
    );
    RAISE EXCEPTION 'session keyset accepted a missing or foreign cursor';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.list_user_sessions(
      '01993ea0-4fff-7000-8000-000000000002', NULL, 100
    );
    RAISE EXCEPTION 'session keyset accepted a missing current session';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.list_user_sessions(
      '01993ea0-2000-7000-8000-000000000405', NULL, 102
    );
    RAISE EXCEPTION 'session keyset accepted an oversized page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM app.list_user_sessions(
      '01993ea0-2000-7000-8000-000000000405', NULL, NULL
    );
    RAISE EXCEPTION 'session keyset accepted an unbounded NULL page';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;

  IF NOT app.revoke_user_session(
    '01993ea0-4000-7000-8000-000000000001', 'user_logout',
    '01993ea0-4002-7000-8000-000000000001', NULL, NULL,
    '192.0.2.10'::inet, 'rls-security-test/1.0'
  ) THEN
    RAISE EXCEPTION 'paginated live session could not be revoked';
  END IF;
END
$test$;
ROLLBACK TO SAVEPOINT session_pagination_probe;
RELEASE SAVEPOINT session_pagination_probe;

SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000103', true);
DO $test$
BEGIN
  IF app.has_platform_permission('platform.tenant.read')
     OR app.has_platform_permission('platform.tenant.create') THEN
    RAISE EXCEPTION 'ungranted user received platform tenant permissions';
  END IF;

  BEGIN
    PERFORM app.list_platform_tenants(NULL, 100);
    RAISE EXCEPTION 'ungranted user listed platform tenants';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.create_platform_tenant(
      '01993ea0-2000-7000-8000-000000000721',
      '01993ea0-2000-7000-8000-000000000722',
      'forbidden-created', 'Forbidden Tenant', 'UTC', 'en',
      '01993ea0-2000-7000-8000-000000000723', NULL, NULL,
      '192.0.2.10'::inet, 'rls-security-test/1.0', 'totp'
    );
    RAISE EXCEPTION 'ungranted user created a tenant';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Database-backed throttling records all attempts and rate-bounds append-only audit
-- contention to max_attempts+1 events for one privacy-preserving key/window.
SELECT set_config('app.user_id', '', true);
SELECT * FROM app.record_auth_rate_limit_failure(
  ARRAY['local_login'::public.auth_rate_limit_scope],
  ARRAY[decode(repeat('41', 32), 'hex')], ARRAY[60], ARRAY[2], ARRAY[120],
  '01993ea0-2000-7000-8000-000000000811', 'invalid_credentials', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
SELECT * FROM app.record_auth_rate_limit_failure(
  ARRAY['local_login'::public.auth_rate_limit_scope],
  ARRAY[decode(repeat('41', 32), 'hex')], ARRAY[60], ARRAY[2], ARRAY[120],
  '01993ea0-2000-7000-8000-000000000812', 'invalid_credentials', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
SELECT * FROM app.record_auth_rate_limit_failure(
  ARRAY['local_login'::public.auth_rate_limit_scope],
  ARRAY[decode(repeat('41', 32), 'hex')], ARRAY[60], ARRAY[2], ARRAY[120],
  '01993ea0-2000-7000-8000-000000000813', 'blocked_probe', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);
SELECT * FROM app.record_auth_rate_limit_failure(
  ARRAY['local_login'::public.auth_rate_limit_scope],
  ARRAY[decode(repeat('41', 32), 'hex')], ARRAY[60], ARRAY[2], ARRAY[120],
  '01993ea0-2000-7000-8000-000000000814', 'blocked_probe', NULL, NULL,
  '192.0.2.10'::inet, 'rls-security-test/1.0', 'local_password'
);

DO $test$
DECLARE
  attempts integer;
  blocked timestamp with time zone;
BEGIN
  SELECT rate.attempt_count, rate.blocked_until INTO attempts, blocked
  FROM app.get_auth_rate_limit('local_login', decode(repeat('41', 32), 'hex')) AS rate;
  IF attempts <> 4 OR blocked IS NULL THEN
    RAISE EXCEPTION 'rate limit expected four attempts and a block, saw %, %', attempts, blocked;
  END IF;

END
$test$;

-- Runtime cleanup is worker-only, non-starvable across state classes, and
-- prunes retained session chains child-first only after the whole family is dead.
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM app.prune_expired_auth_state(1);
    RAISE EXCEPTION 'API unexpectedly invoked authentication-state cleanup';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM app.clear_auth_rate_limit(
      'local_login', decode(repeat('41', 32), 'hex')
    );
    RAISE EXCEPTION 'API unexpectedly cleared an arbitrary shared rate meter';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.auth_rate_limits (
  id, scope, key_digest, attempt_count, window_started_at,
  window_expires_at, blocked_until, updated_at
)
VALUES
  (
    '01993ea0-2000-7000-8000-000000000901', 'recovery_code',
    decode(repeat('d1', 32), 'hex'), 1,
    transaction_timestamp() - interval '40 days',
    transaction_timestamp() - interval '39 days', NULL,
    transaction_timestamp() - interval '39 days'
  ),
  (
    '01993ea0-2000-7000-8000-000000000902', 'recovery_code',
    decode(repeat('d2', 32), 'hex'), 1,
    transaction_timestamp() - interval '38 days',
    transaction_timestamp() - interval '37 days', NULL,
    transaction_timestamp() - interval '37 days'
  );

INSERT INTO public.auth_challenges (
  id, user_id, challenge_rate_key_digest, mfa_rate_key_digest,
  login_account_rate_key_digest,
  token_digest, purpose, attempts, max_attempts, expires_at,
  consumed_at, last_attempt_at, created_at
)
VALUES
  (
    '01993ea0-2000-7000-8000-000000000903',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('d9', 32), 'hex'), decode(repeat('d3', 32), 'hex'),
    decode(repeat('d4', 32), 'hex'),
    decode(repeat('d5', 32), 'hex'), 'mfa_login', 1, 3,
    transaction_timestamp() - interval '39 days',
    transaction_timestamp() - interval '38 days',
    transaction_timestamp() - interval '38 days',
    transaction_timestamp() - interval '40 days'
  ),
  (
    '01993ea0-2000-7000-8000-000000000904',
    '01993ea0-2000-7000-8000-000000000201',
    decode(repeat('da', 32), 'hex'), decode(repeat('d6', 32), 'hex'),
    decode(repeat('d7', 32), 'hex'),
    decode(repeat('d8', 32), 'hex'), 'mfa_login', 1, 3,
    transaction_timestamp() - interval '37 days',
    transaction_timestamp() - interval '36 days',
    transaction_timestamp() - interval '36 days',
    transaction_timestamp() - interval '38 days'
  );

INSERT INTO public.auth_sessions (
  id, user_id, rotation_family_id, token_digest, csrf_secret_digest,
  authentication_method, mfa_satisfied_at, last_seen_at, idle_expires_at,
  absolute_expires_at, revoked_at, revoke_reason, rotated_from_session_id,
  created_at
)
VALUES
  (
    '01993ea0-2000-7000-8000-000000000911',
    '01993ea0-2000-7000-8000-000000000201',
    '01993ea0-2000-7000-8000-000000000910',
    decode(repeat('e1', 32), 'hex'), decode(repeat('e2', 32), 'hex'),
    'totp', transaction_timestamp() - interval '69 days',
    transaction_timestamp() - interval '69 days',
    transaction_timestamp() - interval '68 days',
    transaction_timestamp() - interval '67 days',
    transaction_timestamp() - interval '66 days', 'retention_test', NULL,
    transaction_timestamp() - interval '70 days'
  ),
  (
    '01993ea0-2000-7000-8000-000000000912',
    '01993ea0-2000-7000-8000-000000000201',
    '01993ea0-2000-7000-8000-000000000910',
    decode(repeat('e3', 32), 'hex'), decode(repeat('e4', 32), 'hex'),
    'totp', transaction_timestamp() - interval '64 days',
    transaction_timestamp() - interval '64 days',
    transaction_timestamp() - interval '63 days',
    transaction_timestamp() - interval '62 days',
    transaction_timestamp() - interval '61 days', 'retention_test',
    '01993ea0-2000-7000-8000-000000000911',
    transaction_timestamp() - interval '65 days'
  ),
  (
    '01993ea0-2000-7000-8000-000000000914',
    '01993ea0-2000-7000-8000-000000000201',
    '01993ea0-2000-7000-8000-000000000913',
    decode(repeat('e5', 32), 'hex'), decode(repeat('e6', 32), 'hex'),
    'totp', transaction_timestamp() - interval '69 days',
    transaction_timestamp() - interval '69 days',
    transaction_timestamp() - interval '68 days',
    transaction_timestamp() - interval '67 days',
    transaction_timestamp() - interval '66 days', 'retention_test', NULL,
    transaction_timestamp() - interval '70 days'
  ),
  (
    '01993ea0-2000-7000-8000-000000000915',
    '01993ea0-2000-7000-8000-000000000201',
    '01993ea0-2000-7000-8000-000000000913',
    decode(repeat('e7', 32), 'hex'), decode(repeat('e8', 32), 'hex'),
    'totp', transaction_timestamp() - interval '1 day',
    transaction_timestamp(),
    date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
    date_trunc('milliseconds', transaction_timestamp()) + interval '2 hours', NULL, NULL,
    '01993ea0-2000-7000-8000-000000000914',
    transaction_timestamp() - interval '1 day'
  );

RESET ROLE;
SET LOCAL ROLE "periapsis_worker";
DO $test$
DECLARE
  pruned record;
BEGIN
  BEGIN
    PERFORM app.prune_expired_auth_state(NULL);
    RAISE EXCEPTION 'worker cleanup accepted an unbounded NULL batch';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  SELECT * INTO pruned FROM app.prune_expired_auth_state(1);
  IF pruned.rate_limits_deleted <> 1
     OR pruned.challenges_deleted <> 1
     OR pruned.sessions_deleted <> 2 THEN
    RAISE EXCEPTION 'per-class cleanup was starved or exceeded its cap: %', pruned;
  END IF;
  BEGIN
    PERFORM count(*) FROM public.auth_rate_limits;
    RAISE EXCEPTION 'worker unexpectedly read protected auth state directly';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  remaining_count integer;
BEGIN
  SELECT count(*) INTO remaining_count
  FROM public.auth_sessions
  WHERE id IN (
    '01993ea0-2000-7000-8000-000000000911',
    '01993ea0-2000-7000-8000-000000000912'
  );
  IF remaining_count <> 0 THEN
    RAISE EXCEPTION 'session cleanup split an expired rotation family';
  END IF;
  SELECT count(*) INTO remaining_count
  FROM public.auth_sessions
  WHERE id IN (
    '01993ea0-2000-7000-8000-000000000914',
    '01993ea0-2000-7000-8000-000000000915'
  );
  IF remaining_count <> 2 THEN
    RAISE EXCEPTION 'cleanup touched a live session family';
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_worker";
DO $test$
DECLARE
  pruned record;
BEGIN
  SELECT * INTO pruned FROM app.prune_expired_auth_state(1);
  IF pruned.rate_limits_deleted <> 1
     OR pruned.challenges_deleted <> 1
     OR pruned.sessions_deleted <> 0 THEN
    RAISE EXCEPTION 'second bounded cleanup did not make fair progress: %', pruned;
  END IF;
END
$test$;

-- On the historical 0032 boundary, readiness compares the exact ordered
-- timestamp-and-hash migration history through v5. Later migrations retire
-- that compatibility edge; its dedicated upgrade tests retain coverage there.
-- The test harness retains its bootstrap superuser for deliberate journal tamper;
-- neither migrator nor any runtime role receives direct journal UPDATE authority.
RESET ROLE;
DO $test$
DECLARE
  current_count bigint;
  current_latest_created_at bigint;
  current_latest_hash text;
  current_fingerprint text;
  current_prefix_fingerprint text;
  predecessor_expected_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  legacy_baseline_count bigint;
  legacy_baseline_latest_created_at bigint;
  legacy_baseline_latest_hash text;
  legacy_baseline_fingerprint text;
  drifted_current_count bigint;
  drifted_current_latest_created_at bigint;
  drifted_current_latest_hash text;
  drifted_current_fingerprint text;
  drifted_predecessor_count bigint;
  drifted_predecessor_latest_created_at bigint;
  drifted_predecessor_latest_hash text;
  drifted_predecessor_fingerprint text;
  truncated_current_count bigint;
  truncated_current_latest_created_at bigint;
  truncated_current_latest_hash text;
  truncated_current_fingerprint text;
  truncated_predecessor_count bigint;
  truncated_predecessor_latest_created_at bigint;
  truncated_predecessor_latest_hash text;
  truncated_predecessor_fingerprint text;
  restored_current_count bigint;
  restored_current_latest_created_at bigint;
  restored_current_latest_hash text;
  restored_current_fingerprint text;
  restored_predecessor_count bigint;
  restored_predecessor_latest_created_at bigint;
  restored_predecessor_latest_hash text;
  restored_predecessor_fingerprint text;
  first_migration_id integer;
  first_migration_hash text;
  first_migration_created_at bigint;
  second_migration_created_at bigint;
  final_migration_id integer;
  final_migration_hash text;
  final_migration_created_at bigint;
  penultimate_migration_hash text;
  penultimate_migration_created_at bigint;
BEGIN
  IF (SELECT count(*) FROM drizzle.__drizzle_migrations) <> 33 THEN
    RETURN;
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO current_count, current_latest_created_at,
         current_latest_hash, current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO predecessor_count, predecessor_latest_created_at,
         predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO legacy_baseline_count, legacy_baseline_latest_created_at,
         legacy_baseline_latest_hash, legacy_baseline_fingerprint
  FROM app.schema_compatibility() AS compatibility;

  current_prefix_fingerprint := regexp_replace(
    current_fingerprint,
    ':[^:]+$',
    ''
  );
  predecessor_expected_fingerprint := regexp_replace(
    current_fingerprint,
    '(:[^:]+){3}$',
    ''
  );

  IF current_count IS DISTINCT FROM 33
     OR current_latest_created_at IS DISTINCT FROM 1787592230466
     OR predecessor_count IS DISTINCT FROM 30
     OR predecessor_latest_created_at IS DISTINCT FROM 1787582150087
     OR predecessor_fingerprint IS DISTINCT FROM predecessor_expected_fingerprint THEN
    RAISE EXCEPTION 'current and sealed predecessor compatibility projections do not match the exact 30 -> 33 edge';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM app.schema_compatibility_v3() AS retired
    WHERE retired.applied_count IS DISTINCT FROM 0
       OR retired.latest_created_at IS DISTINCT FROM 0
       OR retired.latest_hash IS DISTINCT FROM 'UNSUPPORTED'
       OR retired.migration_fingerprint IS DISTINCT FROM 'UNSUPPORTED'
  ) THEN
    RAISE EXCEPTION 'retired v3 compatibility projection did not return its impossible sentinel';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM app.schema_compatibility_v2() AS retired
    WHERE retired.applied_count IS DISTINCT FROM 0
       OR retired.latest_created_at IS DISTINCT FROM 0
       OR retired.latest_hash IS DISTINCT FROM 'UNSUPPORTED'
       OR retired.migration_fingerprint IS DISTINCT FROM 'UNSUPPORTED'
  ) THEN
    RAISE EXCEPTION 'retired v2 compatibility projection did not return its impossible sentinel';
  END IF;

  IF legacy_baseline_count IS DISTINCT FROM 0
     OR legacy_baseline_latest_created_at IS DISTINCT FROM 0
     OR legacy_baseline_latest_hash IS DISTINCT FROM 'UNSUPPORTED'
     OR legacy_baseline_fingerprint IS DISTINCT FROM 'UNSUPPORTED' THEN
    RAISE EXCEPTION 'retired legacy compatibility projection did not return its impossible sentinel';
  END IF;

  SELECT migration.id, migration.hash, migration.created_at
    INTO first_migration_id, first_migration_hash, first_migration_created_at
  FROM drizzle.__drizzle_migrations AS migration
  ORDER BY migration.created_at, migration.id
  LIMIT 1;

  SELECT migration.created_at
    INTO second_migration_created_at
  FROM drizzle.__drizzle_migrations AS migration
  ORDER BY migration.created_at, migration.id
  OFFSET 1
  LIMIT 1;

  IF first_migration_created_at + 1 >= second_migration_created_at THEN
    RAISE EXCEPTION 'timestamp-drift probe would reorder the migration journal';
  END IF;

  UPDATE drizzle.__drizzle_migrations
  SET created_at = first_migration_created_at + 1
  WHERE id = first_migration_id;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO drifted_current_count, drifted_current_latest_created_at,
         drifted_current_latest_hash, drifted_current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO drifted_predecessor_count, drifted_predecessor_latest_created_at,
         drifted_predecessor_latest_hash, drifted_predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  IF drifted_current_count IS DISTINCT FROM current_count
     OR drifted_current_latest_created_at IS DISTINCT FROM current_latest_created_at
     OR drifted_current_latest_hash IS DISTINCT FROM current_latest_hash
     OR drifted_current_fingerprint IS NOT DISTINCT FROM current_fingerprint THEN
    RAISE EXCEPTION 'current readiness accepted an interior migration timestamp drift';
  END IF;

  IF drifted_predecessor_count IS DISTINCT FROM 0
     OR drifted_predecessor_latest_created_at IS DISTINCT FROM 0
     OR drifted_predecessor_latest_hash IS DISTINCT FROM 'UNSUPPORTED'
     OR drifted_predecessor_fingerprint IS DISTINCT FROM 'UNSUPPORTED' THEN
    RAISE EXCEPTION 'sealed predecessor projection accepted an interior timestamp drift';
  END IF;

  BEGIN
    PERFORM app.seal_schema_compatibility_manifest(
      current_count,
      current_latest_created_at,
      current_latest_hash,
      current_fingerprint
    );
    RAISE EXCEPTION 'seal accepted an interior migration timestamp drift';
  EXCEPTION WHEN SQLSTATE '55000' THEN NULL;
  END;

  UPDATE drizzle.__drizzle_migrations
  SET created_at = first_migration_created_at
  WHERE id = first_migration_id;

  PERFORM app.seal_schema_compatibility_manifest(
    current_count,
    current_latest_created_at,
    current_latest_hash,
    current_fingerprint
  );

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO restored_current_count, restored_current_latest_created_at,
         restored_current_latest_hash, restored_current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO restored_predecessor_count, restored_predecessor_latest_created_at,
         restored_predecessor_latest_hash, restored_predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  IF restored_current_count IS DISTINCT FROM current_count
     OR restored_current_latest_created_at IS DISTINCT FROM current_latest_created_at
     OR restored_current_latest_hash IS DISTINCT FROM current_latest_hash
     OR restored_current_fingerprint IS DISTINCT FROM current_fingerprint
     OR restored_predecessor_count IS DISTINCT FROM predecessor_count
     OR restored_predecessor_latest_created_at IS DISTINCT FROM predecessor_latest_created_at
     OR restored_predecessor_latest_hash IS DISTINCT FROM predecessor_latest_hash
     OR restored_predecessor_fingerprint IS DISTINCT FROM predecessor_fingerprint THEN
    RAISE EXCEPTION 'restoring and resealing timestamp drift did not recover exact readiness';
  END IF;

  UPDATE drizzle.__drizzle_migrations
  SET hash = repeat('0', 64)
  WHERE id = first_migration_id;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO drifted_current_count, drifted_current_latest_created_at,
         drifted_current_latest_hash, drifted_current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO drifted_predecessor_count, drifted_predecessor_latest_created_at,
         drifted_predecessor_latest_hash, drifted_predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  UPDATE drizzle.__drizzle_migrations
  SET hash = first_migration_hash
  WHERE id = first_migration_id;

  IF drifted_current_count IS DISTINCT FROM current_count
     OR drifted_current_latest_created_at IS DISTINCT FROM current_latest_created_at
     OR drifted_current_latest_hash IS DISTINCT FROM current_latest_hash
     OR drifted_current_fingerprint IS NOT DISTINCT FROM current_fingerprint THEN
    RAISE EXCEPTION 'ordered migration fingerprint did not isolate earlier-history drift';
  END IF;

  IF drifted_predecessor_count IS DISTINCT FROM 0
     OR drifted_predecessor_latest_created_at IS DISTINCT FROM 0
     OR drifted_predecessor_latest_hash IS DISTINCT FROM 'UNSUPPORTED'
     OR drifted_predecessor_fingerprint IS DISTINCT FROM 'UNSUPPORTED' THEN
    RAISE EXCEPTION 'sealed predecessor projection accepted an earlier-history drift';
  END IF;

  SELECT migration.id, migration.hash, migration.created_at
    INTO final_migration_id, final_migration_hash, final_migration_created_at
  FROM drizzle.__drizzle_migrations AS migration
  ORDER BY migration.created_at DESC, migration.id DESC
  LIMIT 1;

  IF final_migration_created_at IS DISTINCT FROM current_latest_created_at
     OR final_migration_hash IS DISTINCT FROM current_latest_hash THEN
    RAISE EXCEPTION 'current compatibility projection does not identify the final journal row';
  END IF;

  SELECT migration.hash, migration.created_at
    INTO penultimate_migration_hash, penultimate_migration_created_at
  FROM drizzle.__drizzle_migrations AS migration
  ORDER BY migration.created_at DESC, migration.id DESC
  OFFSET 1
  LIMIT 1;

  DELETE FROM drizzle.__drizzle_migrations
  WHERE id = final_migration_id;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO truncated_current_count, truncated_current_latest_created_at,
         truncated_current_latest_hash, truncated_current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO truncated_predecessor_count, truncated_predecessor_latest_created_at,
         truncated_predecessor_latest_hash, truncated_predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  IF truncated_current_count IS DISTINCT FROM current_count - 1
     OR truncated_current_latest_created_at IS DISTINCT FROM penultimate_migration_created_at
     OR truncated_current_latest_hash IS DISTINCT FROM penultimate_migration_hash
     OR truncated_current_fingerprint IS DISTINCT FROM current_prefix_fingerprint
     OR truncated_current_fingerprint IS NOT DISTINCT FROM current_fingerprint THEN
    RAISE EXCEPTION 'v5 did not expose the exact incomplete journal after deleting 0032';
  END IF;

  IF truncated_predecessor_count IS DISTINCT FROM 0
     OR truncated_predecessor_latest_created_at IS DISTINCT FROM 0
     OR truncated_predecessor_latest_hash IS DISTINCT FROM 'UNSUPPORTED'
     OR truncated_predecessor_fingerprint IS DISTINCT FROM 'UNSUPPORTED' THEN
    RAISE EXCEPTION 'sealed v4 exposed a released prefix after deleting 0032';
  END IF;

  BEGIN
    PERFORM app.seal_schema_compatibility_manifest(
      current_count,
      current_latest_created_at,
      current_latest_hash,
      current_fingerprint
    );
    RAISE EXCEPTION 'seal accepted a journal with 0032 deleted';
  EXCEPTION WHEN SQLSTATE '55000' THEN NULL;
  END;

  INSERT INTO drizzle.__drizzle_migrations (id, hash, created_at)
  VALUES (final_migration_id, final_migration_hash, final_migration_created_at);

  PERFORM app.seal_schema_compatibility_manifest(
    current_count,
    current_latest_created_at,
    current_latest_hash,
    current_fingerprint
  );

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO restored_current_count, restored_current_latest_created_at,
         restored_current_latest_hash, restored_current_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
    INTO restored_predecessor_count, restored_predecessor_latest_created_at,
         restored_predecessor_latest_hash, restored_predecessor_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  IF restored_current_count IS DISTINCT FROM current_count
     OR restored_current_latest_created_at IS DISTINCT FROM current_latest_created_at
     OR restored_current_latest_hash IS DISTINCT FROM current_latest_hash
     OR restored_current_fingerprint IS DISTINCT FROM current_fingerprint
     OR restored_predecessor_count IS DISTINCT FROM predecessor_count
     OR restored_predecessor_latest_created_at IS DISTINCT FROM predecessor_latest_created_at
     OR restored_predecessor_latest_hash IS DISTINCT FROM predecessor_latest_hash
     OR restored_predecessor_fingerprint IS DISTINCT FROM predecessor_fingerprint THEN
    RAISE EXCEPTION 'restoring and resealing 0032 did not recover exact readiness';
  END IF;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
DO $test$
BEGIN
  BEGIN
    PERFORM count(*) FROM drizzle.__drizzle_migrations;
    RAISE EXCEPTION 'API unexpectedly read the migration journal directly';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Platform audit is globally append-only, independently chained, and directly readable
-- only by the auditor database role. Sequence allocation is contiguous despite all
-- callers supplying placeholder sequence values.
RESET ROLE;
SET LOCAL ROLE "periapsis_auditor";
DO $test$
DECLARE
  invalid_count integer;
  failure_events integer;
  sequence_gaps integer;
  missing_context_count integer;
  sensitive_metadata_count integer;
  challenge_events integer;
  tenant_switch_events integer;
  logout_events integer;
  attributed_password_failures integer;
BEGIN
  BEGIN
    PERFORM app.read_platform_audit_events(0, NULL);
    RAISE EXCEPTION 'auditor unexpectedly received an unbounded function page';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  SELECT count(*) INTO invalid_count
  FROM app.verify_platform_audit_chain()
  WHERE NOT valid;
  IF invalid_count <> 0 THEN
    RAISE EXCEPTION 'platform audit chain contains % invalid rows', invalid_count;
  END IF;

  SELECT count(*) INTO sequence_gaps
  FROM (
    SELECT event.sequence,
           row_number() OVER (ORDER BY event.sequence) AS expected_sequence
    FROM public.platform_audit_events AS event
  ) AS ordered
  WHERE ordered.sequence <> ordered.expected_sequence;
  IF sequence_gaps <> 0 THEN
    RAISE EXCEPTION 'platform audit sequence contains % gaps', sequence_gaps;
  END IF;

  SELECT count(*) INTO failure_events
  FROM public.platform_audit_events
  WHERE action = 'authentication.failure';
  IF failure_events <> 7 THEN
    RAISE EXCEPTION 'auth audit expected 7 one-per-failure events, saw %', failure_events;
  END IF;

  SELECT count(*) INTO missing_context_count
  FROM public.platform_audit_events
  WHERE ip_address IS NULL
     OR user_agent IS NULL
     OR authentication_method IS NULL;
  IF missing_context_count <> 0 THEN
    RAISE EXCEPTION 'platform audit omitted bounded request context on % events', missing_context_count;
  END IF;

  SELECT count(*) INTO sensitive_metadata_count
  FROM public.platform_audit_events AS event
  WHERE event.metadata ?| ARRAY[
    'password', 'password_phc', 'token', 'token_digest', 'csrf_token',
    'totp_secret', 'recovery_code', 'assertion', 'email'
  ];
  IF sensitive_metadata_count <> 0 THEN
    RAISE EXCEPTION 'platform audit metadata retained sensitive authentication fields';
  END IF;

  SELECT count(*) INTO challenge_events
  FROM public.platform_audit_events
  WHERE action = 'authentication.mfa_challenge.created';
  SELECT count(*) INTO tenant_switch_events
  FROM public.platform_audit_events
  WHERE action = 'authentication.session.tenant_switched';
  SELECT count(*) INTO logout_events
  FROM public.platform_audit_events
  WHERE action = 'authentication.logout.succeeded';
  SELECT count(*) INTO attributed_password_failures
  FROM public.platform_audit_events
  WHERE action = 'authentication.failure'
    AND resource_type = 'user'
    AND resource_id = '01993ea0-2000-7000-8000-000000000201';
  IF challenge_events <> 4 OR tenant_switch_events <> 1
     OR logout_events <> 1 OR attributed_password_failures <> 1 THEN
    RAISE EXCEPTION 'platform audit action/attribution counts drifted: %, %, %, %',
      challenge_events, tenant_switch_events, logout_events,
      attributed_password_failures;
  END IF;

  BEGIN
    UPDATE public.platform_audit_events SET reason = 'tamper';
    RAISE EXCEPTION 'auditor mutated platform audit';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
BEGIN
  BEGIN
    DELETE FROM public.platform_audit_events;
    RAISE EXCEPTION 'platform audit append-only trigger did not fire';
  EXCEPTION
    WHEN object_not_in_prerequisite_state THEN NULL;
  END;
END
$test$;

-- Phase 2B.1 tenant authorization is exercised through the same definer-only
-- surface used by the API. The fixtures deliberately include isolated
-- role.read, role.manage, and role.grant actors plus a second tenant.
INSERT INTO public.tenants (id, slug, name)
VALUES
  ('01993ea0-4000-7000-8000-000000000001', 'rbac-acme', 'RBAC Acme'),
  ('01993ea0-4000-7000-8000-000000000002', 'rbac-globex', 'RBAC Globex');

INSERT INTO public.audit_chain_heads (tenant_id)
VALUES
  ('01993ea0-4000-7000-8000-000000000001'),
  ('01993ea0-4000-7000-8000-000000000002');

INSERT INTO public.users (id, email, display_name)
VALUES
  ('01993ea0-4000-7000-8000-000000000101', 'rbac.admin.acme@example.invalid', 'RBAC Acme Admin'),
  ('01993ea0-4000-7000-8000-000000000102', 'rbac.target.acme@example.invalid', 'RBAC Acme Target'),
  ('01993ea0-4000-7000-8000-000000000103', 'rbac.invited.acme@example.invalid', 'RBAC Acme Invitee'),
  ('01993ea0-4000-7000-8000-000000000104', 'rbac.reader.acme@example.invalid', 'RBAC Acme Reader'),
  ('01993ea0-4000-7000-8000-000000000105', 'rbac.manager.acme@example.invalid', 'RBAC Acme Manager'),
  ('01993ea0-4000-7000-8000-000000000106', 'rbac.grantor.acme@example.invalid', 'RBAC Acme Grantor'),
  ('01993ea0-4000-7000-8000-000000000107', 'rbac.none.acme@example.invalid', 'RBAC Acme No Permission'),
  ('01993ea0-4000-7000-8000-000000000108', 'rbac.admin.globex@example.invalid', 'RBAC Globex Admin'),
  ('01993ea0-4000-7000-8000-000000000109', 'rbac.target.globex@example.invalid', 'RBAC Globex Target');

INSERT INTO public.tenant_memberships (
  id, tenant_id, user_id, role, status
)
VALUES
  ('01993ea0-4000-7000-8000-000000000201', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000101', 'tenant_admin', 'active'),
  ('01993ea0-4000-7000-8000-000000000202', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000102', 'analyst', 'active'),
  ('01993ea0-4000-7000-8000-000000000203', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000103', 'customer_user', 'invited'),
  ('01993ea0-4000-7000-8000-000000000204', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000104', 'analyst', 'active'),
  ('01993ea0-4000-7000-8000-000000000205', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000105', 'analyst', 'active'),
  ('01993ea0-4000-7000-8000-000000000206', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000106', 'analyst', 'active'),
  ('01993ea0-4000-7000-8000-000000000207', '01993ea0-4000-7000-8000-000000000001', '01993ea0-4000-7000-8000-000000000107', 'analyst', 'active'),
  ('01993ea0-4000-7000-8000-000000000208', '01993ea0-4000-7000-8000-000000000002', '01993ea0-4000-7000-8000-000000000108', 'tenant_admin', 'active'),
  ('01993ea0-4000-7000-8000-000000000209', '01993ea0-4000-7000-8000-000000000002', '01993ea0-4000-7000-8000-000000000109', 'analyst', 'active');

SELECT app.seed_tenant_authorization(
  '01993ea0-4000-7000-8000-000000000001',
  '01993ea0-4000-7000-8000-000000000201'
);
SELECT app.seed_tenant_authorization(
  '01993ea0-4000-7000-8000-000000000002',
  '01993ea0-4000-7000-8000-000000000208'
);

-- A known tenant-creation grant proves that persisted direct paths remain
-- visible in direct-grant inventory independently of source ownership.
INSERT INTO public.tenant_membership_role_grants (
  id, tenant_id, membership_id, role_id, source_id,
  granted_by_membership_id, grant_reason
)
SELECT
  '01993ea0-4000-7000-8000-000000000405',
  '01993ea0-4000-7000-8000-000000000001',
  '01993ea0-4000-7000-8000-000000000202',
  role.id,
  source.id,
  '01993ea0-4000-7000-8000-000000000201',
  'Tenant-creation provenance visibility proof.'
FROM public.tenant_roles AS role
JOIN public.tenant_authorization_sources AS source
  ON source.tenant_id = role.tenant_id
 AND source.key = 'tenant_creation'
WHERE role.tenant_id = '01993ea0-4000-7000-8000-000000000001'
  AND role.key = 'analyst';

RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-4000-7000-8000-000000000001', true);
SELECT set_config('app.user_id', '01993ea0-4000-7000-8000-000000000101', true);

DO $test$
DECLARE
  context_row record;
  first_role record;
  replay_role record;
  first_grant record;
  replay_grant record;
  admin_role_id uuid;
  analyst_role_id uuid;
  count_rows integer;
  next_version integer;
BEGIN
  SELECT * INTO STRICT context_row
  FROM app.get_current_tenant_authorization_context();
  IF context_row.tenant_id <> '01993ea0-4000-7000-8000-000000000001'
     OR context_row.membership_id <> '01993ea0-4000-7000-8000-000000000201'
     OR context_row.membership_status <> 'active'
     OR context_row.compatibility_role <> 'tenant_admin'
     OR context_row.authorization_revision <= 0
     OR context_row.evaluated_at IS NULL THEN
    RAISE EXCEPTION 'tenant authorization context projection drifted';
  END IF;

  SELECT count(*) INTO count_rows
  FROM app.list_tenant_permission_catalog(NULL, 100) AS permission
  WHERE permission.display_name <> ''
    AND permission.allowed_scopes = ARRAY['tenant']::public.authorization_scope[]
    AND permission.principal_kinds = ARRAY['human']::text[]
    AND permission.permission_key = ANY (ARRAY[
      'permission.read', 'role.read', 'role.manage', 'role.grant',
      'user.read', 'membership.manage', 'group.read', 'group.manage',
      'group.membership.manage'
    ]::text[]);
  IF count_rows <> 9 THEN
    RAISE EXCEPTION 'permission catalog omitted a baseline named tenant/human permission, saw %', count_rows;
  END IF;

  SELECT count(*) INTO count_rows
  FROM app.list_tenant_roles(NULL, false, 20);
  IF count_rows <> 8 THEN
    RAISE EXCEPTION 'built-in role list expected 8 rows, saw %', count_rows;
  END IF;

  SELECT role_id INTO STRICT admin_role_id
  FROM app.list_tenant_roles(NULL, false, 20)
  WHERE role_key = 'tenant_admin';
  SELECT role_id INTO STRICT analyst_role_id
  FROM app.list_tenant_roles(NULL, false, 20)
  WHERE role_key = 'analyst';

  SELECT count(*) INTO count_rows
  FROM app.get_tenant_role_policy(admin_role_id, 501)
  WHERE scope = 'tenant' AND delegable
    AND permission_key = ANY (ARRAY[
      'permission.read', 'role.read', 'role.manage', 'role.grant',
      'user.read', 'membership.manage', 'group.read', 'group.manage',
      'group.membership.manage'
    ]::text[]);
  IF count_rows <> 9 THEN
    RAISE EXCEPTION 'tenant_admin omitted a baseline delegable tuple, saw %', count_rows;
  END IF;
  SELECT count(*) INTO count_rows
  FROM app.get_tenant_role_policy(analyst_role_id, 20)
  WHERE permission_key = 'settings.read'
    AND scope = 'tenant'
    AND NOT delegable;
  IF count_rows <> 1 OR (
    SELECT count(*) FROM app.get_tenant_role_policy(analyst_role_id, 20)
  ) <> 1 THEN
    RAISE EXCEPTION 'analyst built-in role omitted or exceeded its settings.read baseline';
  END IF;

  SELECT count(*) INTO count_rows
  FROM app.list_tenant_users(NULL, 20)
  WHERE membership_status = 'invited';
  IF count_rows <> 1 THEN
    RAISE EXCEPTION 'tenant user list did not retain the invited member';
  END IF;

  SELECT * INTO STRICT context_row
  FROM app.list_tenant_membership_role_grants_v2(
    '01993ea0-4000-7000-8000-000000000101', NULL, true, 20
  );
  IF context_row.membership_id <> '01993ea0-4000-7000-8000-000000000201'
     OR context_row.role_key <> 'tenant_admin'
     OR context_row.source_kind <> 'tenant_creation'
     OR context_row.source_authoritative IS DISTINCT FROM false
     OR context_row.source_retired_at IS NOT NULL
     OR context_row.source_type <> 'system'
     OR context_row.grant_state <> 'active'
     OR context_row.version <> 1 THEN
    RAISE EXCEPTION 'tenant creator direct-grant provenance projection drifted';
  END IF;

  SELECT * INTO STRICT context_row
  FROM app.get_tenant_membership_role_grant_v2(
    '01993ea0-4000-7000-8000-000000000405'
  );
  IF context_row.membership_id <> '01993ea0-4000-7000-8000-000000000202'
     OR context_row.target_user_id <> '01993ea0-4000-7000-8000-000000000102'
     OR context_row.role_key <> 'analyst'
     OR context_row.source_kind <> 'tenant_creation'
     OR context_row.source_authoritative IS DISTINCT FROM false
     OR context_row.source_retired_at IS NOT NULL
     OR context_row.source_type <> 'system'
     OR context_row.grant_state <> 'active'
     OR context_row.version <> 1 THEN
    RAISE EXCEPTION 'tenant-creation direct-grant getter provenance projection drifted';
  END IF;

  BEGIN
    PERFORM app.revoke_tenant_user_role_grant(
      '01993ea0-4000-7000-8000-000000000405', 1,
      'Source-owned grants cannot be manually revoked.',
      '01993ea0-4000-7000-8000-000000000523',
      '01993ea0-4000-7000-8000-000000000623',
      '01993ea0-4000-7000-8000-000000000723',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'tenant-creation grant was manually revoked';
  EXCEPTION WHEN no_data_found THEN NULL;
  END;

  SELECT * INTO STRICT first_role
  FROM app.create_tenant_role(
    '01993ea0-4000-7000-8000-000000000301',
    sha256(convert_to('rbac-reader-role', 'UTF8')),
    'rbac_reader', 'RBAC reader', 'Read-only proof role.',
    ARRAY['role.read'], ARRAY['tenant']::public.authorization_scope[],
    ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
    '01993ea0-4000-7000-8000-000000000501',
    '01993ea0-4000-7000-8000-000000000601',
    '01993ea0-4000-7000-8000-000000000701',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  SELECT * INTO STRICT replay_role
  FROM app.create_tenant_role(
    '01993ea0-4000-7000-8000-000000000399',
    sha256(convert_to('rbac-reader-role', 'UTF8')),
    'rbac_reader', 'RBAC reader', 'Read-only proof role.',
    ARRAY['role.read'], ARRAY['tenant']::public.authorization_scope[],
    ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
    '01993ea0-4000-7000-8000-000000000509',
    '01993ea0-4000-7000-8000-000000000601',
    '01993ea0-4000-7000-8000-000000000701',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  IF first_role.result_resource_id <> '01993ea0-4000-7000-8000-000000000301'
     OR first_role.result_version <> 1 OR first_role.replayed
     OR replay_role.result_resource_id <> first_role.result_resource_id
     OR replay_role.result_version <> first_role.result_version
     OR NOT replay_role.replayed THEN
    RAISE EXCEPTION 'role idempotency replay result drifted';
  END IF;

  BEGIN
    PERFORM * FROM app.create_tenant_role(
      '01993ea0-4000-7000-8000-000000000398',
      sha256(convert_to('rbac-reader-role', 'UTF8')),
      'rbac_reader_changed', 'Changed', '',
      ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
      ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
      '01993ea0-4000-7000-8000-000000000508',
      '01993ea0-4000-7000-8000-000000000601',
      '01993ea0-4000-7000-8000-000000000701',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'idempotency key accepted a different role request';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;

  PERFORM * FROM app.create_tenant_role(
    '01993ea0-4000-7000-8000-000000000302',
    sha256(convert_to('rbac-manager-role', 'UTF8')),
    'rbac_manager', 'RBAC manager', 'Manage-only proof role.',
    ARRAY['role.manage'], ARRAY['tenant']::public.authorization_scope[],
    ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
    '01993ea0-4000-7000-8000-000000000502',
    '01993ea0-4000-7000-8000-000000000602',
    '01993ea0-4000-7000-8000-000000000702',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  PERFORM * FROM app.create_tenant_role(
    '01993ea0-4000-7000-8000-000000000303',
    sha256(convert_to('rbac-grantor-role', 'UTF8')),
    'rbac_grantor', 'RBAC grantor', 'Grant-only exact ceiling proof role.',
    ARRAY['role.grant'], ARRAY['tenant']::public.authorization_scope[],
    ARRAY['role.grant'], ARRAY['tenant']::public.authorization_scope[],
    '01993ea0-4000-7000-8000-000000000503',
    '01993ea0-4000-7000-8000-000000000603',
    '01993ea0-4000-7000-8000-000000000703',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );

  SELECT * INTO STRICT first_grant
  FROM app.grant_tenant_user_role(
    '01993ea0-4000-7000-8000-000000000401',
    sha256(convert_to('rbac-reader-grant', 'UTF8')),
    '01993ea0-4000-7000-8000-000000000104',
    '01993ea0-4000-7000-8000-000000000301',
    'Reader matrix proof.', NULL,
    '01993ea0-4000-7000-8000-000000000511',
    '01993ea0-4000-7000-8000-000000000611',
    '01993ea0-4000-7000-8000-000000000711',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  SELECT * INTO STRICT replay_grant
  FROM app.grant_tenant_user_role(
    '01993ea0-4000-7000-8000-000000000499',
    sha256(convert_to('rbac-reader-grant', 'UTF8')),
    '01993ea0-4000-7000-8000-000000000104',
    '01993ea0-4000-7000-8000-000000000301',
    'Reader matrix proof.', NULL,
    '01993ea0-4000-7000-8000-000000000519',
    '01993ea0-4000-7000-8000-000000000611',
    '01993ea0-4000-7000-8000-000000000711',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  IF first_grant.result_resource_id <> '01993ea0-4000-7000-8000-000000000401'
     OR first_grant.result_version <> 1 OR first_grant.replayed
     OR replay_grant.result_resource_id <> first_grant.result_resource_id
     OR replay_grant.result_version <> first_grant.result_version
     OR NOT replay_grant.replayed THEN
    RAISE EXCEPTION 'direct role grant idempotency replay result drifted';
  END IF;

  PERFORM * FROM app.grant_tenant_user_role(
    '01993ea0-4000-7000-8000-000000000402',
    sha256(convert_to('rbac-manager-grant', 'UTF8')),
    '01993ea0-4000-7000-8000-000000000105',
    '01993ea0-4000-7000-8000-000000000302',
    'Manager matrix proof.', NULL,
    '01993ea0-4000-7000-8000-000000000512',
    '01993ea0-4000-7000-8000-000000000612',
    '01993ea0-4000-7000-8000-000000000712',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  PERFORM * FROM app.grant_tenant_user_role(
    '01993ea0-4000-7000-8000-000000000403',
    sha256(convert_to('rbac-grantor-grant', 'UTF8')),
    '01993ea0-4000-7000-8000-000000000106',
    '01993ea0-4000-7000-8000-000000000303',
    'Grantor matrix proof.', NULL,
    '01993ea0-4000-7000-8000-000000000513',
    '01993ea0-4000-7000-8000-000000000613',
    '01993ea0-4000-7000-8000-000000000713',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  PERFORM * FROM app.grant_tenant_user_role(
    '01993ea0-4000-7000-8000-000000000404',
    sha256(convert_to('rbac-target-grant', 'UTF8')),
    '01993ea0-4000-7000-8000-000000000102', analyst_role_id,
    'Direct projection proof.', NULL,
    '01993ea0-4000-7000-8000-000000000514',
    '01993ea0-4000-7000-8000-000000000614',
    '01993ea0-4000-7000-8000-000000000714',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );

  SELECT count(*) INTO count_rows
  FROM app.list_tenant_membership_role_grants_v2(
    '01993ea0-4000-7000-8000-000000000102', NULL, false, 20
  )
  WHERE source_type = 'direct' AND grant_id = '01993ea0-4000-7000-8000-000000000404';
  IF count_rows <> 1 THEN
    RAISE EXCEPTION 'direct-grant list did not isolate the manual grant';
  END IF;

  BEGIN
    PERFORM * FROM app.list_tenant_membership_role_grants_v2(
      '01993ea0-4000-7000-8000-000000000109', NULL, false, 20
    );
    RAISE EXCEPTION 'cross-tenant user grant list did not fail closed';
  EXCEPTION WHEN no_data_found THEN NULL;
  END;

  PERFORM * FROM app.create_tenant_role(
    '01993ea0-4000-7000-8000-000000000304',
    sha256(convert_to('rbac-archivable-role', 'UTF8')),
    'rbac_archivable', 'RBAC archivable', 'State conflict proof role.',
    ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
    ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
    '01993ea0-4000-7000-8000-000000000515',
    '01993ea0-4000-7000-8000-000000000615',
    '01993ea0-4000-7000-8000-000000000715',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  );
  BEGIN
    PERFORM app.update_tenant_role_metadata(
      '01993ea0-4000-7000-8000-000000000304', NULL,
      'NULL version bypassed metadata guard', NULL,
      '01993ea0-4000-7000-8000-000000000521',
      '01993ea0-4000-7000-8000-000000000621',
      '01993ea0-4000-7000-8000-000000000721',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'NULL role metadata version bypassed optimistic locking';
  EXCEPTION WHEN serialization_failure THEN NULL;
  END;
  SELECT count(*) INTO count_rows
  FROM app.get_tenant_role('01993ea0-4000-7000-8000-000000000304')
  WHERE display_name = 'RBAC archivable'
    AND description = 'State conflict proof role.'
    AND version = 1
    AND archived_at IS NULL;
  IF count_rows <> 1 THEN
    RAISE EXCEPTION 'NULL role metadata version changed the targeted role';
  END IF;

  SELECT app.archive_tenant_role(
    '01993ea0-4000-7000-8000-000000000304', 1,
    '01993ea0-4000-7000-8000-000000000516',
    '01993ea0-4000-7000-8000-000000000616',
    '01993ea0-4000-7000-8000-000000000716',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  ) INTO next_version;
  IF next_version <> 2 THEN
    RAISE EXCEPTION 'role archive did not advance its strong version';
  END IF;
  BEGIN
    PERFORM app.archive_tenant_role(
      '01993ea0-4000-7000-8000-000000000304', 1,
      '01993ea0-4000-7000-8000-000000000518',
      '01993ea0-4000-7000-8000-000000000618',
      '01993ea0-4000-7000-8000-000000000718',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'archived role ignored stale If-Match precedence';
  EXCEPTION WHEN serialization_failure THEN NULL;
  END;
  BEGIN
    PERFORM app.archive_tenant_role(
      '01993ea0-4000-7000-8000-000000000304', 2,
      '01993ea0-4000-7000-8000-000000000518',
      '01993ea0-4000-7000-8000-000000000618',
      '01993ea0-4000-7000-8000-000000000718',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'already-archived role did not report a state conflict';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;
  END;

  BEGIN
    PERFORM app.revoke_tenant_user_role_grant(
      '01993ea0-4000-7000-8000-000000000404', NULL,
      'NULL version direct grant revocation proof.',
      '01993ea0-4000-7000-8000-000000000522',
      '01993ea0-4000-7000-8000-000000000622',
      '01993ea0-4000-7000-8000-000000000722',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'NULL direct-grant version bypassed optimistic locking';
  EXCEPTION WHEN serialization_failure THEN NULL;
  END;
  SELECT count(*) INTO count_rows
  FROM app.get_tenant_membership_role_grant_v2(
    '01993ea0-4000-7000-8000-000000000404'
  )
  WHERE version = 1
    AND grant_state = 'active'
    AND revoked_at IS NULL
    AND revoked_by_membership_id IS NULL
    AND revoked_by_user_id IS NULL
    AND revoke_reason IS NULL;
  IF count_rows <> 1 THEN
    RAISE EXCEPTION 'NULL direct-grant version changed the targeted grant';
  END IF;

  SELECT app.revoke_tenant_user_role_grant(
    '01993ea0-4000-7000-8000-000000000404', 1,
    'Direct grant revocation proof.',
    '01993ea0-4000-7000-8000-000000000517',
    '01993ea0-4000-7000-8000-000000000617',
    '01993ea0-4000-7000-8000-000000000717',
    '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
  ) INTO next_version;
  IF next_version <> 2 THEN
    RAISE EXCEPTION 'role-grant revocation did not advance its strong version';
  END IF;
  BEGIN
    PERFORM app.revoke_tenant_user_role_grant(
      '01993ea0-4000-7000-8000-000000000404', 1, 'Stale proof.',
      '01993ea0-4000-7000-8000-000000000520',
      '01993ea0-4000-7000-8000-000000000620',
      '01993ea0-4000-7000-8000-000000000720',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'revoked grant ignored stale If-Match precedence';
  EXCEPTION WHEN serialization_failure THEN NULL;
  END;
  BEGIN
    PERFORM app.revoke_tenant_user_role_grant(
      '01993ea0-4000-7000-8000-000000000404', 2, 'Duplicate proof.',
      '01993ea0-4000-7000-8000-000000000520',
      '01993ea0-4000-7000-8000-000000000620',
      '01993ea0-4000-7000-8000-000000000720',
      '192.0.2.40', 'Periapsis RBAC security proof', 'totp'
    );
    RAISE EXCEPTION 'already-revoked grant did not report a state conflict';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;
  END;

  BEGIN
    PERFORM count(*) FROM public.tenant_roles;
    RAISE EXCEPTION 'API directly read protected tenant role rows';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE public.tenant_authorization_commands SET result_version = 2;
    RAISE EXCEPTION 'API directly mutated authorization command rows';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM count(*) FROM public.tenant_security_groups;
    RAISE EXCEPTION 'API directly read protected tenant security group rows';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM count(*) FROM public.tenant_security_group_memberships;
    RAISE EXCEPTION 'API directly read protected tenant security group membership rows';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE public.tenant_security_group_role_grants SET version = version;
    RAISE EXCEPTION 'API directly mutated protected tenant security group role grants';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- Isolated getter authorization: each exact getter supports the permission
-- needed by its use case, while role lists remain role.read-only.
SELECT set_config('app.user_id', '01993ea0-4000-7000-8000-000000000104', true);
DO $test$
DECLARE
  admin_role_id uuid;
BEGIN
  SELECT role_id INTO STRICT admin_role_id
  FROM app.list_tenant_roles(NULL, false, 20)
  WHERE role_key = 'tenant_admin';
  PERFORM * FROM app.get_tenant_role(admin_role_id);
  PERFORM * FROM app.get_tenant_role_policy(admin_role_id, 20);
END
$test$;

SELECT set_config('app.user_id', '01993ea0-4000-7000-8000-000000000105', true);
DO $test$
BEGIN
  PERFORM * FROM app.get_tenant_role('01993ea0-4000-7000-8000-000000000301');
  PERFORM * FROM app.get_tenant_role_policy('01993ea0-4000-7000-8000-000000000301', 20);
  BEGIN
    PERFORM * FROM app.list_tenant_roles(NULL, false, 20);
    RAISE EXCEPTION 'role.manage-only actor listed tenant roles';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

SELECT set_config('app.user_id', '01993ea0-4000-7000-8000-000000000106', true);
DO $test$
BEGIN
  PERFORM * FROM app.get_tenant_role('01993ea0-4000-7000-8000-000000000301');
  PERFORM * FROM app.get_tenant_role_policy('01993ea0-4000-7000-8000-000000000301', 20);
  BEGIN
    PERFORM * FROM app.list_tenant_roles(NULL, false, 20);
    RAISE EXCEPTION 'role.grant-only actor listed tenant roles';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

SELECT set_config('app.user_id', '01993ea0-4000-7000-8000-000000000107', true);
DO $test$
BEGIN
  BEGIN
    PERFORM * FROM app.get_tenant_role('01993ea0-4000-7000-8000-000000000301');
    RAISE EXCEPTION 'permissionless actor read exact tenant role metadata';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM * FROM app.get_tenant_role_policy('01993ea0-4000-7000-8000-000000000301', 20);
    RAISE EXCEPTION 'permissionless actor read exact tenant role policy';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

-- A tenant inserted after migrations has no authorization state and therefore
-- fails closed; compatibility role text does not grant authority.
RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
INSERT INTO public.tenants (id, slug, name)
VALUES (
  '01993ea0-1000-7000-8000-000000000003',
  'uninitialized-legacy',
  'Uninitialized Legacy Tenant'
);
INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
VALUES (
  '01993ea0-1000-7000-8000-000000000303',
  '01993ea0-1000-7000-8000-000000000003',
  '01993ea0-1000-7000-8000-000000000101',
  'tenant_admin',
  'active'
);
RESET ROLE;
SET LOCAL ROLE "periapsis_api";
SELECT set_config('app.tenant_id', '01993ea0-1000-7000-8000-000000000003', true);
SELECT set_config('app.user_id', '01993ea0-1000-7000-8000-000000000101', true);
DO $test$
BEGIN
  BEGIN
    PERFORM * FROM app.get_current_tenant_authorization_context();
    RAISE EXCEPTION 'uninitialized legacy tenant received authority';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$test$;

RESET ROLE;
SET LOCAL ROLE "periapsis_migrator";
DO $test$
DECLARE
  audit_count integer;
BEGIN
  SELECT count(*) INTO audit_count
  FROM public.audit_events AS event
  WHERE event.id IN (
    '01993ea0-4000-7000-8000-000000000521',
    '01993ea0-4000-7000-8000-000000000522',
    '01993ea0-4000-7000-8000-000000000523'
  );
  IF audit_count <> 0 THEN
    RAISE EXCEPTION 'rejected authorization mutation probes persisted audit events';
  END IF;

  SELECT count(*) INTO audit_count
  FROM public.audit_events AS event
  WHERE event.tenant_id = '01993ea0-4000-7000-8000-000000000001'
    AND event.action IN (
      'tenant.role.created', 'tenant.role_grant.created',
      'tenant.role.archived', 'tenant.role_grant.revoked'
    )
    AND event.ip_address = '192.0.2.40'::inet
    AND event.user_agent = 'Periapsis RBAC security proof'
    AND event.authentication_method = 'totp';
  IF audit_count <> 10 THEN
    RAISE EXCEPTION 'authorization mutation audit attribution expected 10 rows, saw %', audit_count;
  END IF;

  BEGIN
    INSERT INTO public.tenant_authorization_commands (
      id, tenant_id, actor_membership_id, operation,
      key_digest, request_digest, result_resource_id, result_version
    ) VALUES (
      '01993ea0-4000-7000-8000-000000000801',
      '01993ea0-4000-7000-8000-000000000001',
      '01993ea0-4000-7000-8000-000000000201',
      'tenant_role.create',
      sha256(convert_to('foreign-result', 'UTF8')),
      sha256(convert_to('foreign-request', 'UTF8')),
      (SELECT role.id FROM public.tenant_roles AS role
       WHERE role.tenant_id = '01993ea0-4000-7000-8000-000000000002'
         AND role.key = 'tenant_admin'),
      1
    );
    RAISE EXCEPTION 'authorization command accepted a foreign-tenant result';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;

  BEGIN
    UPDATE public.tenant_membership_role_grants
    SET revoked_at = transaction_timestamp()
    WHERE id = '01993ea0-4000-7000-8000-000000000405';
    RAISE EXCEPTION 'partial role-grant revocation metadata escaped its CHECK';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  BEGIN
    UPDATE public.tenant_memberships
    SET status = 'suspended'
    WHERE tenant_id = '01993ea0-4000-7000-8000-000000000001'
      AND id = '01993ea0-4000-7000-8000-000000000201';
    SET CONSTRAINTS "tenant_memberships_recovery_guard" IMMEDIATE;
    RAISE EXCEPTION 'last recovery administrator invariant was not enforced';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_memberships AS membership
    WHERE membership.id = '01993ea0-4000-7000-8000-000000000201'
      AND membership.status = 'active'
  ) THEN
    RAISE EXCEPTION 'failed recovery-admin mutation was not rolled back';
  END IF;
END
$test$;

ROLLBACK;
