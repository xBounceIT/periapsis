-- Audit export and retention is a closed, dual-stream operations boundary.
-- Runtime roles receive EXECUTE on narrow ABIs only; every stored row remains
-- behind FORCE RLS and the no-login, no-bypass owner.
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_audit_operations_owner') THEN
    CREATE ROLE periapsis_audit_operations_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$role$;
--> statement-breakpoint
GRANT USAGE ON SCHEMA app, public TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE TABLE public.platform_user_authorization_epochs (
  user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
  permission_epoch bigint DEFAULT 1 NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT platform_user_authorization_epochs_value_check
    CHECK (permission_epoch BETWEEN 1 AND 9007199254740991)
);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_export_jobs (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  requester_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  requester_membership_id uuid NOT NULL,
  requester_session_id uuid NOT NULL REFERENCES public.auth_sessions(id) ON DELETE RESTRICT,
  membership_lifecycle_revision bigint NOT NULL,
  permission_epoch bigint NOT NULL,
  normalized_filter jsonb NOT NULL,
  filter_digest bytea NOT NULL,
  projection_version integer DEFAULT 1 NOT NULL,
  format text DEFAULT 'jsonl' NOT NULL,
  state text DEFAULT 'pending' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  attempts smallint DEFAULT 0 NOT NULL,
  maximum_attempts smallint DEFAULT 5 NOT NULL,
  failure_code text DEFAULT 'none' NOT NULL,
  requested_at timestamp with time zone DEFAULT now() NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  available_at timestamp with time zone DEFAULT now() NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  lease_worker_id uuid,
  lease_fence bytea,
  lease_claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  artifact_id uuid,
  object_key text,
  artifact_digest bytea,
  artifact_rows bigint,
  artifact_bytes bigint,
  artifact_expires_at timestamp with time zone,
  terminal_at timestamp with time zone,
  CONSTRAINT tenant_audit_export_jobs_tenant_id_key UNIQUE (tenant_id,id),
  CONSTRAINT tenant_audit_export_jobs_requester_membership_fk
    FOREIGN KEY (tenant_id,requester_membership_id,requester_user_id)
    REFERENCES public.tenant_memberships(tenant_id,id,user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_audit_export_jobs_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE
    AND membership_lifecycle_revision BETWEEN 1 AND 9007199254740991
    AND permission_epoch BETWEEN 1 AND 9007199254740991
    AND octet_length(filter_digest) = 32
    AND jsonb_typeof(normalized_filter) = 'object'
    AND pg_column_size(normalized_filter) <= 65536
    AND projection_version = 1 AND format = 'jsonl'
    AND revision BETWEEN 1 AND 9007199254740991
    AND attempts BETWEEN 0 AND maximum_attempts AND maximum_attempts BETWEEN 1 AND 10
    AND updated_at >= requested_at AND available_at >= requested_at
    AND expires_at > requested_at AND expires_at <= requested_at + interval '7 days'
    AND state IN ('pending','running','cancellation_requested','succeeded','failed','cancelled','authorization_revoked','expired')
    AND failure_code IN ('none','transient_storage','transient_database','authorization_revoked','output_limit','lease_expired','expired','internal')
    AND ((lease_worker_id IS NULL AND lease_fence IS NULL AND lease_claimed_at IS NULL AND lease_expires_at IS NULL)
      OR (state IN ('running','cancellation_requested') AND lease_worker_id IS NOT NULL
        AND octet_length(lease_fence) = 32 AND lease_expires_at > lease_claimed_at))
    AND ((artifact_id IS NULL AND object_key IS NULL AND artifact_digest IS NULL
          AND artifact_rows IS NULL AND artifact_bytes IS NULL AND artifact_expires_at IS NULL)
      OR (state = 'succeeded' AND (uuid_extract_version(artifact_id) = 7) IS TRUE
          AND object_key = ('tenants/' || tenant_id::text || '/audit/exports/' || id::text || '/v1.jsonl')
          AND octet_length(artifact_digest) = 32 AND artifact_rows >= 0
          AND artifact_bytes >= 0 AND artifact_expires_at = expires_at))
  )
);
--> statement-breakpoint
CREATE INDEX tenant_audit_export_jobs_queue_idx
  ON public.tenant_audit_export_jobs(state,available_at,tenant_id,id);
--> statement-breakpoint
CREATE INDEX tenant_audit_export_jobs_requester_idx
  ON public.tenant_audit_export_jobs(tenant_id,requester_membership_id,requested_at,id);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_operation_receipts (
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  membership_id uuid NOT NULL,
  action text NOT NULL,
  idempotency_key_digest bytea NOT NULL,
  payload_digest bytea NOT NULL,
  response jsonb NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  CONSTRAINT tenant_audit_operation_receipts_pkey PRIMARY KEY
    (tenant_id,actor_user_id,membership_id,action,idempotency_key_digest),
  CONSTRAINT tenant_audit_operation_receipts_membership_fk
    FOREIGN KEY (tenant_id,membership_id,actor_user_id)
    REFERENCES public.tenant_memberships(tenant_id,id,user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_audit_operation_receipts_shape_check CHECK (
    action IN ('export.create','export.cancel','retention.change','legal_hold.place','legal_hold.release')
    AND octet_length(idempotency_key_digest) = 32
    AND octet_length(payload_digest) = 32
    AND jsonb_typeof(response) = 'object' AND pg_column_size(response) <= 65536
    AND expires_at > created_at AND expires_at <= created_at + interval '7 days'
  )
);
--> statement-breakpoint
CREATE INDEX tenant_audit_operation_receipts_expiry_idx
  ON public.tenant_audit_operation_receipts(expires_at,tenant_id,actor_user_id);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_export_manifests (
  tenant_id uuid NOT NULL,
  job_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  job_revision bigint NOT NULL,
  projection_version integer NOT NULL,
  format text NOT NULL,
  object_key text NOT NULL,
  digest bytea NOT NULL,
  rows bigint NOT NULL,
  bytes bigint NOT NULL,
  published_at timestamp with time zone NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  CONSTRAINT tenant_audit_export_manifests_pkey PRIMARY KEY (tenant_id,job_id,artifact_id),
  CONSTRAINT tenant_audit_export_manifests_artifact_key UNIQUE (artifact_id),
  CONSTRAINT tenant_audit_export_manifests_job_fk FOREIGN KEY (tenant_id,job_id)
    REFERENCES public.tenant_audit_export_jobs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_audit_export_manifests_shape_check CHECK (
    (uuid_extract_version(artifact_id) = 7) IS TRUE
    AND job_revision BETWEEN 1 AND 9007199254740991
    AND projection_version = 1 AND format = 'jsonl'
    AND object_key = ('tenants/' || tenant_id::text || '/audit/exports/' || job_id::text || '/v1.jsonl')
    AND octet_length(digest) = 32 AND rows >= 0 AND bytes >= 0
    AND expires_at > published_at
  )
);
--> statement-breakpoint

CREATE TABLE public.platform_audit_export_jobs (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  requester_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  requester_session_id uuid NOT NULL REFERENCES public.auth_sessions(id) ON DELETE RESTRICT,
  permission_epoch bigint NOT NULL,
  normalized_filter jsonb NOT NULL,
  filter_digest bytea NOT NULL,
  projection_version integer DEFAULT 1 NOT NULL,
  format text DEFAULT 'jsonl' NOT NULL,
  state text DEFAULT 'pending' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  attempts smallint DEFAULT 0 NOT NULL,
  maximum_attempts smallint DEFAULT 5 NOT NULL,
  failure_code text DEFAULT 'none' NOT NULL,
  requested_at timestamp with time zone DEFAULT now() NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  available_at timestamp with time zone DEFAULT now() NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  lease_worker_id uuid,
  lease_fence bytea,
  lease_claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  artifact_id uuid,
  object_key text,
  artifact_digest bytea,
  artifact_rows bigint,
  artifact_bytes bigint,
  artifact_expires_at timestamp with time zone,
  terminal_at timestamp with time zone,
  CONSTRAINT platform_audit_export_jobs_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE
    AND permission_epoch BETWEEN 1 AND 9007199254740991
    AND octet_length(filter_digest) = 32
    AND jsonb_typeof(normalized_filter) = 'object' AND pg_column_size(normalized_filter) <= 65536
    AND projection_version = 1 AND format = 'jsonl'
    AND revision BETWEEN 1 AND 9007199254740991
    AND attempts BETWEEN 0 AND maximum_attempts AND maximum_attempts BETWEEN 1 AND 10
    AND updated_at >= requested_at AND available_at >= requested_at
    AND expires_at > requested_at AND expires_at <= requested_at + interval '7 days'
    AND state IN ('pending','running','cancellation_requested','succeeded','failed','cancelled','authorization_revoked','expired')
    AND failure_code IN ('none','transient_storage','transient_database','authorization_revoked','output_limit','lease_expired','expired','internal')
    AND ((lease_worker_id IS NULL AND lease_fence IS NULL AND lease_claimed_at IS NULL AND lease_expires_at IS NULL)
      OR (state IN ('running','cancellation_requested') AND lease_worker_id IS NOT NULL
        AND octet_length(lease_fence) = 32 AND lease_expires_at > lease_claimed_at))
    AND ((artifact_id IS NULL AND object_key IS NULL AND artifact_digest IS NULL
          AND artifact_rows IS NULL AND artifact_bytes IS NULL AND artifact_expires_at IS NULL)
      OR (state = 'succeeded' AND (uuid_extract_version(artifact_id) = 7) IS TRUE
          AND object_key = ('platform/audit/exports/' || id::text || '/v1.jsonl')
          AND octet_length(artifact_digest) = 32 AND artifact_rows >= 0
          AND artifact_bytes >= 0 AND artifact_expires_at = expires_at))
  )
);
--> statement-breakpoint
CREATE INDEX platform_audit_export_jobs_queue_idx
  ON public.platform_audit_export_jobs(state,available_at,id);
--> statement-breakpoint
CREATE INDEX platform_audit_export_jobs_requester_idx
  ON public.platform_audit_export_jobs(requester_user_id,requested_at,id);
--> statement-breakpoint

CREATE TABLE public.platform_audit_operation_receipts (
  actor_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  action text NOT NULL,
  idempotency_key_digest bytea NOT NULL,
  payload_digest bytea NOT NULL,
  response jsonb NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  CONSTRAINT platform_audit_operation_receipts_pkey PRIMARY KEY
    (actor_user_id,action,idempotency_key_digest),
  CONSTRAINT platform_audit_operation_receipts_shape_check CHECK (
    action IN ('export.create','export.cancel','retention.change','legal_hold.place','legal_hold.release')
    AND octet_length(idempotency_key_digest) = 32 AND octet_length(payload_digest) = 32
    AND jsonb_typeof(response) = 'object' AND pg_column_size(response) <= 65536
    AND expires_at > created_at AND expires_at <= created_at + interval '7 days'
  )
);
--> statement-breakpoint
CREATE INDEX platform_audit_operation_receipts_expiry_idx
  ON public.platform_audit_operation_receipts(expires_at,actor_user_id);
--> statement-breakpoint

CREATE TABLE public.platform_audit_export_manifests (
  job_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  job_revision bigint NOT NULL,
  projection_version integer NOT NULL,
  format text NOT NULL,
  object_key text NOT NULL,
  digest bytea NOT NULL,
  rows bigint NOT NULL,
  bytes bigint NOT NULL,
  published_at timestamp with time zone NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  CONSTRAINT platform_audit_export_manifests_pkey PRIMARY KEY (job_id,artifact_id),
  CONSTRAINT platform_audit_export_manifests_artifact_key UNIQUE (artifact_id),
  CONSTRAINT platform_audit_export_manifests_job_fk FOREIGN KEY (job_id)
    REFERENCES public.platform_audit_export_jobs(id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT platform_audit_export_manifests_shape_check CHECK (
    (uuid_extract_version(artifact_id) = 7) IS TRUE
    AND job_revision BETWEEN 1 AND 9007199254740991
    AND projection_version = 1 AND format = 'jsonl'
    AND object_key = ('platform/audit/exports/' || job_id::text || '/v1.jsonl')
    AND octet_length(digest) = 32 AND rows >= 0 AND bytes >= 0
    AND expires_at > published_at
  )
);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_retention_policies (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE RESTRICT,
  retention_days integer DEFAULT 365 NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  updated_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  reason text NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT tenant_audit_retention_policies_shape_check CHECK (
    retention_days BETWEEN 30 AND 3650 AND revision BETWEEN 1 AND 9007199254740991
    AND updated_at >= created_at AND reason = btrim(reason)
    AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
  )
);
--> statement-breakpoint

CREATE TABLE public.platform_audit_retention_policy (
  singleton boolean PRIMARY KEY DEFAULT true NOT NULL,
  retention_days integer DEFAULT 730 NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  updated_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  reason text NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT platform_audit_retention_policy_singleton_check CHECK (singleton IS TRUE),
  CONSTRAINT platform_audit_retention_policy_shape_check CHECK (
    retention_days BETWEEN 30 AND 3650 AND revision BETWEEN 1 AND 9007199254740991
    AND updated_at >= created_at AND reason = btrim(reason)
    AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
  )
);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_legal_holds (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  state text DEFAULT 'active' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  placed_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  placed_at timestamp with time zone DEFAULT now() NOT NULL,
  placement_reason text NOT NULL,
  released_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  released_at timestamp with time zone,
  release_reason text,
  CONSTRAINT tenant_audit_legal_holds_tenant_id_key UNIQUE (tenant_id,id),
  CONSTRAINT tenant_audit_legal_holds_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE AND revision BETWEEN 1 AND 9007199254740991
    AND placement_reason = btrim(placement_reason)
    AND octet_length(placement_reason) BETWEEN 1 AND 2048 AND placement_reason !~ '[[:cntrl:]]'
    AND ((state = 'active' AND revision = 1 AND released_by_user_id IS NULL
          AND released_at IS NULL AND release_reason IS NULL)
      OR (state = 'released' AND revision = 2 AND released_by_user_id IS NOT NULL
          AND released_at >= placed_at AND release_reason = btrim(release_reason)
          AND octet_length(release_reason) BETWEEN 1 AND 2048 AND release_reason !~ '[[:cntrl:]]'))
  )
);
--> statement-breakpoint
CREATE UNIQUE INDEX tenant_audit_legal_holds_active_key
  ON public.tenant_audit_legal_holds(tenant_id) WHERE state = 'active';
--> statement-breakpoint

CREATE TABLE public.platform_audit_legal_holds (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  state text DEFAULT 'active' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  placed_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  placed_at timestamp with time zone DEFAULT now() NOT NULL,
  placement_reason text NOT NULL,
  released_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  released_at timestamp with time zone,
  release_reason text,
  CONSTRAINT platform_audit_legal_holds_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE AND revision BETWEEN 1 AND 9007199254740991
    AND placement_reason = btrim(placement_reason)
    AND octet_length(placement_reason) BETWEEN 1 AND 2048 AND placement_reason !~ '[[:cntrl:]]'
    AND ((state = 'active' AND revision = 1 AND released_by_user_id IS NULL
          AND released_at IS NULL AND release_reason IS NULL)
      OR (state = 'released' AND revision = 2 AND released_by_user_id IS NOT NULL
          AND released_at >= placed_at AND release_reason = btrim(release_reason)
          AND octet_length(release_reason) BETWEEN 1 AND 2048 AND release_reason !~ '[[:cntrl:]]'))
  )
);
--> statement-breakpoint
CREATE UNIQUE INDEX platform_audit_legal_holds_active_key
  ON public.platform_audit_legal_holds(state) WHERE state = 'active';
--> statement-breakpoint

CREATE TABLE public.tenant_audit_segments (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  start_sequence bigint NOT NULL,
  end_sequence bigint NOT NULL,
  previous_hash character(64) NOT NULL,
  end_hash character(64) NOT NULL,
  event_count bigint NOT NULL,
  cutoff_at timestamp with time zone NOT NULL,
  state text DEFAULT 'closed' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  reason text NOT NULL,
  object_key text NOT NULL,
  digest bytea,
  bytes bigint,
  signing_key_id text,
  signature bytea,
  closed_at timestamp with time zone DEFAULT now() NOT NULL,
  preserved_at timestamp with time zone,
  pruned_at timestamp with time zone,
  CONSTRAINT tenant_audit_segments_tenant_id_key UNIQUE (tenant_id,id),
  CONSTRAINT tenant_audit_segments_tenant_range_key UNIQUE (tenant_id,start_sequence),
  CONSTRAINT tenant_audit_segments_tenant_end_key UNIQUE (tenant_id,end_sequence),
  CONSTRAINT tenant_audit_segments_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE
    AND start_sequence > 0 AND end_sequence >= start_sequence
    AND event_count = end_sequence - start_sequence + 1
    AND previous_hash ~ '^[0-9a-f]{64}$' AND end_hash ~ '^[0-9a-f]{64}$'
    AND revision BETWEEN 1 AND 3 AND reason = btrim(reason)
    AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
    AND object_key = ('tenants/' || tenant_id::text || '/audit/segments/' || start_sequence::text || '-' || end_sequence::text || '/' || id::text || '.jsonl')
    AND ((state = 'closed' AND revision = 1 AND digest IS NULL AND bytes IS NULL
          AND signing_key_id IS NULL AND signature IS NULL AND preserved_at IS NULL AND pruned_at IS NULL)
      OR (state = 'preserved' AND revision = 2 AND octet_length(digest) = 32 AND bytes > 0
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64
          AND preserved_at >= closed_at AND pruned_at IS NULL)
      OR (state = 'pruned' AND revision = 3 AND octet_length(digest) = 32 AND bytes > 0
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64
          AND preserved_at >= closed_at AND pruned_at >= preserved_at))
  )
);
--> statement-breakpoint
CREATE INDEX tenant_audit_segments_state_idx
  ON public.tenant_audit_segments(state,closed_at,tenant_id,id);
--> statement-breakpoint

CREATE TABLE public.platform_audit_segments (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  start_sequence bigint NOT NULL,
  end_sequence bigint NOT NULL,
  previous_hash character(64) NOT NULL,
  end_hash character(64) NOT NULL,
  event_count bigint NOT NULL,
  cutoff_at timestamp with time zone NOT NULL,
  state text DEFAULT 'closed' NOT NULL,
  revision bigint DEFAULT 1 NOT NULL,
  reason text NOT NULL,
  object_key text NOT NULL,
  digest bytea,
  bytes bigint,
  signing_key_id text,
  signature bytea,
  closed_at timestamp with time zone DEFAULT now() NOT NULL,
  preserved_at timestamp with time zone,
  pruned_at timestamp with time zone,
  CONSTRAINT platform_audit_segments_start_key UNIQUE (start_sequence),
  CONSTRAINT platform_audit_segments_end_key UNIQUE (end_sequence),
  CONSTRAINT platform_audit_segments_shape_check CHECK (
    (uuid_extract_version(id) = 7) IS TRUE
    AND start_sequence > 0 AND end_sequence >= start_sequence
    AND event_count = end_sequence - start_sequence + 1
    AND previous_hash ~ '^[0-9a-f]{64}$' AND end_hash ~ '^[0-9a-f]{64}$'
    AND revision BETWEEN 1 AND 3 AND reason = btrim(reason)
    AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
    AND object_key = ('platform/audit/segments/' || start_sequence::text || '-' || end_sequence::text || '/' || id::text || '.jsonl')
    AND ((state = 'closed' AND revision = 1 AND digest IS NULL AND bytes IS NULL
          AND signing_key_id IS NULL AND signature IS NULL AND preserved_at IS NULL AND pruned_at IS NULL)
      OR (state = 'preserved' AND revision = 2 AND octet_length(digest) = 32 AND bytes > 0
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64
          AND preserved_at >= closed_at AND pruned_at IS NULL)
      OR (state = 'pruned' AND revision = 3 AND octet_length(digest) = 32 AND bytes > 0
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64
          AND preserved_at >= closed_at AND pruned_at >= preserved_at))
  )
);
--> statement-breakpoint
CREATE INDEX platform_audit_segments_state_idx
  ON public.platform_audit_segments(state,closed_at,id);
--> statement-breakpoint

CREATE TABLE public.tenant_audit_retention_anchors (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE RESTRICT,
  retained_through_sequence bigint DEFAULT 0 NOT NULL,
  retained_through_hash character(64) DEFAULT repeat('0',64) NOT NULL,
  last_segment_id uuid,
  segment_digest bytea,
  signing_key_id text,
  signature bytea,
  revision bigint DEFAULT 1 NOT NULL,
  reason text DEFAULT 'initial retention anchor' NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT tenant_audit_retention_anchors_segment_fk
    FOREIGN KEY (tenant_id,last_segment_id)
    REFERENCES public.tenant_audit_segments(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_audit_retention_anchors_shape_check CHECK (
    retained_through_sequence >= 0 AND retained_through_hash ~ '^[0-9a-f]{64}$'
    AND revision BETWEEN 1 AND 9007199254740991
    AND reason = btrim(reason) AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
    AND ((retained_through_sequence = 0 AND retained_through_hash = repeat('0',64)
          AND last_segment_id IS NULL AND segment_digest IS NULL AND signing_key_id IS NULL AND signature IS NULL)
      OR (retained_through_sequence > 0 AND last_segment_id IS NOT NULL AND octet_length(segment_digest) = 32
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64))
  )
);
--> statement-breakpoint

CREATE TABLE public.platform_audit_retention_anchor (
  singleton boolean PRIMARY KEY DEFAULT true NOT NULL,
  retained_through_sequence bigint DEFAULT 0 NOT NULL,
  retained_through_hash character(64) DEFAULT repeat('0',64) NOT NULL,
  last_segment_id uuid REFERENCES public.platform_audit_segments(id) ON DELETE RESTRICT,
  segment_digest bytea,
  signing_key_id text,
  signature bytea,
  revision bigint DEFAULT 1 NOT NULL,
  reason text DEFAULT 'initial retention anchor' NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT platform_audit_retention_anchor_singleton_check CHECK (singleton IS TRUE),
  CONSTRAINT platform_audit_retention_anchor_shape_check CHECK (
    retained_through_sequence >= 0 AND retained_through_hash ~ '^[0-9a-f]{64}$'
    AND revision BETWEEN 1 AND 9007199254740991
    AND reason = btrim(reason) AND octet_length(reason) BETWEEN 1 AND 2048 AND reason !~ '[[:cntrl:]]'
    AND ((retained_through_sequence = 0 AND retained_through_hash = repeat('0',64)
          AND last_segment_id IS NULL AND segment_digest IS NULL AND signing_key_id IS NULL AND signature IS NULL)
      OR (retained_through_sequence > 0 AND last_segment_id IS NOT NULL AND octet_length(segment_digest) = 32
          AND signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' AND octet_length(signature) = 64))
  )
);
--> statement-breakpoint

-- Every audit-operations table is forced through the non-login owner policy.
DO $function$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'platform_user_authorization_epochs','tenant_audit_export_jobs',
    'tenant_audit_operation_receipts','tenant_audit_export_manifests',
    'platform_audit_export_jobs','platform_audit_operation_receipts',
    'platform_audit_export_manifests','tenant_audit_retention_policies',
    'platform_audit_retention_policy','tenant_audit_legal_holds',
    'platform_audit_legal_holds','tenant_audit_segments','platform_audit_segments',
    'tenant_audit_retention_anchors','platform_audit_retention_anchor'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',relation_name);
  END LOOP;
END;
$function$;
--> statement-breakpoint

CREATE POLICY platform_user_authorization_epochs_owner_access
  ON public.platform_user_authorization_epochs FOR ALL TO periapsis_audit_operations_owner
  USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_export_jobs_owner_access
  ON public.tenant_audit_export_jobs FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_operation_receipts_owner_access
  ON public.tenant_audit_operation_receipts FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_export_manifests_owner_access
  ON public.tenant_audit_export_manifests FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_export_jobs_owner_access
  ON public.platform_audit_export_jobs FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_operation_receipts_owner_access
  ON public.platform_audit_operation_receipts FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_export_manifests_owner_access
  ON public.platform_audit_export_manifests FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_retention_policies_owner_access
  ON public.tenant_audit_retention_policies FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_retention_policy_owner_access
  ON public.platform_audit_retention_policy FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_legal_holds_owner_access
  ON public.tenant_audit_legal_holds FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_legal_holds_owner_access
  ON public.platform_audit_legal_holds FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_segments_owner_access
  ON public.tenant_audit_segments FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_segments_owner_access
  ON public.platform_audit_segments FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_retention_anchors_owner_access
  ON public.tenant_audit_retention_anchors FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_audit_retention_anchor_owner_access
  ON public.platform_audit_retention_anchor FOR ALL TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint

REVOKE ALL ON TABLE public.platform_user_authorization_epochs,
  public.tenant_audit_export_jobs, public.tenant_audit_operation_receipts,
  public.tenant_audit_export_manifests, public.platform_audit_export_jobs,
  public.platform_audit_operation_receipts, public.platform_audit_export_manifests,
  public.tenant_audit_retention_policies, public.platform_audit_retention_policy,
  public.tenant_audit_legal_holds, public.platform_audit_legal_holds,
  public.tenant_audit_segments, public.platform_audit_segments,
  public.tenant_audit_retention_anchors, public.platform_audit_retention_anchor
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.platform_user_authorization_epochs,
  public.tenant_audit_export_jobs, public.tenant_audit_operation_receipts,
  public.tenant_audit_export_manifests, public.platform_audit_export_jobs,
  public.platform_audit_operation_receipts, public.platform_audit_export_manifests,
  public.tenant_audit_retention_policies, public.platform_audit_retention_policy,
  public.tenant_audit_legal_holds, public.platform_audit_legal_holds,
  public.tenant_audit_segments, public.platform_audit_segments,
  public.tenant_audit_retention_anchors, public.platform_audit_retention_anchor
TO periapsis_audit_operations_owner;
--> statement-breakpoint
DO $function$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'platform_user_authorization_epochs','tenant_audit_export_jobs',
    'tenant_audit_operation_receipts','tenant_audit_export_manifests',
    'platform_audit_export_jobs','platform_audit_operation_receipts',
    'platform_audit_export_manifests','tenant_audit_retention_policies',
    'platform_audit_retention_policy','tenant_audit_legal_holds',
    'platform_audit_legal_holds','tenant_audit_segments','platform_audit_segments',
    'tenant_audit_retention_anchors','platform_audit_retention_anchor'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO periapsis_audit_operations_owner',relation_name);
  END LOOP;
END;
$function$;
--> statement-breakpoint

INSERT INTO public.tenant_permissions(id,key,display_name,description,service_account_allowed)
VALUES
  (uuidv7(),'audit.export','Export security audit log','Create, inspect, cancel, and download redacted tenant audit exports.',false),
  (uuidv7(),'audit.retention.manage','Manage audit retention','Change tenant audit retention and explicit legal holds.',false)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.tenant_permission_scopes(permission_id,scope)
SELECT permission.id,'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN ('audit.export','audit.retention.manage')
ON CONFLICT DO NOTHING;
--> statement-breakpoint
INSERT INTO public.tenant_role_permissions(tenant_id,role_id,permission_id,scope)
SELECT role.tenant_id,role.id,permission.id,'tenant'::public.authorization_scope
FROM public.tenant_roles AS role
CROSS JOIN public.tenant_permissions AS permission
WHERE role.key = 'tenant_admin' AND role.system_role AND role.archived_at IS NULL
  AND role.principal_kind = 'human'
  AND permission.key IN ('audit.export','audit.retention.manage')
ON CONFLICT DO NOTHING;
--> statement-breakpoint
INSERT INTO public.tenant_role_delegation_ceilings(tenant_id,role_id,permission_id,scope)
SELECT grant_row.tenant_id,grant_row.role_id,grant_row.permission_id,grant_row.scope
FROM public.tenant_role_permissions AS grant_row
JOIN public.tenant_roles AS role ON role.tenant_id = grant_row.tenant_id AND role.id = grant_row.role_id
JOIN public.tenant_permissions AS permission ON permission.id = grant_row.permission_id
WHERE role.key = 'tenant_admin' AND role.system_role AND role.archived_at IS NULL
  AND role.principal_kind = 'human'
  AND permission.key IN ('audit.export','audit.retention.manage')
  AND grant_row.scope = 'tenant'::public.authorization_scope
ON CONFLICT DO NOTHING;
--> statement-breakpoint

-- Keep the explicit tenant-admin grant policy correct for tenants provisioned
-- after this migration. The predecessor creates the system roles first; this
-- successor then adds only the two audit-operation permissions and ceilings.
CREATE FUNCTION app.private_seed_tenant_audit_operations_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR NOT EXISTS (
       SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
     ) THEN
    RAISE EXCEPTION 'invalid tenant audit authorization seed'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenant_role_permissions(
    tenant_id,role_id,permission_id,scope
  )
  SELECT role.tenant_id,role.id,permission.id,
         'tenant'::public.authorization_scope
  FROM public.tenant_roles AS role
  CROSS JOIN public.tenant_permissions AS permission
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.archived_at IS NULL
    AND role.principal_kind = 'human'
    AND permission.key IN ('audit.export','audit.retention.manage')
  ON CONFLICT DO NOTHING;

  INSERT INTO public.tenant_role_delegation_ceilings(
    tenant_id,role_id,permission_id,scope
  )
  SELECT grant_row.tenant_id,grant_row.role_id,
         grant_row.permission_id,grant_row.scope
  FROM public.tenant_role_permissions AS grant_row
  JOIN public.tenant_roles AS role
    ON role.tenant_id = grant_row.tenant_id
   AND role.id = grant_row.role_id
  JOIN public.tenant_permissions AS permission
    ON permission.id = grant_row.permission_id
  WHERE grant_row.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.archived_at IS NULL
    AND role.principal_kind = 'human'
    AND permission.key IN ('audit.export','audit.retention.manage')
    AND grant_row.scope = 'tenant'::public.authorization_scope
  ON CONFLICT DO NOTHING;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_audit_operations_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_audit_operations_authorization_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor, periapsis_audit_operations_owner;
--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid,uuid)
  RENAME TO seed_tenant_authorization_audit_operations_compatibility_impl;
--> statement-breakpoint
CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_audit_operations_compatibility_impl(
    p_tenant_id,p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_audit_operations_authorization_v1(
    p_tenant_id
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid,uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid,uuid),
  app.seed_tenant_authorization_audit_operations_compatibility_impl(uuid,uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor, periapsis_audit_operations_owner;
--> statement-breakpoint

INSERT INTO public.platform_permissions(id,key,description)
VALUES
  (uuidv7(),'platform.audit.export','Create, inspect, cancel, and download redacted platform audit exports.'),
  (uuidv7(),'platform.audit.retention.manage','Change platform audit retention and explicit legal holds.')
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_role_permissions(role_id,permission_id)
SELECT role.id,permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE (role.key = 'platform_super_admin'
       AND permission.key IN ('platform.audit.export','platform.audit.retention.manage'))
   OR (role.key = 'platform_auditor' AND permission.key = 'platform.audit.export')
ON CONFLICT DO NOTHING;
--> statement-breakpoint

-- Establish a stable platform authorization epoch after catalog seeding. The
-- role-permission trigger below advances every active grantee of a changed role.
INSERT INTO public.platform_user_authorization_epochs(user_id)
SELECT DISTINCT grant_row.user_id
FROM public.user_platform_roles AS grant_row
WHERE grant_row.revoked_at IS NULL
ON CONFLICT (user_id) DO NOTHING;
--> statement-breakpoint

CREATE FUNCTION app.private_bump_platform_user_authorization_epoch_v1(p_user_id uuid)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result_epoch bigint;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'platform authorization subject is required' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.platform_user_authorization_epochs(user_id,permission_epoch,updated_at)
  VALUES (p_user_id,2,clock_timestamp())
  ON CONFLICT (user_id) DO UPDATE
  SET permission_epoch = public.platform_user_authorization_epochs.permission_epoch + 1,
      updated_at = greatest(public.platform_user_authorization_epochs.updated_at,clock_timestamp())
  WHERE public.platform_user_authorization_epochs.permission_epoch < 9007199254740991
  RETURNING permission_epoch INTO result_epoch;
  IF result_epoch IS NULL THEN
    RAISE EXCEPTION 'platform authorization epoch is exhausted' USING ERRCODE = '22003';
  END IF;
  RETURN result_epoch;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_bump_platform_user_authorization_epoch_v1(uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_bump_platform_user_authorization_epoch_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.bump_platform_authorization_epoch_on_user_role_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM app.private_bump_platform_user_authorization_epoch_v1(NEW.user_id);
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    PERFORM app.private_bump_platform_user_authorization_epoch_v1(OLD.user_id);
    RETURN OLD;
  END IF;
  IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
    PERFORM app.private_bump_platform_user_authorization_epoch_v1(OLD.user_id);
    PERFORM app.private_bump_platform_user_authorization_epoch_v1(NEW.user_id);
  ELSIF OLD.role_id IS DISTINCT FROM NEW.role_id
     OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at THEN
    PERFORM app.private_bump_platform_user_authorization_epoch_v1(NEW.user_id);
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.bump_platform_authorization_epoch_on_user_role_v1()
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.bump_platform_authorization_epoch_on_user_role_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER user_platform_roles_audit_epoch_v1
AFTER INSERT OR UPDATE OR DELETE ON public.user_platform_roles
FOR EACH ROW EXECUTE FUNCTION app.bump_platform_authorization_epoch_on_user_role_v1();
--> statement-breakpoint

CREATE FUNCTION app.bump_platform_authorization_epoch_on_role_permission_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected_role_id uuid;
  affected_user record;
BEGIN
  FOR affected_role_id IN
    SELECT DISTINCT role_id
    FROM (VALUES
      (CASE WHEN TG_OP = 'INSERT' THEN NULL::uuid ELSE OLD.role_id END),
      (CASE WHEN TG_OP = 'DELETE' THEN NULL::uuid ELSE NEW.role_id END)
    ) AS roles(role_id)
    WHERE role_id IS NOT NULL
  LOOP
    FOR affected_user IN
      SELECT DISTINCT grant_row.user_id
      FROM public.user_platform_roles AS grant_row
      WHERE grant_row.role_id = affected_role_id AND grant_row.revoked_at IS NULL
      ORDER BY grant_row.user_id
    LOOP
      PERFORM app.private_bump_platform_user_authorization_epoch_v1(affected_user.user_id);
    END LOOP;
  END LOOP;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.bump_platform_authorization_epoch_on_role_permission_v1()
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.bump_platform_authorization_epoch_on_role_permission_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER platform_role_permissions_audit_epoch_v1
AFTER INSERT OR UPDATE OR DELETE ON public.platform_role_permissions
FOR EACH ROW EXECUTE FUNCTION app.bump_platform_authorization_epoch_on_role_permission_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_audit_operation_reason_is_safe_v1(p_reason text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
  SELECT octet_length(p_reason) BETWEEN 1 AND 500
     AND p_reason !~ '[^ -~]'
     AND left(p_reason,1) <> ' ' AND right(p_reason,1) <> ' '
     AND position(',' IN p_reason) = 0
     AND app.private_platform_audit_reason_is_safe_v1(p_reason);
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_audit_operation_reason_is_safe_v1(text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_audit_operation_reason_is_safe_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_audit_export_filter_is_valid_v1(p_filter jsonb,p_stream text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT p_stream IN ('tenant','platform')
     AND jsonb_typeof(p_filter) = 'object'
     AND p_filter = jsonb_strip_nulls(p_filter)
     AND pg_column_size(p_filter) <= 65536
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_filter) AS member(key)
       WHERE member.key NOT IN (
         'occurredFrom','occurredBefore','actorType','actorUserId','actorServiceAccountId',
         'actionPrefix','resourceType','resourceId','requestId','correlationId','outcome','search'
       )
     )
     AND (p_stream = 'tenant' OR NOT (p_filter ? 'actorServiceAccountId'))
     AND (NOT (p_filter ? 'occurredFrom') OR jsonb_typeof(p_filter->'occurredFrom') = 'string')
     AND (NOT (p_filter ? 'occurredBefore') OR jsonb_typeof(p_filter->'occurredBefore') = 'string')
     AND (NOT (p_filter ? 'actorType') OR p_filter->>'actorType' IN ('user','service_account','system'))
     AND (NOT (p_filter ? 'outcome') OR p_filter->>'outcome' IN ('success','failure','denied'))
     AND (NOT (p_filter ? 'actionPrefix') OR p_filter->>'actionPrefix' ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$')
     AND (NOT (p_filter ? 'resourceType') OR p_filter->>'resourceType' ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$')
     AND (NOT (p_filter ? 'search') OR octet_length(p_filter->>'search') BETWEEN 1 AND 256
          AND p_filter->>'search' !~ '[[:cntrl:]]')
     AND (NOT (p_filter ? 'actorUserId') OR (p_filter->>'actorUserId')::uuid IS NOT NULL)
     AND (NOT (p_filter ? 'actorServiceAccountId') OR (p_filter->>'actorServiceAccountId')::uuid IS NOT NULL)
     AND (NOT (p_filter ? 'resourceId') OR (p_filter->>'resourceId')::uuid IS NOT NULL)
     AND (NOT (p_filter ? 'requestId') OR (p_filter->>'requestId')::uuid IS NOT NULL)
     AND (NOT (p_filter ? 'correlationId') OR (p_filter->>'correlationId')::uuid IS NOT NULL)
     AND (NOT (p_filter ? 'occurredFrom') OR NOT (p_filter ? 'occurredBefore')
          OR (p_filter->>'occurredFrom')::timestamp with time zone < (p_filter->>'occurredBefore')::timestamp with time zone);
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_audit_export_filter_is_valid_v1(jsonb,text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_audit_export_filter_is_valid_v1(jsonb,text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_audit_export_job_document_v1(p_job public.tenant_audit_export_jobs)
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'id',p_job.id,'stream','tenant','tenantId',p_job.tenant_id,
    'requesterUserId',p_job.requester_user_id,
    'filter',p_job.normalized_filter,'filterSha256',encode(p_job.filter_digest,'hex'),
    'projectionVersion',p_job.projection_version,'format',p_job.format,
    'state',p_job.state,'revision',p_job.revision,'attempts',p_job.attempts,
    'maximumAttempts',p_job.maximum_attempts,'failureCode',p_job.failure_code,
    'requestedAt',p_job.requested_at,'updatedAt',p_job.updated_at,
    'availableAt',p_job.available_at,'expiresAt',p_job.expires_at,
    'terminalAt',p_job.terminal_at,
    'artifact',CASE WHEN p_job.artifact_id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',p_job.artifact_id,'sha256',encode(p_job.artifact_digest,'hex'),
      'rows',p_job.artifact_rows,'bytes',p_job.artifact_bytes,'expiresAt',p_job.artifact_expires_at
    ) END
  ));
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_tenant_audit_export_job_document_v1(public.tenant_audit_export_jobs)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_tenant_audit_export_job_document_v1(public.tenant_audit_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_audit_export_job_document_v1(p_job public.platform_audit_export_jobs)
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'id',p_job.id,'stream','platform','requesterUserId',p_job.requester_user_id,
    'filter',p_job.normalized_filter,'filterSha256',encode(p_job.filter_digest,'hex'),
    'projectionVersion',p_job.projection_version,'format',p_job.format,
    'state',p_job.state,'revision',p_job.revision,'attempts',p_job.attempts,
    'maximumAttempts',p_job.maximum_attempts,'failureCode',p_job.failure_code,
    'requestedAt',p_job.requested_at,'updatedAt',p_job.updated_at,
    'availableAt',p_job.available_at,'expiresAt',p_job.expires_at,
    'terminalAt',p_job.terminal_at,
    'artifact',CASE WHEN p_job.artifact_id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',p_job.artifact_id,'sha256',encode(p_job.artifact_digest,'hex'),
      'rows',p_job.artifact_rows,'bytes',p_job.artifact_bytes,'expiresAt',p_job.artifact_expires_at
    ) END
  ));
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_audit_export_job_document_v1(public.platform_audit_export_jobs)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_audit_export_job_document_v1(public.platform_audit_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

-- Tenant operations need reason-bearing audit rows; the historical reader
-- helper predates the reason column and is deliberately not widened in place.
CREATE FUNCTION app.private_append_tenant_audit_operation_v1(
  p_session_id uuid,p_event_id uuid,p_action text,p_resource_type text,p_resource_id uuid,
  p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text,p_reason text,
  p_before jsonb,p_after jsonb,p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  authentication_method text;
BEGIN
  IF (uuid_extract_version(p_event_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE
     OR p_ip_address IS NULL OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_action !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR p_resource_type !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit operation envelope' USING ERRCODE = '22023';
  END IF;
  authentication_method := app.require_live_audit_session_v1(p_session_id,context_tenant);
  PERFORM app.current_tenant_membership_id();
  INSERT INTO public.audit_events(
    id,tenant_id,sequence,actor_type,actor_user_id,action,resource_type,resource_id,
    request_id,correlation_id,ip_address,user_agent,authentication_method,outcome,
    reason,before,after,metadata
  ) VALUES (
    p_event_id,context_tenant,1,'user',actor_id,p_action,p_resource_type,p_resource_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,authentication_method,'success',
    p_reason,p_before,p_after,coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_tenant_audit_operation_v1(
  uuid,uuid,text,text,uuid,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_tenant_audit_operation_v1(
  uuid,uuid,text,text,uuid,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE POLICY audit_events_audit_operations_insert
  ON public.audit_events FOR INSERT TO periapsis_audit_operations_owner
  WITH CHECK (
    tenant_id = nullif(current_setting('app.tenant_id',true),'')::uuid
    AND actor_type = 'user'
    AND actor_user_id = nullif(current_setting('app.user_id',true),'')::uuid
    AND actor_service_account_id IS NULL
  );
--> statement-breakpoint
GRANT INSERT ON TABLE public.audit_events TO periapsis_audit_operations_owner;
--> statement-breakpoint

-- The owner can inspect only through its sealed functions. Broad owner-only
-- SELECT policies are required for worker reauthorization across tenant GUCs;
-- the role is NOLOGIN and no runtime role is a member.
CREATE POLICY auth_sessions_audit_operations_select ON public.auth_sessions
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY users_audit_operations_select ON public.users
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenants_audit_operations_select ON public.tenants
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_memberships_audit_operations_select ON public.tenant_memberships
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_authorization_states_audit_operations_select ON public.tenant_authorization_states
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY user_platform_roles_audit_operations_select ON public.user_platform_roles
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_roles_audit_operations_select ON public.platform_roles
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_role_permissions_audit_operations_select ON public.platform_role_permissions
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_permissions_audit_operations_select ON public.platform_permissions
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
GRANT SELECT ON TABLE public.auth_sessions,public.users,public.tenants,
  public.tenant_memberships,public.tenant_authorization_states,
  public.user_platform_roles,public.platform_roles,public.platform_role_permissions,
  public.platform_permissions TO periapsis_audit_operations_owner;
--> statement-breakpoint
-- PostgreSQL checks table UPDATE privilege for row-locking clauses even for
-- FOR SHARE. The NOLOGIN owner receives that prerequisite only on the three
-- fenced rows. FORCE RLS deliberately has no UPDATE policy, so the owner can
-- neither lock nor mutate them directly; the narrow migrator-owned authority
-- helpers below are the only RLS-bypassing lock boundary.
GRANT UPDATE ON TABLE public.auth_sessions,public.tenant_memberships,
  public.tenant_authorization_states TO periapsis_audit_operations_owner;
--> statement-breakpoint
-- The two narrow migrator-owned authority helpers initialize and lock the
-- platform epoch row before reading the exact session and role permission
-- graph. The migrator is the existing NOLOGIN/BYPASSRLS schema authority;
-- no runtime role receives table access.
GRANT SELECT,INSERT,UPDATE ON TABLE public.platform_user_authorization_epochs
TO periapsis_migrator;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.context_tenant_id(),app.context_user_id(),
  app.current_tenant_membership_id(),app.require_live_audit_session_v1(uuid,uuid),
  app.current_tenant_human_has_exact_permission_v3(text,public.authorization_scope),
  app.platform_user_has_permission(uuid,text),app.private_platform_audit_reason_is_safe_v1(text),
  app.append_platform_audit_event(uuid,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,inet,text,text,public.audit_outcome,text,jsonb)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_require_tenant_audit_operation_actor_v1(
  p_session_id uuid,p_permission text,p_require_read boolean
)
RETURNS TABLE(
  actor_user_id uuid,membership_id uuid,membership_lifecycle_revision bigint,
  permission_epoch bigint,authentication_method text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_user uuid := app.context_user_id();
  locked_membership public.tenant_memberships%ROWTYPE;
  locked_epoch bigint;
  locked_session public.auth_sessions%ROWTYPE;
BEGIN
  IF p_permission NOT IN ('audit.export','audit.retention.manage') OR p_require_read IS NULL THEN
    RAISE EXCEPTION 'invalid tenant audit operation authority' USING ERRCODE = '22023';
  END IF;
  SELECT state.revision INTO locked_epoch
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = context_tenant AND state.revision BETWEEN 1 AND 9007199254740991
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is unavailable' USING ERRCODE = '42501';
  END IF;
  SELECT membership.* INTO locked_membership
  FROM public.tenant_memberships AS membership
  JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
  WHERE membership.tenant_id = context_tenant AND membership.user_id = context_user
    AND membership.status = 'active' AND tenant.status = 'active'
  FOR SHARE OF membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active tenant membership is required' USING ERRCODE = '42501';
  END IF;
  SELECT session.* INTO locked_session
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.id = p_session_id AND session.user_id = context_user
    AND session.active_tenant_id = context_tenant AND session.revoked_at IS NULL
    AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at <= transaction_timestamp()
    AND identity.active
  FOR SHARE OF session;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant audit session is required' USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(p_permission,'tenant')
     OR (p_require_read AND NOT app.current_tenant_human_has_exact_permission_v3('audit.read','tenant')) THEN
    RAISE EXCEPTION 'tenant audit operation permission is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT context_user,locked_membership.id,
    locked_membership.lifecycle_revision::bigint,locked_epoch,locked_session.authentication_method;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_require_tenant_audit_operation_actor_v1(uuid,text,boolean)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_require_tenant_audit_operation_actor_v1(uuid,text,boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_require_tenant_audit_operation_actor_v1(uuid,text,boolean)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_require_platform_audit_operation_actor_v1(
  p_session_id uuid,p_permission text,p_require_read boolean
)
RETURNS TABLE(actor_user_id uuid,permission_epoch bigint,authentication_method text)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_user uuid := app.context_user_id();
  locked_epoch bigint;
  locked_session public.auth_sessions%ROWTYPE;
BEGIN
  IF p_permission NOT IN ('platform.audit.export','platform.audit.retention.manage') OR p_require_read IS NULL THEN
    RAISE EXCEPTION 'invalid platform audit operation authority' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.platform_user_authorization_epochs(user_id)
  VALUES (context_user) ON CONFLICT (user_id) DO NOTHING;
  SELECT epoch.permission_epoch INTO locked_epoch
  FROM public.platform_user_authorization_epochs AS epoch
  WHERE epoch.user_id = context_user FOR SHARE;
  SELECT session.* INTO locked_session
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.id = p_session_id AND session.user_id = context_user
    AND session.revoked_at IS NULL AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at <= transaction_timestamp()
    AND identity.active
  FOR SHARE OF session;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live platform audit session is required' USING ERRCODE = '42501';
  END IF;
  IF NOT app.platform_user_has_permission(context_user,p_permission)
     OR (p_require_read AND NOT app.platform_user_has_permission(context_user,'platform.audit.read')) THEN
    RAISE EXCEPTION 'platform audit operation permission is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT context_user,locked_epoch,locked_session.authentication_method;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_require_platform_audit_operation_actor_v1(uuid,text,boolean)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_require_platform_audit_operation_actor_v1(uuid,text,boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_require_platform_audit_operation_actor_v1(uuid,text,boolean)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.create_tenant_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_job_id uuid,
  p_normalized_filter jsonb,p_filter_digest bytea,p_retention_seconds bigint,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  existing_receipt public.tenant_audit_operation_receipts%ROWTYPE;
  created_job public.tenant_audit_export_jobs%ROWTYPE;
  result_document jsonb;
  expected_payload_digest bytea;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.export' OR p_read_permission IS DISTINCT FROM 'audit.read'
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR octet_length(p_filter_digest) IS DISTINCT FROM 32
     OR (uuid_extract_version(p_job_id) = 7) IS NOT TRUE
     OR NOT app.private_audit_export_filter_is_valid_v1(p_normalized_filter,'tenant')
     OR p_filter_digest IS DISTINCT FROM sha256(convert_to(p_normalized_filter::text,'UTF8'))
     OR p_retention_seconds NOT BETWEEN 900 AND 604800
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit export request' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'filter',p_normalized_filter,'retentionSeconds',p_retention_seconds,
    'projectionVersion',1,'format','jsonl','reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'tenant audit export payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(
    p_session_id,'audit.export',true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor.actor_user_id::text || ':' || actor.membership_id::text
      || ':export.create:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'export.create'
    AND idempotency_key_digest = p_idempotency_key_digest
    AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt
  FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'export.create'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'tenant audit export idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.private_append_tenant_audit_operation_v1(
      p_session_id,p_audit_event_id,'audit.export.create_replayed','audit_export',
      (existing_receipt.response->'job'->>'id')::uuid,p_request_id,p_correlation_id,
      p_ip_address,p_user_agent,p_reason,NULL,NULL,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  INSERT INTO public.tenant_audit_export_jobs(
    id,tenant_id,requester_user_id,requester_membership_id,requester_session_id,
    membership_lifecycle_revision,permission_epoch,normalized_filter,filter_digest,
    expires_at
  ) VALUES (
    p_job_id,context_tenant,actor.actor_user_id,actor.membership_id,p_session_id,
    actor.membership_lifecycle_revision,actor.permission_epoch,p_normalized_filter,
    p_filter_digest,transaction_timestamp() + make_interval(secs => p_retention_seconds::double precision)
  ) RETURNING * INTO created_job;
  result_document := jsonb_build_object(
    'job',app.private_tenant_audit_export_job_document_v1(created_job),'replayed',false
  );
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.export.created','audit_export',created_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,NULL,
    jsonb_build_object('state','pending','revision',1),
    jsonb_build_object('filterSha256',encode(p_filter_digest,'hex'),'projectionVersion',1,'format','jsonl')
  );
  INSERT INTO public.tenant_audit_operation_receipts(
    tenant_id,actor_user_id,membership_id,action,idempotency_key_digest,payload_digest,
    response,expires_at
  ) VALUES (
    context_tenant,actor.actor_user_id,actor.membership_id,'export.create',
    p_idempotency_key_digest,p_payload_digest,result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.create_tenant_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  locked_job public.tenant_audit_export_jobs%ROWTYPE;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.export' OR p_read_permission IS DISTINCT FROM 'audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit export status request' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(p_session_id,'audit.export',true);
  SELECT * INTO locked_job FROM public.tenant_audit_export_jobs AS job
  WHERE job.tenant_id = context_tenant AND job.id = p_export_id
    AND job.requester_user_id = actor.actor_user_id
    AND job.requester_membership_id = actor.membership_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant audit export not found' USING ERRCODE = 'P0002';
  END IF;
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.export.status_accessed','audit_export',locked_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,'audit export status accessed',
    NULL,NULL,jsonb_build_object('state',locked_job.state,'revision',locked_job.revision)
  );
  RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.cancel_tenant_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,p_expected_revision bigint,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  existing_receipt public.tenant_audit_operation_receipts%ROWTYPE;
  locked_job public.tenant_audit_export_jobs%ROWTYPE;
  previous_state text;
  previous_revision bigint;
  result_document jsonb;
  expected_payload_digest bytea;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.export' OR p_read_permission IS DISTINCT FROM 'audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE
     OR p_expected_revision NOT BETWEEN 1 AND 9007199254740990
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit export cancellation' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'exportId',p_export_id,'expectedRevision',p_expected_revision,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'tenant audit export cancellation digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(p_session_id,'audit.export',true);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor.actor_user_id::text || ':' || actor.membership_id::text
      || ':export.cancel:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'export.cancel'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'export.cancel'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'tenant audit export cancellation idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.private_append_tenant_audit_operation_v1(
      p_session_id,p_audit_event_id,'audit.export.cancel_replayed','audit_export',p_export_id,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,NULL,NULL,
      jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_job FROM public.tenant_audit_export_jobs AS job
  WHERE job.tenant_id = context_tenant AND job.id = p_export_id
    AND job.requester_user_id = actor.actor_user_id
    AND job.requester_membership_id = actor.membership_id
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit export not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_job.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'tenant audit export revision conflict' USING ERRCODE = '40001';
  END IF;
  IF locked_job.state NOT IN ('pending','running') THEN
    RAISE EXCEPTION 'tenant audit export is not cancellable' USING ERRCODE = '55000';
  END IF;
  previous_state := locked_job.state; previous_revision := locked_job.revision;
  UPDATE public.tenant_audit_export_jobs AS job SET
    state = CASE WHEN job.state = 'pending' THEN 'cancelled' ELSE 'cancellation_requested' END,
    revision = job.revision + 1,updated_at = greatest(job.updated_at,clock_timestamp()),
    terminal_at = CASE WHEN job.state = 'pending' THEN greatest(job.updated_at,clock_timestamp()) ELSE NULL END,
    failure_code = 'none'
  WHERE job.tenant_id = context_tenant AND job.id = locked_job.id
  RETURNING * INTO locked_job;
  result_document := jsonb_build_object(
    'job',app.private_tenant_audit_export_job_document_v1(locked_job),'replayed',false
  );
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.export.cancelled','audit_export',locked_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,
    jsonb_build_object('state',previous_state,'revision',previous_revision),
    jsonb_build_object('state',locked_job.state,'revision',locked_job.revision),'{}'::jsonb
  );
  INSERT INTO public.tenant_audit_operation_receipts(
    tenant_id,actor_user_id,membership_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    context_tenant,actor.actor_user_id,actor.membership_id,'export.cancel',
    p_idempotency_key_digest,p_payload_digest,result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.cancel_tenant_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.cancel_tenant_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.cancel_tenant_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.authorize_tenant_audit_export_download_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS TABLE(
  artifact_id uuid,object_key text,digest bytea,rows bigint,bytes bigint,
  expires_at timestamp with time zone,filename text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  locked_job public.tenant_audit_export_jobs%ROWTYPE;
  locked_manifest public.tenant_audit_export_manifests%ROWTYPE;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.export' OR p_read_permission IS DISTINCT FROM 'audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit export download' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(p_session_id,'audit.export',true);
  SELECT * INTO locked_job FROM public.tenant_audit_export_jobs AS job
  WHERE job.tenant_id = context_tenant AND job.id = p_export_id
    AND job.requester_user_id = actor.actor_user_id
    AND job.requester_membership_id = actor.membership_id
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit export not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_job.membership_lifecycle_revision IS DISTINCT FROM actor.membership_lifecycle_revision
     OR locked_job.permission_epoch IS DISTINCT FROM actor.permission_epoch THEN
    RAISE EXCEPTION 'tenant audit export authorization pin is stale' USING ERRCODE = '42501';
  END IF;
  IF locked_job.state <> 'succeeded' OR locked_job.expires_at <= transaction_timestamp()
     OR locked_job.artifact_id IS NULL THEN
    RAISE EXCEPTION 'tenant audit export is unavailable' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO locked_manifest FROM public.tenant_audit_export_manifests AS manifest
  WHERE manifest.tenant_id = context_tenant AND manifest.job_id = locked_job.id
    AND manifest.artifact_id = locked_job.artifact_id
    AND manifest.job_revision = locked_job.revision
    AND manifest.object_key = locked_job.object_key
    AND manifest.digest = locked_job.artifact_digest
    AND manifest.rows = locked_job.artifact_rows AND manifest.bytes = locked_job.artifact_bytes
    AND manifest.expires_at = locked_job.expires_at AND manifest.expires_at > transaction_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit export manifest is unavailable' USING ERRCODE = '55000'; END IF;
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.export.downloaded','audit_export',locked_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,'audit export downloaded',NULL,NULL,
    jsonb_build_object('artifactId',locked_manifest.artifact_id,'sha256',encode(locked_manifest.digest,'hex'),
      'rows',locked_manifest.rows,'bytes',locked_manifest.bytes)
  );
  RETURN QUERY SELECT locked_manifest.artifact_id,locked_manifest.object_key,
    locked_manifest.digest,locked_manifest.rows,locked_manifest.bytes,locked_manifest.expires_at,
    'tenant-audit-' || context_tenant::text || '-' || locked_job.id::text || '.jsonl';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.authorize_tenant_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.authorize_tenant_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.authorize_tenant_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_job_id uuid,
  p_normalized_filter jsonb,p_filter_digest bytea,p_retention_seconds bigint,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  existing_receipt public.platform_audit_operation_receipts%ROWTYPE;
  created_job public.platform_audit_export_jobs%ROWTYPE;
  result_document jsonb;
  expected_payload_digest bytea;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.export'
     OR p_read_permission IS DISTINCT FROM 'platform.audit.read'
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR octet_length(p_filter_digest) IS DISTINCT FROM 32
     OR (uuid_extract_version(p_job_id) = 7) IS NOT TRUE
     OR NOT app.private_audit_export_filter_is_valid_v1(p_normalized_filter,'platform')
     OR p_filter_digest IS DISTINCT FROM sha256(convert_to(p_normalized_filter::text,'UTF8'))
     OR p_retention_seconds NOT BETWEEN 900 AND 604800
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform audit export request' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'filter',p_normalized_filter,'retentionSeconds',p_retention_seconds,
    'projectionVersion',1,'format','jsonl','reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'platform audit export payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.export',true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform:' || actor.actor_user_id::text || ':export.create:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'export.create'
    AND idempotency_key_digest = p_idempotency_key_digest
    AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'export.create'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'platform audit export idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.append_platform_audit_event(
      p_audit_event_id,'user',actor.actor_user_id,'audit.export.create_replayed','platform_audit_export',
      (existing_receipt.response->'job'->>'id')::uuid,p_request_id,p_correlation_id,p_ip_address,
      p_user_agent,actor.authentication_method,'success',p_reason,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  INSERT INTO public.platform_audit_export_jobs(
    id,requester_user_id,requester_session_id,permission_epoch,normalized_filter,filter_digest,expires_at
  ) VALUES (
    p_job_id,actor.actor_user_id,p_session_id,actor.permission_epoch,p_normalized_filter,p_filter_digest,
    transaction_timestamp() + make_interval(secs => p_retention_seconds::double precision)
  ) RETURNING * INTO created_job;
  result_document := jsonb_build_object(
    'job',app.private_platform_audit_export_job_document_v1(created_job),'replayed',false
  );
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.export.created','platform_audit_export',created_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,'success',p_reason,
    jsonb_build_object('state','pending','revision',1,'filterSha256',encode(p_filter_digest,'hex'),
      'projectionVersion',1,'format','jsonl')
  );
  INSERT INTO public.platform_audit_operation_receipts(
    actor_user_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    actor.actor_user_id,'export.create',p_idempotency_key_digest,p_payload_digest,
    result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.create_platform_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_platform_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_platform_audit_export_v1(
  uuid,text,text,bytea,bytea,uuid,jsonb,bytea,bigint,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  locked_job public.platform_audit_export_jobs%ROWTYPE;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.export'
     OR p_read_permission IS DISTINCT FROM 'platform.audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit export status request' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.export',true
  );
  SELECT * INTO locked_job FROM public.platform_audit_export_jobs AS job
  WHERE job.id = p_export_id AND job.requester_user_id = actor.actor_user_id FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export not found' USING ERRCODE = 'P0002'; END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.export.status_accessed','platform_audit_export',
    locked_job.id,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
    'success','audit export status accessed',jsonb_build_object('state',locked_job.state,'revision',locked_job.revision)
  );
  RETURN app.private_platform_audit_export_job_document_v1(locked_job);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_platform_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_audit_export_v1(uuid,text,text,uuid,uuid,uuid,uuid,inet,text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.cancel_platform_audit_export_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,p_expected_revision bigint,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  existing_receipt public.platform_audit_operation_receipts%ROWTYPE;
  locked_job public.platform_audit_export_jobs%ROWTYPE;
  previous_state text;
  previous_revision bigint;
  result_document jsonb;
  expected_payload_digest bytea;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.export'
     OR p_read_permission IS DISTINCT FROM 'platform.audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE
     OR p_expected_revision NOT BETWEEN 1 AND 9007199254740990
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform audit export cancellation' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'exportId',p_export_id,'expectedRevision',p_expected_revision,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'platform audit export cancellation digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.export',true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform:' || actor.actor_user_id::text || ':export.cancel:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'export.cancel'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'export.cancel'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'platform audit export cancellation idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.append_platform_audit_event(
      p_audit_event_id,'user',actor.actor_user_id,'audit.export.cancel_replayed','platform_audit_export',
      p_export_id,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
      'success',p_reason,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_job FROM public.platform_audit_export_jobs AS job
  WHERE job.id = p_export_id AND job.requester_user_id = actor.actor_user_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_job.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'platform audit export revision conflict' USING ERRCODE = '40001';
  END IF;
  IF locked_job.state NOT IN ('pending','running') THEN
    RAISE EXCEPTION 'platform audit export is not cancellable' USING ERRCODE = '55000';
  END IF;
  previous_state := locked_job.state; previous_revision := locked_job.revision;
  UPDATE public.platform_audit_export_jobs AS job SET
    state = CASE WHEN job.state = 'pending' THEN 'cancelled' ELSE 'cancellation_requested' END,
    revision = job.revision + 1,updated_at = greatest(job.updated_at,clock_timestamp()),
    terminal_at = CASE WHEN job.state = 'pending' THEN greatest(job.updated_at,clock_timestamp()) ELSE NULL END,
    failure_code = 'none'
  WHERE job.id = locked_job.id RETURNING * INTO locked_job;
  result_document := jsonb_build_object(
    'job',app.private_platform_audit_export_job_document_v1(locked_job),'replayed',false
  );
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.export.cancelled','platform_audit_export',locked_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,'success',p_reason,
    jsonb_build_object('previousState',previous_state,'previousRevision',previous_revision,
      'state',locked_job.state,'revision',locked_job.revision)
  );
  INSERT INTO public.platform_audit_operation_receipts(
    actor_user_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    actor.actor_user_id,'export.cancel',p_idempotency_key_digest,p_payload_digest,
    result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.cancel_platform_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.cancel_platform_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.cancel_platform_audit_export_v1(
  uuid,text,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.authorize_platform_audit_export_download_v1(
  p_session_id uuid,p_permission text,p_read_permission text,p_export_id uuid,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS TABLE(
  artifact_id uuid,object_key text,digest bytea,rows bigint,bytes bigint,
  expires_at timestamp with time zone,filename text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  locked_job public.platform_audit_export_jobs%ROWTYPE;
  locked_manifest public.platform_audit_export_manifests%ROWTYPE;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.export'
     OR p_read_permission IS DISTINCT FROM 'platform.audit.read'
     OR (uuid_extract_version(p_export_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit export download' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.export',true
  );
  SELECT * INTO locked_job FROM public.platform_audit_export_jobs AS job
  WHERE job.id = p_export_id AND job.requester_user_id = actor.actor_user_id FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_job.permission_epoch IS DISTINCT FROM actor.permission_epoch THEN
    RAISE EXCEPTION 'platform audit export authorization pin is stale' USING ERRCODE = '42501';
  END IF;
  IF locked_job.state <> 'succeeded' OR locked_job.expires_at <= transaction_timestamp()
     OR locked_job.artifact_id IS NULL THEN
    RAISE EXCEPTION 'platform audit export is unavailable' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO locked_manifest FROM public.platform_audit_export_manifests AS manifest
  WHERE manifest.job_id = locked_job.id AND manifest.artifact_id = locked_job.artifact_id
    AND manifest.job_revision = locked_job.revision AND manifest.object_key = locked_job.object_key
    AND manifest.digest = locked_job.artifact_digest
    AND manifest.rows = locked_job.artifact_rows AND manifest.bytes = locked_job.artifact_bytes
    AND manifest.expires_at = locked_job.expires_at AND manifest.expires_at > transaction_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export manifest is unavailable' USING ERRCODE = '55000'; END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.export.downloaded','platform_audit_export',locked_job.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,'success',
    'audit export downloaded',jsonb_build_object('artifactId',locked_manifest.artifact_id,
      'sha256',encode(locked_manifest.digest,'hex'),'rows',locked_manifest.rows,'bytes',locked_manifest.bytes)
  );
  RETURN QUERY SELECT locked_manifest.artifact_id,locked_manifest.object_key,
    locked_manifest.digest,locked_manifest.rows,locked_manifest.bytes,locked_manifest.expires_at,
    'platform-audit-' || locked_job.id::text || '.jsonl';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.authorize_platform_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.authorize_platform_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.authorize_platform_audit_export_download_v1(
  uuid,text,text,uuid,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ensure_tenant_audit_retention_state_v1(
  p_tenant_id uuid,p_actor_user_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  inserted_policy boolean := false;
BEGIN
  INSERT INTO public.tenant_audit_retention_policies(
    tenant_id,retention_days,revision,updated_by_user_id,reason
  ) VALUES (p_tenant_id,365,1,p_actor_user_id,'default audit retention policy initialized')
  ON CONFLICT (tenant_id) DO NOTHING;
  inserted_policy := FOUND;
  INSERT INTO public.tenant_audit_retention_anchors(tenant_id)
  VALUES (p_tenant_id) ON CONFLICT (tenant_id) DO NOTHING;
  RETURN inserted_policy;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_ensure_tenant_audit_retention_state_v1(uuid,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ensure_tenant_audit_retention_state_v1(uuid,uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_audit_retention_state_document_v1(p_tenant_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'stream','tenant','tenantId',policy.tenant_id,
    'policy',jsonb_build_object('retentionDays',policy.retention_days,'revision',policy.revision,'updatedAt',policy.updated_at),
    'anchor',jsonb_build_object('retainedThroughSequence',anchor.retained_through_sequence,
      'retainedThroughHash',anchor.retained_through_hash,'revision',anchor.revision,'updatedAt',anchor.updated_at),
    'activeLegalHold',CASE WHEN hold.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',hold.id,'state',hold.state,'revision',hold.revision,'placedAt',hold.placed_at,'releasedAt',hold.released_at
    ) END
  ))
  FROM public.tenant_audit_retention_policies AS policy
  JOIN public.tenant_audit_retention_anchors AS anchor ON anchor.tenant_id = policy.tenant_id
  LEFT JOIN LATERAL (
    SELECT legal_hold.* FROM public.tenant_audit_legal_holds AS legal_hold
    WHERE legal_hold.tenant_id = policy.tenant_id AND legal_hold.state = 'active'
    ORDER BY legal_hold.id LIMIT 1
  ) AS hold ON true
  WHERE policy.tenant_id = p_tenant_id;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_tenant_audit_retention_state_document_v1(uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_tenant_audit_retention_state_document_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_audit_retention_v1(
  p_session_id uuid,p_permission text,p_audit_event_id uuid,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  initialized boolean;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.retention.manage' THEN
    RAISE EXCEPTION 'invalid tenant audit retention read' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(
    p_session_id,'audit.retention.manage',false
  );
  initialized := app.private_ensure_tenant_audit_retention_state_v1(context_tenant,actor.actor_user_id);
  result_document := app.private_tenant_audit_retention_state_document_v1(context_tenant);
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,
    CASE WHEN initialized THEN 'audit.retention.initialized' ELSE 'audit.retention.status_accessed' END,
    'audit_retention',context_tenant,p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    CASE WHEN initialized THEN 'default audit retention policy initialized' ELSE 'audit retention status accessed' END,
    NULL,NULL,jsonb_build_object('retentionDays',result_document->'policy'->'retentionDays',
      'policyRevision',result_document->'policy'->'revision',
      'retainedThroughSequence',result_document->'anchor'->'retainedThroughSequence')
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.update_tenant_audit_retention_v1(
  p_session_id uuid,p_permission text,p_expected_revision bigint,p_retention_days integer,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  existing_receipt public.tenant_audit_operation_receipts%ROWTYPE;
  locked_policy public.tenant_audit_retention_policies%ROWTYPE;
  previous_days integer;
  previous_revision bigint;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.retention.manage'
     OR p_expected_revision NOT BETWEEN 1 AND 9007199254740990
     OR p_retention_days NOT BETWEEN 30 AND 3650
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit retention change' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'expectedRevision',p_expected_revision,'retentionDays',p_retention_days,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'tenant audit retention payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(
    p_session_id,'audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||context_tenant::text,0));
  PERFORM app.private_ensure_tenant_audit_retention_state_v1(context_tenant,actor.actor_user_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor.actor_user_id::text || ':' || actor.membership_id::text
      || ':retention.change:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'retention.change'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'retention.change'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'tenant audit retention idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.private_append_tenant_audit_operation_v1(
      p_session_id,p_audit_event_id,'audit.retention.change_replayed','audit_retention',context_tenant,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,NULL,NULL,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_policy FROM public.tenant_audit_retention_policies AS policy
  WHERE policy.tenant_id = context_tenant FOR UPDATE;
  IF locked_policy.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'tenant audit retention revision conflict' USING ERRCODE = '40001';
  END IF;
  previous_days := locked_policy.retention_days; previous_revision := locked_policy.revision;
  UPDATE public.tenant_audit_retention_policies SET
    retention_days = p_retention_days,revision = revision + 1,
    updated_by_user_id = actor.actor_user_id,reason = p_reason,
    updated_at = greatest(updated_at,clock_timestamp())
  WHERE tenant_id = context_tenant RETURNING * INTO locked_policy;
  result_document := jsonb_build_object(
    'state',app.private_tenant_audit_retention_state_document_v1(context_tenant),'replayed',false
  );
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.retention.changed','audit_retention',context_tenant,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,
    jsonb_build_object('retentionDays',previous_days,'revision',previous_revision),
    jsonb_build_object('retentionDays',locked_policy.retention_days,'revision',locked_policy.revision),'{}'::jsonb
  );
  INSERT INTO public.tenant_audit_operation_receipts(
    tenant_id,actor_user_id,membership_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    context_tenant,actor.actor_user_id,actor.membership_id,'retention.change',
    p_idempotency_key_digest,p_payload_digest,result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.update_tenant_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_tenant_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_tenant_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.place_tenant_audit_legal_hold_v1(
  p_session_id uuid,p_permission text,p_hold_id uuid,p_idempotency_key_digest bytea,
  p_payload_digest bytea,p_reason text,p_audit_event_id uuid,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  existing_receipt public.tenant_audit_operation_receipts%ROWTYPE;
  created_hold public.tenant_audit_legal_holds%ROWTYPE;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.retention.manage'
     OR (uuid_extract_version(p_hold_id) = 7) IS NOT TRUE
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit legal hold' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object('reason',p_reason)::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'tenant audit legal hold payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(
    p_session_id,'audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||context_tenant::text,0));
  PERFORM app.private_ensure_tenant_audit_retention_state_v1(context_tenant,actor.actor_user_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor.actor_user_id::text || ':' || actor.membership_id::text
      || ':legal_hold.place:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'legal_hold.place'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'legal_hold.place'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'tenant legal hold idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.private_append_tenant_audit_operation_v1(
      p_session_id,p_audit_event_id,'audit.legal_hold.place_replayed','audit_legal_hold',
      (existing_receipt.response->'hold'->>'id')::uuid,p_request_id,p_correlation_id,
      p_ip_address,p_user_agent,p_reason,NULL,NULL,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  INSERT INTO public.tenant_audit_legal_holds(
    id,tenant_id,placed_by_user_id,placement_reason
  ) VALUES (p_hold_id,context_tenant,actor.actor_user_id,p_reason)
  RETURNING * INTO created_hold;
  result_document := jsonb_build_object('hold',jsonb_build_object(
    'id',created_hold.id,'state',created_hold.state,'revision',created_hold.revision,
    'placedAt',created_hold.placed_at
  ),'replayed',false);
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.legal_hold.placed','audit_legal_hold',created_hold.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,NULL,
    jsonb_build_object('state','active','revision',1),'{}'::jsonb
  );
  INSERT INTO public.tenant_audit_operation_receipts(
    tenant_id,actor_user_id,membership_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    context_tenant,actor.actor_user_id,actor.membership_id,'legal_hold.place',
    p_idempotency_key_digest,p_payload_digest,result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.place_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.place_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.place_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.release_tenant_audit_legal_hold_v1(
  p_session_id uuid,p_permission text,p_hold_id uuid,p_expected_revision bigint,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor record;
  existing_receipt public.tenant_audit_operation_receipts%ROWTYPE;
  locked_hold public.tenant_audit_legal_holds%ROWTYPE;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.retention.manage'
     OR (uuid_extract_version(p_hold_id) = 7) IS NOT TRUE OR p_expected_revision IS DISTINCT FROM 1
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit legal hold release' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'holdId',p_hold_id,'expectedRevision',p_expected_revision,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'tenant audit legal hold release digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_tenant_audit_operation_actor_v1(
    p_session_id,'audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||context_tenant::text,0));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor.actor_user_id::text || ':' || actor.membership_id::text
      || ':legal_hold.release:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'legal_hold.release'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.tenant_audit_operation_receipts
  WHERE tenant_id = context_tenant AND actor_user_id = actor.actor_user_id
    AND membership_id = actor.membership_id AND action = 'legal_hold.release'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'tenant legal hold release idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.private_append_tenant_audit_operation_v1(
      p_session_id,p_audit_event_id,'audit.legal_hold.release_replayed','audit_legal_hold',p_hold_id,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,NULL,NULL,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_hold FROM public.tenant_audit_legal_holds AS hold
  WHERE hold.tenant_id = context_tenant AND hold.id = p_hold_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit legal hold not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_hold.revision IS DISTINCT FROM p_expected_revision OR locked_hold.state <> 'active' THEN
    RAISE EXCEPTION 'tenant audit legal hold revision conflict' USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_audit_legal_holds SET
    state = 'released',revision = 2,released_by_user_id = actor.actor_user_id,
    released_at = greatest(placed_at,clock_timestamp()),release_reason = p_reason
  WHERE tenant_id = context_tenant AND id = p_hold_id RETURNING * INTO locked_hold;
  result_document := jsonb_build_object('hold',jsonb_build_object(
    'id',locked_hold.id,'state',locked_hold.state,'revision',locked_hold.revision,
    'placedAt',locked_hold.placed_at,'releasedAt',locked_hold.released_at
  ),'replayed',false);
  PERFORM app.private_append_tenant_audit_operation_v1(
    p_session_id,p_audit_event_id,'audit.legal_hold.released','audit_legal_hold',locked_hold.id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_reason,
    jsonb_build_object('state','active','revision',1),jsonb_build_object('state','released','revision',2),'{}'::jsonb
  );
  INSERT INTO public.tenant_audit_operation_receipts(
    tenant_id,actor_user_id,membership_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    context_tenant,actor.actor_user_id,actor.membership_id,'legal_hold.release',
    p_idempotency_key_digest,p_payload_digest,result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.release_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.release_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.release_tenant_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ensure_platform_audit_retention_state_v1(p_actor_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  inserted_policy boolean := false;
BEGIN
  INSERT INTO public.platform_audit_retention_policy(
    singleton,retention_days,revision,updated_by_user_id,reason
  ) VALUES (true,730,1,p_actor_user_id,'default platform audit retention policy initialized')
  ON CONFLICT (singleton) DO NOTHING;
  inserted_policy := FOUND;
  INSERT INTO public.platform_audit_retention_anchor(singleton)
  VALUES (true) ON CONFLICT (singleton) DO NOTHING;
  RETURN inserted_policy;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_ensure_platform_audit_retention_state_v1(uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ensure_platform_audit_retention_state_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_audit_retention_state_document_v1()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'stream','platform',
    'policy',jsonb_build_object('retentionDays',policy.retention_days,'revision',policy.revision,'updatedAt',policy.updated_at),
    'anchor',jsonb_build_object('retainedThroughSequence',anchor.retained_through_sequence,
      'retainedThroughHash',anchor.retained_through_hash,'revision',anchor.revision,'updatedAt',anchor.updated_at),
    'activeLegalHold',CASE WHEN hold.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',hold.id,'state',hold.state,'revision',hold.revision,'placedAt',hold.placed_at,'releasedAt',hold.released_at
    ) END
  ))
  FROM public.platform_audit_retention_policy AS policy
  JOIN public.platform_audit_retention_anchor AS anchor ON anchor.singleton = policy.singleton
  LEFT JOIN LATERAL (
    SELECT legal_hold.* FROM public.platform_audit_legal_holds AS legal_hold
    WHERE legal_hold.state = 'active' ORDER BY legal_hold.id LIMIT 1
  ) AS hold ON true
  WHERE policy.singleton;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_audit_retention_state_document_v1()
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_audit_retention_state_document_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_audit_retention_v1(
  p_session_id uuid,p_permission text,p_audit_event_id uuid,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  initialized boolean;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.retention.manage' THEN
    RAISE EXCEPTION 'invalid platform audit retention read' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.retention.manage',false
  );
  initialized := app.private_ensure_platform_audit_retention_state_v1(actor.actor_user_id);
  result_document := app.private_platform_audit_retention_state_document_v1();
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,
    CASE WHEN initialized THEN 'audit.retention.initialized' ELSE 'audit.retention.status_accessed' END,
    'platform_audit_retention',NULL,p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    actor.authentication_method,'success',
    CASE WHEN initialized THEN 'default platform audit retention policy initialized' ELSE 'audit retention status accessed' END,
    jsonb_build_object('retentionDays',result_document->'policy'->'retentionDays',
      'policyRevision',result_document->'policy'->'revision',
      'retainedThroughSequence',result_document->'anchor'->'retainedThroughSequence')
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_platform_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_audit_retention_v1(uuid,text,uuid,uuid,uuid,inet,text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_audit_retention_v1(
  p_session_id uuid,p_permission text,p_expected_revision bigint,p_retention_days integer,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  existing_receipt public.platform_audit_operation_receipts%ROWTYPE;
  locked_policy public.platform_audit_retention_policy%ROWTYPE;
  previous_days integer;
  previous_revision bigint;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.retention.manage'
     OR p_expected_revision NOT BETWEEN 1 AND 9007199254740990
     OR p_retention_days NOT BETWEEN 30 AND 3650
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform audit retention change' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'expectedRevision',p_expected_revision,'retentionDays',p_retention_days,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'platform audit retention payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  PERFORM app.private_ensure_platform_audit_retention_state_v1(actor.actor_user_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform:' || actor.actor_user_id::text || ':retention.change:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'retention.change'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'retention.change'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'platform audit retention idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.append_platform_audit_event(
      p_audit_event_id,'user',actor.actor_user_id,'audit.retention.change_replayed','platform_audit_retention',
      NULL,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
      'success',p_reason,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_policy FROM public.platform_audit_retention_policy AS policy
  WHERE policy.singleton FOR UPDATE;
  IF locked_policy.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'platform audit retention revision conflict' USING ERRCODE = '40001';
  END IF;
  previous_days := locked_policy.retention_days; previous_revision := locked_policy.revision;
  UPDATE public.platform_audit_retention_policy SET
    retention_days = p_retention_days,revision = revision + 1,
    updated_by_user_id = actor.actor_user_id,reason = p_reason,
    updated_at = greatest(updated_at,clock_timestamp())
  WHERE singleton RETURNING * INTO locked_policy;
  result_document := jsonb_build_object(
    'state',app.private_platform_audit_retention_state_document_v1(),'replayed',false
  );
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.retention.changed','platform_audit_retention',NULL,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,'success',p_reason,
    jsonb_build_object('previousRetentionDays',previous_days,'previousRevision',previous_revision,
      'retentionDays',locked_policy.retention_days,'revision',locked_policy.revision)
  );
  INSERT INTO public.platform_audit_operation_receipts(
    actor_user_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    actor.actor_user_id,'retention.change',p_idempotency_key_digest,p_payload_digest,
    result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.update_platform_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_platform_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_platform_audit_retention_v1(
  uuid,text,bigint,integer,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.place_platform_audit_legal_hold_v1(
  p_session_id uuid,p_permission text,p_hold_id uuid,p_idempotency_key_digest bytea,
  p_payload_digest bytea,p_reason text,p_audit_event_id uuid,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  existing_receipt public.platform_audit_operation_receipts%ROWTYPE;
  created_hold public.platform_audit_legal_holds%ROWTYPE;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.retention.manage'
     OR (uuid_extract_version(p_hold_id) = 7) IS NOT TRUE
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform audit legal hold' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object('reason',p_reason)::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'platform audit legal hold payload digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  PERFORM app.private_ensure_platform_audit_retention_state_v1(actor.actor_user_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform:' || actor.actor_user_id::text || ':legal_hold.place:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'legal_hold.place'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'legal_hold.place'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'platform legal hold idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.append_platform_audit_event(
      p_audit_event_id,'user',actor.actor_user_id,'audit.legal_hold.place_replayed','platform_audit_legal_hold',
      (existing_receipt.response->'hold'->>'id')::uuid,p_request_id,p_correlation_id,p_ip_address,
      p_user_agent,actor.authentication_method,'success',p_reason,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  INSERT INTO public.platform_audit_legal_holds(id,placed_by_user_id,placement_reason)
  VALUES (p_hold_id,actor.actor_user_id,p_reason) RETURNING * INTO created_hold;
  result_document := jsonb_build_object('hold',jsonb_build_object(
    'id',created_hold.id,'state',created_hold.state,'revision',created_hold.revision,
    'placedAt',created_hold.placed_at
  ),'replayed',false);
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.legal_hold.placed','platform_audit_legal_hold',
    created_hold.id,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
    'success',p_reason,jsonb_build_object('state','active','revision',1)
  );
  INSERT INTO public.platform_audit_operation_receipts(
    actor_user_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    actor.actor_user_id,'legal_hold.place',p_idempotency_key_digest,p_payload_digest,
    result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.place_platform_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.place_platform_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.place_platform_audit_legal_hold_v1(
  uuid,text,uuid,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.release_platform_audit_legal_hold_v1(
  p_session_id uuid,p_permission text,p_hold_id uuid,p_expected_revision bigint,
  p_idempotency_key_digest bytea,p_payload_digest bytea,p_reason text,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  existing_receipt public.platform_audit_operation_receipts%ROWTYPE;
  locked_hold public.platform_audit_legal_holds%ROWTYPE;
  expected_payload_digest bytea;
  result_document jsonb;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.retention.manage'
     OR (uuid_extract_version(p_hold_id) = 7) IS NOT TRUE OR p_expected_revision IS DISTINCT FROM 1
     OR octet_length(p_idempotency_key_digest) IS DISTINCT FROM 32
     OR octet_length(p_payload_digest) IS DISTINCT FROM 32
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform audit legal hold release' USING ERRCODE = '22023';
  END IF;
  expected_payload_digest := sha256(convert_to(jsonb_build_object(
    'holdId',p_hold_id,'expectedRevision',p_expected_revision,'reason',p_reason
  )::text,'UTF8'));
  IF p_payload_digest IS DISTINCT FROM expected_payload_digest THEN
    RAISE EXCEPTION 'platform audit legal hold release digest mismatch' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO actor FROM app.private_require_platform_audit_operation_actor_v1(
    p_session_id,'platform.audit.retention.manage',false
  );
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform:' || actor.actor_user_id::text || ':legal_hold.release:' || encode(p_idempotency_key_digest,'hex'),0
  ));
  DELETE FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'legal_hold.release'
    AND idempotency_key_digest = p_idempotency_key_digest AND expires_at <= transaction_timestamp();
  SELECT * INTO existing_receipt FROM public.platform_audit_operation_receipts
  WHERE actor_user_id = actor.actor_user_id AND action = 'legal_hold.release'
    AND idempotency_key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF existing_receipt.payload_digest IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'platform legal hold release idempotency key was reused' USING ERRCODE = '23505';
    END IF;
    PERFORM app.append_platform_audit_event(
      p_audit_event_id,'user',actor.actor_user_id,'audit.legal_hold.release_replayed','platform_audit_legal_hold',
      p_hold_id,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
      'success',p_reason,jsonb_build_object('replayed',true)
    );
    RETURN jsonb_set(existing_receipt.response,'{replayed}','true'::jsonb,false);
  END IF;
  SELECT * INTO locked_hold FROM public.platform_audit_legal_holds AS hold
  WHERE hold.id = p_hold_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit legal hold not found' USING ERRCODE = 'P0002'; END IF;
  IF locked_hold.revision IS DISTINCT FROM p_expected_revision OR locked_hold.state <> 'active' THEN
    RAISE EXCEPTION 'platform audit legal hold revision conflict' USING ERRCODE = '40001';
  END IF;
  UPDATE public.platform_audit_legal_holds SET
    state = 'released',revision = 2,released_by_user_id = actor.actor_user_id,
    released_at = greatest(placed_at,clock_timestamp()),release_reason = p_reason
  WHERE id = p_hold_id RETURNING * INTO locked_hold;
  result_document := jsonb_build_object('hold',jsonb_build_object(
    'id',locked_hold.id,'state',locked_hold.state,'revision',locked_hold.revision,
    'placedAt',locked_hold.placed_at,'releasedAt',locked_hold.released_at
  ),'replayed',false);
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor.actor_user_id,'audit.legal_hold.released','platform_audit_legal_hold',
    locked_hold.id,p_request_id,p_correlation_id,p_ip_address,p_user_agent,actor.authentication_method,
    'success',p_reason,jsonb_build_object('previousState','active','previousRevision',1,
      'state','released','revision',2)
  );
  INSERT INTO public.platform_audit_operation_receipts(
    actor_user_id,action,idempotency_key_digest,payload_digest,response,expires_at
  ) VALUES (
    actor.actor_user_id,'legal_hold.release',p_idempotency_key_digest,p_payload_digest,
    result_document,transaction_timestamp()+interval '24 hours'
  );
  RETURN result_document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.release_platform_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.release_platform_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.release_platform_audit_legal_hold_v1(
  uuid,text,uuid,bigint,bytea,bytea,text,uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE POLICY audit_events_audit_operations_system_insert
  ON public.audit_events FOR INSERT TO periapsis_audit_operations_owner
  WITH CHECK (
    actor_type = 'system' AND actor_user_id IS NULL
    AND actor_service_account_id IS NULL AND impersonated_by_user_id IS NULL
  );
--> statement-breakpoint

CREATE FUNCTION app.private_append_tenant_audit_worker_v1(
  p_tenant_id uuid,p_event_id uuid,p_action text,p_resource_type text,p_resource_id uuid,
  p_reason text,p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_event_id) = 7) IS NOT TRUE
     OR p_action !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR p_resource_type !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant audit worker envelope' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events(
    id,tenant_id,sequence,actor_type,action,resource_type,resource_id,
    authentication_method,outcome,reason,metadata
  ) VALUES (
    p_event_id,p_tenant_id,1,'system',p_action,p_resource_type,p_resource_id,
    'worker','success',p_reason,coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_tenant_audit_worker_v1(uuid,uuid,text,text,uuid,text,jsonb)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_tenant_audit_worker_v1(uuid,uuid,text,text,uuid,text,jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_audit_export_job_authorized_v1(p_job public.tenant_audit_export_jobs)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  epoch_revision bigint;
  membership_revision bigint;
  live_session boolean;
BEGIN
  PERFORM set_config('app.tenant_id',p_job.tenant_id::text,true);
  PERFORM set_config('app.user_id',p_job.requester_user_id::text,true);
  SELECT state.revision INTO epoch_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_job.tenant_id FOR SHARE;
  SELECT membership.lifecycle_revision::bigint INTO membership_revision
  FROM public.tenant_memberships AS membership
  JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = p_job.tenant_id
    AND membership.id = p_job.requester_membership_id
    AND membership.user_id = p_job.requester_user_id
    AND membership.status = 'active' AND tenant.status = 'active' AND identity.active
  FOR SHARE OF membership;
  SELECT true INTO live_session
  FROM public.auth_sessions AS session
  WHERE session.id = p_job.requester_session_id AND session.user_id = p_job.requester_user_id
    AND session.active_tenant_id = p_job.tenant_id AND session.revoked_at IS NULL
    AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL AND session.mfa_satisfied_at <= transaction_timestamp()
  FOR SHARE;
  RETURN coalesce(epoch_revision = p_job.permission_epoch,false)
     AND coalesce(membership_revision = p_job.membership_lifecycle_revision,false)
     AND coalesce(live_session,false)
     AND app.current_tenant_human_has_exact_permission_v3('audit.export','tenant')
     AND app.current_tenant_human_has_exact_permission_v3('audit.read','tenant');
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_tenant_audit_export_job_authorized_v1(public.tenant_audit_export_jobs)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_tenant_audit_export_job_authorized_v1(public.tenant_audit_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_tenant_audit_export_job_authorized_v1(public.tenant_audit_export_jobs)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_audit_export_job_authorized_v1(p_job public.platform_audit_export_jobs)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  epoch_revision bigint;
  live_session boolean;
BEGIN
  PERFORM set_config('app.tenant_id','',true);
  PERFORM set_config('app.user_id',p_job.requester_user_id::text,true);
  SELECT epoch.permission_epoch INTO epoch_revision
  FROM public.platform_user_authorization_epochs AS epoch
  WHERE epoch.user_id = p_job.requester_user_id FOR SHARE;
  SELECT true INTO live_session
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.id = p_job.requester_session_id AND session.user_id = p_job.requester_user_id
    AND session.revoked_at IS NULL AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL AND session.mfa_satisfied_at <= transaction_timestamp()
    AND identity.active
  FOR SHARE OF session;
  RETURN coalesce(epoch_revision = p_job.permission_epoch,false)
     AND coalesce(live_session,false)
     AND app.platform_user_has_permission(p_job.requester_user_id,'platform.audit.export')
     AND app.platform_user_has_permission(p_job.requester_user_id,'platform.audit.read');
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_audit_export_job_authorized_v1(public.platform_audit_export_jobs)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_audit_export_job_authorized_v1(public.platform_audit_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_platform_audit_export_job_authorized_v1(public.platform_audit_export_jobs)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.claim_tenant_audit_export_v1(
  p_worker_id uuid,p_lease_fence bytea,p_lease_seconds integer,p_audit_event_id uuid
)
RETURNS TABLE(
  job_id uuid,tenant_id uuid,normalized_filter jsonb,projection_version integer,
  format text,object_key text,expires_at timestamp with time zone,lease_expires_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  candidate public.tenant_audit_export_jobs%ROWTYPE;
  changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR p_lease_seconds NOT BETWEEN 30 AND 900
     OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit export claim' USING ERRCODE = '22023';
  END IF;
  LOOP
    SELECT job.* INTO candidate FROM public.tenant_audit_export_jobs AS job
    WHERE (
      (job.state = 'pending' AND job.available_at <= transaction_timestamp())
      OR (job.state IN ('running','cancellation_requested') AND job.lease_expires_at <= transaction_timestamp())
    )
    ORDER BY job.available_at,job.tenant_id,job.id
    FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    changed_at := greatest(candidate.updated_at,clock_timestamp());
    IF candidate.state = 'cancellation_requested' THEN
      UPDATE public.tenant_audit_export_jobs AS job SET state='cancelled',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL
      WHERE job.tenant_id=candidate.tenant_id AND job.id=candidate.id;
      PERFORM app.private_append_tenant_audit_worker_v1(candidate.tenant_id,p_audit_event_id,
        'audit.export.cancelled','audit_export',candidate.id,'audit export cancellation acknowledged',
        jsonb_build_object('workerId',p_worker_id));
      RETURN;
    END IF;
    IF candidate.expires_at <= transaction_timestamp() THEN
      UPDATE public.tenant_audit_export_jobs AS job SET state='expired',failure_code='expired',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL
      WHERE job.tenant_id=candidate.tenant_id AND job.id=candidate.id;
      CONTINUE;
    END IF;
    IF candidate.state='running' AND candidate.attempts >= candidate.maximum_attempts THEN
      UPDATE public.tenant_audit_export_jobs AS job SET state='failed',failure_code='lease_expired',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL
      WHERE job.tenant_id=candidate.tenant_id AND job.id=candidate.id;
      PERFORM app.private_append_tenant_audit_worker_v1(candidate.tenant_id,p_audit_event_id,
        'audit.export.failed','audit_export',candidate.id,'audit export lease attempts exhausted',
        jsonb_build_object('failureCode','lease_expired'));
      RETURN;
    END IF;
    IF NOT app.private_tenant_audit_export_job_authorized_v1(candidate) THEN
      UPDATE public.tenant_audit_export_jobs AS job SET state='authorization_revoked',failure_code='authorization_revoked',
        revision=job.revision+1,updated_at=changed_at,terminal_at=changed_at,
        lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL
      WHERE job.tenant_id=candidate.tenant_id AND job.id=candidate.id;
      PERFORM app.private_append_tenant_audit_worker_v1(candidate.tenant_id,p_audit_event_id,
        'audit.export.authorization_revoked','audit_export',candidate.id,
        'audit export authorization pin is no longer live',jsonb_build_object('requesterUserId',candidate.requester_user_id));
      RETURN;
    END IF;
    UPDATE public.tenant_audit_export_jobs AS job SET state='running',revision=job.revision+1,
      attempts=job.attempts+1,failure_code='none',updated_at=changed_at,
      lease_worker_id=p_worker_id,lease_fence=p_lease_fence,lease_claimed_at=changed_at,
      lease_expires_at=changed_at+make_interval(secs=>p_lease_seconds)
    WHERE job.tenant_id=candidate.tenant_id AND job.id=candidate.id RETURNING job.* INTO candidate;
    RETURN QUERY SELECT candidate.id,candidate.tenant_id,candidate.normalized_filter,
      candidate.projection_version,candidate.format,
      'tenants/'||candidate.tenant_id::text||'/audit/exports/'||candidate.id::text||'/v1.jsonl',
      candidate.expires_at,candidate.lease_expires_at;
    RETURN;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_tenant_audit_export_v1(uuid,bytea,integer,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_tenant_audit_export_v1(uuid,bytea,integer,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_tenant_audit_export_v1(uuid,bytea,integer,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.claim_platform_audit_export_v1(
  p_worker_id uuid,p_lease_fence bytea,p_lease_seconds integer,p_audit_event_id uuid
)
RETURNS TABLE(
  job_id uuid,normalized_filter jsonb,projection_version integer,format text,
  object_key text,expires_at timestamp with time zone,lease_expires_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  candidate public.platform_audit_export_jobs%ROWTYPE;
  changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR p_lease_seconds NOT BETWEEN 30 AND 900
     OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit export claim' USING ERRCODE = '22023';
  END IF;
  LOOP
    SELECT job.* INTO candidate FROM public.platform_audit_export_jobs AS job
    WHERE ((job.state='pending' AND job.available_at<=transaction_timestamp())
        OR (job.state IN ('running','cancellation_requested') AND job.lease_expires_at<=transaction_timestamp()))
    ORDER BY job.available_at,job.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    changed_at:=greatest(candidate.updated_at,clock_timestamp());
    IF candidate.state='cancellation_requested' THEN
      UPDATE public.platform_audit_export_jobs AS job SET state='cancelled',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL WHERE job.id=candidate.id;
      PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.cancelled',
        'platform_audit_export',candidate.id,NULL,NULL,NULL,'worker','worker','success',
        'audit export cancellation acknowledged',jsonb_build_object('workerId',p_worker_id));
      RETURN;
    END IF;
    IF candidate.expires_at<=transaction_timestamp() THEN
      UPDATE public.platform_audit_export_jobs AS job SET state='expired',failure_code='expired',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL WHERE job.id=candidate.id;
      CONTINUE;
    END IF;
    IF candidate.state='running' AND candidate.attempts>=candidate.maximum_attempts THEN
      UPDATE public.platform_audit_export_jobs AS job SET state='failed',failure_code='lease_expired',revision=job.revision+1,
        updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
        lease_claimed_at=NULL,lease_expires_at=NULL WHERE job.id=candidate.id;
      PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.failed',
        'platform_audit_export',candidate.id,NULL,NULL,NULL,'worker','worker','success',
        'audit export lease attempts exhausted',jsonb_build_object('failureCode','lease_expired'));
      RETURN;
    END IF;
    IF NOT app.private_platform_audit_export_job_authorized_v1(candidate) THEN
      UPDATE public.platform_audit_export_jobs AS job SET state='authorization_revoked',failure_code='authorization_revoked',
        revision=job.revision+1,updated_at=changed_at,terminal_at=changed_at,
        lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL WHERE job.id=candidate.id;
      PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.authorization_revoked',
        'platform_audit_export',candidate.id,NULL,NULL,NULL,'worker','worker','success',
        'audit export authorization pin is no longer live',jsonb_build_object('requesterUserId',candidate.requester_user_id));
      RETURN;
    END IF;
    UPDATE public.platform_audit_export_jobs AS job SET state='running',revision=job.revision+1,
      attempts=job.attempts+1,failure_code='none',updated_at=changed_at,
      lease_worker_id=p_worker_id,lease_fence=p_lease_fence,lease_claimed_at=changed_at,
      lease_expires_at=changed_at+make_interval(secs=>p_lease_seconds)
    WHERE job.id=candidate.id RETURNING job.* INTO candidate;
    RETURN QUERY SELECT candidate.id,candidate.normalized_filter,candidate.projection_version,
      candidate.format,'platform/audit/exports/'||candidate.id::text||'/v1.jsonl',
      candidate.expires_at,candidate.lease_expires_at;
    RETURN;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_platform_audit_export_v1(uuid,bytea,integer,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_platform_audit_export_v1(uuid,bytea,integer,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_platform_audit_export_v1(uuid,bytea,integer,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE POLICY audit_events_audit_operations_select ON public.audit_events
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_events_audit_operations_select ON public.platform_audit_events
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
GRANT SELECT ON TABLE public.audit_events,public.platform_audit_events
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.read_tenant_audit_export_page_v1(
  p_worker_id uuid,p_job_id uuid,p_lease_fence bytea,p_after_sequence bigint,p_limit integer
)
RETURNS TABLE(sequence bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_job public.tenant_audit_export_jobs%ROWTYPE;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_job_id)=7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR p_after_sequence < 0 OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid tenant audit export page request' USING ERRCODE='22023';
  END IF;
  SELECT * INTO locked_job FROM public.tenant_audit_export_jobs AS job
  WHERE job.id=p_job_id AND job.state='running' AND job.lease_worker_id=p_worker_id
    AND job.lease_fence=p_lease_fence AND job.lease_expires_at>transaction_timestamp()
    AND job.expires_at>transaction_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit export lease is not live' USING ERRCODE='42501'; END IF;
  IF NOT app.private_tenant_audit_export_job_authorized_v1(locked_job) THEN
    RAISE EXCEPTION 'tenant audit export authorization pin is not live' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT event.sequence,jsonb_strip_nulls(jsonb_build_object(
    'projectionVersion',1,'stream','tenant','tenantId',event.tenant_id,
    'sequence',event.sequence,'id',event.id,'occurredAt',event.occurred_at,
    'actorType',event.actor_type,'actorUserId',event.actor_user_id,
    'actorServiceAccountId',event.actor_service_account_id,
    'impersonatedByUserId',event.impersonated_by_user_id,
    'action',event.action,'resourceType',event.resource_type,'resourceId',event.resource_id,
    'requestId',event.request_id,'correlationId',event.correlation_id,
    'ipAddress',event.ip_address,'userAgent',event.user_agent,
    'authenticationMethod',event.authentication_method,'outcome',event.outcome,
    'reason',event.reason,'before',event.before,'after',event.after,'metadata',event.metadata,
    'previousHash',event.previous_hash,'eventHash',event.event_hash
  ))
  FROM public.audit_events AS event
  WHERE event.tenant_id=locked_job.tenant_id AND event.sequence>p_after_sequence
    AND (NOT (locked_job.normalized_filter?'occurredFrom')
      OR event.occurred_at >= (locked_job.normalized_filter->>'occurredFrom')::timestamp with time zone)
    AND (NOT (locked_job.normalized_filter?'occurredBefore')
      OR event.occurred_at < (locked_job.normalized_filter->>'occurredBefore')::timestamp with time zone)
    AND (NOT (locked_job.normalized_filter?'actorType')
      OR event.actor_type::text=locked_job.normalized_filter->>'actorType')
    AND (NOT (locked_job.normalized_filter?'actorUserId')
      OR event.actor_user_id=(locked_job.normalized_filter->>'actorUserId')::uuid)
    AND (NOT (locked_job.normalized_filter?'actorServiceAccountId')
      OR event.actor_service_account_id=(locked_job.normalized_filter->>'actorServiceAccountId')::uuid)
    AND (NOT (locked_job.normalized_filter?'actionPrefix')
      OR event.action=locked_job.normalized_filter->>'actionPrefix'
      OR event.action LIKE (locked_job.normalized_filter->>'actionPrefix')||'.%')
    AND (NOT (locked_job.normalized_filter?'resourceType')
      OR event.resource_type=locked_job.normalized_filter->>'resourceType')
    AND (NOT (locked_job.normalized_filter?'resourceId')
      OR event.resource_id=(locked_job.normalized_filter->>'resourceId')::uuid)
    AND (NOT (locked_job.normalized_filter?'requestId')
      OR event.request_id=(locked_job.normalized_filter->>'requestId')::uuid)
    AND (NOT (locked_job.normalized_filter?'correlationId')
      OR event.correlation_id=(locked_job.normalized_filter->>'correlationId')::uuid)
    AND (NOT (locked_job.normalized_filter?'outcome')
      OR event.outcome::text=locked_job.normalized_filter->>'outcome')
    AND (NOT (locked_job.normalized_filter?'search')
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(event.action))>0
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(event.resource_type))>0
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(coalesce(event.reason,'')))>0)
  ORDER BY event.sequence LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_tenant_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_tenant_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_tenant_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_platform_audit_export_page_v1(
  p_worker_id uuid,p_job_id uuid,p_lease_fence bytea,p_after_sequence bigint,p_limit integer
)
RETURNS TABLE(sequence bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_job public.platform_audit_export_jobs%ROWTYPE;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_job_id)=7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR p_after_sequence<0 OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid platform audit export page request' USING ERRCODE='22023';
  END IF;
  SELECT * INTO locked_job FROM public.platform_audit_export_jobs AS job
  WHERE job.id=p_job_id AND job.state='running' AND job.lease_worker_id=p_worker_id
    AND job.lease_fence=p_lease_fence AND job.lease_expires_at>transaction_timestamp()
    AND job.expires_at>transaction_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export lease is not live' USING ERRCODE='42501'; END IF;
  IF NOT app.private_platform_audit_export_job_authorized_v1(locked_job) THEN
    RAISE EXCEPTION 'platform audit export authorization pin is not live' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT event.sequence,jsonb_strip_nulls(jsonb_build_object(
    'projectionVersion',1,'stream','platform','sequence',event.sequence,'id',event.id,
    'occurredAt',event.occurred_at,'actorType',event.actor_type,'actorUserId',event.actor_user_id,
    'action',event.action,'resourceType',event.resource_type,'resourceId',event.resource_id,
    'requestId',event.request_id,'correlationId',event.correlation_id,
    'ipAddress',event.ip_address,'userAgent',event.user_agent,
    'authenticationMethod',event.authentication_method,'outcome',event.outcome,
    'reason',event.reason,'before',event.before,'after',event.after,'metadata',event.metadata,
    'previousHash',event.previous_hash,'eventHash',event.event_hash
  ))
  FROM public.platform_audit_events AS event
  WHERE event.sequence>p_after_sequence
    AND (NOT (locked_job.normalized_filter?'occurredFrom')
      OR event.occurred_at >= (locked_job.normalized_filter->>'occurredFrom')::timestamp with time zone)
    AND (NOT (locked_job.normalized_filter?'occurredBefore')
      OR event.occurred_at < (locked_job.normalized_filter->>'occurredBefore')::timestamp with time zone)
    AND (NOT (locked_job.normalized_filter?'actorType')
      OR event.actor_type::text=locked_job.normalized_filter->>'actorType')
    AND (NOT (locked_job.normalized_filter?'actorUserId')
      OR event.actor_user_id=(locked_job.normalized_filter->>'actorUserId')::uuid)
    AND (NOT (locked_job.normalized_filter?'actionPrefix')
      OR event.action=locked_job.normalized_filter->>'actionPrefix'
      OR event.action LIKE (locked_job.normalized_filter->>'actionPrefix')||'.%')
    AND (NOT (locked_job.normalized_filter?'resourceType')
      OR event.resource_type=locked_job.normalized_filter->>'resourceType')
    AND (NOT (locked_job.normalized_filter?'resourceId')
      OR event.resource_id=(locked_job.normalized_filter->>'resourceId')::uuid)
    AND (NOT (locked_job.normalized_filter?'requestId')
      OR event.request_id=(locked_job.normalized_filter->>'requestId')::uuid)
    AND (NOT (locked_job.normalized_filter?'correlationId')
      OR event.correlation_id=(locked_job.normalized_filter->>'correlationId')::uuid)
    AND (NOT (locked_job.normalized_filter?'outcome')
      OR event.outcome::text=locked_job.normalized_filter->>'outcome')
    AND (NOT (locked_job.normalized_filter?'search')
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(event.action))>0
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(event.resource_type))>0
      OR position(lower(locked_job.normalized_filter->>'search') IN lower(coalesce(event.reason,'')))>0)
  ORDER BY event.sequence LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_platform_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_platform_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_platform_audit_export_page_v1(uuid,uuid,bytea,bigint,integer)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.finalize_tenant_audit_export_v1(
  p_worker_id uuid,p_job_id uuid,p_lease_fence bytea,p_artifact_id uuid,
  p_digest bytea,p_rows bigint,p_bytes bigint,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_job public.tenant_audit_export_jobs%ROWTYPE;
  changed_at timestamp with time zone;
  derived_key text;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE OR (uuid_extract_version(p_job_id)=7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR (uuid_extract_version(p_artifact_id)=7) IS NOT TRUE OR octet_length(p_digest) IS DISTINCT FROM 32
     OR p_rows NOT BETWEEN 0 AND 1000000 OR p_bytes NOT BETWEEN 0 AND 1073741824
     OR (p_rows=0) IS DISTINCT FROM (p_bytes=0)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit export finalization' USING ERRCODE='22023';
  END IF;
  SELECT * INTO locked_job FROM public.tenant_audit_export_jobs AS job
  WHERE job.id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit export lease is not owned' USING ERRCODE='42501'; END IF;
  IF locked_job.state='succeeded'
     AND locked_job.artifact_id=p_artifact_id
     AND locked_job.artifact_digest=p_digest
     AND locked_job.artifact_rows=p_rows
     AND locked_job.artifact_bytes=p_bytes THEN
    RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
  END IF;
  IF locked_job.lease_worker_id IS DISTINCT FROM p_worker_id
     OR locked_job.lease_fence IS DISTINCT FROM p_lease_fence
     OR locked_job.state NOT IN ('running','cancellation_requested') THEN
    RAISE EXCEPTION 'tenant audit export lease is not owned' USING ERRCODE='42501';
  END IF;
  changed_at:=greatest(locked_job.updated_at,clock_timestamp());
  IF locked_job.state='cancellation_requested' THEN
    UPDATE public.tenant_audit_export_jobs SET state='cancelled',revision=revision+1,
      updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
      lease_claimed_at=NULL,lease_expires_at=NULL
    WHERE tenant_id=locked_job.tenant_id AND id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.private_append_tenant_audit_worker_v1(locked_job.tenant_id,p_audit_event_id,
      'audit.export.cancelled','audit_export',locked_job.id,'audit export cancellation acknowledged',
      jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
  END IF;
  IF locked_job.lease_expires_at<=transaction_timestamp() THEN
    RAISE EXCEPTION 'tenant audit export lease expired' USING ERRCODE='42501';
  END IF;
  IF locked_job.expires_at<=transaction_timestamp() THEN
    UPDATE public.tenant_audit_export_jobs SET state='expired',failure_code='expired',
      revision=revision+1,updated_at=changed_at,terminal_at=changed_at,
      lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL
    WHERE tenant_id=locked_job.tenant_id AND id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.private_append_tenant_audit_worker_v1(locked_job.tenant_id,p_audit_event_id,
      'audit.export.expired','audit_export',locked_job.id,'audit export retention expired',
      jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
  END IF;
  IF NOT app.private_tenant_audit_export_job_authorized_v1(locked_job) THEN
    UPDATE public.tenant_audit_export_jobs SET state='authorization_revoked',failure_code='authorization_revoked',
      revision=revision+1,updated_at=changed_at,terminal_at=changed_at,
      lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL
    WHERE tenant_id=locked_job.tenant_id AND id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.private_append_tenant_audit_worker_v1(locked_job.tenant_id,p_audit_event_id,
      'audit.export.authorization_revoked','audit_export',locked_job.id,
      'audit export authorization pin is no longer live',jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
  END IF;
  derived_key:='tenants/'||locked_job.tenant_id::text||'/audit/exports/'||locked_job.id::text||'/v1.jsonl';
  UPDATE public.tenant_audit_export_jobs SET state='succeeded',revision=revision+1,
    failure_code='none',updated_at=changed_at,terminal_at=changed_at,
    lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL,
    artifact_id=p_artifact_id,object_key=derived_key,artifact_digest=p_digest,
    artifact_rows=p_rows,artifact_bytes=p_bytes,artifact_expires_at=expires_at
  WHERE tenant_id=locked_job.tenant_id AND id=locked_job.id RETURNING * INTO locked_job;
  INSERT INTO public.tenant_audit_export_manifests(
    tenant_id,job_id,artifact_id,job_revision,projection_version,format,object_key,
    digest,rows,bytes,published_at,expires_at
  ) VALUES (
    locked_job.tenant_id,locked_job.id,p_artifact_id,locked_job.revision,
    locked_job.projection_version,locked_job.format,derived_key,p_digest,p_rows,p_bytes,changed_at,locked_job.expires_at
  );
  PERFORM app.private_append_tenant_audit_worker_v1(locked_job.tenant_id,p_audit_event_id,
    'audit.export.completed','audit_export',locked_job.id,'audit export artifact published',
    jsonb_build_object('artifactId',p_artifact_id,'sha256',encode(p_digest,'hex'),'rows',p_rows,'bytes',p_bytes));
  RETURN app.private_tenant_audit_export_job_document_v1(locked_job);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.finalize_tenant_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.finalize_tenant_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.finalize_tenant_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.finalize_platform_audit_export_v1(
  p_worker_id uuid,p_job_id uuid,p_lease_fence bytea,p_artifact_id uuid,
  p_digest bytea,p_rows bigint,p_bytes bigint,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_job public.platform_audit_export_jobs%ROWTYPE;
  changed_at timestamp with time zone;
  derived_key text;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE OR (uuid_extract_version(p_job_id)=7) IS NOT TRUE
     OR octet_length(p_lease_fence) IS DISTINCT FROM 32
     OR (uuid_extract_version(p_artifact_id)=7) IS NOT TRUE OR octet_length(p_digest) IS DISTINCT FROM 32
     OR p_rows NOT BETWEEN 0 AND 1000000 OR p_bytes NOT BETWEEN 0 AND 1073741824
     OR (p_rows=0) IS DISTINCT FROM (p_bytes=0)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit export finalization' USING ERRCODE='22023';
  END IF;
  SELECT * INTO locked_job FROM public.platform_audit_export_jobs AS job
  WHERE job.id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit export lease is not owned' USING ERRCODE='42501'; END IF;
  IF locked_job.state='succeeded'
     AND locked_job.artifact_id=p_artifact_id
     AND locked_job.artifact_digest=p_digest
     AND locked_job.artifact_rows=p_rows
     AND locked_job.artifact_bytes=p_bytes THEN
    RETURN app.private_platform_audit_export_job_document_v1(locked_job);
  END IF;
  IF locked_job.lease_worker_id IS DISTINCT FROM p_worker_id
     OR locked_job.lease_fence IS DISTINCT FROM p_lease_fence
     OR locked_job.state NOT IN ('running','cancellation_requested') THEN
    RAISE EXCEPTION 'platform audit export lease is not owned' USING ERRCODE='42501';
  END IF;
  changed_at:=greatest(locked_job.updated_at,clock_timestamp());
  IF locked_job.state='cancellation_requested' THEN
    UPDATE public.platform_audit_export_jobs SET state='cancelled',revision=revision+1,
      updated_at=changed_at,terminal_at=changed_at,lease_worker_id=NULL,lease_fence=NULL,
      lease_claimed_at=NULL,lease_expires_at=NULL WHERE id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.cancelled',
      'platform_audit_export',locked_job.id,NULL,NULL,NULL,'worker','worker','success',
      'audit export cancellation acknowledged',jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_platform_audit_export_job_document_v1(locked_job);
  END IF;
  IF locked_job.lease_expires_at<=transaction_timestamp() THEN
    RAISE EXCEPTION 'platform audit export lease expired' USING ERRCODE='42501';
  END IF;
  IF locked_job.expires_at<=transaction_timestamp() THEN
    UPDATE public.platform_audit_export_jobs SET state='expired',failure_code='expired',
      revision=revision+1,updated_at=changed_at,terminal_at=changed_at,
      lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL
    WHERE id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.expired',
      'platform_audit_export',locked_job.id,NULL,NULL,NULL,'worker','worker','success',
      'audit export retention expired',jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_platform_audit_export_job_document_v1(locked_job);
  END IF;
  IF NOT app.private_platform_audit_export_job_authorized_v1(locked_job) THEN
    UPDATE public.platform_audit_export_jobs SET state='authorization_revoked',failure_code='authorization_revoked',
      revision=revision+1,updated_at=changed_at,terminal_at=changed_at,
      lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL
    WHERE id=locked_job.id RETURNING * INTO locked_job;
    PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.authorization_revoked',
      'platform_audit_export',locked_job.id,NULL,NULL,NULL,'worker','worker','success',
      'audit export authorization pin is no longer live',jsonb_build_object('workerId',p_worker_id));
    RETURN app.private_platform_audit_export_job_document_v1(locked_job);
  END IF;
  derived_key:='platform/audit/exports/'||locked_job.id::text||'/v1.jsonl';
  UPDATE public.platform_audit_export_jobs SET state='succeeded',revision=revision+1,
    failure_code='none',updated_at=changed_at,terminal_at=changed_at,
    lease_worker_id=NULL,lease_fence=NULL,lease_claimed_at=NULL,lease_expires_at=NULL,
    artifact_id=p_artifact_id,object_key=derived_key,artifact_digest=p_digest,
    artifact_rows=p_rows,artifact_bytes=p_bytes,artifact_expires_at=expires_at
  WHERE id=locked_job.id RETURNING * INTO locked_job;
  INSERT INTO public.platform_audit_export_manifests(
    job_id,artifact_id,job_revision,projection_version,format,object_key,digest,rows,bytes,published_at,expires_at
  ) VALUES (
    locked_job.id,p_artifact_id,locked_job.revision,locked_job.projection_version,locked_job.format,
    derived_key,p_digest,p_rows,p_bytes,changed_at,locked_job.expires_at
  );
  PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.export.completed',
    'platform_audit_export',locked_job.id,NULL,NULL,NULL,'worker','worker','success',
    'audit export artifact published',jsonb_build_object('artifactId',p_artifact_id,
      'sha256',encode(p_digest,'hex'),'rows',p_rows,'bytes',p_bytes));
  RETURN app.private_platform_audit_export_job_document_v1(locked_job);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.finalize_platform_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.finalize_platform_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.finalize_platform_audit_export_v1(uuid,uuid,bytea,uuid,bytea,bigint,bigint,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE POLICY audit_chain_heads_audit_operations_select ON public.audit_chain_heads
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_chain_head_audit_operations_select ON public.platform_audit_chain_head
  FOR SELECT TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
GRANT SELECT ON TABLE public.audit_chain_heads,public.platform_audit_chain_head
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE'
     AND current_user='periapsis_audit_operations_owner'
     AND OLD.tenant_id::text=current_setting('app.audit_retention_prune_tenant_id',true)
     AND OLD.sequence BETWEEN current_setting('app.audit_retention_prune_start',true)::bigint
                          AND current_setting('app.audit_retention_prune_end',true)::bigint
     AND current_setting('app.audit_retention_prune_segment_id',true)<>'' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit events are append-only' USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.reject_audit_event_mutation() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reject_audit_event_mutation()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.reject_platform_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE'
     AND current_user='periapsis_audit_operations_owner'
     AND OLD.sequence BETWEEN current_setting('app.platform_audit_retention_prune_start',true)::bigint
                          AND current_setting('app.platform_audit_retention_prune_end',true)::bigint
     AND current_setting('app.platform_audit_retention_prune_segment_id',true)<>'' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'platform audit events are append-only' USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.reject_platform_audit_event_mutation() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reject_platform_audit_event_mutation()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT DELETE ON TABLE public.audit_events,public.platform_audit_events
TO periapsis_audit_operations_owner;
--> statement-breakpoint
CREATE POLICY audit_events_audit_operations_delete ON public.audit_events
  FOR DELETE TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_events_audit_operations_delete ON public.platform_audit_events
  FOR DELETE TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint

-- Closing a retention segment must serialize against the canonical append
-- head. Those pre-existing heads are FORCE-RLS tables owned by the migrator;
-- expose only the two fixed lock operations to the NOLOGIN audit owner.
CREATE FUNCTION app.private_lock_tenant_audit_retention_chain_v1(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit retention chain lock' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM public.audit_chain_heads AS head
  WHERE head.tenant_id=p_tenant_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant audit retention chain head is unavailable' USING ERRCODE='42501';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_lock_tenant_audit_retention_chain_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_lock_tenant_audit_retention_chain_v1(uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_lock_tenant_audit_retention_chain_v1(uuid)
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_lock_platform_audit_retention_chain_v1()
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  PERFORM 1 FROM public.platform_audit_chain_head AS head
  WHERE head.singleton FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform audit retention chain head is unavailable' USING ERRCODE='42501';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_lock_platform_audit_retention_chain_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_lock_platform_audit_retention_chain_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor,
  periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_lock_platform_audit_retention_chain_v1()
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.close_tenant_audit_segment_v1(
  p_worker_id uuid,p_tenant_id uuid,p_max_events integer,p_reason text,p_audit_event_id uuid
)
RETURNS TABLE(
  segment_id uuid,tenant_id uuid,start_sequence bigint,end_sequence bigint,
  previous_hash character(64),end_hash character(64),event_count bigint,
  object_key text,cutoff_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  policy_days integer;
  locked_anchor public.tenant_audit_retention_anchors%ROWTYPE;
  first_sequence bigint;
  last_sequence bigint;
  first_previous_hash character(64);
  last_event_hash character(64);
  selected_count bigint;
  new_segment_id uuid:=uuidv7();
  effective_cutoff timestamp with time zone;
  derived_key text;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE
     OR p_max_events NOT BETWEEN 1 AND 100000
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit segment closure' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||p_tenant_id::text,0));
  IF EXISTS (SELECT 1 FROM public.tenant_audit_legal_holds AS hold
             WHERE hold.tenant_id=p_tenant_id AND hold.state='active') THEN RETURN; END IF;
  SELECT policy.retention_days INTO policy_days
  FROM public.tenant_audit_retention_policies AS policy WHERE policy.tenant_id=p_tenant_id FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  INSERT INTO public.tenant_audit_retention_anchors(tenant_id)
  VALUES(p_tenant_id)
  ON CONFLICT ON CONSTRAINT tenant_audit_retention_anchors_pkey DO NOTHING;
  SELECT * INTO locked_anchor FROM public.tenant_audit_retention_anchors AS anchor
  WHERE anchor.tenant_id=p_tenant_id FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM public.tenant_audit_segments AS segment
    WHERE segment.tenant_id=p_tenant_id
      AND segment.start_sequence=locked_anchor.retained_through_sequence+1
      AND segment.state IN ('closed','preserved')
  ) THEN RETURN; END IF;
  effective_cutoff:=transaction_timestamp()-make_interval(days=>policy_days);
  PERFORM app.private_lock_tenant_audit_retention_chain_v1(p_tenant_id);
  WITH eligible AS (
    SELECT event.sequence,event.previous_hash,event.event_hash
    FROM public.audit_events AS event
    WHERE event.tenant_id=p_tenant_id
      AND event.sequence>locked_anchor.retained_through_sequence
      AND event.occurred_at<effective_cutoff
    ORDER BY event.sequence LIMIT p_max_events
  )
  SELECT min(eligible.sequence),max(eligible.sequence),
    (array_agg(eligible.previous_hash ORDER BY eligible.sequence))[1],
    (array_agg(eligible.event_hash ORDER BY eligible.sequence DESC))[1],count(*)::bigint
  INTO first_sequence,last_sequence,first_previous_hash,last_event_hash,selected_count
  FROM eligible;
  IF selected_count IS NULL OR selected_count=0 THEN RETURN; END IF;
  IF first_sequence<>locked_anchor.retained_through_sequence+1
     OR first_previous_hash<>locked_anchor.retained_through_hash
     OR selected_count<>last_sequence-first_sequence+1 THEN
    RAISE EXCEPTION 'tenant audit retention prefix is not contiguous' USING ERRCODE='55000';
  END IF;
  derived_key:='tenants/'||p_tenant_id::text||'/audit/segments/'||first_sequence::text||'-'||
    last_sequence::text||'/'||new_segment_id::text||'.jsonl';
  INSERT INTO public.tenant_audit_segments(
    id,tenant_id,start_sequence,end_sequence,previous_hash,end_hash,event_count,
    cutoff_at,reason,object_key
  ) VALUES (
    new_segment_id,p_tenant_id,first_sequence,last_sequence,first_previous_hash,last_event_hash,
    selected_count,effective_cutoff,p_reason,derived_key
  );
  PERFORM app.private_append_tenant_audit_worker_v1(p_tenant_id,p_audit_event_id,
    'audit.retention.segment_closed','audit_retention_segment',new_segment_id,p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',first_sequence,
      'endSequence',last_sequence,'eventCount',selected_count,'cutoffAt',effective_cutoff));
  RETURN QUERY SELECT new_segment_id,p_tenant_id,first_sequence,last_sequence,
    first_previous_hash,last_event_hash,selected_count,derived_key,effective_cutoff;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.close_tenant_audit_segment_v1(uuid,uuid,integer,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.close_tenant_audit_segment_v1(uuid,uuid,integer,text,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.close_tenant_audit_segment_v1(uuid,uuid,integer,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.close_platform_audit_segment_v1(
  p_worker_id uuid,p_max_events integer,p_reason text,p_audit_event_id uuid
)
RETURNS TABLE(
  segment_id uuid,start_sequence bigint,end_sequence bigint,previous_hash character(64),
  end_hash character(64),event_count bigint,object_key text,cutoff_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  policy_days integer;
  locked_anchor public.platform_audit_retention_anchor%ROWTYPE;
  first_sequence bigint; last_sequence bigint; selected_count bigint;
  first_previous_hash character(64); last_event_hash character(64);
  new_segment_id uuid:=uuidv7(); effective_cutoff timestamp with time zone; derived_key text;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE OR p_max_events NOT BETWEEN 1 AND 100000
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit segment closure' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  IF EXISTS (SELECT 1 FROM public.platform_audit_legal_holds WHERE state='active') THEN RETURN; END IF;
  SELECT retention_days INTO policy_days FROM public.platform_audit_retention_policy
  WHERE singleton FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  INSERT INTO public.platform_audit_retention_anchor(singleton) VALUES(true)
  ON CONFLICT(singleton) DO NOTHING;
  SELECT * INTO locked_anchor FROM public.platform_audit_retention_anchor WHERE singleton FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM public.platform_audit_segments AS segment
    WHERE segment.start_sequence=locked_anchor.retained_through_sequence+1
      AND segment.state IN ('closed','preserved')
  ) THEN RETURN; END IF;
  effective_cutoff:=transaction_timestamp()-make_interval(days=>policy_days);
  PERFORM app.private_lock_platform_audit_retention_chain_v1();
  WITH eligible AS (
    SELECT event.sequence,event.previous_hash,event.event_hash
    FROM public.platform_audit_events AS event
    WHERE event.sequence>locked_anchor.retained_through_sequence AND event.occurred_at<effective_cutoff
    ORDER BY event.sequence LIMIT p_max_events
  )
  SELECT min(eligible.sequence),max(eligible.sequence),
    (array_agg(eligible.previous_hash ORDER BY eligible.sequence))[1],
    (array_agg(eligible.event_hash ORDER BY eligible.sequence DESC))[1],count(*)::bigint
  INTO first_sequence,last_sequence,first_previous_hash,last_event_hash,selected_count FROM eligible;
  IF selected_count IS NULL OR selected_count=0 THEN RETURN; END IF;
  IF first_sequence<>locked_anchor.retained_through_sequence+1
     OR first_previous_hash<>locked_anchor.retained_through_hash
     OR selected_count<>last_sequence-first_sequence+1 THEN
    RAISE EXCEPTION 'platform audit retention prefix is not contiguous' USING ERRCODE='55000';
  END IF;
  derived_key:='platform/audit/segments/'||first_sequence::text||'-'||last_sequence::text||'/'||new_segment_id::text||'.jsonl';
  INSERT INTO public.platform_audit_segments(
    id,start_sequence,end_sequence,previous_hash,end_hash,event_count,cutoff_at,reason,object_key
  ) VALUES(new_segment_id,first_sequence,last_sequence,first_previous_hash,last_event_hash,
    selected_count,effective_cutoff,p_reason,derived_key);
  PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,'audit.retention.segment_closed',
    'platform_audit_retention_segment',new_segment_id,NULL,NULL,NULL,'worker','worker','success',p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',first_sequence,
      'endSequence',last_sequence,'eventCount',selected_count,'cutoffAt',effective_cutoff));
  RETURN QUERY SELECT new_segment_id,first_sequence,last_sequence,first_previous_hash,last_event_hash,
    selected_count,derived_key,effective_cutoff;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.close_platform_audit_segment_v1(uuid,integer,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.close_platform_audit_segment_v1(uuid,integer,text,uuid)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.close_platform_audit_segment_v1(uuid,integer,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

-- Retention artifacts use the same explicit, redacted projection as exports.
-- The worker receives neither relation privileges nor a generic audit reader.
CREATE FUNCTION app.read_tenant_audit_segment_page_v1(
  p_worker_id uuid,p_tenant_id uuid,p_segment_id uuid,p_after_sequence bigint,p_limit integer
)
RETURNS TABLE(sequence bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.tenant_audit_segments%ROWTYPE;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_after_sequence<0 OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid tenant audit segment page request' USING ERRCODE='22023';
  END IF;
  SELECT segment.* INTO locked_segment
  FROM public.tenant_audit_segments AS segment
  WHERE segment.tenant_id=p_tenant_id AND segment.id=p_segment_id
    AND segment.state='closed' AND segment.revision=1
  FOR SHARE;
  IF NOT FOUND OR p_after_sequence<locked_segment.start_sequence-1
     OR p_after_sequence>locked_segment.end_sequence THEN
    RAISE EXCEPTION 'tenant audit segment is not readable' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT event.sequence,jsonb_strip_nulls(jsonb_build_object(
    'projectionVersion',1,'stream','tenant','tenantId',event.tenant_id,
    'sequence',event.sequence,'id',event.id,'occurredAt',event.occurred_at,
    'actorType',event.actor_type,'actorUserId',event.actor_user_id,
    'actorServiceAccountId',event.actor_service_account_id,
    'impersonatedByUserId',event.impersonated_by_user_id,
    'action',event.action,'resourceType',event.resource_type,'resourceId',event.resource_id,
    'requestId',event.request_id,'correlationId',event.correlation_id,
    'ipAddress',event.ip_address,'userAgent',event.user_agent,
    'authenticationMethod',event.authentication_method,'outcome',event.outcome,
    'reason',event.reason,'before',event.before,'after',event.after,'metadata',event.metadata,
    'previousHash',event.previous_hash,'eventHash',event.event_hash
  ))
  FROM public.audit_events AS event
  WHERE event.tenant_id=p_tenant_id AND event.sequence>p_after_sequence
    AND event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence
  ORDER BY event.sequence LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_tenant_audit_segment_page_v1(uuid,uuid,uuid,bigint,integer)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_tenant_audit_segment_page_v1(uuid,uuid,uuid,bigint,integer)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_tenant_audit_segment_page_v1(uuid,uuid,uuid,bigint,integer)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_platform_audit_segment_page_v1(
  p_worker_id uuid,p_segment_id uuid,p_after_sequence bigint,p_limit integer
)
RETURNS TABLE(sequence bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.platform_audit_segments%ROWTYPE;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_after_sequence<0 OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid platform audit segment page request' USING ERRCODE='22023';
  END IF;
  SELECT segment.* INTO locked_segment
  FROM public.platform_audit_segments AS segment
  WHERE segment.id=p_segment_id AND segment.state='closed' AND segment.revision=1
  FOR SHARE;
  IF NOT FOUND OR p_after_sequence<locked_segment.start_sequence-1
     OR p_after_sequence>locked_segment.end_sequence THEN
    RAISE EXCEPTION 'platform audit segment is not readable' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT event.sequence,jsonb_strip_nulls(jsonb_build_object(
    'projectionVersion',1,'stream','platform','sequence',event.sequence,'id',event.id,
    'occurredAt',event.occurred_at,'actorType',event.actor_type,'actorUserId',event.actor_user_id,
    'action',event.action,'resourceType',event.resource_type,'resourceId',event.resource_id,
    'requestId',event.request_id,'correlationId',event.correlation_id,
    'ipAddress',event.ip_address,'userAgent',event.user_agent,
    'authenticationMethod',event.authentication_method,'outcome',event.outcome,
    'reason',event.reason,'before',event.before,'after',event.after,'metadata',event.metadata,
    'previousHash',event.previous_hash,'eventHash',event.event_hash
  ))
  FROM public.platform_audit_events AS event
  WHERE event.sequence>p_after_sequence
    AND event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence
  ORDER BY event.sequence LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_platform_audit_segment_page_v1(uuid,uuid,bigint,integer)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_platform_audit_segment_page_v1(uuid,uuid,bigint,integer)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_platform_audit_segment_page_v1(uuid,uuid,bigint,integer)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.preserve_tenant_audit_segment_v1(
  p_worker_id uuid,p_tenant_id uuid,p_segment_id uuid,p_expected_revision bigint,
  p_digest bytea,p_bytes bigint,p_signing_key_id text,p_signature bytea,
  p_reason text,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.tenant_audit_segments%ROWTYPE;
  changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_expected_revision<>1 OR octet_length(p_digest) IS DISTINCT FROM 32
     OR p_bytes NOT BETWEEN 1 AND 1073741824
     OR p_signing_key_id !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
     OR octet_length(p_signature) IS DISTINCT FROM 64
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit segment preservation' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||p_tenant_id::text,0));
  SELECT segment.* INTO locked_segment FROM public.tenant_audit_segments AS segment
  WHERE segment.tenant_id=p_tenant_id AND segment.id=p_segment_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit segment not found' USING ERRCODE='P0002'; END IF;
  IF locked_segment.state='preserved' AND locked_segment.revision=2
     AND locked_segment.digest=p_digest AND locked_segment.bytes=p_bytes
     AND locked_segment.signing_key_id=p_signing_key_id
     AND locked_segment.signature=p_signature THEN
    RETURN jsonb_build_object('id',locked_segment.id,'tenantId',locked_segment.tenant_id,
      'state',locked_segment.state,'revision',locked_segment.revision,
      'startSequence',locked_segment.start_sequence,'endSequence',locked_segment.end_sequence,
      'objectKey',locked_segment.object_key,'sha256',encode(locked_segment.digest,'hex'),
      'bytes',locked_segment.bytes,'signingKeyId',locked_segment.signing_key_id,
      'preservedAt',locked_segment.preserved_at);
  END IF;
  IF locked_segment.state<>'closed' OR locked_segment.revision<>p_expected_revision THEN
    RAISE EXCEPTION 'tenant audit segment revision conflict' USING ERRCODE='40001';
  END IF;
  changed_at:=greatest(locked_segment.closed_at,clock_timestamp());
  UPDATE public.tenant_audit_segments SET state='preserved',revision=2,digest=p_digest,
    bytes=p_bytes,signing_key_id=p_signing_key_id,signature=p_signature,
    preserved_at=changed_at
  WHERE tenant_id=p_tenant_id AND id=p_segment_id RETURNING * INTO locked_segment;
  PERFORM app.private_append_tenant_audit_worker_v1(p_tenant_id,p_audit_event_id,
    'audit.retention.segment_preserved','audit_retention_segment',p_segment_id,p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',locked_segment.start_sequence,
      'endSequence',locked_segment.end_sequence,'sha256',encode(p_digest,'hex'),
      'bytes',p_bytes,'signingKeyId',p_signing_key_id));
  RETURN jsonb_build_object('id',locked_segment.id,'tenantId',locked_segment.tenant_id,
    'state',locked_segment.state,'revision',locked_segment.revision,
    'startSequence',locked_segment.start_sequence,'endSequence',locked_segment.end_sequence,
    'objectKey',locked_segment.object_key,'sha256',encode(locked_segment.digest,'hex'),
    'bytes',locked_segment.bytes,'signingKeyId',locked_segment.signing_key_id,
    'preservedAt',locked_segment.preserved_at);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.preserve_tenant_audit_segment_v1(uuid,uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.preserve_tenant_audit_segment_v1(uuid,uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.preserve_tenant_audit_segment_v1(uuid,uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.preserve_platform_audit_segment_v1(
  p_worker_id uuid,p_segment_id uuid,p_expected_revision bigint,p_digest bytea,p_bytes bigint,
  p_signing_key_id text,p_signature bytea,p_reason text,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.platform_audit_segments%ROWTYPE;
  changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_expected_revision<>1 OR octet_length(p_digest) IS DISTINCT FROM 32
     OR p_bytes NOT BETWEEN 1 AND 1073741824
     OR p_signing_key_id !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
     OR octet_length(p_signature) IS DISTINCT FROM 64
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit segment preservation' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  SELECT segment.* INTO locked_segment FROM public.platform_audit_segments AS segment
  WHERE segment.id=p_segment_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit segment not found' USING ERRCODE='P0002'; END IF;
  IF locked_segment.state='preserved' AND locked_segment.revision=2
     AND locked_segment.digest=p_digest AND locked_segment.bytes=p_bytes
     AND locked_segment.signing_key_id=p_signing_key_id
     AND locked_segment.signature=p_signature THEN
    RETURN jsonb_build_object('id',locked_segment.id,'state',locked_segment.state,
      'revision',locked_segment.revision,'startSequence',locked_segment.start_sequence,
      'endSequence',locked_segment.end_sequence,'objectKey',locked_segment.object_key,
      'sha256',encode(locked_segment.digest,'hex'),'bytes',locked_segment.bytes,
      'signingKeyId',locked_segment.signing_key_id,'preservedAt',locked_segment.preserved_at);
  END IF;
  IF locked_segment.state<>'closed' OR locked_segment.revision<>p_expected_revision THEN
    RAISE EXCEPTION 'platform audit segment revision conflict' USING ERRCODE='40001';
  END IF;
  changed_at:=greatest(locked_segment.closed_at,clock_timestamp());
  UPDATE public.platform_audit_segments SET state='preserved',revision=2,digest=p_digest,
    bytes=p_bytes,signing_key_id=p_signing_key_id,signature=p_signature,preserved_at=changed_at
  WHERE id=p_segment_id RETURNING * INTO locked_segment;
  PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,
    'audit.retention.segment_preserved','platform_audit_retention_segment',p_segment_id,
    NULL,NULL,NULL,'worker','worker','success',p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',locked_segment.start_sequence,
      'endSequence',locked_segment.end_sequence,'sha256',encode(p_digest,'hex'),
      'bytes',p_bytes,'signingKeyId',p_signing_key_id));
  RETURN jsonb_build_object('id',locked_segment.id,'state',locked_segment.state,
    'revision',locked_segment.revision,'startSequence',locked_segment.start_sequence,
    'endSequence',locked_segment.end_sequence,'objectKey',locked_segment.object_key,
    'sha256',encode(locked_segment.digest,'hex'),'bytes',locked_segment.bytes,
    'signingKeyId',locked_segment.signing_key_id,'preservedAt',locked_segment.preserved_at);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.preserve_platform_audit_segment_v1(uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.preserve_platform_audit_segment_v1(uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.preserve_platform_audit_segment_v1(uuid,uuid,bigint,bytea,bigint,text,bytea,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE TABLE public.tenant_audit_retention_prune_capabilities (
  backend_pid integer NOT NULL,
  transaction_id bigint NOT NULL,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  segment_id uuid NOT NULL,
  start_sequence bigint NOT NULL,
  end_sequence bigint NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT tenant_audit_retention_prune_capabilities_pkey
    PRIMARY KEY (backend_pid,transaction_id),
  CONSTRAINT tenant_audit_retention_prune_capabilities_segment_fk
    FOREIGN KEY (tenant_id,segment_id)
    REFERENCES public.tenant_audit_segments(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_audit_retention_prune_capabilities_shape_check CHECK (
    backend_pid>0 AND transaction_id>0 AND start_sequence>0
    AND end_sequence>=start_sequence
  )
);
--> statement-breakpoint
ALTER TABLE public.tenant_audit_retention_prune_capabilities
  ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.tenant_audit_retention_prune_capabilities
  FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.tenant_audit_retention_prune_capabilities
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_audit_retention_prune_capabilities
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor,periapsis_migrator;
--> statement-breakpoint
CREATE POLICY tenant_audit_retention_prune_capabilities_owner_all_v1
ON public.tenant_audit_retention_prune_capabilities FOR ALL
TO periapsis_audit_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_retention_prune_capabilities_migrator_select_v1
ON public.tenant_audit_retention_prune_capabilities FOR SELECT
TO periapsis_migrator USING (true);
--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_audit_retention_prune_capabilities
TO periapsis_migrator;
--> statement-breakpoint

-- LDAP JIT evidence may be retired only while the corresponding, terminal
-- aggregate is wholly covered by the segment being advanced into the anchor.
-- Successful authority and every surviving provenance/receipt remain a hard
-- FK-independent fence. Runtime roles never receive DELETE on these tables.
CREATE POLICY tenant_ldap_jit_runs_audit_operations_select_v1
ON public.tenant_ldap_jit_authentication_runs FOR SELECT
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_ldap_jit_runs_audit_operations_delete_v1
ON public.tenant_ldap_jit_authentication_runs FOR DELETE
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_ldap_jit_run_mappings_audit_operations_select_v1
ON public.tenant_ldap_jit_run_mappings FOR SELECT
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_ldap_jit_run_mappings_audit_operations_delete_v1
ON public.tenant_ldap_jit_run_mappings FOR DELETE
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY auth_session_ldap_provenance_audit_operations_select_v1
ON public.auth_session_ldap_provenance FOR SELECT
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_post_primary_ldap_provenance_audit_operations_select_v1
ON public.tenant_post_primary_ldap_provenance FOR SELECT
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_ldap_jit_authority_receipts_audit_operations_select_v1
ON public.tenant_ldap_jit_authority_issuance_receipts FOR SELECT
TO periapsis_audit_operations_owner USING (true);
--> statement-breakpoint
GRANT SELECT,DELETE ON TABLE public.tenant_ldap_jit_authentication_runs,
  public.tenant_ldap_jit_run_mappings TO periapsis_audit_operations_owner;
--> statement-breakpoint
GRANT SELECT ON TABLE public.auth_session_ldap_provenance,
  public.tenant_post_primary_ldap_provenance,
  public.tenant_ldap_jit_authority_issuance_receipts
TO periapsis_audit_operations_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ldap_jit_run_is_retention_eligible_v1(
  p_tenant_id uuid,p_jit_run_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
       SELECT 1
       FROM public.tenant_audit_retention_prune_capabilities AS capability
       WHERE capability.backend_pid=pg_backend_pid()
         AND capability.transaction_id=txid_current()
         AND capability.tenant_id=p_tenant_id
         AND capability.segment_id::text=current_setting('app.audit_retention_prune_segment_id',true)
         AND capability.start_sequence=current_setting('app.audit_retention_prune_start',true)::bigint
         AND capability.end_sequence=current_setting('app.audit_retention_prune_end',true)::bigint
     )
     AND p_tenant_id::text=current_setting('app.audit_retention_prune_tenant_id',true)
     AND current_setting('app.audit_retention_prune_segment_id',true)<>''
     AND EXISTS (
       SELECT 1
       FROM public.tenant_ldap_jit_authentication_runs AS run
       JOIN public.audit_events AS begin_event
         ON begin_event.tenant_id=run.tenant_id AND begin_event.id=run.begin_audit_event_id
       JOIN public.audit_events AS terminal_event
         ON terminal_event.tenant_id=run.tenant_id AND terminal_event.id=run.terminal_audit_event_id
       WHERE run.tenant_id=p_tenant_id AND run.id=p_jit_run_id
         AND run.status IN ('denied','failed','stale','expired')
         AND run.completed_at IS NOT NULL AND run.terminal_audit_event_id IS NOT NULL
         AND begin_event.sequence BETWEEN current_setting('app.audit_retention_prune_start',true)::bigint
                                      AND current_setting('app.audit_retention_prune_end',true)::bigint
         AND terminal_event.sequence BETWEEN current_setting('app.audit_retention_prune_start',true)::bigint
                                         AND current_setting('app.audit_retention_prune_end',true)::bigint
         AND NOT EXISTS (
           SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
           WHERE provenance.tenant_id=run.tenant_id
             AND (provenance.jit_run_id=run.id OR provenance.root_jit_run_id=run.id)
         )
         AND NOT EXISTS (
           SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
           WHERE provenance.tenant_id=run.tenant_id
             AND (provenance.jit_run_id=run.id OR provenance.root_jit_run_id=run.id)
         )
         AND NOT EXISTS (
           SELECT 1 FROM public.tenant_ldap_jit_authority_issuance_receipts AS receipt
           WHERE receipt.tenant_id=run.tenant_id AND receipt.jit_run_id=run.id
         )
     );
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_ldap_jit_run_is_retention_eligible_v1(uuid,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ldap_jit_run_is_retention_eligible_v1(uuid,uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE'
     AND app.private_ldap_jit_run_is_retention_eligible_v1(OLD.tenant_id,OLD.jit_run_id) THEN
    RETURN OLD;
  END IF;
  IF TG_OP<>'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping pins are append-only' USING ERRCODE='42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_ldap_jit_authentication_runs AS run
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id=NEW.tenant_id AND rule.id=NEW.mapping_rule_id
     AND rule.binding_id=NEW.binding_id
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id=rule.tenant_id AND epoch.id=NEW.source_epoch_id
     AND epoch.mapping_rule_id=rule.id AND epoch.binding_id=rule.binding_id
     AND epoch.source_id=NEW.source_id
    WHERE run.tenant_id=NEW.tenant_id AND run.id=NEW.jit_run_id
      AND run.binding_id=NEW.binding_id AND run.status='network_pending'
      AND rule.enabled AND rule.archived_at IS NULL
      AND rule.current_source_epoch_id=epoch.id
      AND rule.version=NEW.mapping_version
      AND rule.configuration_revision=NEW.configuration_revision
      AND rule.priority=NEW.priority
      AND epoch.configuration_revision=NEW.configuration_revision
      AND epoch.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping pin is not exact' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1() OWNER TO periapsis_migrator;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_jit_run_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    IF app.private_ldap_jit_run_is_retention_eligible_v1(OLD.tenant_id,OLD.id) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'tenant LDAP JIT authentication runs are append-only' USING ERRCODE='42501';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'network_pending' OR NEW.version<>1
       OR NEW.result_authorization_revision IS NOT NULL THEN
      RAISE EXCEPTION 'tenant LDAP JIT authentication run must begin pending' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id,NEW.tenant_id,NEW.receipt_digest,NEW.provider_id,NEW.provider_kind,
    NEW.binding_id,NEW.provider_version,NEW.configuration_version,NEW.bind_secret_id,
    NEW.bind_secret_version,NEW.bind_secret_key_version,NEW.bind_secret_algorithm,
    NEW.endpoint_snapshot_digest,NEW.binding_version,NEW.binding_auth_revision,
    NEW.binding_access_epoch_id,NEW.rule_set_revision,NEW.authorization_revision,
    NEW.network_rate_key_digest,NEW.account_rate_key_digest,NEW.provider_rate_key_digest,
    NEW.begin_audit_event_id,NEW.request_id,NEW.correlation_id,NEW.started_at,NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id,OLD.tenant_id,OLD.receipt_digest,OLD.provider_id,OLD.provider_kind,
    OLD.binding_id,OLD.provider_version,OLD.configuration_version,OLD.bind_secret_id,
    OLD.bind_secret_version,OLD.bind_secret_key_version,OLD.bind_secret_algorithm,
    OLD.endpoint_snapshot_digest,OLD.binding_version,OLD.binding_auth_revision,
    OLD.binding_access_epoch_id,OLD.rule_set_revision,OLD.authorization_revision,
    OLD.network_rate_key_digest,OLD.account_rate_key_digest,OLD.provider_rate_key_digest,
    OLD.begin_audit_event_id,OLD.request_id,OLD.correlation_id,OLD.started_at,OLD.expires_at
  ) OR NEW.version<>OLD.version+1 OR NOT (
    (OLD.status='network_pending' AND NEW.status='planning'
      AND OLD.result_authorization_revision IS NULL AND NEW.result_authorization_revision IS NULL)
    OR (OLD.status IN ('network_pending','planning') AND NEW.status IN ('failed','stale','expired')
      AND OLD.result_authorization_revision IS NULL AND NEW.result_authorization_revision IS NULL)
    OR (OLD.status='planning' AND NEW.status IN ('succeeded','denied')
      AND OLD.result_authorization_revision IS NULL AND NEW.result_authorization_revision>0)
  ) THEN
    RAISE EXCEPTION 'tenant LDAP JIT authentication transition is invalid' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_jit_run_v1() OWNER TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.prune_tenant_audit_segment_v1(
  p_worker_id uuid,p_tenant_id uuid,p_segment_id uuid,p_expected_revision bigint,
  p_observed_object_key text,p_observed_digest bytea,p_observed_bytes bigint,
  p_observed_signing_key_id text,p_observed_signature bytea,p_signature_verified boolean,
  p_reason text,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.tenant_audit_segments%ROWTYPE;
  locked_anchor public.tenant_audit_retention_anchors%ROWTYPE;
  checked_count bigint; checked_start bigint; checked_end bigint;
  checked_previous character(64); checked_hash character(64);
  deleted_events bigint; deleted_jit_runs bigint; changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_expected_revision<>2 OR p_observed_object_key IS NULL
     OR octet_length(p_observed_digest) IS DISTINCT FROM 32 OR p_observed_bytes<=0
     OR p_observed_signing_key_id !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
     OR octet_length(p_observed_signature) IS DISTINCT FROM 64
     OR p_signature_verified IS NOT TRUE
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit segment prune' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:tenant:'||p_tenant_id::text,0));
  IF EXISTS (
    SELECT 1 FROM public.tenant_audit_legal_holds AS hold
    WHERE hold.tenant_id=p_tenant_id AND hold.state='active'
  ) THEN
    RAISE EXCEPTION 'tenant audit retention is under legal hold' USING ERRCODE='42501';
  END IF;
  SELECT segment.* INTO locked_segment FROM public.tenant_audit_segments AS segment
  WHERE segment.tenant_id=p_tenant_id AND segment.id=p_segment_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'tenant audit segment not found' USING ERRCODE='P0002'; END IF;
  IF locked_segment.state='pruned' AND locked_segment.revision=3
     AND locked_segment.object_key=p_observed_object_key
     AND locked_segment.digest=p_observed_digest AND locked_segment.bytes=p_observed_bytes
     AND locked_segment.signing_key_id=p_observed_signing_key_id
     AND locked_segment.signature=p_observed_signature THEN
    SELECT anchor.* INTO locked_anchor FROM public.tenant_audit_retention_anchors AS anchor
    WHERE anchor.tenant_id=p_tenant_id;
    RETURN jsonb_build_object('segmentId',locked_segment.id,'state',locked_segment.state,
      'revision',locked_segment.revision,'retainedThroughSequence',locked_anchor.retained_through_sequence,
      'retainedThroughHash',locked_anchor.retained_through_hash,'anchorRevision',locked_anchor.revision,
      'eventsPruned',locked_segment.event_count,'jitAggregatesPruned',0,'prunedAt',locked_segment.pruned_at);
  END IF;
  IF locked_segment.state<>'preserved' OR locked_segment.revision<>p_expected_revision THEN
    RAISE EXCEPTION 'tenant audit segment revision conflict' USING ERRCODE='40001';
  END IF;
  IF locked_segment.object_key IS DISTINCT FROM p_observed_object_key
     OR locked_segment.digest IS DISTINCT FROM p_observed_digest
     OR locked_segment.bytes IS DISTINCT FROM p_observed_bytes
     OR locked_segment.signing_key_id IS DISTINCT FROM p_observed_signing_key_id
     OR locked_segment.signature IS DISTINCT FROM p_observed_signature THEN
    RAISE EXCEPTION 'tenant audit preserved object attestation mismatch' USING ERRCODE='55000';
  END IF;
  INSERT INTO public.tenant_audit_retention_anchors(tenant_id) VALUES(p_tenant_id)
  ON CONFLICT(tenant_id) DO NOTHING;
  SELECT anchor.* INTO locked_anchor FROM public.tenant_audit_retention_anchors AS anchor
  WHERE anchor.tenant_id=p_tenant_id FOR UPDATE;
  IF locked_segment.start_sequence<>locked_anchor.retained_through_sequence+1
     OR locked_segment.previous_hash<>locked_anchor.retained_through_hash THEN
    RAISE EXCEPTION 'tenant audit segment does not extend the protected anchor' USING ERRCODE='55000';
  END IF;
  SELECT count(*)::bigint,min(event.sequence),max(event.sequence),
    (array_agg(event.previous_hash ORDER BY event.sequence))[1],
    (array_agg(event.event_hash ORDER BY event.sequence DESC))[1]
  INTO checked_count,checked_start,checked_end,checked_previous,checked_hash
  FROM public.audit_events AS event
  WHERE event.tenant_id=p_tenant_id
    AND event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence;
  IF checked_count<>locked_segment.event_count OR checked_start<>locked_segment.start_sequence
     OR checked_end<>locked_segment.end_sequence
     OR checked_previous<>locked_segment.previous_hash OR checked_hash<>locked_segment.end_hash
     OR EXISTS (
       SELECT 1 FROM (
         SELECT event.sequence,
           row_number() OVER (ORDER BY event.sequence)+locked_segment.start_sequence-1 AS expected_sequence,
           lag(event.event_hash,1,locked_segment.previous_hash) OVER (ORDER BY event.sequence) AS expected_previous,
           event.previous_hash
         FROM public.audit_events AS event
         WHERE event.tenant_id=p_tenant_id
           AND event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence
       ) AS checked
       WHERE checked.sequence<>checked.expected_sequence
          OR checked.previous_hash<>checked.expected_previous
     ) THEN
    RAISE EXCEPTION 'tenant audit segment database prefix is not exact' USING ERRCODE='55000';
  END IF;

  PERFORM set_config('app.audit_retention_prune_tenant_id',p_tenant_id::text,true);
  PERFORM set_config('app.audit_retention_prune_segment_id',p_segment_id::text,true);
  PERFORM set_config('app.audit_retention_prune_start',locked_segment.start_sequence::text,true);
  PERFORM set_config('app.audit_retention_prune_end',locked_segment.end_sequence::text,true);
  INSERT INTO public.tenant_audit_retention_prune_capabilities(
    backend_pid,transaction_id,tenant_id,segment_id,start_sequence,end_sequence
  ) VALUES (
    pg_backend_pid(),txid_current(),p_tenant_id,p_segment_id,
    locked_segment.start_sequence,locked_segment.end_sequence
  );

  DELETE FROM public.tenant_ldap_jit_run_mappings AS mapping
  WHERE mapping.tenant_id=p_tenant_id
    AND app.private_ldap_jit_run_is_retention_eligible_v1(mapping.tenant_id,mapping.jit_run_id);
  DELETE FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.tenant_id=p_tenant_id
    AND app.private_ldap_jit_run_is_retention_eligible_v1(run.tenant_id,run.id);
  GET DIAGNOSTICS deleted_jit_runs=ROW_COUNT;

  DELETE FROM public.audit_events AS event
  WHERE event.tenant_id=p_tenant_id
    AND event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence;
  GET DIAGNOSTICS deleted_events=ROW_COUNT;
  IF deleted_events<>locked_segment.event_count THEN
    RAISE EXCEPTION 'tenant audit retention delete count mismatch' USING ERRCODE='55000';
  END IF;
  DELETE FROM public.tenant_audit_retention_prune_capabilities AS capability
  WHERE capability.backend_pid=pg_backend_pid() AND capability.transaction_id=txid_current();
  changed_at:=greatest(locked_segment.preserved_at,clock_timestamp());
  UPDATE public.tenant_audit_segments SET state='pruned',revision=3,pruned_at=changed_at
  WHERE tenant_id=p_tenant_id AND id=p_segment_id RETURNING * INTO locked_segment;
  UPDATE public.tenant_audit_retention_anchors SET
    retained_through_sequence=locked_segment.end_sequence,
    retained_through_hash=locked_segment.end_hash,last_segment_id=locked_segment.id,
    segment_digest=locked_segment.digest,signing_key_id=locked_segment.signing_key_id,
    signature=locked_segment.signature,revision=revision+1,reason=p_reason,updated_at=changed_at
  WHERE tenant_id=p_tenant_id RETURNING * INTO locked_anchor;
  PERFORM app.private_append_tenant_audit_worker_v1(p_tenant_id,p_audit_event_id,
    'audit.retention.prefix_pruned','audit_retention_segment',p_segment_id,p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',locked_segment.start_sequence,
      'endSequence',locked_segment.end_sequence,'eventCount',deleted_events,
      'jitAggregatesPruned',deleted_jit_runs,'anchorRevision',locked_anchor.revision,
      'sha256',encode(locked_segment.digest,'hex'),'signingKeyId',locked_segment.signing_key_id));
  RETURN jsonb_build_object('segmentId',locked_segment.id,'state',locked_segment.state,
    'revision',locked_segment.revision,'retainedThroughSequence',locked_anchor.retained_through_sequence,
    'retainedThroughHash',locked_anchor.retained_through_hash,'anchorRevision',locked_anchor.revision,
    'eventsPruned',deleted_events,'jitAggregatesPruned',deleted_jit_runs,'prunedAt',changed_at);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.prune_tenant_audit_segment_v1(
  uuid,uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prune_tenant_audit_segment_v1(
  uuid,uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.prune_tenant_audit_segment_v1(
  uuid,uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.prune_platform_audit_segment_v1(
  p_worker_id uuid,p_segment_id uuid,p_expected_revision bigint,
  p_observed_object_key text,p_observed_digest bytea,p_observed_bytes bigint,
  p_observed_signing_key_id text,p_observed_signature bytea,p_signature_verified boolean,
  p_reason text,p_audit_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_segment public.platform_audit_segments%ROWTYPE;
  locked_anchor public.platform_audit_retention_anchor%ROWTYPE;
  checked_count bigint; checked_start bigint; checked_end bigint;
  checked_previous character(64); checked_hash character(64);
  deleted_events bigint; changed_at timestamp with time zone;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_segment_id)=7) IS NOT TRUE
     OR p_expected_revision<>2 OR p_observed_object_key IS NULL
     OR octet_length(p_observed_digest) IS DISTINCT FROM 32 OR p_observed_bytes<=0
     OR p_observed_signing_key_id !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
     OR octet_length(p_observed_signature) IS DISTINCT FROM 64
     OR p_signature_verified IS NOT TRUE
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit segment prune' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-retention:platform',0));
  IF EXISTS (SELECT 1 FROM public.platform_audit_legal_holds WHERE state='active') THEN
    RAISE EXCEPTION 'platform audit retention is under legal hold' USING ERRCODE='42501';
  END IF;
  SELECT segment.* INTO locked_segment FROM public.platform_audit_segments AS segment
  WHERE segment.id=p_segment_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'platform audit segment not found' USING ERRCODE='P0002'; END IF;
  IF locked_segment.state='pruned' AND locked_segment.revision=3
     AND locked_segment.object_key=p_observed_object_key
     AND locked_segment.digest=p_observed_digest AND locked_segment.bytes=p_observed_bytes
     AND locked_segment.signing_key_id=p_observed_signing_key_id
     AND locked_segment.signature=p_observed_signature THEN
    SELECT anchor.* INTO locked_anchor FROM public.platform_audit_retention_anchor AS anchor
    WHERE anchor.singleton;
    RETURN jsonb_build_object('segmentId',locked_segment.id,'state',locked_segment.state,
      'revision',locked_segment.revision,'retainedThroughSequence',locked_anchor.retained_through_sequence,
      'retainedThroughHash',locked_anchor.retained_through_hash,'anchorRevision',locked_anchor.revision,
      'eventsPruned',locked_segment.event_count,'prunedAt',locked_segment.pruned_at);
  END IF;
  IF locked_segment.state<>'preserved' OR locked_segment.revision<>p_expected_revision THEN
    RAISE EXCEPTION 'platform audit segment revision conflict' USING ERRCODE='40001';
  END IF;
  IF locked_segment.object_key IS DISTINCT FROM p_observed_object_key
     OR locked_segment.digest IS DISTINCT FROM p_observed_digest
     OR locked_segment.bytes IS DISTINCT FROM p_observed_bytes
     OR locked_segment.signing_key_id IS DISTINCT FROM p_observed_signing_key_id
     OR locked_segment.signature IS DISTINCT FROM p_observed_signature THEN
    RAISE EXCEPTION 'platform audit preserved object attestation mismatch' USING ERRCODE='55000';
  END IF;
  INSERT INTO public.platform_audit_retention_anchor(singleton) VALUES(true)
  ON CONFLICT(singleton) DO NOTHING;
  SELECT anchor.* INTO locked_anchor FROM public.platform_audit_retention_anchor AS anchor
  WHERE anchor.singleton FOR UPDATE;
  IF locked_segment.start_sequence<>locked_anchor.retained_through_sequence+1
     OR locked_segment.previous_hash<>locked_anchor.retained_through_hash THEN
    RAISE EXCEPTION 'platform audit segment does not extend the protected anchor' USING ERRCODE='55000';
  END IF;
  SELECT count(*)::bigint,min(event.sequence),max(event.sequence),
    (array_agg(event.previous_hash ORDER BY event.sequence))[1],
    (array_agg(event.event_hash ORDER BY event.sequence DESC))[1]
  INTO checked_count,checked_start,checked_end,checked_previous,checked_hash
  FROM public.platform_audit_events AS event
  WHERE event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence;
  IF checked_count<>locked_segment.event_count OR checked_start<>locked_segment.start_sequence
     OR checked_end<>locked_segment.end_sequence
     OR checked_previous<>locked_segment.previous_hash OR checked_hash<>locked_segment.end_hash
     OR EXISTS (
       SELECT 1 FROM (
         SELECT event.sequence,
           row_number() OVER (ORDER BY event.sequence)+locked_segment.start_sequence-1 AS expected_sequence,
           lag(event.event_hash,1,locked_segment.previous_hash) OVER (ORDER BY event.sequence) AS expected_previous,
           event.previous_hash
         FROM public.platform_audit_events AS event
         WHERE event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence
       ) AS checked
       WHERE checked.sequence<>checked.expected_sequence
          OR checked.previous_hash<>checked.expected_previous
     ) THEN
    RAISE EXCEPTION 'platform audit segment database prefix is not exact' USING ERRCODE='55000';
  END IF;
  PERFORM set_config('app.platform_audit_retention_prune_segment_id',p_segment_id::text,true);
  PERFORM set_config('app.platform_audit_retention_prune_start',locked_segment.start_sequence::text,true);
  PERFORM set_config('app.platform_audit_retention_prune_end',locked_segment.end_sequence::text,true);
  DELETE FROM public.platform_audit_events AS event
  WHERE event.sequence BETWEEN locked_segment.start_sequence AND locked_segment.end_sequence;
  GET DIAGNOSTICS deleted_events=ROW_COUNT;
  IF deleted_events<>locked_segment.event_count THEN
    RAISE EXCEPTION 'platform audit retention delete count mismatch' USING ERRCODE='55000';
  END IF;
  changed_at:=greatest(locked_segment.preserved_at,clock_timestamp());
  UPDATE public.platform_audit_segments SET state='pruned',revision=3,pruned_at=changed_at
  WHERE id=p_segment_id RETURNING * INTO locked_segment;
  UPDATE public.platform_audit_retention_anchor SET
    retained_through_sequence=locked_segment.end_sequence,
    retained_through_hash=locked_segment.end_hash,last_segment_id=locked_segment.id,
    segment_digest=locked_segment.digest,signing_key_id=locked_segment.signing_key_id,
    signature=locked_segment.signature,revision=revision+1,reason=p_reason,updated_at=changed_at
  WHERE singleton RETURNING * INTO locked_anchor;
  PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,
    'audit.retention.prefix_pruned','platform_audit_retention_segment',p_segment_id,
    NULL,NULL,NULL,'worker','worker','success',p_reason,
    jsonb_build_object('workerId',p_worker_id,'startSequence',locked_segment.start_sequence,
      'endSequence',locked_segment.end_sequence,'eventCount',deleted_events,
      'anchorRevision',locked_anchor.revision,'sha256',encode(locked_segment.digest,'hex'),
      'signingKeyId',locked_segment.signing_key_id));
  RETURN jsonb_build_object('segmentId',locked_segment.id,'state',locked_segment.state,
    'revision',locked_segment.revision,'retainedThroughSequence',locked_anchor.retained_through_sequence,
    'retainedThroughHash',locked_anchor.retained_through_hash,'anchorRevision',locked_anchor.revision,
    'eventsPruned',deleted_events,'prunedAt',changed_at);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.prune_platform_audit_segment_v1(
  uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prune_platform_audit_segment_v1(
  uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.prune_platform_audit_segment_v1(
  uuid,uuid,bigint,text,bytea,bigint,text,bytea,boolean,text,uuid
) TO periapsis_worker;
--> statement-breakpoint

-- Additive verifier ABI. The v1 ABI remains callable for old SQL consumers;
-- HTTP uses v2 so an anchored prefix is represented explicitly. With an
-- initial zero anchor this is byte-for-byte the original chain calculation.
CREATE POLICY tenant_audit_retention_anchors_reader_select_v1
ON public.tenant_audit_retention_anchors FOR SELECT
TO periapsis_audit_reader_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_retention_anchor_reader_select_v1
ON public.platform_audit_retention_anchor FOR SELECT
TO periapsis_audit_reader_owner USING (true);
--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_audit_retention_anchors,
  public.platform_audit_retention_anchor TO periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.verify_tenant_audit_chain_v2(
  p_session_id uuid,p_permission text,p_access_audit_id uuid,p_access_request_id uuid,
  p_access_correlation_id uuid,p_access_ip_address inet,p_access_user_agent text,p_tenant_id uuid
)
RETURNS TABLE(
  event_count bigint,last_sequence bigint,first_invalid_sequence bigint,
  head_valid boolean,valid boolean,verified_at timestamp with time zone,
  retained_through_sequence bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid:=app.context_tenant_id();
  authentication_method text; anchor_sequence bigint:=0;
  anchor_hash character(64):=repeat('0',64)::character(64);
  live_count bigint; result_event_count bigint; result_last_sequence bigint;
  result_first_invalid_sequence bigint; result_head_valid boolean; result_valid boolean;
  result_verified_at timestamp with time zone:=transaction_timestamp();
  result_last_hash character(64);
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.read' OR p_tenant_id IS DISTINCT FROM context_tenant
     OR (uuid_extract_version(p_access_audit_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id)=7) IS NOT TRUE
     OR p_access_ip_address IS NULL OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid tenant audit verification' USING ERRCODE='22023';
  END IF;
  authentication_method:=app.require_live_audit_session_v1(p_session_id,context_tenant);
  IF NOT app.current_tenant_human_has_exact_permission_v3('audit.read','tenant') THEN
    RAISE EXCEPTION 'audit.read tenant scope is required' USING ERRCODE='42501';
  END IF;
  SELECT anchor.retained_through_sequence,anchor.retained_through_hash
  INTO anchor_sequence,anchor_hash
  FROM public.tenant_audit_retention_anchors AS anchor
  WHERE anchor.tenant_id=context_tenant;
  IF NOT FOUND THEN anchor_sequence:=0; anchor_hash:=repeat('0',64)::character(64); END IF;
  WITH ordered AS (
    SELECT event AS event_record,event.sequence,event.event_hash,event.previous_hash,
      anchor_sequence+row_number() OVER (ORDER BY event.sequence) AS expected_sequence,
      lag(event.event_hash,1,anchor_hash) OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.audit_events AS event
    WHERE event.tenant_id=context_tenant AND event.sequence>anchor_sequence
  ), checked AS (
    SELECT ordered.*,(ordered.sequence=ordered.expected_sequence
      AND ordered.previous_hash=ordered.expected_previous_hash
      AND ordered.event_hash=app.calculate_audit_event_hash(
        ordered.event_record,ordered.expected_previous_hash
      )) IS TRUE AS row_valid FROM ordered
  ), summary AS (
    SELECT count(*)::bigint AS live_count,coalesce(max(sequence),anchor_sequence)::bigint AS last_sequence,
      min(sequence) FILTER(WHERE NOT row_valid) AS first_invalid_sequence,
      coalesce((array_agg(event_hash ORDER BY sequence DESC))[1],anchor_hash) AS last_hash
    FROM checked
  )
  SELECT summary.live_count,summary.last_sequence,summary.first_invalid_sequence,summary.last_hash,
    EXISTS(SELECT 1 FROM public.audit_chain_heads AS head
      WHERE head.tenant_id=context_tenant AND head.last_sequence=summary.last_sequence
        AND head.last_event_hash=summary.last_hash)
  INTO live_count,result_last_sequence,result_first_invalid_sequence,result_last_hash,result_head_valid
  FROM summary;
  result_event_count:=anchor_sequence+live_count;
  result_valid:=result_head_valid AND result_first_invalid_sequence IS NULL
    AND live_count=result_last_sequence-anchor_sequence;
  PERFORM app.append_tenant_authorization_audit(
    p_access_audit_id,'audit.chain_verified','audit_log',context_tenant,
    p_access_request_id,p_access_correlation_id,p_access_ip_address,p_access_user_agent,
    authentication_method,NULL,NULL,jsonb_build_object(
      'eventCount',result_event_count,'lastSequence',result_last_sequence,
      'retainedThroughSequence',anchor_sequence,
      'firstInvalidSequence',result_first_invalid_sequence,
      'headValid',result_head_valid,'valid',result_valid
    )
  );
  RETURN QUERY SELECT result_event_count,result_last_sequence,result_first_invalid_sequence,
    result_head_valid,result_valid,result_verified_at,anchor_sequence;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.verify_tenant_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text,uuid)
  OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_tenant_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text,uuid)
FROM PUBLIC,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_tenant_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text,uuid)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.verify_platform_audit_chain_v2(
  p_session_id uuid,p_permission text,p_access_audit_id uuid,p_access_request_id uuid,
  p_access_correlation_id uuid,p_access_ip_address inet,p_access_user_agent text
)
RETURNS TABLE(
  event_count bigint,last_sequence bigint,first_invalid_sequence bigint,
  head_valid boolean,valid boolean,verified_at timestamp with time zone,
  retained_through_sequence bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid:=app.context_user_id(); authentication_method text;
  anchor_sequence bigint:=0; anchor_hash character(64):=repeat('0',64)::character(64);
  live_count bigint; result_event_count bigint; result_last_sequence bigint;
  result_first_invalid_sequence bigint; result_head_valid boolean; result_valid boolean;
  result_verified_at timestamp with time zone:=transaction_timestamp();
  result_last_hash character(64);
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.read'
     OR (uuid_extract_version(p_access_audit_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id)=7) IS NOT TRUE
     OR p_access_ip_address IS NULL OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid platform audit verification' USING ERRCODE='22023';
  END IF;
  authentication_method:=app.require_live_audit_session_v1(p_session_id,NULL);
  IF NOT app.platform_user_has_permission(actor_id,'platform.audit.read') THEN
    RAISE EXCEPTION 'platform.audit.read permission is required' USING ERRCODE='42501';
  END IF;
  SELECT anchor.retained_through_sequence,anchor.retained_through_hash
  INTO anchor_sequence,anchor_hash FROM public.platform_audit_retention_anchor AS anchor
  WHERE anchor.singleton;
  IF NOT FOUND THEN anchor_sequence:=0; anchor_hash:=repeat('0',64)::character(64); END IF;
  WITH ordered AS (
    SELECT event AS event_record,event.sequence,event.event_hash,event.previous_hash,
      anchor_sequence+row_number() OVER (ORDER BY event.sequence) AS expected_sequence,
      lag(event.event_hash,1,anchor_hash) OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.platform_audit_events AS event WHERE event.sequence>anchor_sequence
  ), checked AS (
    SELECT ordered.*,(ordered.sequence=ordered.expected_sequence
      AND ordered.previous_hash=ordered.expected_previous_hash
      AND ordered.event_hash=app.calculate_platform_audit_event_hash(
        ordered.event_record,ordered.expected_previous_hash
      )) IS TRUE AS row_valid FROM ordered
  ), summary AS (
    SELECT count(*)::bigint AS live_count,coalesce(max(sequence),anchor_sequence)::bigint AS last_sequence,
      min(sequence) FILTER(WHERE NOT row_valid) AS first_invalid_sequence,
      coalesce((array_agg(event_hash ORDER BY sequence DESC))[1],anchor_hash) AS last_hash
    FROM checked
  )
  SELECT summary.live_count,summary.last_sequence,summary.first_invalid_sequence,summary.last_hash,
    EXISTS(SELECT 1 FROM public.platform_audit_chain_head AS head
      WHERE head.singleton AND head.last_sequence=summary.last_sequence
        AND head.last_event_hash=summary.last_hash)
  INTO live_count,result_last_sequence,result_first_invalid_sequence,result_last_hash,result_head_valid
  FROM summary;
  result_event_count:=anchor_sequence+live_count;
  result_valid:=result_head_valid AND result_first_invalid_sequence IS NULL
    AND live_count=result_last_sequence-anchor_sequence;
  PERFORM app.append_platform_audit_event(
    p_access_audit_id,'user',actor_id,'audit.chain_verified','platform_audit_log',NULL,
    p_access_request_id,p_access_correlation_id,p_access_ip_address,p_access_user_agent,
    authentication_method,'success',NULL,jsonb_build_object(
      'eventCount',result_event_count,'lastSequence',result_last_sequence,
      'retainedThroughSequence',anchor_sequence,
      'firstInvalidSequence',result_first_invalid_sequence,
      'headValid',result_head_valid,'valid',result_valid
    )
  );
  RETURN QUERY SELECT result_event_count,result_last_sequence,result_first_invalid_sequence,
    result_head_valid,result_valid,result_verified_at,anchor_sequence;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.verify_platform_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text)
  OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_platform_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text)
FROM PUBLIC,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_platform_audit_chain_v2(uuid,text,uuid,uuid,uuid,inet,text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.prune_tenant_audit_operation_receipts_v1(
  p_worker_id uuid,p_tenant_id uuid,p_limit integer,p_reason text,p_audit_event_id uuid
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE deleted_count integer;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE
     OR p_limit NOT BETWEEN 1 AND 1000
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit receipt prune' USING ERRCODE='22023';
  END IF;
  WITH candidates AS (
    SELECT receipt.ctid FROM public.tenant_audit_operation_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id AND receipt.expires_at<=transaction_timestamp()
    ORDER BY receipt.expires_at,receipt.actor_user_id,receipt.action
    FOR UPDATE SKIP LOCKED LIMIT p_limit
  )
  DELETE FROM public.tenant_audit_operation_receipts AS receipt
  USING candidates WHERE receipt.ctid=candidates.ctid;
  GET DIAGNOSTICS deleted_count=ROW_COUNT;
  IF deleted_count>0 THEN
    PERFORM app.private_append_tenant_audit_worker_v1(p_tenant_id,p_audit_event_id,
      'audit.operations.receipts_pruned','audit_operation_receipt',NULL,p_reason,
      jsonb_build_object('workerId',p_worker_id,'deletedCount',deleted_count));
  END IF;
  RETURN deleted_count;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.prune_tenant_audit_operation_receipts_v1(uuid,uuid,integer,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prune_tenant_audit_operation_receipts_v1(uuid,uuid,integer,text,uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.prune_tenant_audit_operation_receipts_v1(uuid,uuid,integer,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.prune_platform_audit_operation_receipts_v1(
  p_worker_id uuid,p_limit integer,p_reason text,p_audit_event_id uuid
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE deleted_count integer;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE OR p_limit NOT BETWEEN 1 AND 1000
     OR NOT app.private_audit_operation_reason_is_safe_v1(p_reason)
     OR (uuid_extract_version(p_audit_event_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit receipt prune' USING ERRCODE='22023';
  END IF;
  WITH candidates AS (
    SELECT receipt.ctid FROM public.platform_audit_operation_receipts AS receipt
    WHERE receipt.expires_at<=transaction_timestamp()
    ORDER BY receipt.expires_at,receipt.actor_user_id,receipt.action
    FOR UPDATE SKIP LOCKED LIMIT p_limit
  )
  DELETE FROM public.platform_audit_operation_receipts AS receipt
  USING candidates WHERE receipt.ctid=candidates.ctid;
  GET DIAGNOSTICS deleted_count=ROW_COUNT;
  IF deleted_count>0 THEN
    PERFORM app.append_platform_audit_event(p_audit_event_id,'system',NULL,
      'audit.operations.receipts_pruned','platform_audit_operation_receipt',NULL,
      NULL,NULL,NULL,'worker','worker','success',p_reason,
      jsonb_build_object('workerId',p_worker_id,'deletedCount',deleted_count));
  END IF;
  RETURN deleted_count;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.prune_platform_audit_operation_receipts_v1(uuid,integer,text,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prune_platform_audit_operation_receipts_v1(uuid,integer,text,uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.prune_platform_audit_operation_receipts_v1(uuid,integer,text,uuid)
TO periapsis_worker;
--> statement-breakpoint

-- Worker scheduling remains a narrow capability: it reveals only tenant IDs
-- that have an explicit policy, unfinished protected segment, or expired
-- operation receipts. Runtime roles receive no relation-level discovery grant.
CREATE FUNCTION app.list_tenant_audit_retention_candidates_v1(
  p_worker_id uuid,p_limit integer
)
RETURNS TABLE(tenant_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid tenant audit retention candidate request' USING ERRCODE='22023';
  END IF;
  RETURN QUERY
  SELECT candidate.tenant_id
  FROM (
    SELECT policy.tenant_id FROM public.tenant_audit_retention_policies AS policy
    UNION
    SELECT segment.tenant_id FROM public.tenant_audit_segments AS segment
      WHERE segment.state IN ('closed','preserved')
    UNION
    SELECT receipt.tenant_id FROM public.tenant_audit_operation_receipts AS receipt
      WHERE receipt.expires_at<=transaction_timestamp()
  ) AS candidate
  ORDER BY candidate.tenant_id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_audit_retention_candidates_v1(uuid,integer)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_audit_retention_candidates_v1(uuid,integer)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_audit_retention_candidates_v1(uuid,integer)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_audit_retention_work_v1(
  p_worker_id uuid,p_tenant_id uuid
)
RETURNS TABLE(
  segment_id uuid,tenant_id uuid,state text,revision bigint,start_sequence bigint,
  end_sequence bigint,previous_hash character(64),end_hash character(64),
  event_count bigint,object_key text,digest bytea,bytes bigint,
  signing_key_id text,signature bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE anchor_sequence bigint:=0;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_tenant_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant audit retention work request' USING ERRCODE='22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_audit_legal_holds AS hold
    WHERE hold.tenant_id=p_tenant_id AND hold.state='active'
  ) THEN RETURN; END IF;
  SELECT anchor.retained_through_sequence INTO anchor_sequence
  FROM public.tenant_audit_retention_anchors AS anchor
  WHERE anchor.tenant_id=p_tenant_id;
  IF NOT FOUND THEN anchor_sequence:=0; END IF;
  RETURN QUERY
  SELECT segment.id,segment.tenant_id,segment.state,segment.revision,
    segment.start_sequence,segment.end_sequence,segment.previous_hash,
    segment.end_hash,segment.event_count,segment.object_key,segment.digest,
    segment.bytes,segment.signing_key_id,segment.signature
  FROM public.tenant_audit_segments AS segment
  WHERE segment.tenant_id=p_tenant_id
    AND segment.start_sequence=anchor_sequence+1
    AND segment.state IN ('closed','preserved')
  ORDER BY segment.id LIMIT 1;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_audit_retention_work_v1(uuid,uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_audit_retention_work_v1(uuid,uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_audit_retention_work_v1(uuid,uuid)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_audit_retention_work_v1(p_worker_id uuid)
RETURNS TABLE(
  segment_id uuid,state text,revision bigint,start_sequence bigint,end_sequence bigint,
  previous_hash character(64),end_hash character(64),event_count bigint,
  object_key text,digest bytea,bytes bigint,signing_key_id text,signature bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE anchor_sequence bigint:=0;
BEGIN
  IF (uuid_extract_version(p_worker_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid platform audit retention work request' USING ERRCODE='22023';
  END IF;
  IF EXISTS (SELECT 1 FROM public.platform_audit_legal_holds WHERE state='active') THEN
    RETURN;
  END IF;
  SELECT anchor.retained_through_sequence INTO anchor_sequence
  FROM public.platform_audit_retention_anchor AS anchor WHERE anchor.singleton;
  IF NOT FOUND THEN anchor_sequence:=0; END IF;
  RETURN QUERY
  SELECT segment.id,segment.state,segment.revision,segment.start_sequence,
    segment.end_sequence,segment.previous_hash,segment.end_hash,segment.event_count,
    segment.object_key,segment.digest,segment.bytes,segment.signing_key_id,
    segment.signature
  FROM public.platform_audit_segments AS segment
  WHERE segment.start_sequence=anchor_sequence+1
    AND segment.state IN ('closed','preserved')
  ORDER BY segment.id LIMIT 1;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_platform_audit_retention_work_v1(uuid)
  OWNER TO periapsis_audit_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_audit_retention_work_v1(uuid)
FROM PUBLIC,periapsis_api,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_audit_retention_work_v1(uuid)
TO periapsis_worker;
--> statement-breakpoint
