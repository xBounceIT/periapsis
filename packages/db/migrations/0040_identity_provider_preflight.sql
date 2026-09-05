-- Validate the legacy local-identity shape before the additive provider schema
-- makes global email optional. The migration runner holds these locks through
-- every pending migration in the same outer transaction, so the backfill that
-- follows cannot race a bootstrap or authorization mutation.
LOCK TABLE "public"."users" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."local_break_glass_credentials" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."tenant_memberships" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."tenant_permissions" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."tenant_authorization_sources" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint

DO $preflight$
DECLARE
  invalid_local_user_id uuid;
  conflicting_permission_key text;
  conflicting_source_id uuid;
BEGIN
  SELECT credential.user_id
  INTO invalid_local_user_id
  FROM public.local_break_glass_credentials AS credential
  JOIN public.users AS identity ON identity.id = credential.user_id
  WHERE identity.email IS NULL
     OR identity.email <> lower(btrim(identity.email))
     OR position('@' IN identity.email) <= 1
     OR char_length(identity.email) > 320
     OR identity.email ~ '[[:cntrl:]]'
  ORDER BY credential.user_id
  LIMIT 1;

  IF invalid_local_user_id IS NOT NULL THEN
    RAISE EXCEPTION
      'identity-provider preflight failed: local credential user % has no canonical login email',
      invalid_local_user_id
      USING ERRCODE = '23514';
  END IF;

  SELECT permission.key
  INTO conflicting_permission_key
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'identity_mapping.manage',
    'identity_mapping.read',
    'identity_provider.manage',
    'identity_provider.read',
    'identity_provider.test',
    'identity_sync.run'
  )
  ORDER BY permission.key
  LIMIT 1;

  IF conflicting_permission_key IS NOT NULL THEN
    RAISE EXCEPTION
      'identity-provider preflight failed: permission key % already exists outside the canonical slice',
      conflicting_permission_key
      USING ERRCODE = '23505';
  END IF;

  SELECT source.id
  INTO conflicting_source_id
  FROM public.tenant_authorization_sources AS source
  WHERE source.key LIKE 'identity_provider_access:%'
     OR source.key LIKE 'identity_mapping_rule:%'
  ORDER BY source.tenant_id, source.id
  LIMIT 1;

  IF conflicting_source_id IS NOT NULL THEN
    RAISE EXCEPTION
      'identity-provider preflight failed: authorization source % uses a reserved identity-provider namespace',
      conflicting_source_id
      USING ERRCODE = '23505';
  END IF;
END;
$preflight$;
