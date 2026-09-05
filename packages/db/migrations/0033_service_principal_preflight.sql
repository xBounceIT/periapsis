-- Fail closed before changing the principal and audit ABIs. These locks are held by
-- the migration runner's outer transaction through the additive and compatibility
-- stages, so the validated legacy rows cannot change underneath the backfill.
LOCK TABLE "public"."audit_events" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."alerts" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."tenant_roles" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "public"."tenant_permissions" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint

DO $preflight$
DECLARE
  invalid_audit_event_id uuid;
  invalid_service_role_id uuid;
  conflicting_permission_key text;
  unmapped_alert_id uuid;
BEGIN
  SELECT event.id
  INTO invalid_audit_event_id
  FROM public.audit_events AS event
  WHERE event.actor_type = 'service_account'
  ORDER BY event.tenant_id, event.sequence
  LIMIT 1;

  IF invalid_audit_event_id IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal preflight failed: historical service-account audit event % has no attributable service account',
      invalid_audit_event_id
      USING ERRCODE = '23514';
  END IF;

  SELECT role.id
  INTO invalid_service_role_id
  FROM public.tenant_roles AS role
  WHERE role.key = 'service_account'
    AND (
      role.system_role IS DISTINCT FROM true
      OR role.protected_role IS DISTINCT FROM false
      OR role.archived_at IS NOT NULL
    )
  ORDER BY role.tenant_id, role.id
  LIMIT 1;

  IF invalid_service_role_id IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal preflight failed: built-in service-account role % has an incompatible lifecycle or provenance',
      invalid_service_role_id
      USING ERRCODE = '23514';
  END IF;

  SELECT permission.key
  INTO conflicting_permission_key
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'alert.create',
    'service_account.credential.manage',
    'service_account.manage',
    'service_account.read'
  )
  ORDER BY permission.key
  LIMIT 1;

  IF conflicting_permission_key IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal preflight failed: permission key % already exists outside the canonical slice',
      conflicting_permission_key
      USING ERRCODE = '23505';
  END IF;

  SELECT alert.id
  INTO unmapped_alert_id
  FROM public.alerts AS alert
  WHERE NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = alert.tenant_id
      AND membership.user_id = alert.created_by
  )
  ORDER BY alert.tenant_id, alert.id
  LIMIT 1;

  IF unmapped_alert_id IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal preflight failed: legacy alert % has no tenant membership attribution',
      unmapped_alert_id
      USING ERRCODE = '23503';
  END IF;
END;
$preflight$;
