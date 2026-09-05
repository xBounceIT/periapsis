-- Materialize the local login identity before the legacy users.email column is
-- permitted to be absent for future federated users.
INSERT INTO public.user_login_identifiers (
  id,
  user_id,
  kind,
  canonical_value,
  verified_at,
  created_at,
  updated_at
)
SELECT uuidv7(),
       credential.user_id,
       'local_email'::public.login_identifier_kind,
       identity.email,
       credential.created_at,
       credential.created_at,
       greatest(credential.updated_at, identity.updated_at)
FROM public.local_break_glass_credentials AS credential
JOIN public.users AS identity ON identity.id = credential.user_id
ORDER BY credential.user_id;--> statement-breakpoint

UPDATE public.local_break_glass_credentials AS credential
SET login_identifier_id = identifier.id
FROM public.user_login_identifiers AS identifier
WHERE identifier.user_id = credential.user_id
  AND identifier.kind = 'local_email'
  AND identifier.retired_at IS NULL;--> statement-breakpoint

DO $backfill_check$
DECLARE
  missing_local_identifier_user_id uuid;
BEGIN
  SELECT credential.user_id
  INTO missing_local_identifier_user_id
  FROM public.local_break_glass_credentials AS credential
  LEFT JOIN public.user_login_identifiers AS identifier
    ON identifier.id = credential.login_identifier_id
   AND identifier.user_id = credential.user_id
   AND identifier.kind = 'local_email'
   AND identifier.retired_at IS NULL
  WHERE identifier.id IS NULL
  ORDER BY credential.user_id
  LIMIT 1;

  IF missing_local_identifier_user_id IS NOT NULL THEN
    RAISE EXCEPTION
      'identity-provider backfill failed: local credential user % has no active local login identifier',
      missing_local_identifier_user_id
      USING ERRCODE = '23514';
  END IF;
END;
$backfill_check$;--> statement-breakpoint

INSERT INTO public.tenant_user_profiles (
  tenant_id,
  membership_id,
  user_id,
  display_name,
  first_name,
  last_name,
  email,
  version,
  created_at,
  updated_at
)
SELECT membership.tenant_id,
       membership.id,
       membership.user_id,
       identity.display_name,
       identity.first_name,
       identity.last_name,
       identity.email,
       1,
       membership.created_at,
       greatest(membership.updated_at, identity.updated_at)
FROM public.tenant_memberships AS membership
JOIN public.users AS identity ON identity.id = membership.user_id
ORDER BY membership.tenant_id, membership.id;--> statement-breakpoint

-- Existing bootstrap code inserts a User and local credential in one protected
-- database function. This trigger keeps that ABI rolling-compatible while the
-- application moves to explicit login identifiers.
CREATE FUNCTION app.bind_local_login_identifier_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  canonical_email text;
  identifier_id uuid;
BEGIN
  IF NEW.login_identifier_id IS NULL THEN
    SELECT identifier.id
    INTO identifier_id
    FROM public.user_login_identifiers AS identifier
    WHERE identifier.user_id = NEW.user_id
      AND identifier.kind = 'local_email'
      AND identifier.verified_at IS NOT NULL
      AND identifier.retired_at IS NULL
    ORDER BY identifier.id
    LIMIT 1;

    IF identifier_id IS NULL THEN
      SELECT identity.email
      INTO canonical_email
      FROM public.users AS identity
      WHERE identity.id = NEW.user_id
        AND identity.active
      FOR KEY SHARE;

      IF canonical_email IS NULL THEN
        RAISE EXCEPTION 'local credential requires a canonical login identifier'
          USING ERRCODE = '23514';
      END IF;

      INSERT INTO public.user_login_identifiers (
        id,
        user_id,
        kind,
        canonical_value,
        verified_at,
        created_at,
        updated_at
      )
      VALUES (
        uuidv7(),
        NEW.user_id,
        'local_email',
        canonical_email,
        COALESCE(NEW.created_at, transaction_timestamp()),
        COALESCE(NEW.created_at, transaction_timestamp()),
        COALESCE(NEW.updated_at, NEW.created_at, transaction_timestamp())
      )
      RETURNING id INTO identifier_id;
    END IF;

    NEW.login_identifier_id := identifier_id;
  END IF;

  PERFORM 1
  FROM public.user_login_identifiers AS identifier
  WHERE identifier.id = NEW.login_identifier_id
    AND identifier.user_id = NEW.user_id
    AND identifier.kind = 'local_email'
    AND identifier.verified_at IS NOT NULL
    AND identifier.retired_at IS NULL;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'local credential requires an active local email identifier'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.bind_local_login_identifier_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.bind_local_login_identifier_v1() FROM PUBLIC;--> statement-breakpoint

CREATE TRIGGER local_break_glass_credentials_bind_identifier
BEFORE INSERT OR UPDATE OF user_id, login_identifier_id
ON public.local_break_glass_credentials
FOR EACH ROW
EXECUTE FUNCTION app.bind_local_login_identifier_v1();--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.get_local_break_glass_credential(p_email text)
RETURNS TABLE (
  user_id uuid,
  password_phc text,
  password_algorithm text,
  password_version integer,
  must_rotate boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT credential.user_id,
         credential.password_phc,
         credential.password_algorithm,
         credential.password_version,
         credential.must_rotate
  FROM public.user_login_identifiers AS identifier
  JOIN public.local_break_glass_credentials AS credential
    ON credential.login_identifier_id = identifier.id
   AND credential.user_id = identifier.user_id
  JOIN public.users AS identity ON identity.id = credential.user_id
  WHERE identifier.kind = 'local_email'
    AND identifier.canonical_value = lower(btrim(p_email))
    AND identifier.verified_at IS NOT NULL
    AND identifier.retired_at IS NULL
    AND identity.active = true
    AND credential.disabled_at IS NULL;
$function$;
