-- last_observed_at is the last successful exact-provider observation. Account
-- retirement is a lifecycle mutation, not an IdP observation. Replace the v1
-- trigger forward-only so the sealed v36 migrations remain immutable while a
-- retirement preserves that timestamp before the row is written.
CREATE FUNCTION app.guard_platform_federated_external_identity_v2()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform federated identities are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF ROW(NEW.id, NEW.platform_provider_id, NEW.provider_kind, NEW.user_id,
           NEW.subject_format, NEW.subject_ciphertext, NEW.subject_nonce,
           NEW.key_version, NEW.admitted_configuration_revision,
           NEW.admitted_security_revision, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.platform_provider_id, OLD.provider_kind, OLD.user_id,
           OLD.subject_format, OLD.subject_ciphertext, OLD.subject_nonce,
           OLD.key_version, OLD.admitted_configuration_revision,
           OLD.admitted_security_revision, OLD.created_at)
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at < OLD.last_observed_at
       OR OLD.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'platform federated identity transition is invalid'
        USING ERRCODE = '23514';
    END IF;

    IF NEW.retired_at IS NULL THEN
      IF NEW.version <> OLD.version
         OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'platform federated identity observation is invalid'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      IF NEW.version <> OLD.version + 1
         OR NEW.retired_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'platform federated identity retirement is invalid'
          USING ERRCODE = '23514';
      END IF;
      NEW.last_observed_at := OLD.last_observed_at;
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

DROP TRIGGER platform_federated_external_identities_guard_v1
  ON public.platform_federated_external_identities;
--> statement-breakpoint

CREATE TRIGGER platform_federated_external_identities_guard_v2
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_federated_external_identities
FOR EACH ROW
EXECUTE FUNCTION app.guard_platform_federated_external_identity_v2();
--> statement-breakpoint

ALTER FUNCTION app.guard_platform_federated_external_identity_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_platform_federated_external_identity_v2()
  FROM PUBLIC, periapsis_worker;
