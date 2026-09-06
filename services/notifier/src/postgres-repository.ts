import { sql } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";
import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres, { type Sql } from "postgres";

import {
  createDeliveryClaim,
  type DeliveryClaim,
  type DeliveryRepository,
} from "./delivery.js";
import {
  NotificationConfigurationError,
  NotificationConflictError,
  NotificationValidationError,
  type DeliveryFailureClass,
} from "./errors.js";
import {
  createFanoutClaim,
  type FanoutClaim,
  type FanoutCommitResult,
  type NotificationFanoutInputs,
  type NotificationFanoutRepository,
  type PlannedEmailDelivery,
} from "./fanout.js";
import {
  isContextObject,
  isNotificationEventType,
  type ContextValue,
  type NotificationActorKind,
  type NotificationAudience,
  type NotificationEventType,
  type NotificationObjectType,
} from "./event.js";
import {
  createNotificationProtectedSecret,
  type NotificationProtectedSecret,
  type NotificationSecretKind,
} from "./keyring.js";
import type { RecipientCandidateInput } from "./planner.js";
import type {
  GroupingPolicyInput,
  NotificationConditionInput,
  NotificationRuleInput,
  QuietHoursInput,
  RecipientSelectorInput,
  RecipientSelectorKind,
  RetryPolicyInput,
} from "./rule.js";
import type { NotifierRepository } from "./runtime.js";
import {
  createSmtpConfiguration,
  type SanitizedProviderResponse,
  type SmtpConfiguration,
  type SmtpSecurityMode,
} from "./smtp.js";
import type { SmtpConfigurationRepository } from "./smtp-resolver.js";
import type { SmtpHealthConfigurationRepository } from "./smtp-health.js";
import type { NotificationTemplateInput } from "./template.js";
import {
  expectedMigrationFingerprint,
  expectedNotificationDispatchReadinessV51SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV51SourceHash,
  expectedPrivateReleaseRuntimeReadinessV51SourceHash,
  expectedReleaseRuntimeReadinessV51SourceHash,
  expectedSchemaCompatibilityV51SourceHash,
} from "./schema-compatibility.gen.js";
import {
  createWebhookDeliveryClaim,
  type WebhookDeliveryClaim,
  type WebhookDeliveryRepository,
} from "./webhook-worker.js";
import type {
  SanitizedWebhookResponse,
  WebhookPayloadSnapshotInput,
} from "./webhook.js";
import {
  createWebhookConfigurationPolicyPin,
  createWebhookDeliveryPolicyPin,
  createWebhookLocalDevelopmentPin,
  createWebhookUrlPolicyVersion,
  type LiveWebhookUrlPolicySource,
  type WebhookDeliveryEgressPin,
  type WebhookUrlPolicyRuleInput,
  type WebhookUrlPolicyVersion,
} from "./webhook-url-policy.js";
import { requireUuidV7 } from "./validation.js";

interface CancelableQuery<T> extends PromiseLike<T> {
  cancel(): void;
}

interface DrizzleCancelableQueryTag {
  <T extends Record<string, unknown>[] = Record<string, unknown>[]>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): CancelableQuery<T>;
}

type PostgresQueryParameter = null | boolean | number | string | Date;

interface DatabaseErrorShape {
  readonly code?: unknown;
}

export interface PostgresNotificationRepositoryOptions {
  readonly databaseUrl: string;
  readonly maximumConnections?: number;
  readonly allowPlainLocalSmtp?: boolean;
  readonly allowPlainLocalWebhooks?: boolean;
}

export class PostgresNotificationRepository
  implements
    NotifierRepository,
    NotificationFanoutRepository,
    DeliveryRepository,
    WebhookDeliveryRepository,
    LiveWebhookUrlPolicySource,
    SmtpConfigurationRepository,
    SmtpHealthConfigurationRepository
{
  readonly #database: PostgresJsDatabase & {
    readonly $client: Sql<Record<string, never>>;
  };
  // oxlint-disable-next-line no-unused-private-class-members -- tagged-template private uses are not recognized by this rule.
  readonly #sql: DrizzleCancelableQueryTag;
  readonly #allowPlainLocalSmtp: boolean;
  readonly #allowPlainLocalWebhooks: boolean;
  #closed = false;

  constructor(options: PostgresNotificationRepositoryOptions) {
    if (
      typeof options.databaseUrl !== "string" ||
      options.databaseUrl.length < 1 ||
      options.databaseUrl.length > 8_192
    ) {
      throw new NotificationConfigurationError();
    }
    const maximumConnections = options.maximumConnections ?? 10;
    if (
      !Number.isInteger(maximumConnections) ||
      maximumConnections < 1 ||
      maximumConnections > 64
    ) {
      throw new NotificationConfigurationError();
    }
    const client = postgres(options.databaseUrl, {
      max: maximumConnections,
      connect_timeout: 10,
      idle_timeout: 30,
      max_lifetime: 60 * 30,
      prepare: false,
      connection: {
        application_name: "periapsis_notifier",
        TimeZone: "UTC",
        statement_timeout: 30_000,
        lock_timeout: 5_000,
        idle_in_transaction_session_timeout: 30_000,
      },
    });
    this.#database = drizzle({ client });
    const dialect = new PgDialect();
    this.#sql = <
      T extends Record<string, unknown>[] = Record<string, unknown>[],
    >(
      strings: TemplateStringsArray,
      ...parameters: readonly unknown[]
    ): CancelableQuery<T> => {
      const statement = dialect.sqlToQuery(sql<T>(strings, ...parameters));
      // Drizzle owns query construction and PostgreSQL placeholder binding. The
      // underlying postgres-js query is retained so AbortSignal can still issue
      // a protocol-level cancellation instead of merely abandoning a Promise.
      return this.#database.$client.unsafe<T>(
        statement.sql,
        toPostgresQueryParameters(statement.params),
      );
    };
    this.#allowPlainLocalSmtp = options.allowPlainLocalSmtp === true;
    this.#allowPlainLocalWebhooks = options.allowPlainLocalWebhooks === true;
  }

  async claimFanoutBatch(input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }): Promise<readonly FanoutClaim[]> {
    const rows = await this.#query(
      () =>
        this.#sql<{ claim: unknown }[]>`
          SELECT claim
          FROM app.claim_notification_fanout_batch_v1(
            ${input.workerId}, ${input.limit}, ${input.leaseDurationMs}, ${input.now}
          )
        `,
      input.signal,
      false,
    );
    return Object.freeze(rows.map((row) => decodeFanoutClaim(row.claim)));
  }

  async heartbeatFanout(
    claim: FanoutClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean> {
    const rows = await this.#query(
      () =>
        this.#sql<{ retained: boolean }[]>`
          SELECT app.heartbeat_notification_fanout_v1(
            ${claim.id}, ${claim.fenceToken}, ${leaseUntil}
          ) AS retained
        `,
      signal,
      true,
    );
    return requireSingleRow(rows).retained;
  }

  async loadFanoutInputs(
    claim: FanoutClaim,
    signal: AbortSignal,
  ): Promise<NotificationFanoutInputs> {
    const rows = await this.#query(
      () =>
        this.#sql<{ value: unknown }[]>`
          SELECT app.load_notification_fanout_inputs_v3(
            ${claim.id}, ${claim.fenceToken}
          ) AS value
        `,
      signal,
      true,
    );
    return decodeFanoutInputs(requireSingleRow(rows).value);
  }

  async commitFanout(
    claim: FanoutClaim,
    deliveries: readonly PlannedEmailDelivery[],
    at: Date,
    signal: AbortSignal,
  ): Promise<FanoutCommitResult> {
    const rows = await this.#query(
      () =>
        this.#sql<{ value: unknown }[]>`
          SELECT app.commit_notification_fanout_v3(
            ${claim.id}, ${claim.fenceToken},
            ${JSON.stringify(deliveries)}::jsonb, ${at}
          ) AS value
        `,
      signal,
      true,
    );
    return decodeFanoutCommitResult(requireSingleRow(rows).value);
  }

  async retryFanout(
    claim: FanoutClaim,
    nextAttemptAt: Date,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#query(
      () =>
        this.#sql`
          SELECT app.retry_notification_fanout_v1(
            ${claim.id}, ${claim.fenceToken}, ${nextAttemptAt}, ${at}
          )
        `,
      signal,
      true,
    );
  }

  async deadLetterFanout(
    claim: FanoutClaim,
    reason: "configuration" | "security" | "validation" | "attempts_exhausted",
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#query(
      () =>
        this.#sql`
          SELECT app.dead_letter_notification_fanout_v1(
            ${claim.id}, ${claim.fenceToken}, ${reason}, ${at}
          )
        `,
      signal,
      true,
    );
  }

  async claimBatch(input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }): Promise<readonly DeliveryClaim[]> {
    const rows = await this.#query(
      () =>
        this.#sql<{ claim: unknown }[]>`
          SELECT claim
          FROM app.claim_notification_delivery_batch_v1(
            ${input.workerId}, ${input.limit}, ${input.leaseDurationMs}, ${input.now}
          )
        `,
      input.signal,
      false,
    );
    return Object.freeze(rows.map((row) => decodeDeliveryClaim(row.claim)));
  }

  async heartbeat(
    claim: DeliveryClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean> {
    return await this.#heartbeatDelivery(
      claim.id,
      claim.fenceToken,
      leaseUntil,
      signal,
    );
  }

  async reserveSubmission(
    claim: DeliveryClaim,
    stableMessageId: string,
    at: Date,
    signal: AbortSignal,
  ): Promise<"reserved" | "already_delivered" | "uncertain"> {
    return await this.#reserveDelivery(
      claim.id,
      claim.fenceToken,
      "email",
      stableMessageId,
      at,
      signal,
    );
  }

  async complete(
    claim: DeliveryClaim,
    response: SanitizedProviderResponse,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#completeDelivery(
      claim.id,
      claim.fenceToken,
      "email",
      response,
      at,
      signal,
    );
  }

  async completeReplay(
    claim: DeliveryClaim,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#completeDeliveryReplay(
      claim.id,
      claim.fenceToken,
      "email",
      at,
      signal,
    );
  }

  async retry(
    claim: DeliveryClaim,
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
    at: Date,
    safeAfterReservation: boolean,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#retryDelivery(
      claim.id,
      claim.fenceToken,
      "email",
      failureClass,
      nextAttemptAt,
      at,
      safeAfterReservation,
      signal,
    );
  }

  async deadLetter(
    claim: DeliveryClaim,
    failureClass: DeliveryFailureClass | "submission_uncertain",
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#deadLetterDelivery(
      claim.id,
      claim.fenceToken,
      "email",
      failureClass,
      at,
      signal,
    );
  }

  async claimWebhookBatch(input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }): Promise<readonly WebhookDeliveryClaim[]> {
    const rows = await this.#query(
      () =>
        this.#sql<{ claim: unknown }[]>`
          WITH runtime AS MATERIALIZED (
            SELECT set_config(
              'app.webhook_plain_local_exemption',
              ${this.#allowPlainLocalWebhooks ? "true" : "false"},
              true
            )
          )
          SELECT claimed.claim
          FROM runtime
          CROSS JOIN LATERAL app.claim_notification_webhook_delivery_batch_v1(
            ${input.workerId}, ${input.limit}, ${input.leaseDurationMs}, ${input.now}
          ) AS claimed
        `,
      input.signal,
      false,
    );
    return Object.freeze(
      rows.map((row) =>
        decodeWebhookClaim(row.claim, this.#allowPlainLocalWebhooks),
      ),
    );
  }

  async loadCurrent(input: {
    tenantId: string;
    policyId: string;
    phase: "attempt" | "connect";
    signal: AbortSignal;
  }): Promise<WebhookUrlPolicyVersion | null> {
    if (input.phase !== "attempt" && input.phase !== "connect") {
      throw new NotificationValidationError(
        "webhook URL policy phase is invalid",
      );
    }
    const rows = await this.#query(
      () =>
        this.#sql<{ policy: unknown }[]>`
          SELECT policy
          FROM app.get_current_webhook_url_policy_for_delivery_v1(
            ${input.tenantId}, ${input.policyId}
          )
        `,
      input.signal,
      false,
    );
    const row = requireSingleRow(rows);
    return row.policy === null ? null : decodeWebhookUrlPolicy(row.policy);
  }

  async loadLocalDevelopmentAuthorization(input: {
    tenantId: string;
    phase: "attempt" | "connect";
    signal: AbortSignal;
  }): Promise<boolean> {
    requireUuidV7(input.tenantId, "local webhook delivery tenant id");
    if (input.phase !== "attempt" && input.phase !== "connect") {
      throw new NotificationValidationError(
        "webhook URL policy phase is invalid",
      );
    }
    const rows = await this.#query(
      () =>
        this.#sql<{ allowed: unknown }[]>`
          WITH runtime AS MATERIALIZED (
            SELECT set_config(
              'app.webhook_plain_local_exemption',
              ${this.#allowPlainLocalWebhooks ? "true" : "false"},
              true
            )
          )
          SELECT authorized.allowed
          FROM runtime
          CROSS JOIN LATERAL app.get_local_webhook_delivery_authorization_v1(
            ${input.tenantId}
          )
            AS authorized
        `,
      input.signal,
      false,
    );
    return requireBoolean(requireSingleRow(rows).allowed);
  }

  async heartbeatWebhook(
    claim: WebhookDeliveryClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean> {
    return await this.#heartbeatDelivery(
      claim.id,
      claim.fenceToken,
      leaseUntil,
      signal,
    );
  }

  async reserveWebhookSubmission(
    claim: WebhookDeliveryClaim,
    stableSubmissionId: string,
    at: Date,
    signal: AbortSignal,
  ): Promise<"reserved" | "already_delivered" | "uncertain"> {
    return await this.#reserveDelivery(
      claim.id,
      claim.fenceToken,
      "webhook",
      stableSubmissionId,
      at,
      signal,
    );
  }

  async completeWebhook(
    claim: WebhookDeliveryClaim,
    response: SanitizedWebhookResponse,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#completeDelivery(
      claim.id,
      claim.fenceToken,
      "webhook",
      response,
      at,
      signal,
    );
  }

  async completeWebhookReplay(
    claim: WebhookDeliveryClaim,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#completeDeliveryReplay(
      claim.id,
      claim.fenceToken,
      "webhook",
      at,
      signal,
    );
  }

  async retryWebhook(
    claim: WebhookDeliveryClaim,
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
    at: Date,
    safeAfterReservation: boolean,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#retryDelivery(
      claim.id,
      claim.fenceToken,
      "webhook",
      failureClass,
      nextAttemptAt,
      at,
      safeAfterReservation,
      signal,
    );
  }

  async deadLetterWebhook(
    claim: WebhookDeliveryClaim,
    failureClass: DeliveryFailureClass | "submission_uncertain",
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#deadLetterDelivery(
      claim.id,
      claim.fenceToken,
      "webhook",
      failureClass,
      at,
      signal,
    );
  }

  async loadPinnedForTenant(
    tenantId: string,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<SmtpConfiguration | null> {
    return this.#loadPinned(tenantId, pin, signal);
  }

  async loadPinnedForProbe(
    tenantId: string | undefined,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<SmtpConfiguration | null> {
    return this.#loadPinned(tenantId, pin, signal);
  }

  async #loadPinned(
    tenantId: string | undefined,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<SmtpConfiguration | null> {
    let rows: Record<string, unknown>[];
    try {
      rows = await this.#query(
        () =>
          this.#sql`
            SELECT *
            FROM app.load_pinned_smtp_configuration_v2(
              ${tenantId ?? null}, ${pin.scope}, ${pin.id}, ${pin.version}
            )
          `,
        signal,
        true,
      );
    } catch (error) {
      // Code-first rolling deploy: v1 cannot serve the platform-admin probe
      // because it requires a tenant, so that path remains fail-closed until
      // the v2 migration is present.
      if (!isUndefinedFunction(error) || tenantId === undefined) throw error;
      rows = await this.#query(
        () =>
          this.#sql`
            SELECT *
            FROM app.load_pinned_smtp_configuration_v1(
              ${tenantId}, ${pin.scope}, ${pin.id}, ${pin.version}
            )
          `,
        signal,
        true,
      );
    }
    if (rows.length === 0) return null;
    if (rows.length !== 1) throw new NotificationConfigurationError();
    return decodeSmtpConfiguration(
      rows[0]!,
      tenantId,
      pin,
      this.#allowPlainLocalSmtp,
    );
  }

  async readiness(
    signal: AbortSignal,
  ): Promise<Readonly<{ queueDepth: number; oldestPendingSeconds: number }>> {
    type ReadinessRow = {
      queue_depth: number | string;
      role_safe: boolean;
      schema_safe: boolean;
      source_safe: boolean;
      oldest_pending_seconds: number | string;
    };
    let rows: ReadinessRow[];
    const availabilityRows = await this.#query(
      () => this.#sql<{ available: boolean }[]>`
        SELECT pg_catalog.to_regprocedure(
          'app.notification_dispatch_readiness_v51()'
        ) IS NOT NULL AS available
      `,
      signal,
      true,
    );
    const availability = requireSingleRow(availabilityRows).available;
    if (typeof availability !== "boolean") {
      throw new NotificationConfigurationError();
    }
    try {
      if (availability) {
        rows = await this.#query(
          () => this.#sql<ReadinessRow[]>`
          WITH expected(
            signature, source_hash, owner_name, language_name,
            expected_config, expected_result, expected_acl_roles,
            expected_returns_set
          ) AS (
            VALUES
              (
                'app.schema_compatibility_v51()',
                ${expectedSchemaCompatibilityV51SourceHash}::text,
                'periapsis_migrator', 'plpgsql',
                ARRAY[
                  'search_path=pg_catalog',
                  ${`app.schema_compatibility_fingerprint=${expectedMigrationFingerprint}`}
                ]::text[],
                'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
                ARRAY[
                  'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
                ]::text[], true
              ),
              (
                'app.private_release_runtime_dependency_surface_hash_v51()',
                ${expectedPrivateReleaseRuntimeDependencySurfaceHashV51SourceHash}::text,
                'periapsis_migrator', 'sql',
                ARRAY[
                  'search_path=pg_catalog, public, app',
                  'quote_all_identifiers=off', 'TimeZone=UTC',
                  'DateStyle=ISO, YMD', 'IntervalStyle=postgres',
                  'extra_float_digits=3', 'bytea_output=hex',
                  'standard_conforming_strings=on', 'lc_numeric=C'
                ]::text[], 'text',
                ARRAY['periapsis_migrator']::text[], false
              ),
              (
                'app.private_release_runtime_schema_readiness_v51()',
                ${expectedPrivateReleaseRuntimeReadinessV51SourceHash}::text,
                'periapsis_migrator', 'plpgsql',
                ARRAY['search_path=pg_catalog, public, app']::text[],
                'boolean', ARRAY['periapsis_migrator']::text[], false
              ),
              (
                'app.release_runtime_schema_readiness_v51()',
                ${expectedReleaseRuntimeReadinessV51SourceHash}::text,
                'periapsis_migrator', 'plpgsql',
                ARRAY['search_path=pg_catalog, public, app']::text[],
                'boolean', ARRAY[
                  'periapsis_api', 'periapsis_migrator',
                  'periapsis_notification_readiness_owner',
                  'periapsis_worker'
                ]::text[], false
              ),
              (
                'app.notification_dispatch_readiness_v51()',
                ${expectedNotificationDispatchReadinessV51SourceHash}::text,
                'periapsis_notification_readiness_owner', 'plpgsql',
                ARRAY['search_path=pg_catalog, public, app']::text[],
                'TABLE(queue_depth bigint, role_safe boolean, schema_safe boolean, oldest_pending_seconds bigint)',
                ARRAY[
                  'periapsis_migrator',
                  'periapsis_notification_readiness_owner',
                  'periapsis_notifier'
                ]::text[], true
              )
          ),
          actual AS (
            SELECT expected.*,
                   function_row.oid AS function_oid,
                   pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                     function_row.prosrc, 'UTF8'
                   )), 'hex') AS actual_source_hash,
                   owner.rolname AS actual_owner_name,
                   language.lanname AS actual_language_name,
                   function_row.*
            FROM expected
            LEFT JOIN pg_catalog.pg_proc AS function_row
              ON function_row.oid=
                pg_catalog.to_regprocedure(expected.signature)
            LEFT JOIN pg_catalog.pg_roles AS owner
              ON owner.oid=function_row.proowner
            LEFT JOIN pg_catalog.pg_language AS language
              ON language.oid=function_row.prolang
          ),
          trusted AS (
            SELECT count(function_oid)=5 AND coalesce(bool_and(
              actual_source_hash=source_hash
              AND actual_owner_name=owner_name
              AND actual_language_name=language_name
              AND prokind='f' AND provolatile='s' AND prosecdef
              AND NOT proisstrict AND NOT proleakproof AND proparallel='u'
              AND pronargs=0 AND pronargdefaults=0
              AND proargtypes=''::pg_catalog.oidvector
              AND proargdefaults IS NULL AND provariadic=0 AND prosupport=0
              AND proretset=expected_returns_set
              AND procost=100::real
              AND prorows=CASE WHEN expected_returns_set
                THEN 1000::real ELSE 0::real END
              AND protrftypes IS NULL AND probin IS NULL
              AND prosqlbody IS NULL
              AND proconfig IS NOT DISTINCT FROM expected_config
              AND pg_catalog.pg_get_function_result(function_oid)=
                expected_result
              AND (
                SELECT count(*)=pg_catalog.cardinality(expected_acl_roles)
                  AND pg_catalog.array_agg(
                    coalesce(grantee.rolname::text, 'PUBLIC')
                    ORDER BY coalesce(grantee.rolname::text, 'PUBLIC')
                      COLLATE "C"
                  ) IS NOT DISTINCT FROM expected_acl_roles
                  AND coalesce(bool_and(
                    function_acl.grantor=proowner
                    AND function_acl.privilege_type='EXECUTE'
                    AND NOT function_acl.is_grantable
                  ),false)
                FROM pg_catalog.aclexplode(coalesce(
                  proacl,pg_catalog.acldefault('f',proowner)
                )) AS function_acl
                LEFT JOIN pg_catalog.pg_roles AS grantee
                  ON grantee.oid=function_acl.grantee
              )
            ),false) AS source_safe
            FROM actual
          )
          SELECT readiness.queue_depth, readiness.role_safe,
                 readiness.schema_safe, trusted.source_safe,
                 readiness.oldest_pending_seconds
          FROM app.notification_dispatch_readiness_v51() AS readiness
          CROSS JOIN trusted
          `,
          signal,
          true,
        );
      } else {
        rows = await this.#query(
          () => this.#sql<ReadinessRow[]>`
          SELECT queue_depth, role_safe, schema_safe,
                 true AS source_safe, oldest_pending_seconds
          FROM app.notification_dispatch_readiness_v4()
          `,
          signal,
          true,
        );
      }
    } catch (error) {
      // Once the V51 root has been observed, an undefined dependency is
      // schema drift rather than a rolling-deploy signal. The V4 path is also
      // configuration-invalid if its advertised compatibility root vanished.
      if (!signal.aborted && isUndefinedFunction(error)) {
        throw new NotificationConfigurationError();
      }
      throw error;
    }
    const row = requireSingleRow(rows);
    if (!row.role_safe || !row.schema_safe || !row.source_safe) {
      throw new NotificationConfigurationError();
    }
    const value = row.queue_depth;
    const queueDepth = typeof value === "string" ? Number(value) : value;
    const oldestValue = row.oldest_pending_seconds;
    const oldestPendingSeconds =
      typeof oldestValue === "string" ? Number(oldestValue) : oldestValue;
    if (
      !Number.isSafeInteger(queueDepth) ||
      queueDepth < 0 ||
      queueDepth > 9_007_199_254_740_991 ||
      !Number.isSafeInteger(oldestPendingSeconds) ||
      oldestPendingSeconds < 0 ||
      oldestPendingSeconds > 9_007_199_254_740_991
    ) {
      throw new NotificationConfigurationError();
    }
    return Object.freeze({ queueDepth, oldestPendingSeconds });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#database.$client.end({ timeout: 5 });
  }

  async #heartbeatDelivery(
    deliveryId: string,
    fenceToken: string,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean> {
    const rows = await this.#query(
      () =>
        this.#sql<{ retained: boolean }[]>`
          SELECT app.heartbeat_notification_delivery_v1(
            ${deliveryId}, ${fenceToken}, ${leaseUntil}
          ) AS retained
        `,
      signal,
      true,
    );
    return requireSingleRow(rows).retained;
  }

  async #reserveDelivery(
    deliveryId: string,
    fenceToken: string,
    channel: "email" | "webhook",
    reservationId: string,
    at: Date,
    signal: AbortSignal,
  ): Promise<"reserved" | "already_delivered" | "uncertain"> {
    const rows = await this.#query(
      () =>
        this.#sql<{ outcome: string }[]>`
          SELECT app.reserve_notification_delivery_submission_v2(
            ${deliveryId}, ${fenceToken}, ${channel}, ${reservationId}, ${at}
          ) AS outcome
        `,
      signal,
      true,
    );
    const outcome = requireSingleRow(rows).outcome;
    if (
      outcome !== "reserved" &&
      outcome !== "already_delivered" &&
      outcome !== "uncertain"
    ) {
      throw new NotificationValidationError(
        "database returned an invalid reservation outcome",
      );
    }
    return outcome;
  }

  async #completeDelivery(
    deliveryId: string,
    fenceToken: string,
    channel: "email" | "webhook",
    response: SanitizedProviderResponse | SanitizedWebhookResponse,
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    try {
      await this.#query(
        () =>
          this.#sql`
            SELECT app.complete_notification_delivery_v3(
              ${deliveryId}, ${fenceToken}, ${channel},
              ${JSON.stringify(response)}::jsonb, ${at}
            )
          `,
        signal,
        true,
      );
    } catch (error) {
      if (!isUndefinedFunction(error)) throw error;
      await this.#query(
        () =>
          this.#sql`
            SELECT app.complete_notification_delivery_v2(
              ${deliveryId}, ${fenceToken}, ${channel},
              ${JSON.stringify(response)}::jsonb, ${at}
            )
          `,
        signal,
        true,
      );
    }
  }

  async #completeDeliveryReplay(
    deliveryId: string,
    fenceToken: string,
    channel: "email" | "webhook",
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#query(
      () =>
        this.#sql`
          SELECT app.complete_notification_delivery_replay_v2(
            ${deliveryId}, ${fenceToken}, ${channel}, ${at}
          )
        `,
      signal,
      true,
    );
  }

  async #retryDelivery(
    deliveryId: string,
    fenceToken: string,
    channel: "email" | "webhook",
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
    at: Date,
    safeAfterReservation: boolean,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#query(
      () =>
        this.#sql`
          SELECT app.retry_notification_delivery_v2(
            ${deliveryId}, ${fenceToken}, ${channel}, ${failureClass},
            ${nextAttemptAt}, ${at}, ${safeAfterReservation}
          )
        `,
      signal,
      true,
    );
  }

  async #deadLetterDelivery(
    deliveryId: string,
    fenceToken: string,
    channel: "email" | "webhook",
    failureClass: DeliveryFailureClass | "submission_uncertain",
    at: Date,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#query(
      () =>
        this.#sql`
          SELECT app.dead_letter_notification_delivery_v2(
            ${deliveryId}, ${fenceToken}, ${channel}, ${failureClass}, ${at}
          )
        `,
      signal,
      true,
    );
  }

  async #query<T>(
    create: () => CancelableQuery<T>,
    signal: AbortSignal,
    retryTransportFailure: boolean,
  ): Promise<T> {
    if (this.#closed) throw new NotificationConfigurationError();
    if (signal.aborted) throw signal.reason;
    try {
      return await awaitCancelable(create(), signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      if (!retryTransportFailure || !isTransportFailure(error)) {
        throw translateDatabaseError(error);
      }
    }
    try {
      return await awaitCancelable(create(), signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      throw translateDatabaseError(error);
    }
  }
}

export function createPostgresNotificationRepository(
  options: PostgresNotificationRepositoryOptions,
): PostgresNotificationRepository {
  return new PostgresNotificationRepository(options);
}

async function awaitCancelable<T>(
  query: CancelableQuery<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    query.cancel();
    throw signal.reason;
  }
  const abort = (): void => query.cancel();
  signal.addEventListener("abort", abort, { once: true });
  try {
    return await query;
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

function translateDatabaseError(error: unknown): unknown {
  const code = databaseErrorCode(error);
  if (code === "40001" || code === "23505" || code === "P0002") {
    return new NotificationConflictError();
  }
  if (code === "0A000" || code === "42501") {
    return new NotificationConfigurationError();
  }
  if (code === "22023" || code === "23514" || code === "55000") {
    return new NotificationValidationError(
      "database rejected notification data",
    );
  }
  return error;
}

function isTransportFailure(error: unknown): boolean {
  const code = databaseErrorCode(error);
  return (
    code === undefined ||
    code.startsWith("08") ||
    [
      "57P01",
      "57P02",
      "57P03",
      "ECONNRESET",
      "ECONNREFUSED",
      "EPIPE",
      "ETIMEDOUT",
    ].includes(code)
  );
}

function databaseErrorCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object") return undefined;
  const code = (error as DatabaseErrorShape).code;
  return typeof code === "string" ? code : undefined;
}

function isUndefinedFunction(error: unknown): boolean {
  return databaseErrorCode(error) === "42883";
}

function toPostgresQueryParameters(
  values: readonly unknown[],
): PostgresQueryParameter[] {
  return values.map((value) => {
    if (
      value === null ||
      typeof value === "boolean" ||
      typeof value === "number" ||
      typeof value === "string" ||
      value instanceof Date
    ) {
      return value;
    }
    throw new NotificationValidationError(
      "notification query contains an unsupported database parameter",
    );
  });
}

function decodeFanoutClaim(value: unknown): FanoutClaim {
  const row = requireRecord(value);
  const event = requireRecord(row.event);
  return createFanoutClaim({
    id: requireString(row.id),
    tenantId: requireString(row.tenantId),
    event: {
      id: requireString(event.id),
      tenantId: requireString(event.tenantId),
      type: requireNotificationEventType(event.type),
      objectType: requireNotificationObjectType(event.objectType),
      objectId: requireString(event.objectId),
      objectVersion: requireIntegerValue(event.objectVersion),
      occurredAt: requireDate(event.occurredAt),
      actorKind: requireNotificationActorKind(event.actorKind),
      ...(event.actorId === undefined
        ? {}
        : { actorId: requireString(event.actorId) }),
      source: requireString(event.source),
      context: requireContextObject(event.context),
      maximumAudience: requireNotificationAudience(event.maximumAudience),
      ...(event.traceContext === undefined || event.traceContext === null
        ? {}
        : { traceContext: decodeTraceContext(event.traceContext) }),
    },
    attempt: requireIntegerValue(row.attempt),
    maximumAttempts: requireIntegerValue(row.maximumAttempts),
    fenceToken: requireString(row.fenceToken),
    leaseUntil: requireDate(row.leaseUntil),
  });
}

function decodeFanoutInputs(value: unknown): NotificationFanoutInputs {
  const row = requireRecord(value);
  const rules = requireArray(row.rules).map(decodeRuleInput);
  const candidates = requireArray(row.candidates).map(decodeCandidateInput);
  const templates = requireArray(row.templates).map(decodeTemplateInput);
  const smtpValue = row.smtpConfiguration;
  const smtpConfiguration =
    smtpValue === null
      ? null
      : (() => {
          const pin = requireRecord(smtpValue);
          return Object.freeze({
            scope: requireSmtpScope(pin.scope),
            id: requireString(pin.id),
            version: requireIntegerValue(pin.version),
          });
        })();
  return Object.freeze({
    rules: Object.freeze(rules),
    candidates: Object.freeze(candidates),
    templates: Object.freeze(templates),
    smtpConfiguration,
  });
}

function decodeRuleInput(value: unknown): NotificationRuleInput {
  const row = requireRecord(value);
  return {
    id: requireString(row.id),
    tenantId: requireString(row.tenantId),
    name: requireString(row.name),
    description: requireString(row.description),
    eventType: requireNotificationEventType(row.eventType),
    objectType: requireNotificationObjectType(row.objectType),
    condition: decodeCondition(row.condition),
    recipients: requireArray(row.recipients).map(decodeRecipientSelector),
    templateId: requireString(row.templateId),
    templateVersion: requireIntegerValue(row.templateVersion),
    channel: requireNotificationChannel(row.channel),
    priority: requireIntegerValue(row.priority),
    delayMs: requireIntegerValue(row.delayMs),
    ...(row.quietHours === undefined || row.quietHours === null
      ? {}
      : { quietHours: decodeQuietHours(row.quietHours) }),
    deduplicationWindowMs: requireIntegerValue(row.deduplicationWindowMs),
    grouping: decodeGroupingPolicy(row.grouping),
    retry: decodeRetryPolicy(row.retry),
    enabled: requireBoolean(row.enabled),
    version: requireIntegerValue(row.version),
    effectiveFrom: requireDate(row.effectiveFrom),
    ...(row.effectiveUntil === undefined || row.effectiveUntil === null
      ? {}
      : { effectiveUntil: requireDate(row.effectiveUntil) }),
  };
}

function decodeCandidateInput(value: unknown): RecipientCandidateInput {
  const row = requireRecord(value);
  return {
    tenantId: requireString(row.tenantId),
    email: requireString(row.email),
    audience: requireNotificationAudience(row.audience),
    kinds: requireArray(row.kinds).map(requireCandidateRecipientKind),
    ...(row.values === undefined || row.values === null
      ? {}
      : { values: decodeCandidateValues(row.values) }),
    ...(row.principalId === undefined || row.principalId === null
      ? {}
      : { principalId: requireString(row.principalId) }),
    enabled: requireBoolean(row.enabled),
    emailAllowed: requireBoolean(row.emailAllowed),
  };
}

function decodeTemplateInput(value: unknown): NotificationTemplateInput {
  const row = requireRecord(value);
  return {
    id: requireString(row.id),
    tenantId: requireString(row.tenantId),
    key: requireString(row.key),
    name: requireString(row.name),
    language: requireString(row.language),
    version: requireIntegerValue(row.version),
    subject: requireString(row.subject),
    html: requireString(row.html),
    ...(row.plainText === undefined || row.plainText === null
      ? {}
      : { plainText: requireString(row.plainText) }),
    ...(row.css === undefined || row.css === null
      ? {}
      : { css: requireString(row.css) }),
  };
}

function decodeFanoutCommitResult(value: unknown): FanoutCommitResult {
  const row = requireRecord(value);
  return Object.freeze({
    outcome: requireFanoutCommitOutcome(row.outcome),
    emailCount: requireIntegerValue(row.emailCount),
    webhookCount: requireIntegerValue(row.webhookCount),
    cancelledWebhookCount: requireIntegerValue(row.cancelledWebhookCount),
    totalCount: requireIntegerValue(row.totalCount),
  });
}

function decodeDeliveryClaim(value: unknown): DeliveryClaim {
  const row = requireRecord(value);
  return createDeliveryClaim({
    id: requireString(row.id),
    tenantId: requireString(row.tenantId),
    eventId: requireString(row.eventId),
    ruleId: requireString(row.ruleId),
    ruleVersion: requireIntegerValue(row.ruleVersion),
    smtpConfigurationScope: requireSmtpScope(row.smtpConfigurationScope),
    smtpConfigurationId: requireString(row.smtpConfigurationId),
    smtpConfigurationVersion: requireIntegerValue(row.smtpConfigurationVersion),
    deduplicationKey: requireString(row.deduplicationKey),
    recipient: requireString(row.recipient),
    audience: requireNotificationAudience(row.audience),
    context: requireContextObject(row.context),
    template: decodeTemplateInput(row.template),
    retry: decodeRetryPolicy(row.retry),
    attempt: requireIntegerValue(row.attempt),
    fenceToken: requireString(row.fenceToken),
    leaseUntil: requireDate(row.leaseUntil),
    ...(row.traceContext === undefined || row.traceContext === null
      ? {}
      : { traceContext: decodeTraceContext(row.traceContext) }),
  });
}

function decodeWebhookClaim(
  value: unknown,
  allowPlainLocal: boolean,
): WebhookDeliveryClaim {
  const row = requireRecord(value);
  const signingKey = decodeProtectedSecret(row.signingKey, true);
  const payload = decodeWebhookPayload(row.payload);
  const id = requireString(row.id);
  const tenantId = requireString(row.tenantId);
  const configurationId = requireString(row.configurationId);
  const configurationVersion = requireIntegerValue(row.configurationVersion);
  const endpointUrl = requireString(row.endpointUrl);
  const egressPin = decodeWebhookEgressPin(
    row,
    {
      id,
      tenantId,
      configurationId,
      configurationVersion,
      endpointUrl,
    },
    allowPlainLocal,
  );
  return createWebhookDeliveryClaim(
    {
      id,
      tenantId,
      eventId: requireString(row.eventId),
      configurationId,
      configurationVersion,
      endpointUrl,
      signingKey,
      timeoutMs: requireIntegerValue(row.timeoutMs),
      createdAt: requireDate(row.createdAt),
      attemptAt: requireDate(row.attemptAt),
      payload,
      retry: decodeRetryPolicy(row.retry),
      attempt: requireIntegerValue(row.attempt),
      fenceToken: requireString(row.fenceToken),
      leaseUntil: requireDate(row.leaseUntil),
      egressPin,
      ...(row.traceContext === undefined || row.traceContext === null
        ? {}
        : { traceContext: decodeTraceContext(row.traceContext) }),
    },
    { allowPlainLocal },
  );
}

function decodeWebhookEgressPin(
  row: Record<string, unknown>,
  delivery: Readonly<{
    id: string;
    tenantId: string;
    configurationId: string;
    configurationVersion: number;
    endpointUrl: string;
  }>,
  allowPlainLocal: boolean,
): WebhookDeliveryEgressPin {
  const localDevelopmentExemption = requireBoolean(
    row.localDevelopmentExemption,
  );
  if (localDevelopmentExemption) {
    if (row.urlPolicy !== null && row.urlPolicy !== undefined) {
      throw new NotificationValidationError(
        "database returned an ambiguous webhook egress pin",
      );
    }
    const pin = createWebhookLocalDevelopmentPin(
      {
        deliveryId: delivery.id,
        configurationId: delivery.configurationId,
        configurationVersion: delivery.configurationVersion,
        tenantId: delivery.tenantId,
        endpointUrl: delivery.endpointUrl,
      },
      { allowPlainLocal },
    );
    if (pin.endpointDigest !== requireString(row.endpointDigest)) {
      throw new NotificationValidationError(
        "database returned a mismatched webhook endpoint pin",
      );
    }
    return pin;
  }
  const policy = decodeWebhookUrlPolicy(row.urlPolicy);
  const configuration = createWebhookConfigurationPolicyPin(policy, {
    configurationId: delivery.configurationId,
    configurationVersion: delivery.configurationVersion,
    tenantId: delivery.tenantId,
    endpointUrl: delivery.endpointUrl,
  });
  const pin = createWebhookDeliveryPolicyPin(configuration, {
    deliveryId: delivery.id,
    configurationId: delivery.configurationId,
    configurationVersion: delivery.configurationVersion,
    tenantId: delivery.tenantId,
    endpointUrl: delivery.endpointUrl,
  });
  if (
    pin.endpointDigest !== requireString(row.endpointDigest) ||
    pin.policyDigest !== requireString(row.policyDigest)
  ) {
    throw new NotificationValidationError(
      "database returned a mismatched webhook policy pin",
    );
  }
  return pin;
}

function decodeWebhookUrlPolicy(value: unknown): WebhookUrlPolicyVersion {
  const row = requireRecord(value);
  const rules = requireArray(row.rules).map(
    (ruleValue): WebhookUrlPolicyRuleInput => {
      const rule = requireRecord(ruleValue);
      const effect = requireString(rule.effect);
      const match = requireString(rule.match);
      if (
        (effect !== "allow" && effect !== "deny") ||
        (match !== "exact" && match !== "subdomains")
      ) {
        throw new NotificationValidationError(
          "database returned an invalid webhook URL policy rule",
        );
      }
      return {
        effect,
        match,
        hostname: requireString(rule.hostname),
        port: requireIntegerValue(rule.port),
      };
    },
  );
  const policy = createWebhookUrlPolicyVersion({
    id: requireString(row.id),
    versionId: requireString(row.versionId),
    tenantId: requireString(row.tenantId),
    version: requireIntegerValue(row.version),
    rules,
    publishedByMembershipId: requireString(row.publishedByMembershipId),
    publishedAt: requireDate(row.publishedAt),
  });
  if (
    policy.digest !== requireString(row.digest) ||
    policy.semanticDigest !== requireString(row.semanticDigest)
  ) {
    throw new NotificationValidationError(
      "database returned an invalid webhook URL policy digest",
    );
  }
  return policy;
}

function decodeTraceContext(value: unknown): {
  traceParent: string;
  traceState?: string;
} {
  const row = requireRecord(value);
  return {
    traceParent: requireString(row.traceParent),
    ...(row.traceState === undefined || row.traceState === null
      ? {}
      : { traceState: requireString(row.traceState) }),
  };
}

function decodeWebhookPayload(value: unknown): WebhookPayloadSnapshotInput {
  const row = requireRecord(value);
  const event = requireRecord(row.event);
  return {
    schemaVersion: requireWebhookSchemaVersion(row.schemaVersion),
    event: {
      id: requireString(event.id),
      type: requireNotificationEventType(event.type),
      objectType: requireNotificationObjectType(event.objectType),
      objectId: requireString(event.objectId),
      objectVersion: requireIntegerValue(event.objectVersion),
      occurredAt: requireDate(event.occurredAt),
      ...(event.actorId === undefined || event.actorId === null
        ? {}
        : { actorId: requireString(event.actorId) }),
    },
    context: requireContextObject(row.context),
  };
}

function decodeSmtpConfiguration(
  row: Record<string, unknown>,
  tenantId: string | undefined,
  pin: Readonly<{
    scope: "tenant" | "platform";
    id: string;
    version: number;
  }>,
  allowPlainLocal: boolean,
): SmtpConfiguration {
  const scope = requireString(row.configuration_scope);
  if (scope !== pin.scope) throw new NotificationConfigurationError();
  const scopedTenant =
    row.tenant_id === null ? undefined : requireString(row.tenant_id);
  if (
    (pin.scope === "tenant" &&
      (tenantId === undefined || scopedTenant !== tenantId)) ||
    (pin.scope === "platform" && scopedTenant !== undefined)
  ) {
    throw new NotificationConfigurationError();
  }
  if (
    requireString(row.configuration_id) !== pin.id ||
    requireIntegerValue(row.configuration_version) !== pin.version
  ) {
    throw new NotificationConfigurationError();
  }
  const passwordSecret = decodeNullableProtectedSecret(
    row,
    "password",
    scopedTenant,
  );
  const dkimSecret = decodeNullableProtectedSecret(row, "dkim", scopedTenant);
  const dkimDomainName = optionalString(row.dkim_domain_name);
  const dkimSelector = optionalString(row.dkim_selector);
  if (
    (dkimSecret === undefined) !== (dkimDomainName === undefined) ||
    (dkimDomainName === undefined) !== (dkimSelector === undefined)
  ) {
    throw new NotificationConfigurationError();
  }
  return createSmtpConfiguration(
    {
      id: requireString(row.configuration_id),
      ...(scopedTenant === undefined ? {} : { tenantId: scopedTenant }),
      name: requireString(row.name),
      host: requireString(row.host),
      port: requireIntegerValue(row.port),
      security: requireSmtpSecurity(row.security),
      ...(row.username === null
        ? {}
        : { username: requireString(row.username) }),
      ...(passwordSecret === undefined ? {} : { passwordSecret }),
      fromName: requireString(row.from_name),
      fromEmail: requireString(row.from_email),
      ...(row.reply_to_email === null
        ? {}
        : { replyToEmail: requireString(row.reply_to_email) }),
      timeoutMs: requireIntegerValue(row.timeout_ms),
      maximumConnections: requireIntegerValue(row.maximum_connections),
      maximumMessagesPerConnection: requireIntegerValue(
        row.maximum_messages_per_connection,
      ),
      rateLimitPerSecond: requireIntegerValue(row.rate_limit_per_second),
      ...(dkimSecret === undefined
        ? {}
        : {
            dkim: {
              domainName: dkimDomainName!,
              selector: dkimSelector!,
              privateKeySecret: dkimSecret,
            },
          }),
      enabled: requireBoolean(row.enabled),
      version: requireIntegerValue(row.configuration_version),
    },
    { allowPlainLocal },
  );
}

function decodeNullableProtectedSecret(
  row: Record<string, unknown>,
  prefix: "password" | "dkim",
  tenantId: string | undefined,
): NotificationProtectedSecret | undefined {
  const secretId = row[`${prefix}_secret_id`];
  if (secretId === null) {
    for (const field of [
      "secret_version",
      "secret_kind",
      "key_version",
      "nonce",
      "ciphertext",
    ]) {
      if (row[`${prefix}_${field}`] !== null) {
        throw new NotificationConfigurationError();
      }
    }
    return undefined;
  }
  return createNotificationProtectedSecret({
    ...(tenantId === undefined ? {} : { tenantId }),
    secretId: requireString(secretId),
    secretVersion: requireIntegerValue(row[`${prefix}_secret_version`]),
    kind: requireSecretKind(row[`${prefix}_secret_kind`]),
    keyVersion: requireIntegerValue(row[`${prefix}_key_version`]),
    nonce: requireBytes(row[`${prefix}_nonce`]),
    ciphertext: requireBytes(row[`${prefix}_ciphertext`]),
  });
}

function decodeProtectedSecret(
  value: unknown,
  base64Encoded: boolean,
): NotificationProtectedSecret {
  const row = requireRecord(value);
  return createNotificationProtectedSecret({
    ...(row.tenantId === undefined || row.tenantId === null
      ? {}
      : { tenantId: requireString(row.tenantId) }),
    secretId: requireString(row.secretId),
    secretVersion: requireIntegerValue(row.secretVersion),
    kind: requireSecretKind(row.kind),
    keyVersion: requireIntegerValue(row.keyVersion),
    nonce: base64Encoded
      ? decodeBase64(requireString(row.nonce))
      : requireBytes(row.nonce),
    ciphertext: base64Encoded
      ? decodeBase64(requireString(row.ciphertext))
      : requireBytes(row.ciphertext),
  });
}

function decodeBase64(value: string): Uint8Array {
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      value,
    )
  ) {
    throw new NotificationValidationError(
      "database returned invalid secret data",
    );
  }
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function requireNotificationEventType(value: unknown): NotificationEventType {
  const text = requireString(value);
  if (isNotificationEventType(text)) return text;
  throw new NotificationValidationError(
    "database returned an invalid event type",
  );
}

function requireNotificationObjectType(value: unknown): NotificationObjectType {
  switch (requireString(value)) {
    case "alert":
      return "alert";
    case "case":
      return "case";
    case "task":
      return "task";
    case "evidence":
      return "evidence";
    case "contact":
      return "contact";
    default:
      throw new NotificationValidationError(
        "database returned an invalid object type",
      );
  }
}

function requireNotificationActorKind(value: unknown): NotificationActorKind {
  switch (requireString(value)) {
    case "human":
      return "human";
    case "service_account":
      return "service_account";
    case "system":
      return "system";
    default:
      throw new NotificationValidationError(
        "database returned an invalid actor kind",
      );
  }
}

function requireNotificationAudience(value: unknown): NotificationAudience {
  switch (requireString(value)) {
    case "operator":
      return "operator";
    case "customer":
      return "customer";
    default:
      throw new NotificationValidationError(
        "database returned an invalid audience",
      );
  }
}

function requireNotificationChannel(value: unknown): "email" | "webhook" {
  switch (requireString(value)) {
    case "email":
      return "email";
    case "webhook":
      return "webhook";
    default:
      throw new NotificationValidationError(
        "database returned an invalid channel",
      );
  }
}

function requireSmtpScope(value: unknown): "tenant" | "platform" {
  switch (requireString(value)) {
    case "tenant":
      return "tenant";
    case "platform":
      return "platform";
    default:
      throw new NotificationValidationError(
        "database returned an invalid SMTP scope",
      );
  }
}

function requireSmtpSecurity(value: unknown): SmtpSecurityMode {
  switch (requireString(value)) {
    case "tls":
      return "tls";
    case "starttls":
      return "starttls";
    case "plain_local":
      return "plain_local";
    default:
      throw new NotificationValidationError(
        "database returned an invalid SMTP security mode",
      );
  }
}

function requireSecretKind(value: unknown): NotificationSecretKind {
  switch (requireString(value)) {
    case "smtp_password":
      return "smtp_password";
    case "smtp_dkim_private_key":
      return "smtp_dkim_private_key";
    case "webhook_signing_key":
      return "webhook_signing_key";
    default:
      throw new NotificationValidationError(
        "database returned an invalid secret kind",
      );
  }
}

function requireContextObject(
  value: unknown,
): Readonly<Record<string, ContextValue>> {
  if (!isContextObject(value)) {
    throw new NotificationValidationError(
      "database returned an invalid context",
    );
  }
  return value;
}

function requireConditionOperator(
  value: unknown,
):
  | "equals"
  | "not_equals"
  | "one_of"
  | "none_of"
  | "contains"
  | "exists"
  | "not_exists" {
  switch (requireString(value)) {
    case "equals":
      return "equals";
    case "not_equals":
      return "not_equals";
    case "one_of":
      return "one_of";
    case "none_of":
      return "none_of";
    case "contains":
      return "contains";
    case "exists":
      return "exists";
    case "not_exists":
      return "not_exists";
    default:
      throw new NotificationValidationError(
        "database returned an invalid condition operator",
      );
  }
}

function decodeCondition(value: unknown): NotificationConditionInput {
  const row = requireRecord(value);
  switch (requireString(row.kind)) {
    case "all":
      return {
        kind: "all",
        children: requireArray(row.children).map(decodeCondition),
      };
    case "any":
      return {
        kind: "any",
        children: requireArray(row.children).map(decodeCondition),
      };
    case "not": {
      const children = requireArray(row.children).map(decodeCondition);
      if (children.length !== 1) {
        throw new NotificationValidationError(
          "database returned an invalid negated condition",
        );
      }
      const child = children[0];
      if (child === undefined) {
        throw new NotificationValidationError(
          "database returned an invalid negated condition",
        );
      }
      return { kind: "not", children: [child] };
    }
    case "predicate": {
      const operator = requireConditionOperator(row.operator);
      const rawValues =
        row.values === undefined ? [] : requireArray(row.values);
      const values = rawValues.map((entry) => {
        if (
          entry === null ||
          typeof entry === "string" ||
          typeof entry === "boolean" ||
          typeof entry === "number"
        ) {
          return entry;
        }
        throw new NotificationValidationError(
          "database returned an invalid condition literal",
        );
      });
      return {
        kind: "predicate",
        path: requireString(row.path),
        operator,
        ...(row.values === undefined ? {} : { values }),
      };
    }
    default:
      throw new NotificationValidationError(
        "database returned an invalid condition",
      );
  }
}

function requireRecipientSelectorKind(value: unknown): RecipientSelectorKind {
  switch (requireString(value)) {
    case "assignee":
      return "assignee";
    case "previous_assignee":
      return "previous_assignee";
    case "operator_team":
      return "operator_team";
    case "watcher":
      return "watcher";
    case "mentioned":
      return "mentioned";
    case "actor":
      return "actor";
    case "tenant_admin":
      return "tenant_admin";
    case "platform_group":
      return "platform_group";
    case "customer_contacts":
      return "customer_contacts";
    case "contact_group":
      return "contact_group";
    case "contact_tag":
      return "contact_tag";
    case "explicit_email":
      return "explicit_email";
    case "custom_email_field":
      return "custom_email_field";
    default:
      throw new NotificationValidationError(
        "database returned an invalid recipient selector",
      );
  }
}

function requireCandidateRecipientKind(
  value: unknown,
): Exclude<RecipientSelectorKind, "explicit_email" | "custom_email_field"> {
  const kind = requireRecipientSelectorKind(value);
  if (kind === "explicit_email" || kind === "custom_email_field") {
    throw new NotificationValidationError(
      "database returned an invalid candidate recipient kind",
    );
  }
  return kind;
}

function decodeRecipientSelector(value: unknown): RecipientSelectorInput {
  const row = requireRecord(value);
  return {
    kind: requireRecipientSelectorKind(row.kind),
    ...(row.value === undefined ? {} : { value: requireString(row.value) }),
    ...(row.authorized === undefined
      ? {}
      : { authorized: requireBoolean(row.authorized) }),
    ...(row.audience === undefined
      ? {}
      : { audience: requireNotificationAudience(row.audience) }),
  };
}

function decodeQuietHours(value: unknown): QuietHoursInput {
  const row = requireRecord(value);
  return {
    timezone: requireString(row.timezone),
    startMinute: requireIntegerValue(row.startMinute),
    endMinute: requireIntegerValue(row.endMinute),
    ...(row.weekdays === undefined
      ? {}
      : { weekdays: requireArray(row.weekdays).map(requireIntegerValue) }),
  };
}

function decodeGroupingPolicy(value: unknown): GroupingPolicyInput {
  const row = requireRecord(value);
  let mode: GroupingPolicyInput["mode"];
  switch (requireString(row.mode)) {
    case "none":
      mode = "none";
      break;
    case "object":
      mode = "object";
      break;
    case "tenant":
      mode = "tenant";
      break;
    default:
      throw new NotificationValidationError(
        "database returned an invalid grouping mode",
      );
  }
  return {
    mode,
    ...(row.windowMs === undefined
      ? {}
      : { windowMs: requireIntegerValue(row.windowMs) }),
    ...(row.maximumItems === undefined
      ? {}
      : { maximumItems: requireIntegerValue(row.maximumItems) }),
  };
}

function decodeRetryPolicy(value: unknown): RetryPolicyInput {
  const row = requireRecord(value);
  return {
    maximumAttempts: requireIntegerValue(row.maximumAttempts),
    initialDelayMs: requireIntegerValue(row.initialDelayMs),
    maximumDelayMs: requireIntegerValue(row.maximumDelayMs),
    multiplier: requireFiniteNumber(row.multiplier),
    jitterPercent: requireIntegerValue(row.jitterPercent),
  };
}

function decodeCandidateValues(
  value: unknown,
): Readonly<Partial<Record<RecipientSelectorKind, readonly string[]>>> {
  const row = requireRecord(value);
  const result: Partial<Record<RecipientSelectorKind, readonly string[]>> = {};
  for (const [rawKind, rawValues] of Object.entries(row)) {
    const kind = requireRecipientSelectorKind(rawKind);
    result[kind] = requireArray(rawValues).map(requireString);
  }
  return Object.freeze(result);
}

function requireFanoutCommitOutcome(
  value: unknown,
): FanoutCommitResult["outcome"] {
  switch (requireString(value)) {
    case "committed":
      return "committed";
    case "already_committed":
      return "already_committed";
    default:
      throw new NotificationValidationError(
        "database returned an invalid fanout outcome",
      );
  }
}

function requireWebhookSchemaVersion(value: unknown): 1 {
  if (requireIntegerValue(value) !== 1) {
    throw new NotificationValidationError(
      "database returned an invalid webhook schema version",
    );
  }
  return 1;
}

function requireFiniteNumber(value: unknown): number {
  const result = typeof value === "string" ? Number(value) : value;
  if (typeof result !== "number" || !Number.isFinite(result)) {
    throw new NotificationValidationError(
      "database returned an invalid number",
    );
  }
  return result;
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new NotificationValidationError(
      "database returned an invalid object",
    );
  }
  return Object.fromEntries(Object.entries(value));
}

function requireArray(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new NotificationValidationError("database returned an invalid array");
  }
  return value;
}

function requireString(value: unknown): string {
  if (typeof value !== "string") {
    throw new NotificationValidationError("database returned invalid text");
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return value === null || value === undefined
    ? undefined
    : requireString(value);
}

function requireIntegerValue(value: unknown): number {
  const result = typeof value === "string" ? Number(value) : value;
  if (typeof result !== "number" || !Number.isSafeInteger(result)) {
    throw new NotificationValidationError(
      "database returned an invalid integer",
    );
  }
  return result;
}

function requireBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new NotificationValidationError(
      "database returned an invalid boolean",
    );
  }
  return value;
}

function requireDate(value: unknown): Date {
  const date =
    value instanceof Date
      ? new Date(value.getTime())
      : new Date(requireString(value));
  if (!Number.isFinite(date.getTime())) {
    throw new NotificationValidationError(
      "database returned an invalid instant",
    );
  }
  return date;
}

function requireBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new NotificationValidationError(
      "database returned invalid secret data",
    );
  }
  return Uint8Array.from(value);
}

function requireSingleRow<T>(rows: readonly T[]): T {
  if (rows.length !== 1) throw new NotificationConfigurationError();
  return rows[0]!;
}
