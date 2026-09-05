package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const notificationMutationDigestSchema = "periapsis/notification/admin-request/sha256/v1"

// NotificationRepository is the only API persistence adapter for notification
// administration. Runtime roles cannot read notification tables directly; all
// projections and writes pass through bounded definer functions after a
// transaction-local actor/tenant context is installed.
type NotificationRepository struct {
	begin     transactionBeginner
	authority *AuthorizationRepository
	keyring   notification.Keyring
}

func NewNotificationRepository(pool *pgxpool.Pool, keyring notification.Keyring) *NotificationRepository {
	return &NotificationRepository{
		begin: poolTransactionBeginner(pool), authority: NewAuthorizationRepository(pool), keyring: keyring,
	}
}

var _ notification.Repository = (*NotificationRepository)(nil)

func (r *NotificationRepository) ResolveAuthority(ctx context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	if r == nil || r.authority == nil {
		return authorization.TenantAuthority{}, notification.ErrUnavailable
	}
	return r.authority.ResolveAuthority(ctx, params)
}

func (r *NotificationRepository) ListRules(ctx context.Context, params notification.ListRulesParams) (notification.RulePage, error) {
	items, next, err := listNotificationResources(ctx, r, params.Human, notification.CursorKindRules, "rule", params.After, params.Limit, nil, decodeNotificationProjection[notification.Rule])
	return notification.RulePage{Items: items, NextCursor: next}, err
}

func (r *NotificationRepository) GetRule(ctx context.Context, params notification.GetRuleParams) (notification.Rule, error) {
	return getNotificationResource[notification.Rule](ctx, r, params.Human, "rule", params.RuleID, nil, false)
}

func (r *NotificationRepository) CreateRule(ctx context.Context, params notification.CreateRuleParams) (notification.IdempotentResult[notification.Rule], error) {
	return mutateTenantNotificationDefinition[notification.Rule](ctx, r, params.Mutation, "rule.create", params.RuleID, nil, ruleNotificationPayload(params.Fields))
}

func (r *NotificationRepository) VersionRule(ctx context.Context, params notification.VersionRuleParams) (notification.IdempotentResult[notification.Rule], error) {
	return mutateTenantNotificationDefinition[notification.Rule](ctx, r, params.Mutation, "rule.version", params.RuleID, &params.ExpectedVersion, ruleNotificationPayload(params.Fields))
}

func (r *NotificationRepository) ListTemplates(ctx context.Context, params notification.ListTemplatesParams) (notification.TemplatePage, error) {
	items, next, err := listNotificationResources(ctx, r, params.Human, notification.CursorKindTemplates, "template", params.After, params.Limit, nil, decodeNotificationProjection[notification.Template])
	return notification.TemplatePage{Items: items, NextCursor: next}, err
}

func (r *NotificationRepository) GetTemplate(ctx context.Context, params notification.GetTemplateParams) (notification.Template, error) {
	return getNotificationResource[notification.Template](ctx, r, params.Human, "template", params.TemplateID, params.Version, false)
}

func (r *NotificationRepository) CreateTemplate(ctx context.Context, params notification.CreateTemplateParams) (notification.IdempotentResult[notification.Template], error) {
	return mutateTenantNotificationDefinition[notification.Template](ctx, r, params.Mutation, "template.create", params.TemplateID, nil, templateNotificationPayload(params.Fields))
}

func (r *NotificationRepository) VersionTemplate(ctx context.Context, params notification.VersionTemplateParams) (notification.IdempotentResult[notification.Template], error) {
	return mutateTenantNotificationDefinition[notification.Template](ctx, r, params.Mutation, "template.version", params.TemplateID, &params.ExpectedVersion, templateNotificationPayload(params.Fields))
}

func (r *NotificationRepository) DuplicateTemplate(ctx context.Context, params notification.DuplicateTemplateParams) (notification.IdempotentResult[notification.Template], error) {
	payload := map[string]any{"sourceTemplateId": params.SourceTemplateID, "sourceVersion": params.SourceVersion, "key": params.Key, "name": params.Name}
	return mutateTenantNotificationDefinition[notification.Template](ctx, r, params.Mutation, "template.duplicate", params.TemplateID, nil, payload)
}

func (r *NotificationRepository) RollbackTemplate(ctx context.Context, params notification.RollbackTemplateParams) (notification.IdempotentResult[notification.Template], error) {
	payload := map[string]any{"sourceVersion": params.SourceVersion, "reason": params.Reason}
	return mutateTenantNotificationDefinition[notification.Template](ctx, r, params.Mutation, "template.rollback", params.TemplateID, &params.ExpectedVersion, payload)
}

func (r *NotificationRepository) EnqueueTemplateTest(ctx context.Context, params notification.EnqueueTemplateTestParams) (notification.IdempotentResult[notification.Delivery], error) {
	payload := map[string]any{"templateId": params.TemplateID, "version": params.Version, "deliveryId": params.DeliveryID, "recipient": params.Recipient, "audience": params.Audience, "context": params.Context, "reason": params.Reason}
	return callTenantNotificationMutation[notification.Delivery](ctx, r, params.Mutation, "template.test", payload, `
		SELECT projection, replayed
		FROM app.enqueue_tenant_notification_template_test_v1(
			$1, $2, $3, $4, $5::public.notification_audience, $6::jsonb,
			$7, $8, $9, $10, $11, $12, $13, $14, $15
		)`, params.TemplateID, params.Version, params.DeliveryID, params.Recipient, string(params.Audience), mustNotificationJSON(params.Context), params.Reason)
}

func (r *NotificationRepository) GetTenantSMTP(ctx context.Context, params notification.GetTenantSMTPParams) (notification.SMTPConfiguration, error) {
	return withinTenantNotificationTransaction(ctx, r, params.Human, false, func(tx databaseTransaction) (notification.SMTPConfiguration, error) {
		return scanNotificationProjection[notification.SMTPConfiguration](tx.QueryRow(ctx, `SELECT app.get_tenant_notification_smtp_v1()`))
	})
}

func (r *NotificationRepository) VersionTenantSMTP(ctx context.Context, params notification.VersionTenantSMTPParams) (notification.IdempotentResult[notification.SMTPConfiguration], error) {
	return mutateNotificationSMTP(ctx, r, "tenant", params.Mutation.Human, notification.PlatformActor{}, params.Mutation.Audit, params.Mutation.OccurredAt, params.Mutation.IdempotencyKey, params.ConfigurationID, params.ExpectedVersion, params.Write)
}

func (r *NotificationRepository) TestTenantSMTP(ctx context.Context, params notification.TestTenantSMTPParams) (notification.IdempotentResult[notification.SMTPProbePreflight], error) {
	payload := map[string]any{"version": params.ConfigurationVersion, "deliveryId": params.DeliveryID, "recipient": params.Recipient, "reason": params.Reason}
	return callTenantNotificationMutation[notification.SMTPProbePreflight](ctx, r, params.Mutation, "smtp.test", payload, `
		SELECT projection, replayed FROM app.test_tenant_notification_smtp_v2(
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`, params.ConfigurationVersion, params.DeliveryID, params.Recipient, params.Reason)
}

func (r *NotificationRepository) GetPlatformSMTP(ctx context.Context, params notification.GetPlatformSMTPParams) (notification.SMTPConfiguration, error) {
	return withinPlatformNotificationTransaction(ctx, r, params.Actor, true, func(tx databaseTransaction) (notification.SMTPConfiguration, error) {
		return scanNotificationProjection[notification.SMTPConfiguration](tx.QueryRow(ctx, `SELECT app.get_platform_notification_smtp_v1()`))
	})
}

func (r *NotificationRepository) VersionPlatformSMTP(ctx context.Context, params notification.VersionPlatformSMTPParams) (notification.IdempotentResult[notification.SMTPConfiguration], error) {
	return mutateNotificationSMTP(ctx, r, "platform", notification.HumanParams{}, params.Mutation.Actor, params.Mutation.Audit, params.Mutation.OccurredAt, params.Mutation.IdempotencyKey, params.ConfigurationID, params.ExpectedVersion, params.Write)
}

func (r *NotificationRepository) TestPlatformSMTP(ctx context.Context, params notification.TestPlatformSMTPParams) (notification.IdempotentResult[notification.SMTPProbePreflight], error) {
	payload := map[string]any{"version": params.ConfigurationVersion, "recipient": params.Recipient, "reason": params.Reason}
	digests, err := notificationMutationDigests("platform", params.Mutation.Actor.UserID, "smtp.test", params.Mutation.IdempotencyKey, payload)
	if err != nil {
		return notification.IdempotentResult[notification.SMTPProbePreflight]{}, err
	}
	return withinPlatformNotificationTransaction(ctx, r, params.Mutation.Actor, false, func(tx databaseTransaction) (notification.IdempotentResult[notification.SMTPProbePreflight], error) {
		return scanIdempotentProjection[notification.SMTPProbePreflight](tx.QueryRow(ctx, `
			SELECT projection, replayed FROM app.test_platform_notification_smtp_v2(
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
			)`, params.ConfigurationVersion, params.Recipient, params.Reason, digests.key, digests.request,
			params.Mutation.OccurredAt, params.Mutation.Audit.RequestID, params.Mutation.Audit.CorrelationID,
			notificationAuditAddress(params.Mutation.Audit.RemoteAddress), params.Mutation.Audit.UserAgent,
			params.Mutation.Actor.AuthenticationMethod))
	})
}

func (r *NotificationRepository) ListDeliveries(ctx context.Context, params notification.ListDeliveriesParams) (notification.DeliveryPage, error) {
	items, next, err := listNotificationResources(ctx, r, params.Human, notification.CursorKindDeliveries, "delivery", params.After, params.Limit, params.Statuses, decodeNotificationProjection[notification.Delivery])
	return notification.DeliveryPage{Items: items, NextCursor: next}, err
}

func (r *NotificationRepository) GetDelivery(ctx context.Context, params notification.GetDeliveryParams) (notification.Delivery, error) {
	return getNotificationResource[notification.Delivery](ctx, r, params.Human, "delivery", params.DeliveryID, nil, true)
}

func (r *NotificationRepository) CreateManualRetry(ctx context.Context, params notification.CreateManualRetryParams) (notification.IdempotentResult[notification.Delivery], error) {
	payload := map[string]any{"sourceDeliveryId": params.SourceDeliveryID, "deliveryId": params.DeliveryID, "expectedAttempt": params.ExpectedAttempt, "acknowledgeUncertain": params.AcknowledgeUncertainSubmission, "reason": params.Reason}
	return callTenantNotificationMutation[notification.Delivery](ctx, r, params.Mutation, "delivery.retry", payload, `
		SELECT projection, replayed FROM app.retry_tenant_notification_delivery_v1(
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)`, params.SourceDeliveryID, params.DeliveryID, params.ExpectedAttempt, params.AcknowledgeUncertainSubmission, params.Reason)
}

func (r *NotificationRepository) ListWebhooks(ctx context.Context, params notification.ListWebhooksParams) (notification.WebhookPage, error) {
	items, next, err := listNotificationResources(ctx, r, params.Human, notification.CursorKindWebhooks, "webhook", params.After, params.Limit, nil, decodeNotificationProjection[notification.WebhookConfiguration])
	return notification.WebhookPage{Items: items, NextCursor: next}, err
}

func (r *NotificationRepository) GetWebhook(ctx context.Context, params notification.GetWebhookParams) (notification.WebhookConfiguration, error) {
	return getNotificationResource[notification.WebhookConfiguration](ctx, r, params.Human, "webhook", params.WebhookID, nil, false)
}

func (r *NotificationRepository) CreateWebhook(ctx context.Context, params notification.CreateWebhookParams) (notification.IdempotentResult[notification.WebhookConfiguration], error) {
	return mutateTenantNotificationDefinition[notification.WebhookConfiguration](ctx, r, params.Mutation, "webhook.create", params.WebhookID, nil, webhookNotificationPayload(params.Write))
}

func (r *NotificationRepository) VersionWebhook(ctx context.Context, params notification.VersionWebhookParams) (notification.IdempotentResult[notification.WebhookConfiguration], error) {
	return mutateTenantNotificationDefinition[notification.WebhookConfiguration](ctx, r, params.Mutation, "webhook.version", params.WebhookID, &params.ExpectedVersion, webhookNotificationPayload(params.Write))
}

func (r *NotificationRepository) EnqueueWebhookTest(ctx context.Context, params notification.EnqueueWebhookTestParams) (notification.IdempotentResult[notification.Delivery], error) {
	payload := map[string]any{"webhookId": params.WebhookID, "version": params.ConfigurationVersion, "deliveryId": params.DeliveryID, "eventType": params.EventType, "context": params.Context, "reason": params.Reason}
	return callTenantNotificationMutation[notification.Delivery](ctx, r, params.Mutation, "webhook.test", payload, `
		SELECT projection, replayed
		FROM app.enqueue_tenant_notification_webhook_test_v1(
			$1, $2, $3, $4::public.notification_event_type, $5::jsonb,
			$6, $7, $8, $9, $10, $11, $12, $13, $14
		)`, params.WebhookID, params.ConfigurationVersion, params.DeliveryID, string(params.EventType), mustNotificationJSON(params.Context), params.Reason)
}

type notificationDigests struct{ key, request []byte }

func notificationMutationDigests(scope string, actorID uuid.UUID, operation, key string, payload any) (notificationDigests, error) {
	if actorID == uuid.Nil || operation == "" || key == "" {
		return notificationDigests{}, notification.ErrInvalidInput
	}
	request, err := json.Marshal(payload)
	if err != nil {
		return notificationDigests{}, notification.ErrInvalidInput
	}
	keyHash := sha256.Sum256([]byte(notificationMutationDigestSchema + "\x00key\x00" + scope + "\x00" + actorID.String() + "\x00" + operation + "\x00" + key))
	requestHash := sha256.Sum256(append([]byte(notificationMutationDigestSchema+"\x00request\x00"+scope+"\x00"+actorID.String()+"\x00"+operation+"\x00"), request...))
	return notificationDigests{key: keyHash[:], request: requestHash[:]}, nil
}

func mutateTenantNotificationDefinition[T any](ctx context.Context, r *NotificationRepository, mutation notification.MutationParams, operation string, resourceID uuid.UUID, expected *int64, payload any) (notification.IdempotentResult[T], error) {
	databasePayload, allowPlainLocal, err := tenantNotificationDatabasePayload(operation, payload)
	if err != nil {
		return notification.IdempotentResult[T]{}, err
	}
	// The development-only exemption is process provenance, not part of the
	// public mutation document. Keeping it outside the request digest preserves
	// exact idempotent retries created before the URL-policy rollout.
	bound := map[string]any{"resourceId": resourceID, "expectedVersion": expected, "payload": databasePayload}
	digests, err := notificationMutationDigests(mutation.Human.TenantID.String(), mutation.Human.Actor.UserID, operation, mutation.IdempotencyKey, bound)
	if err != nil {
		return notification.IdempotentResult[T]{}, err
	}
	return withinTenantNotificationTransaction(ctx, r, mutation.Human, false, func(tx databaseTransaction) (notification.IdempotentResult[T], error) {
		if operation == "webhook.create" || operation == "webhook.version" {
			setting := "false"
			if allowPlainLocal {
				setting = "true"
			}
			if _, err := tx.Exec(
				ctx,
				`SELECT set_config('app.webhook_plain_local_exemption', $1, true)`,
				setting,
			); err != nil {
				return notification.IdempotentResult[T]{}, mapNotificationDatabaseError(err)
			}
		}
		return scanIdempotentProjection[T](tx.QueryRow(ctx, `
			SELECT projection, replayed
			FROM app.mutate_tenant_notification_definition_v1(
				$1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12
			)`, operation, resourceID, expected, mustNotificationJSON(databasePayload), digests.key, digests.request,
			mutation.OccurredAt, mutation.Audit.RequestID, mutation.Audit.CorrelationID,
			notificationAuditAddress(mutation.Audit.RemoteAddress), mutation.Audit.UserAgent,
			mutation.Human.Actor.AuthenticationMethod))
	})
}

func tenantNotificationDatabasePayload(operation string, payload any) (any, bool, error) {
	if operation != "webhook.create" && operation != "webhook.version" {
		return payload, false, nil
	}
	fields, ok := payload.(map[string]any)
	if !ok {
		return nil, false, notification.ErrInvalidInput
	}
	exemption, ok := fields["allowPlainLocalExemption"].(bool)
	if !ok {
		return nil, false, notification.ErrInvalidInput
	}
	databaseFields := make(map[string]any, len(fields)-1)
	for key, value := range fields {
		if key != "allowPlainLocalExemption" {
			databaseFields[key] = value
		}
	}
	return databaseFields, exemption, nil
}

func callTenantNotificationMutation[T any](ctx context.Context, r *NotificationRepository, mutation notification.MutationParams, operation string, payload any, query string, arguments ...any) (notification.IdempotentResult[T], error) {
	digests, err := notificationMutationDigests(mutation.Human.TenantID.String(), mutation.Human.Actor.UserID, operation, mutation.IdempotencyKey, payload)
	if err != nil {
		return notification.IdempotentResult[T]{}, err
	}
	arguments = append(arguments, digests.key, digests.request, mutation.OccurredAt,
		mutation.Audit.RequestID, mutation.Audit.CorrelationID,
		notificationAuditAddress(mutation.Audit.RemoteAddress), mutation.Audit.UserAgent,
		mutation.Human.Actor.AuthenticationMethod)
	return withinTenantNotificationTransaction(ctx, r, mutation.Human, false, func(tx databaseTransaction) (notification.IdempotentResult[T], error) {
		return scanIdempotentProjection[T](tx.QueryRow(ctx, query, arguments...))
	})
}

func mutateNotificationSMTP(ctx context.Context, r *NotificationRepository, scope string, human notification.HumanParams, platform notification.PlatformActor, audit authorization.AuditContext, occurredAt time.Time, idempotencyKey string, configurationID uuid.UUID, expected *int64, write notification.SMTPPersistedWrite) (notification.IdempotentResult[notification.SMTPConfiguration], error) {
	payload := smtpNotificationPayload(write)
	actorID := platform.UserID
	if scope == "tenant" {
		actorID = human.Actor.UserID
	}
	bound := map[string]any{"configurationId": configurationID, "expectedVersion": expected, "payload": payload}
	digests, err := notificationMutationDigests(scope, actorID, "smtp.version", idempotencyKey, bound)
	if err != nil {
		return notification.IdempotentResult[notification.SMTPConfiguration]{}, err
	}
	work := func(tx databaseTransaction) (notification.IdempotentResult[notification.SMTPConfiguration], error) {
		method := platform.AuthenticationMethod
		if scope == "tenant" {
			method = human.Actor.AuthenticationMethod
		}
		return scanIdempotentProjection[notification.SMTPConfiguration](tx.QueryRow(ctx, `
			SELECT projection, replayed FROM app.mutate_notification_smtp_v1(
				$1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12
			)`, scope, configurationID, expected, mustNotificationJSON(payload), digests.key, digests.request,
			occurredAt, audit.RequestID, audit.CorrelationID, notificationAuditAddress(audit.RemoteAddress), audit.UserAgent, method))
	}
	if scope == "tenant" {
		return withinTenantNotificationTransaction(ctx, r, human, false, work)
	}
	return withinPlatformNotificationTransaction(ctx, r, platform, false, work)
}

func ruleNotificationPayload(fields notification.RuleFields) map[string]any {
	payload := map[string]any{
		"name": fields.Name, "description": fields.Description, "eventType": fields.EventType,
		"objectType": fields.ObjectType, "condition": fields.Condition, "recipients": fields.Recipients,
		"templateId": fields.TemplateID, "templateVersion": fields.TemplateVersion, "channel": fields.Channel,
		"priority": fields.Priority, "delayMs": fields.DelayMS, "deduplicationWindowMs": fields.DeduplicationWindowMS,
		"grouping": fields.Grouping, "retry": fields.Retry, "enabled": fields.Enabled, "effectiveFrom": fields.EffectiveFrom,
	}
	if fields.QuietHours != nil {
		payload["quietHours"] = fields.QuietHours
	}
	if fields.EffectiveUntil != nil {
		payload["effectiveUntil"] = fields.EffectiveUntil
	}
	return payload
}

func templateNotificationPayload(fields notification.TemplateFields) map[string]any {
	payload := map[string]any{"key": fields.Key, "name": fields.Name, "language": fields.Language, "subject": fields.Subject, "html": fields.HTML, "sampleData": fields.SampleData, "placeholders": []string{}}
	if fields.PlainText != nil {
		payload["plainText"] = *fields.PlainText
	}
	if fields.CSS != nil {
		payload["css"] = *fields.CSS
	}
	return payload
}

func webhookNotificationPayload(write notification.WebhookPersistedWrite) map[string]any {
	payload := map[string]any{"name": write.Name, "endpointUrl": write.EndpointURL, "allowPlainLocalExemption": write.AllowPlainLocalExemption, "eventTypes": write.EventTypes, "audience": write.Audience, "retainSigningKey": write.RetainSigningKey, "timeoutMs": write.TimeoutMS, "enabled": write.Enabled}
	if write.SigningKey != nil {
		payload["signingKey"] = protectedNotificationSecretPayload(write.SigningKey)
	}
	return payload
}

func smtpNotificationPayload(write notification.SMTPPersistedWrite) map[string]any {
	return map[string]any{
		"name": write.Name, "host": write.Host, "port": write.Port, "security": write.Security,
		"username": write.Username, "password": protectedNotificationSecretPayload(write.Password),
		"retainPassword": write.RetainPassword, "removePassword": write.RemovePassword,
		"fromName": write.FromName, "fromEmail": write.FromEmail, "replyToEmail": write.ReplyToEmail,
		"timeoutMs": write.TimeoutMS, "maximumConnections": write.MaximumConnections,
		"maximumMessagesPerConnection": write.MaximumMessagesPerConnection,
		"rateLimitPerSecond":           write.RateLimitPerSecond, "dkimDomainName": write.DKIMDomainName,
		"dkimSelector": write.DKIMSelector, "dkimPrivateKey": protectedNotificationSecretPayload(write.DKIMPrivateKey),
		"retainDKIMPrivateKey": write.RetainDKIMPrivateKey, "removeDKIM": write.RemoveDKIM, "enabled": write.Enabled,
	}
}

func protectedNotificationSecretPayload(secret *notification.ProtectedSecret) any {
	if secret == nil {
		return nil
	}
	return map[string]any{
		"id": secret.ID, "version": secret.Version, "kind": secret.Kind,
		"keyVersion": secret.Envelope.KeyVersion,
		"nonce":      base64.StdEncoding.EncodeToString(secret.Envelope.Nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(secret.Envelope.Ciphertext),
	}
}

func getNotificationResource[T any](ctx context.Context, r *NotificationRepository, human notification.HumanParams, kind string, id uuid.UUID, version *int64, includeAttempts bool) (T, error) {
	return withinTenantNotificationTransaction(ctx, r, human, false, func(tx databaseTransaction) (T, error) {
		return scanNotificationProjection[T](tx.QueryRow(ctx, `
			SELECT app.get_tenant_notification_resource_v1($1, $2, $3, $4)
		`, kind, id, version, includeAttempts))
	})
}

func listNotificationResources[T any](ctx context.Context, r *NotificationRepository, human notification.HumanParams, cursorKind notification.CursorKind, kind string, after *string, limit int32, statuses []notification.DeliveryStatus, decode func([]byte) (T, error)) ([]T, *string, error) {
	filterValues := make([]string, len(statuses))
	for index, status := range statuses {
		filterValues[index] = string(status)
	}
	slices.Sort(filterValues)
	filter := strings.Join(filterValues, ",")
	var afterTime *time.Time
	var afterID *uuid.UUID
	if after != nil {
		position, err := r.keyring.DecodeCursor(*after, cursorKind, human.TenantID, filter)
		if err != nil {
			return nil, nil, notification.ErrInvalidInput
		}
		afterTime, afterID = &position.CreatedAt, &position.ID
	}
	page, err := withinTenantNotificationTransaction(ctx, r, human, false, func(tx databaseTransaction) (notificationListResult[T], error) {
		rows, err := tx.Query(ctx, `
			SELECT item FROM app.list_tenant_notification_resources_v1(
				$1, $2, $3, $4::public.notification_delivery_status[], $5
			)`, kind, afterTime, afterID, filterValues, limit+1)
		if err != nil {
			return notificationListResult[T]{}, mapNotificationDatabaseError(err)
		}
		defer rows.Close()
		items := make([]T, 0, limit+1)
		positions := make([]notification.CursorPosition, 0, limit+1)
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return notificationListResult[T]{}, mapNotificationDatabaseError(err)
			}
			item, err := decode(raw)
			if err != nil {
				return notificationListResult[T]{}, err
			}
			position, err := notificationProjectionPosition(item)
			if err != nil {
				return notificationListResult[T]{}, err
			}
			items, positions = append(items, item), append(positions, position)
		}
		if err := rows.Err(); err != nil {
			return notificationListResult[T]{}, mapNotificationDatabaseError(err)
		}
		var next *string
		if len(items) > int(limit) {
			items, positions = items[:limit], positions[:limit]
			token, err := r.keyring.EncodeCursor(cursorKind, human.TenantID, filter, positions[len(positions)-1])
			if err != nil {
				return notificationListResult[T]{}, notification.ErrUnavailable
			}
			next = &token
		}
		return notificationListResult[T]{items: items, next: next}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return page.items, page.next, nil
}

type notificationListResult[T any] struct {
	items []T
	next  *string
}

func notificationProjectionPosition(value any) (notification.CursorPosition, error) {
	switch item := value.(type) {
	case notification.Rule:
		return notification.CursorPosition{CreatedAt: item.CreatedAt, ID: item.ID}, nil
	case notification.Template:
		return notification.CursorPosition{CreatedAt: item.CreatedAt, ID: item.ID}, nil
	case notification.Delivery:
		return notification.CursorPosition{CreatedAt: item.CreatedAt, ID: item.ID}, nil
	case notification.WebhookConfiguration:
		return notification.CursorPosition{CreatedAt: item.CreatedAt, ID: item.ID}, nil
	default:
		return notification.CursorPosition{}, notification.ErrUnavailable
	}
}

func scanNotificationProjection[T any](row pgx.Row) (T, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		var zero T
		return zero, mapNotificationDatabaseError(err)
	}
	return decodeNotificationProjection[T](raw)
}

func scanIdempotentProjection[T any](row pgx.Row) (notification.IdempotentResult[T], error) {
	var raw []byte
	var replayed bool
	if err := row.Scan(&raw, &replayed); err != nil {
		return notification.IdempotentResult[T]{}, mapNotificationDatabaseError(err)
	}
	value, err := decodeNotificationProjection[T](raw)
	return notification.IdempotentResult[T]{Value: value, Replayed: replayed}, err
}

func decodeNotificationProjection[T any](raw []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, notification.ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, notification.ErrUnavailable
	}
	return value, nil
}

func mustNotificationJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "null"
	}
	return string(encoded)
}

func withinTenantNotificationTransaction[T any](ctx context.Context, r *NotificationRepository, human notification.HumanParams, readOnly bool, work func(databaseTransaction) (T, error)) (T, error) {
	var zero T
	if r == nil || r.begin == nil || work == nil || human.TenantID == uuid.Nil || human.Actor.UserID == uuid.Nil || human.Actor.ActiveTenantID != human.TenantID {
		return zero, notification.ErrForbidden
	}
	mode := pgx.ReadWrite
	if readOnly {
		mode = pgx.ReadOnly
	}
	result, err := withinTransactionWithOptions(ctx, r.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: mode}, func(tx databaseTransaction) (T, error) {
		installed, err := dbsql.New(tx).SetTenantContext(ctx, dbsql.SetTenantContextParams{TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID)})
		if err != nil || installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
			return zero, notification.ErrUnavailable
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, notification.ErrUnavailable
		}
		return work(tx)
	})
	if err != nil {
		return zero, mapNotificationDatabaseError(err)
	}
	return result, nil
}

func withinPlatformNotificationTransaction[T any](ctx context.Context, r *NotificationRepository, actor notification.PlatformActor, readOnly bool, work func(databaseTransaction) (T, error)) (T, error) {
	var zero T
	if r == nil || r.begin == nil || work == nil || actor.UserID == uuid.Nil {
		return zero, notification.ErrForbidden
	}
	mode := pgx.ReadWrite
	if readOnly {
		mode = pgx.ReadOnly
	}
	result, err := withinTransactionWithOptions(ctx, r.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: mode}, func(tx databaseTransaction) (T, error) {
		installed, err := dbsql.New(tx).SetUserContext(ctx, dbsql.SetUserContextParams{UserID: toDatabaseUUID(actor.UserID)})
		if err != nil || installed != actor.UserID.String() {
			return zero, notification.ErrUnavailable
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, notification.ErrUnavailable
		}
		return work(tx)
	})
	if err != nil {
		return zero, mapNotificationDatabaseError(err)
	}
	return result, nil
}

func notificationAuditAddress(value netip.Addr) netip.Addr {
	if value.IsValid() {
		return value.Unmap()
	}
	return netip.IPv4Unspecified()
}

func mapNotificationDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, notification.ErrForbidden) ||
		errors.Is(err, notification.ErrNotFound) ||
		errors.Is(err, notification.ErrConflict) ||
		errors.Is(err, notification.ErrPreconditionFailed) ||
		errors.Is(err, notification.ErrInvalidInput) ||
		errors.Is(err, notification.ErrUnavailable) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "42501":
			return notification.ErrForbidden
		case "P0002":
			return notification.ErrNotFound
		case "23505":
			return notification.ErrConflict
		case "40001":
			return notification.ErrPreconditionFailed
		case "22023", "23514":
			return notification.ErrInvalidInput
		case "57014":
			return context.DeadlineExceeded
		}
	}
	return fmt.Errorf("%w: notification database operation", notification.ErrUnavailable)
}
