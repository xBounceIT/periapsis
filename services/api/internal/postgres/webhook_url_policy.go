package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

type WebhookURLPolicyRepository struct {
	begin transactionBeginner
}

func NewWebhookURLPolicyRepository(pool *pgxpool.Pool) *WebhookURLPolicyRepository {
	return &WebhookURLPolicyRepository{begin: poolTransactionBeginner(pool)}
}

func (repository *WebhookURLPolicyRepository) Current(
	ctx context.Context,
	params webhookurlpolicy.ReadParams,
) (webhookurlpolicy.Policy, error) {
	if repository == nil || repository.begin == nil ||
		!validAuthorizationRepositoryActor(params.Actor, params.TenantID) {
		return webhookurlpolicy.Policy{}, webhookurlpolicy.ErrRepositoryInvalidInput
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (webhookurlpolicy.Policy, error) {
		if err := installTenantActorContext(ctx, dbsql.New(tx), params.Actor, params.TenantID); err != nil {
			return webhookurlpolicy.Policy{}, mapWebhookURLPolicyDatabaseError(err)
		}
		var document []byte
		err := tx.QueryRow(
			ctx,
			`SELECT policy FROM app.get_tenant_webhook_url_policy_v1($1, $2)`,
			params.Actor.SessionID,
			params.Actor.AuthenticationMethod,
		).Scan(&document)
		if err != nil {
			return webhookurlpolicy.Policy{}, mapWebhookURLPolicyDatabaseError(err)
		}
		return mapWebhookURLPolicyDocument(document)
	})
}

func (repository *WebhookURLPolicyRepository) Publish(
	ctx context.Context,
	params webhookurlpolicy.PublishParams,
) (webhookurlpolicy.PublishResult, error) {
	if repository == nil || repository.begin == nil || params.BuildPlan == nil ||
		params.ValidateResult == nil ||
		!validAuthorizationRepositoryActor(params.Actor, params.TenantID) ||
		params.PublisherMembershipID == uuid.Nil ||
		params.ExpectedVersion < 0 || params.ExpectedVersion >= math.MaxInt32 ||
		params.Command.Operation != "webhook_url_policy.publish" {
		return webhookurlpolicy.PublishResult{}, webhookurlpolicy.ErrRepositoryInvalidInput
	}
	event, err := eventArguments(params.Audit)
	if err != nil {
		return webhookurlpolicy.PublishResult{}, webhookurlpolicy.ErrRepositoryInvalidInput
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (webhookurlpolicy.PublishResult, error) {
		if err := installTenantActorContext(ctx, dbsql.New(tx), params.Actor, params.TenantID); err != nil {
			return webhookurlpolicy.PublishResult{}, mapWebhookURLPolicyDatabaseError(err)
		}
		var replayed bool
		var preparedDocument []byte
		err := tx.QueryRow(
			ctx,
			`SELECT replayed, policy FROM app.prepare_publish_tenant_webhook_url_policy_v1($1, $2, $3, $4)`,
			params.Actor.SessionID,
			params.Actor.AuthenticationMethod,
			params.Command.KeyDigest[:],
			params.Command.RequestDigest[:],
		).Scan(&replayed, &preparedDocument)
		if err != nil {
			return webhookurlpolicy.PublishResult{}, mapWebhookURLPolicyDatabaseError(err)
		}
		var current *webhookurlpolicy.Policy
		if len(preparedDocument) != 0 && string(preparedDocument) != "null" {
			policy, mapErr := mapWebhookURLPolicyDocument(preparedDocument)
			if mapErr != nil {
				return webhookurlpolicy.PublishResult{}, mapErr
			}
			current = &policy
		}
		if replayed {
			if current == nil {
				return webhookurlpolicy.PublishResult{}, errors.New("webhook URL policy replay has no result")
			}
			result := webhookurlpolicy.PublishResult{
				Policy: *current, Command: params.Command, Replayed: true,
			}
			if err := params.ValidateResult(result); err != nil {
				return webhookurlpolicy.PublishResult{}, err
			}
			return result, nil
		}

		plan, err := params.BuildPlan(current)
		if err != nil {
			return webhookurlpolicy.PublishResult{}, err
		}
		next := plan.Next()
		if plan.ExpectedVersion() != params.ExpectedVersion ||
			next.TenantID() != params.TenantID ||
			next.Version() != params.ExpectedVersion+1 ||
			next.PublishedByMembershipID() != params.PublisherMembershipID {
			return webhookurlpolicy.PublishResult{}, errors.New("webhook URL policy plan does not match locked state")
		}
		rules, err := webhookURLPolicyRulesJSON(next.Rules())
		if err != nil {
			return webhookurlpolicy.PublishResult{}, err
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return webhookurlpolicy.PublishResult{}, err
		}
		semanticDigest := next.SemanticDigest()
		policyDigest := next.Digest()
		var committedDocument []byte
		var committedReplay bool
		err = tx.QueryRow(
			ctx,
			`SELECT policy, replayed FROM app.commit_publish_tenant_webhook_url_policy_v1(
				$1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11,
				$12, $13, $14, $15, $16, $17, $18
			)`,
			params.Actor.SessionID,
			params.Actor.AuthenticationMethod,
			int32(params.ExpectedVersion),
			params.Command.KeyDigest[:],
			params.Command.RequestDigest[:],
			next.ID(),
			next.VersionID(),
			rules,
			semanticDigest[:],
			policyDigest[:],
			next.PublishedAt(),
			params.Reason,
			auditID,
			event.requestID,
			event.correlationID,
			params.Audit.RemoteAddress,
			params.Audit.UserAgent,
			params.PublisherMembershipID,
		).Scan(&committedDocument, &committedReplay)
		if err != nil {
			return webhookurlpolicy.PublishResult{}, mapWebhookURLPolicyDatabaseError(err)
		}
		committed, err := mapWebhookURLPolicyDocument(committedDocument)
		if err != nil || !committedReplay && !webhookurlpolicy.SamePolicy(committed, next) {
			return webhookurlpolicy.PublishResult{}, errors.New("database returned unexpected webhook URL policy")
		}
		result := webhookurlpolicy.PublishResult{
			Policy: committed, Command: params.Command, Replayed: committedReplay,
		}
		if err := params.ValidateResult(result); err != nil {
			return webhookurlpolicy.PublishResult{}, err
		}
		return result, nil
	})
}

type webhookURLPolicyDocument struct {
	ID                      uuid.UUID                    `json:"id"`
	VersionID               uuid.UUID                    `json:"versionId"`
	TenantID                uuid.UUID                    `json:"tenantId"`
	Version                 int64                        `json:"version"`
	Rules                   []webhookurlpolicy.RuleInput `json:"rules"`
	PublishedByMembershipID uuid.UUID                    `json:"publishedByMembershipId"`
	PublishedAt             time.Time                    `json:"publishedAt"`
	Digest                  string                       `json:"digest"`
	SemanticDigest          string                       `json:"semanticDigest"`
}

func mapWebhookURLPolicyDocument(document []byte) (webhookurlpolicy.Policy, error) {
	var stored webhookURLPolicyDocument
	if len(document) == 0 || json.Unmarshal(document, &stored) != nil {
		return webhookurlpolicy.Policy{}, errors.New("database returned malformed webhook URL policy")
	}
	policy, err := webhookurlpolicy.NewPolicy(webhookurlpolicy.PolicyInput{
		ID: stored.ID, VersionID: stored.VersionID, TenantID: stored.TenantID,
		Version: stored.Version, Rules: stored.Rules,
		PublishedByMembershipID: stored.PublishedByMembershipID,
		PublishedAt:             stored.PublishedAt,
	})
	digest := policy.Digest()
	semanticDigest := policy.SemanticDigest()
	if err != nil || hex.EncodeToString(digest[:]) != stored.Digest ||
		hex.EncodeToString(semanticDigest[:]) != stored.SemanticDigest {
		return webhookurlpolicy.Policy{}, errors.New("database returned invalid webhook URL policy digest")
	}
	return policy, nil
}

func webhookURLPolicyRulesJSON(rules []webhookurlpolicy.Rule) ([]byte, error) {
	type ruleDocument struct {
		Effect   webhookurlpolicy.RuleEffect `json:"effect"`
		Match    webhookurlpolicy.RuleMatch  `json:"match"`
		Hostname string                      `json:"hostname"`
		Port     int                         `json:"port"`
	}
	document := make([]ruleDocument, len(rules))
	for index, rule := range rules {
		document[index] = ruleDocument{
			Effect: rule.Effect(), Match: rule.Match(),
			Hostname: rule.Hostname(), Port: rule.Port(),
		}
	}
	return json.Marshal(document)
}

func mapWebhookURLPolicyDatabaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return webhookurlpolicy.ErrRepositoryNotFound
	}
	switch postgresCode(err) {
	case "22023", "23514":
		return webhookurlpolicy.ErrRepositoryInvalidInput
	case "42501":
		return webhookurlpolicy.ErrRepositoryForbidden
	case "P0002":
		return webhookurlpolicy.ErrRepositoryNotFound
	case "40001", "23505":
		return webhookurlpolicy.ErrRepositoryConflict
	default:
		return mapCommonDatabaseError(err)
	}
}

var _ webhookurlpolicy.Repository = (*WebhookURLPolicyRepository)(nil)
