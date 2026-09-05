package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

func TestMapWebhookURLPolicyDocumentRestoresCanonicalPolicy(t *testing.T) {
	t.Parallel()
	publishedAt := time.Date(2026, 9, 3, 14, 30, 0, 123_000_000, time.UTC)
	policy, err := webhookurlpolicy.NewPolicy(webhookurlpolicy.PolicyInput{
		ID:                      uuid.MustParse("019d7900-1000-7000-8000-000000000001"),
		VersionID:               uuid.MustParse("019d7900-1000-7000-8000-000000000002"),
		TenantID:                uuid.MustParse("019d7900-1000-7000-8000-000000000003"),
		Version:                 4,
		Rules:                   []webhookurlpolicy.RuleInput{{Effect: webhookurlpolicy.RuleAllow, Match: webhookurlpolicy.RuleExact, Hostname: "hooks.example", Port: 443}, {Effect: webhookurlpolicy.RuleDeny, Match: webhookurlpolicy.RuleSubdomains, Hostname: "blocked.example", Port: 8443}},
		PublishedByMembershipID: uuid.MustParse("019d7900-1000-7000-8000-000000000004"),
		PublishedAt:             publishedAt,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	digest := policy.Digest()
	semanticDigest := policy.SemanticDigest()
	document := []byte(`{
		"id":"019d7900-1000-7000-8000-000000000001",
		"versionId":"019d7900-1000-7000-8000-000000000002",
		"tenantId":"019d7900-1000-7000-8000-000000000003",
		"version":4,
		"rules":[
			{"effect":"allow","match":"exact","hostname":"hooks.example","port":443},
			{"effect":"deny","match":"subdomains","hostname":"blocked.example","port":8443}
		],
		"publishedByMembershipId":"019d7900-1000-7000-8000-000000000004",
		"publishedAt":"2026-09-03T14:30:00.123Z",
		"digest":"` + hex.EncodeToString(digest[:]) + `",
		"semanticDigest":"` + hex.EncodeToString(semanticDigest[:]) + `"
	}`)

	stored, err := mapWebhookURLPolicyDocument(document)
	if err != nil {
		t.Fatalf("map policy: %v", err)
	}
	if !webhookurlpolicy.SamePolicy(stored, policy) {
		t.Fatal("mapped policy differs from its canonical projection")
	}
}

func TestMapWebhookURLPolicyDocumentRejectsMalformedOrForgedRows(t *testing.T) {
	t.Parallel()
	for _, document := range [][]byte{
		nil,
		[]byte(`null`),
		[]byte(`{"id":"not-a-uuid"}`),
		[]byte(`{
			"id":"019d7900-1000-7000-8000-000000000011",
			"versionId":"019d7900-1000-7000-8000-000000000012",
			"tenantId":"019d7900-1000-7000-8000-000000000013",
			"version":1,
			"rules":[],
			"publishedByMembershipId":"019d7900-1000-7000-8000-000000000014",
			"publishedAt":"2026-09-03T14:30:00.123Z",
			"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"semanticDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}`),
	} {
		if _, err := mapWebhookURLPolicyDocument(document); err == nil {
			t.Fatalf("malformed or forged database policy was accepted: %s", document)
		}
	}
}

func TestWebhookURLPolicyDatabaseMappingsRemainClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		code string
		want error
	}{
		{code: "22023", want: webhookurlpolicy.ErrRepositoryInvalidInput},
		{code: "23514", want: webhookurlpolicy.ErrRepositoryInvalidInput},
		{code: "42501", want: webhookurlpolicy.ErrRepositoryForbidden},
		{code: "P0002", want: webhookurlpolicy.ErrRepositoryNotFound},
		{code: "40001", want: webhookurlpolicy.ErrRepositoryConflict},
		{code: "23505", want: webhookurlpolicy.ErrRepositoryConflict},
	} {
		if err := mapWebhookURLPolicyDatabaseError(&pgconn.PgError{Code: test.code}); !errors.Is(err, test.want) {
			t.Fatalf("database code %s mapped to %v, want %v", test.code, err, test.want)
		}
	}
}

func TestWebhookURLPolicyContextPreservesDatabaseErrorClassification(t *testing.T) {
	t.Parallel()
	databaseErr := &pgconn.PgError{Code: "42501"}
	queries := tenantContextQueriesStub{err: databaseErr}
	actor := authorization.Actor{
		UserID: uuid.MustParse("019d7900-1000-7000-8000-000000000031"),
	}
	tenantID := uuid.MustParse("019d7900-1000-7000-8000-000000000032")

	err := installTenantActorContext(context.Background(), queries, actor, tenantID)
	if !errors.Is(err, databaseErr) {
		t.Fatalf("tenant context error = %v, want original database error", err)
	}
	if mapped := mapWebhookURLPolicyDatabaseError(err); !errors.Is(mapped, webhookurlpolicy.ErrRepositoryForbidden) {
		t.Fatalf("mapped tenant context error = %v, want forbidden", mapped)
	}
}

type tenantContextQueriesStub struct {
	row *dbsql.SetTenantContextRow
	err error
}

func (stub tenantContextQueriesStub) SetTenantContext(
	context.Context,
	dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	return stub.row, stub.err
}
