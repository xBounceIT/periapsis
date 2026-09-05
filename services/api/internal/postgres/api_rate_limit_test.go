package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
)

type apiRateLimitQueryStub struct {
	query string
	args  []any
	row   pgx.Row
}

func (q *apiRateLimitQueryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	q.query = query
	q.args = args
	return q.row
}

type apiRateLimitRow func(...any) error

func (row apiRateLimitRow) Scan(destinations ...any) error { return row(destinations...) }

func TestAPIRateLimitRepositoryBindsPurposeSeparatedRules(t *testing.T) {
	queryer := &apiRateLimitQueryStub{row: apiRateLimitRow(func(destinations ...any) error {
		*destinations[0].(*bool) = false
		*destinations[1].(*int) = 2
		return nil
	})}
	repository := NewAPIRateLimitRepository(queryer)
	digestA := []byte("0123456789abcdef0123456789abcdef")
	digestB := []byte("abcdef0123456789abcdef0123456789")

	decision, err := repository.Admit(context.Background(), []apiratelimit.Rule{
		{Scope: apiratelimit.ScopeNetwork, Digest: digestA, Limit: 100},
		{Scope: apiratelimit.ScopeCredential, Digest: digestB, Limit: 60},
	})
	if err != nil || decision.Admitted || decision.RetryAfterSeconds != 2 {
		t.Fatalf("Admit() = %#v, %v", decision, err)
	}
	if !strings.Contains(queryer.query, "app.admit_api_request_v1") ||
		strings.Contains(queryer.query, string(digestA)) || len(queryer.args) != 3 {
		t.Fatalf("query did not use the parameterized shared admission ABI: %q %#v", queryer.query, queryer.args)
	}
	if got := queryer.args[0].([]string); len(got) != 2 || got[0] != apiratelimit.ScopeNetwork || got[1] != apiratelimit.ScopeCredential {
		t.Fatalf("scopes = %#v", got)
	}
	if got := queryer.args[2].([]int32); len(got) != 2 || got[0] != 100 || got[1] != 60 {
		t.Fatalf("limits = %#v", got)
	}
}

func TestAPIRateLimitRepositoryFailsClosed(t *testing.T) {
	validRule := apiratelimit.Rule{
		Scope:  apiratelimit.ScopeNetwork,
		Digest: []byte("0123456789abcdef0123456789abcdef"),
		Limit:  100,
	}
	for name, test := range map[string]struct {
		queryer SchemaQuerier
		rules   []apiratelimit.Rule
	}{
		"query failure": {
			queryer: &apiRateLimitQueryStub{row: apiRateLimitRow(func(...any) error { return context.DeadlineExceeded })},
			rules:   []apiratelimit.Rule{validRule},
		},
		"contradictory row": {
			queryer: &apiRateLimitQueryStub{row: apiRateLimitRow(func(destinations ...any) error {
				*destinations[0].(*bool) = true
				*destinations[1].(*int) = 3
				return nil
			})},
			rules: []apiratelimit.Rule{validRule},
		},
		"negative admitted retry": {
			queryer: &apiRateLimitQueryStub{row: apiRateLimitRow(func(destinations ...any) error {
				*destinations[0].(*bool) = true
				*destinations[1].(*int) = -1
				return nil
			})},
			rules: []apiratelimit.Rule{validRule},
		},
		"invalid scope": {
			queryer: &apiRateLimitQueryStub{},
			rules:   []apiratelimit.Rule{{Scope: "auth", Digest: validRule.Digest, Limit: 1}},
		},
		"invalid digest": {
			queryer: &apiRateLimitQueryStub{},
			rules:   []apiratelimit.Rule{{Scope: apiratelimit.ScopeNetwork, Digest: []byte("short"), Limit: 1}},
		},
		"zero limit": {
			queryer: &apiRateLimitQueryStub{},
			rules:   []apiratelimit.Rule{{Scope: apiratelimit.ScopeNetwork, Digest: validRule.Digest}},
		},
		"too many rules": {
			queryer: &apiRateLimitQueryStub{},
			rules:   []apiratelimit.Rule{validRule, validRule, validRule, validRule},
		},
		"duplicate": {
			queryer: &apiRateLimitQueryStub{},
			rules:   []apiratelimit.Rule{validRule, validRule},
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := NewAPIRateLimitRepository(test.queryer)
			if _, err := repository.Admit(context.Background(), test.rules); err == nil {
				t.Fatal("Admit() accepted unsafe or unavailable persistence")
			}
		})
	}

	repository := NewAPIRateLimitRepository(nil)
	if _, err := repository.Admit(context.Background(), []apiratelimit.Rule{validRule}); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("nil repository error = %v", err)
	}
}

func TestAPIRateLimitRepositoryPreservesCancellation(t *testing.T) {
	validRule := apiratelimit.Rule{
		Scope:  apiratelimit.ScopeNetwork,
		Digest: []byte("0123456789abcdef0123456789abcdef"),
		Limit:  100,
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, test := range map[string]struct {
		ctx      context.Context
		queryErr error
		want     error
	}{
		"driver deadline": {
			ctx: context.Background(), queryErr: context.DeadlineExceeded,
			want: context.DeadlineExceeded,
		},
		"canceled context": {
			ctx: canceled, queryErr: errors.New("driver interrupted"), want: context.Canceled,
		},
	} {
		t.Run(name, func(t *testing.T) {
			queryer := &apiRateLimitQueryStub{
				row: apiRateLimitRow(func(...any) error { return test.queryErr }),
			}
			repository := NewAPIRateLimitRepository(queryer)
			if _, err := repository.Admit(test.ctx, []apiratelimit.Rule{validRule}); !errors.Is(err, test.want) {
				t.Fatalf("Admit() error = %v, want %v", err, test.want)
			}
			if errors.Is(test.want, context.Canceled) && queryer.query != "" {
				t.Fatalf("canceled admission executed query %q", queryer.query)
			}
		})
	}
}
