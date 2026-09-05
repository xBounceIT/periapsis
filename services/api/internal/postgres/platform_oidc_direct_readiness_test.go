package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPlatformOIDCDirectReadinessUsesOnlySealedDirectGate(t *testing.T) {
	queries := 0
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queries++
		if query != platformOIDCDirectReadinessSQL || len(arguments) != 0 {
			t.Fatalf("readiness query = %q, arguments = %d", query, len(arguments))
		}
		return federatedAuthRowFunc(func(destinations ...any) error {
			if len(destinations) != 1 {
				t.Fatalf("readiness destination count = %d", len(destinations))
			}
			ready, ok := destinations[0].(*bool)
			if !ok {
				t.Fatalf("readiness destination type = %T", destinations[0])
			}
			*ready = true
			return nil
		})
	}}}

	if err := repository.ReadyDirectPlatformOIDC(context.Background()); err != nil {
		t.Fatalf("ReadyDirectPlatformOIDC() error = %v", err)
	}
	if queries != 1 {
		t.Fatalf("readiness queries = %d, want 1", queries)
	}
}

func TestPlatformOIDCDirectReadinessFailsClosed(t *testing.T) {
	tests := map[string]struct {
		repository *FederatedAuthRepository
		context    context.Context
	}{
		"nil repository": {},
		"nil queryer":    {repository: &FederatedAuthRepository{}, context: context.Background()},
		"nil context": {repository: &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			context.Context, string, ...any,
		) pgx.Row {
			t.Fatal("query reached with nil context")
			return nil
		}}}},
		"cancelled context": func() struct {
			repository *FederatedAuthRepository
			context    context.Context
		} {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return struct {
				repository *FederatedAuthRepository
				context    context.Context
			}{repository: &FederatedAuthRepository{queryer: federatedAuthQueryerStub{}}, context: ctx}
		}(),
		"false": {
			repository: &FederatedAuthRepository{queryer: directReadinessRow(false, nil)},
			context:    context.Background(),
		},
		"query error": {
			repository: &FederatedAuthRepository{queryer: directReadinessRow(false, errors.New("unavailable"))},
			context:    context.Background(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.repository.ReadyDirectPlatformOIDC(test.context); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("ReadyDirectPlatformOIDC() error = %v", err)
			}
		})
	}
}

func directReadinessRow(ready bool, scanErr error) federatedAuthQueryerStub {
	return federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		return federatedAuthRowFunc(func(destinations ...any) error {
			if scanErr != nil {
				return scanErr
			}
			if query != platformOIDCDirectReadinessSQL || len(arguments) != 0 || len(destinations) != 1 {
				return errors.New("unexpected readiness query")
			}
			value, ok := destinations[0].(*bool)
			if !ok {
				return errors.New("unexpected readiness destination")
			}
			*value = ready
			return nil
		})
	}}
}
