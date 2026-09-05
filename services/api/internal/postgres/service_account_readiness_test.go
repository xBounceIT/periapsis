package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type apiKeyVersionQuerierStub struct {
	row   pgx.Row
	query string
	args  []any
}

func (s *apiKeyVersionQuerierStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	s.query = query
	s.args = append([]any(nil), args...)
	return s.row
}

type apiKeyVersionRowStub struct {
	versions []int32
	err      error
}

func (r apiKeyVersionRowStub) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected destination count")
	}
	target, ok := destinations[0].(*[]int32)
	if !ok {
		return errors.New("unexpected destination type")
	}
	*target = append([]int32(nil), r.versions...)
	return nil
}

func TestAPIKeyVersionInventoryUsesOnlyTheBoundedDefiner(t *testing.T) {
	querier := &apiKeyVersionQuerierStub{row: apiKeyVersionRowStub{versions: []int32{1, 7}}}
	inventory := NewAPIKeyVersionInventory(querier)

	versions, err := inventory.ListLiveAPIKeyVersions(context.Background(), 17)
	if err != nil {
		t.Fatalf("ListLiveAPIKeyVersions() error = %v", err)
	}
	if !reflect.DeepEqual(versions, []int16{1, 7}) {
		t.Fatalf("versions = %#v", versions)
	}
	if querier.query != liveAPIKeyVersionsQuery || !reflect.DeepEqual(querier.args, []any{int32(17)}) {
		t.Fatalf("query = %q, args = %#v", querier.query, querier.args)
	}
	for _, forbidden := range []string{"locator", "secret_digest", "credential_id"} {
		if strings.Contains(strings.ToLower(liveAPIKeyVersionsQuery), forbidden) {
			t.Fatalf("readiness query exposes %q", forbidden)
		}
	}
}

func TestAPIKeyVersionInventoryRejectsInvalidDatabaseProjection(t *testing.T) {
	tests := []struct {
		name     string
		versions []int32
		limit    int32
	}{
		{name: "zero", versions: []int32{0}, limit: 17},
		{name: "unsupported version", versions: []int32{32768}, limit: 17},
		{name: "duplicate", versions: []int32{1, 1}, limit: 17},
		{name: "unsorted", versions: []int32{2, 1}, limit: 17},
		{name: "over limit", versions: []int32{1, 2}, limit: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := NewAPIKeyVersionInventory(&apiKeyVersionQuerierStub{
				row: apiKeyVersionRowStub{versions: test.versions},
			})
			if _, err := inventory.ListLiveAPIKeyVersions(context.Background(), test.limit); err == nil {
				t.Fatal("ListLiveAPIKeyVersions() accepted invalid projection")
			}
		})
	}
}

func TestAPIKeyVersionInventoryPreservesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inventory := NewAPIKeyVersionInventory(&apiKeyVersionQuerierStub{
		row: apiKeyVersionRowStub{err: errors.New("database detail")},
	})
	if _, err := inventory.ListLiveAPIKeyVersions(ctx, 17); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListLiveAPIKeyVersions() error = %v", err)
	}
}
