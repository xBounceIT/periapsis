package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
)

func TestOIDCMaintenanceRepositoryClaimsExactSelectedAuthorityProjection(t *testing.T) {
	for _, authority := range []string{"tenant", "admitted_platform", "direct_platform", "switched_direct_platform"} {
		t.Run(authority, func(t *testing.T) {
			observedAt := oidcPostgresTestNow()
			response := oidcRefreshProjectionDocument(t, authority, observedAt)
			querier := &oidcMaintenanceTestQuerier{handler: func(
				_ context.Context, query string, arguments ...any,
			) pgx.Row {
				if query != claimDueOIDCMaintenanceQuery || len(arguments) != 1 {
					t.Fatalf("unexpected claim query %q %#v", query, arguments)
				}
				assertOIDCClaimRequest(t, arguments[0], oidcmaintenance.KindRefresh, observedAt)
				return oidcMaintenanceTestRow{bytes: response}
			}}
			repository := newOIDCMaintenanceRepositoryWithQuerier(querier)

			work, err := repository.ClaimDue(
				context.Background(), oidcmaintenance.KindRefresh, observedAt,
			)
			if err != nil {
				t.Fatalf("ClaimDue() error = %v", err)
			}
			if work == nil || work.Refresh == nil || work.Kind != oidcmaintenance.KindRefresh {
				t.Fatalf("ClaimDue() work = %+v", work)
			}
			if !work.ObservedAt.Equal(observedAt) {
				t.Fatalf("database observedAt = %s, want %s", work.ObservedAt, observedAt)
			}
			assertOIDCDecodedAuthority(t, authority, work.Refresh.TenantID, work.Refresh.Provider,
				work.Refresh.Admission, work.Refresh.BindingID)
			wantEffectiveTenant := oidcPostgresTestID(1)
			if authority == "direct_platform" {
				wantEffectiveTenant = identity.EntityID{}
			}
			if work.Refresh.EffectiveTenantID != wantEffectiveTenant {
				t.Fatalf("effective tenant = %s, want %s", work.Refresh.EffectiveTenantID, wantEffectiveTenant)
			}
			if work.Refresh.Generation != 3 || work.Refresh.Version != 7 ||
				work.Refresh.ClientSecretRevision != 4 ||
				work.Refresh.TokenDigest != sha256.Sum256([]byte("claimed-refresh-token")) {
				t.Fatalf("unexpected refresh projection: %s", work.Refresh.String())
			}
		})
	}
}

func TestOIDCMaintenanceRepositoryExposesSeparateExactCyclePhaseStatements(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	queries := make([]string, 0, 5)
	cleanupKinds := make([]string, 0, 3)
	querier := &oidcMaintenanceTestQuerier{
		expiryHandler: func(_ context.Context, query string, arguments ...any) pgx.Row {
			queries = append(queries, query)
			if len(arguments) != 1 {
				t.Fatalf("expiry arguments = %#v", arguments)
			}
			request := oidcPostgresJSONArgument(t, arguments[0])
			assertExactOIDCKeys(t, request, "kind", "observedAt")
			if request["kind"] != "access_expiry" {
				t.Fatalf("expiry kind = %#v", request["kind"])
			}
			response, err := json.Marshal(map[string]any{
				"kind": "access_expiry", "observedAt": observedAt, "expired": true,
			})
			return oidcMaintenanceTestRow{bytes: response, err: err}
		},
		cleanupHandler: func(_ context.Context, query string, arguments ...any) pgx.Row {
			queries = append(queries, query)
			if len(arguments) != 1 {
				t.Fatalf("cleanup arguments = %#v", arguments)
			}
			request := oidcPostgresJSONArgument(t, arguments[0])
			assertExactOIDCKeys(t, request, "kind", "observedAt")
			kind, ok := request["kind"].(string)
			if !ok {
				t.Fatalf("cleanup kind = %#v", request["kind"])
			}
			cleanupKinds = append(cleanupKinds, kind)
			response, err := json.Marshal(map[string]any{
				"kind": kind, "observedAt": observedAt, "removed": 0,
			})
			return oidcMaintenanceTestRow{bytes: response, err: err}
		},
		handler: func(_ context.Context, query string, arguments ...any) pgx.Row {
			queries = append(queries, query)
			if len(arguments) != 1 {
				t.Fatalf("claim arguments = %#v", arguments)
			}
			assertOIDCClaimRequest(t, arguments[0], oidcmaintenance.KindRefresh, observedAt)
			return oidcMaintenanceTestRow{}
		},
	}
	repository := newOIDCMaintenanceRepositoryWithQuerier(querier)
	if err := repository.ExpireAccessLease(context.Background(), observedAt); err != nil {
		t.Fatalf("ExpireAccessLease() error = %v", err)
	}
	if err := repository.CleanupFederatedRetention(context.Background(), observedAt); err != nil {
		t.Fatalf("CleanupFederatedRetention() error = %v", err)
	}
	work, err := repository.ClaimDue(
		context.Background(), oidcmaintenance.KindRefresh, observedAt,
	)
	if err != nil || work != nil {
		t.Fatalf("ClaimDue() = %+v, %v", work, err)
	}
	if !reflect.DeepEqual(queries, []string{
		expireOIDCAccessLeaseQuery,
		cleanupFederatedMaintenanceQuery, cleanupFederatedMaintenanceQuery,
		cleanupFederatedMaintenanceQuery, claimDueOIDCMaintenanceQuery,
	}) {
		t.Fatalf("query order = %v", queries)
	}
	if !reflect.DeepEqual(cleanupKinds, oidcMaintenanceCleanupKinds[:]) {
		t.Fatalf("cleanup kinds = %v", cleanupKinds)
	}
}

func TestOIDCMaintenanceRepositoryRejectsUnavailableOrNonExactCyclePhaseReceipts(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	for _, test := range []struct {
		name       string
		repository *OIDCMaintenanceRepository
		run        func(*OIDCMaintenanceRepository) error
		want       error
	}{
		{
			name: "expiry unavailable",
			repository: newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{
				expiryHandler: func(context.Context, string, ...any) pgx.Row {
					return oidcMaintenanceTestRow{err: errors.New("expiry unavailable")}
				},
			}),
			run: func(repository *OIDCMaintenanceRepository) error {
				return repository.ExpireAccessLease(context.Background(), observedAt)
			},
			want: oidcmaintenance.ErrUnavailable,
		},
		{
			name: "expiry extra field",
			repository: newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{
				expiryHandler: func(context.Context, string, ...any) pgx.Row {
					return oidcMaintenanceTestRow{bytes: []byte(`{"kind":"access_expiry","observedAt":"2026-09-04T10:00:00Z","expired":false,"extra":true}`)}
				},
			}),
			run: func(repository *OIDCMaintenanceRepository) error {
				return repository.ExpireAccessLease(context.Background(), observedAt)
			},
			want: oidcmaintenance.ErrInvalidProjection,
		},
		{
			name: "expiry null result",
			repository: newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{
				expiryHandler: func(context.Context, string, ...any) pgx.Row {
					response, err := json.Marshal(map[string]any{
						"kind": "access_expiry", "observedAt": observedAt, "expired": nil,
					})
					return oidcMaintenanceTestRow{bytes: response, err: err}
				},
			}),
			run: func(repository *OIDCMaintenanceRepository) error {
				return repository.ExpireAccessLease(context.Background(), observedAt)
			},
			want: oidcmaintenance.ErrInvalidProjection,
		},
		{
			name: "cleanup unavailable",
			repository: newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{
				cleanupHandler: func(context.Context, string, ...any) pgx.Row {
					return oidcMaintenanceTestRow{err: errors.New("cleanup unavailable")}
				},
			}),
			run: func(repository *OIDCMaintenanceRepository) error {
				return repository.CleanupFederatedRetention(context.Background(), observedAt)
			},
			want: oidcmaintenance.ErrUnavailable,
		},
		{
			name: "cleanup null count",
			repository: newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{
				cleanupHandler: func(context.Context, string, ...any) pgx.Row {
					response, err := json.Marshal(map[string]any{
						"kind":       "logout_continuation",
						"observedAt": observedAt,
						"removed":    nil,
					})
					return oidcMaintenanceTestRow{bytes: response, err: err}
				},
			}),
			run: func(repository *OIDCMaintenanceRepository) error {
				return repository.CleanupFederatedRetention(context.Background(), observedAt)
			},
			want: oidcmaintenance.ErrInvalidProjection,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(test.repository); !errors.Is(err, test.want) {
				t.Fatalf("cycle phase error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOIDCMaintenanceRepositoryDecodesDatabaseObservedAtForScrub(t *testing.T) {
	requestedAt := oidcPostgresTestNow().Add(-2 * time.Minute)
	databaseObservedAt := oidcPostgresTestNow()
	response, err := json.Marshal(map[string]any{
		"kind": "scrub", "observedAt": databaseObservedAt,
		"materialId":     uuid.UUID(oidcPostgresTestID(10)).String(),
		"operationRunId": uuid.UUID(oidcPostgresTestID(13)).String(),
		"completedAt":    databaseObservedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
		context.Context, string, ...any,
	) pgx.Row {
		return oidcMaintenanceTestRow{bytes: response}
	}})

	work, err := repository.ClaimDue(context.Background(), oidcmaintenance.KindScrub, requestedAt)
	if err != nil || work == nil || work.Scrub == nil ||
		!work.ObservedAt.Equal(databaseObservedAt) || !work.Scrub.CompletedAt.Equal(databaseObservedAt) {
		t.Fatalf("ClaimDue(scrub) = %+v, %v", work, err)
	}
}

func TestOIDCMaintenanceRepositoryReadsExactAuthoritativeQueueSnapshot(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	oldestLogout := observedAt.Add(-3 * time.Second)
	oldestRefresh := observedAt.Add(-2 * time.Second)
	response, err := json.Marshal(map[string]any{
		"observedAt": observedAt,
		"categories": map[string]any{
			"logout_retry": map[string]any{
				"dueCount": 4, "reclaimableCount": 2, "deadLetterCount": 1,
				"oldestDueAt": oldestLogout,
			},
			"refresh": map[string]any{
				"dueCount": 3, "reclaimableCount": 1, "oldestDueAt": oldestRefresh,
			},
			"scrub": map[string]any{"dueCount": 0, "oldestDueAt": nil},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
		_ context.Context, query string, arguments ...any,
	) pgx.Row {
		if query != oidcMaintenanceQueueQuery || len(arguments) != 1 ||
			!reflect.DeepEqual(oidcPostgresJSONArgument(t, arguments[0]), map[string]any{}) {
			t.Fatalf("unexpected queue query %q %#v", query, arguments)
		}
		return oidcMaintenanceTestRow{bytes: response}
	}})

	snapshot, err := repository.QueueSnapshot(context.Background())
	if err != nil || !snapshot.ObservedAt.Equal(observedAt) || snapshot.LogoutRetry.DueCount != 4 ||
		snapshot.LogoutRetry.ReclaimableCount != 2 || snapshot.LogoutRetry.DeadLetterCount != 1 ||
		!snapshot.LogoutRetry.OldestDueAt.Equal(oldestLogout) || snapshot.Refresh.DueCount != 3 ||
		snapshot.Refresh.ReclaimableCount != 1 || !snapshot.Refresh.OldestDueAt.Equal(oldestRefresh) ||
		snapshot.Scrub != (oidcmaintenance.QueueCategorySnapshot{}) {
		t.Fatalf("QueueSnapshot() = %+v, %v", snapshot, err)
	}
}

func TestOIDCMaintenanceRepositoryRejectsNonExactQueueSnapshot(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	for _, document := range []map[string]any{
		{
			"observedAt": observedAt,
			"categories": map[string]any{
				"logout_retry": map[string]any{
					"dueCount": 0, "reclaimableCount": 0, "deadLetterCount": 0, "oldestDueAt": nil,
				},
				"refresh": map[string]any{
					"dueCount": 0, "reclaimableCount": 0, "oldestDueAt": nil, "tenant": "leak",
				},
				"scrub": map[string]any{"dueCount": 0, "oldestDueAt": nil},
			},
		},
		{
			"observedAt": observedAt,
			"categories": map[string]any{
				"logout_retry": map[string]any{
					"dueCount": 0, "reclaimableCount": 0, "deadLetterCount": 0,
					"oldestDueAt": observedAt,
				},
				"refresh": map[string]any{"dueCount": 0, "reclaimableCount": 0, "oldestDueAt": nil},
				"scrub":   map[string]any{"dueCount": 0, "oldestDueAt": nil},
			},
		},
	} {
		payload, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
			context.Context, string, ...any,
		) pgx.Row {
			return oidcMaintenanceTestRow{bytes: payload}
		}})
		if _, err := repository.QueueSnapshot(context.Background()); !errors.Is(err, oidcmaintenance.ErrInvalidProjection) {
			t.Fatalf("QueueSnapshot() error = %v", err)
		}
	}
}

func TestOIDCMaintenanceRepositoryDecodesAdmittedPlatformLogoutBinding(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	response := oidcLogoutProjectionDocument(t, "admitted_platform", observedAt)
	repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
		_ context.Context, _ string, _ ...any,
	) pgx.Row {
		return oidcMaintenanceTestRow{bytes: response}
	}})

	work, err := repository.ClaimDue(context.Background(), oidcmaintenance.KindLogoutRetry, observedAt)
	if err != nil {
		t.Fatalf("ClaimDue() error = %v", err)
	}
	if work == nil || work.LogoutRetry == nil {
		t.Fatalf("ClaimDue() work = %+v", work)
	}
	claim := work.LogoutRetry
	assertOIDCDecodedAuthority(t, "admitted_platform", claim.TenantID, claim.Provider,
		claim.Admission, claim.BindingID)
	if claim.Attempt != 1 || claim.MaximumAttempts != 3 || claim.ClaimVersion != 8 ||
		claim.RefreshGeneration != 3 || claim.TokenDigest != sha256.Sum256([]byte("claimed-refresh-token")) {
		t.Fatalf("unexpected logout projection: %s", claim.String())
	}
}

func TestOIDCMaintenanceRepositoryRejectsBusyOrNonExactProjection(t *testing.T) {
	observedAt := oidcPostgresTestNow()
	id := uuid.UUID(oidcPostgresTestID(1)).String()
	valid := oidcRefreshProjectionObject("direct_platform", observedAt)
	tests := []struct {
		name    string
		kind    oidcmaintenance.Kind
		payload any
	}{
		{name: "busy must stay inside direct claim", kind: oidcmaintenance.KindRefresh, payload: map[string]any{
			"kind": "refresh", "category": "busy", "sessionFamilyId": id,
		}},
		{name: "wrong selected category", kind: oidcmaintenance.KindScrub, payload: valid},
		{name: "unknown nested token field", kind: oidcmaintenance.KindRefresh, payload: mutateOIDCMap(valid, func(object map[string]any) {
			object["token"].(map[string]any)["secret"] = "leak"
		})},
		{name: "platform provider null tenant", kind: oidcmaintenance.KindRefresh, payload: mutateOIDCMap(valid, func(object map[string]any) {
			object["provider"].(map[string]any)["tenantId"] = nil
		})},
		{name: "admission null", kind: oidcmaintenance.KindRefresh, payload: mutateOIDCMap(valid, func(object map[string]any) {
			object["admission"] = nil
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
				context.Context, string, ...any,
			) pgx.Row {
				return oidcMaintenanceTestRow{bytes: payload}
			}})
			if _, err := repository.ClaimDue(context.Background(), test.kind, observedAt); !errors.Is(err, oidcmaintenance.ErrInvalidProjection) {
				t.Fatalf("ClaimDue() error = %v", err)
			}
		})
	}
}

func TestOIDCMaintenanceRepositoryLoadsExactHistoricalSecretAcrossScopes(t *testing.T) {
	for _, authority := range []string{"tenant", "admitted_platform", "direct_platform"} {
		t.Run(authority, func(t *testing.T) {
			lookup := oidcPostgresSecretLookup(authority)
			querier := &oidcMaintenanceTestQuerier{handler: func(
				_ context.Context, query string, arguments ...any,
			) pgx.Row {
				if query != loadOIDCMaintenanceSecretQuery || len(arguments) != 1 {
					t.Fatalf("unexpected secret query %q %#v", query, arguments)
				}
				request := oidcPostgresJSONArgument(t, arguments[0])
				assertOIDCSecretLookupJSON(t, authority, request)
				response, err := json.Marshal(map[string]any{
					"lookup": request, "secretId": uuid.UUID(oidcPostgresTestID(20)).String(),
					"keyVersion": 1, "nonce": []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
					"ciphertext": []byte("0123456789abcdefg"),
				})
				if err != nil {
					t.Fatal(err)
				}
				return oidcMaintenanceTestRow{bytes: response}
			}}
			snapshot, err := newOIDCMaintenanceRepositoryWithQuerier(querier).LoadClientSecret(
				context.Background(), lookup,
			)
			if err != nil {
				t.Fatalf("LoadClientSecret() error = %v", err)
			}
			if snapshot.Lookup != lookup || snapshot.SecretID != oidcPostgresTestID(20) ||
				snapshot.Envelope.KeyVersion != 1 || len(snapshot.Envelope.Ciphertext) != 17 {
				t.Fatalf("unexpected secret snapshot: %s", snapshot.String())
			}
		})
	}
}

func TestOIDCMaintenanceRepositoryRejectsNonExactSecretEcho(t *testing.T) {
	lookup := oidcPostgresSecretLookup("direct_platform")
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing explicit null binding", mutate: func(document map[string]any) {
			delete(document["lookup"].(map[string]any), "bindingId")
		}},
		{name: "noncanonical platform provider", mutate: func(document map[string]any) {
			document["lookup"].(map[string]any)["provider"].(map[string]any)["bindingId"] = nil
		}},
		{name: "null admission", mutate: func(document map[string]any) {
			document["lookup"].(map[string]any)["admission"] = nil
		}},
		{name: "wrong revision", mutate: func(document map[string]any) {
			document["lookup"].(map[string]any)["revision"] = float64(5)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
				_ context.Context, _ string, arguments ...any,
			) pgx.Row {
				request := oidcPostgresJSONArgument(t, arguments[0])
				document := map[string]any{
					"lookup": request, "secretId": uuid.UUID(oidcPostgresTestID(20)).String(),
					"keyVersion": float64(1), "nonce": []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
					"ciphertext": []byte("0123456789abcdefg"),
				}
				test.mutate(document)
				response, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				return oidcMaintenanceTestRow{bytes: response}
			}})
			if _, err := repository.LoadClientSecret(context.Background(), lookup); !errors.Is(err, oidcmaintenance.ErrInvalidProjection) {
				t.Fatalf("LoadClientSecret() error = %v", err)
			}
		})
	}
}

func TestOIDCMaintenanceRepositoryCompletionUsesCategorySpecificExactCAS(t *testing.T) {
	now := oidcPostgresTestNow()
	tenantID := oidcPostgresTestID(1)
	materialID := oidcPostgresTestID(2)
	familyID := oidcPostgresTestID(3)
	queries := make([]string, 0, 3)
	documents := make([]map[string]any, 0, 3)
	results := []bool{true, false, true}
	querier := &oidcMaintenanceTestQuerier{handler: func(
		_ context.Context, query string, arguments ...any,
	) pgx.Row {
		queries = append(queries, query)
		documents = append(documents, oidcPostgresJSONArgument(t, arguments[0]))
		result := results[len(documents)-1]
		return oidcMaintenanceTestRow{boolean: &result}
	}}
	repository := newOIDCMaintenanceRepositoryWithQuerier(querier)
	digest := sha256.Sum256([]byte("successor"))
	rotated := oidcmaintenance.RefreshCompletion{
		TenantID: tenantID, EffectiveTenantID: tenantID,
		MaterialID: materialID, SessionFamilyID: familyID,
		ExpectedVersion: 7, ExpectedGeneration: 3, Outcome: oidcmaintenance.RefreshRotated,
		SuccessorGeneration: 4, SuccessorDigest: digest,
		SuccessorToken:  oidcmaintenance.ProtectedToken{KeyVersion: 1, Ciphertext: make([]byte, 29)},
		AccessExpiresAt: now.Add(time.Minute), CompletedAt: now,
	}
	if applied, err := repository.CompleteRefresh(context.Background(), rotated); err != nil || !applied {
		t.Fatalf("CompleteRefresh(rotated) = %t, %v", applied, err)
	}
	rejected := rotated
	rejected.Outcome = oidcmaintenance.RefreshRejected
	rejected.SuccessorGeneration = 0
	rejected.SuccessorDigest = [sha256.Size]byte{}
	rejected.SuccessorToken = oidcmaintenance.ProtectedToken{}
	rejected.AccessExpiresAt = time.Time{}
	if applied, err := repository.CompleteRefresh(context.Background(), rejected); err != nil || applied {
		t.Fatalf("CompleteRefresh(rejected stale) = %t, %v", applied, err)
	}
	logout := oidcmaintenance.LogoutCompletion{
		JobID: oidcPostgresTestID(4), Attempt: 2, ExpectedVersion: 8,
		Outcome: oidcmaintenance.LogoutSafeToRetry, CompletedAt: now, NextTryAt: now.Add(time.Second),
	}
	if applied, err := repository.CompleteLogout(context.Background(), logout); err != nil || !applied {
		t.Fatalf("CompleteLogout() = %t, %v", applied, err)
	}
	if !reflect.DeepEqual(queries, []string{
		completeOIDCRefreshQuery, completeOIDCRefreshQuery, completeOIDCLogoutQuery,
	}) {
		t.Fatalf("completion queries = %v", queries)
	}
	assertExactOIDCKeys(t, documents[0], "tenantId", "effectiveTenantId", "materialId", "sessionFamilyId", "expectedVersion",
		"expectedGeneration", "outcome", "successorGeneration", "successorDigest", "successorToken",
		"accessExpiresAt", "completedAt")
	assertExactOIDCKeys(t, documents[1], "tenantId", "effectiveTenantId", "materialId", "sessionFamilyId", "expectedVersion",
		"expectedGeneration", "outcome", "completedAt")
	assertExactOIDCKeys(t, documents[2], "jobId", "attempt", "expectedVersion", "outcome", "completedAt", "nextTryAt")
}

func TestOIDCMaintenanceRepositoryReadinessFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name  string
		ready bool
		err   error
	}{
		{name: "false"},
		{name: "database error", err: errors.New("database unavailable")},
		{name: "ready", ready: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newOIDCMaintenanceRepositoryWithQuerier(&oidcMaintenanceTestQuerier{handler: func(
				_ context.Context, query string, arguments ...any,
			) pgx.Row {
				if query != oidcMaintenanceReadinessQuery || len(arguments) != 0 {
					t.Fatalf("unexpected readiness query %q %#v", query, arguments)
				}
				return oidcMaintenanceTestRow{boolean: &test.ready, err: test.err}
			}})
			err := repository.Ready(context.Background())
			if (err == nil) != test.ready || test.err != nil && !errors.Is(err, oidcmaintenance.ErrUnavailable) {
				t.Fatalf("Ready() error = %v", err)
			}
		})
	}
}

type oidcMaintenanceTestQuerier struct {
	handler        func(context.Context, string, ...any) pgx.Row
	expiryHandler  func(context.Context, string, ...any) pgx.Row
	cleanupHandler func(context.Context, string, ...any) pgx.Row
}

func (querier *oidcMaintenanceTestQuerier) QueryRow(
	ctx context.Context, query string, arguments ...any,
) pgx.Row {
	if query == expireOIDCAccessLeaseQuery {
		if querier.expiryHandler != nil {
			return querier.expiryHandler(ctx, query, arguments...)
		}
		var request oidcMaintenancePhaseRequestWire
		payload, ok := arguments[0].([]byte)
		if !ok || json.Unmarshal(payload, &request) != nil {
			return oidcMaintenanceTestRow{err: errors.New("invalid access-expiry request")}
		}
		expired := false
		response, err := json.Marshal(oidcAccessExpiryReceiptWire{
			Kind: request.Kind, ObservedAt: request.ObservedAt, Expired: &expired,
		})
		return oidcMaintenanceTestRow{bytes: response, err: err}
	}
	if query == cleanupFederatedMaintenanceQuery {
		if querier.cleanupHandler != nil {
			return querier.cleanupHandler(ctx, query, arguments...)
		}
		var request oidcMaintenancePhaseRequestWire
		payload, ok := arguments[0].([]byte)
		if !ok || json.Unmarshal(payload, &request) != nil {
			return oidcMaintenanceTestRow{err: errors.New("invalid cleanup request")}
		}
		removed := 0
		response, err := json.Marshal(oidcMaintenanceCleanupReceiptWire{
			Kind: request.Kind, ObservedAt: request.ObservedAt, Removed: &removed,
		})
		return oidcMaintenanceTestRow{bytes: response, err: err}
	}
	return querier.handler(ctx, query, arguments...)
}

type oidcMaintenanceTestRow struct {
	bytes   []byte
	boolean *bool
	err     error
}

func (row oidcMaintenanceTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected scan")
	}
	switch destination := destinations[0].(type) {
	case *[]byte:
		*destination = append([]byte(nil), row.bytes...)
	case *bool:
		if row.boolean == nil {
			return errors.New("missing boolean")
		}
		*destination = *row.boolean
	default:
		return errors.New("unexpected destination")
	}
	return nil
}

func assertOIDCClaimRequest(
	t *testing.T, argument any, kind oidcmaintenance.Kind, observedAt time.Time,
) {
	t.Helper()
	document := oidcPostgresJSONArgument(t, argument)
	assertExactOIDCKeys(t, document, "kind", "observedAt")
	if document["kind"] != string(kind) {
		t.Fatalf("claim kind = %#v", document["kind"])
	}
	encoded, ok := document["observedAt"].(string)
	parsed, err := time.Parse(time.RFC3339Nano, encoded)
	if !ok || err != nil || !parsed.Equal(observedAt) {
		t.Fatalf("claim observedAt = %#v", document["observedAt"])
	}
}

func oidcPostgresJSONArgument(t *testing.T, argument any) map[string]any {
	t.Helper()
	payload, ok := argument.([]byte)
	if !ok {
		t.Fatalf("JSON argument type = %T", argument)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("invalid JSON argument: %v", err)
	}
	return document
}

func oidcRefreshProjectionDocument(t *testing.T, authority string, now time.Time) []byte {
	t.Helper()
	payload, err := json.Marshal(oidcRefreshProjectionObject(authority, now))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func oidcRefreshProjectionObject(authority string, now time.Time) map[string]any {
	tenantID, provider, admission, bindingID := oidcPostgresWireAuthority(authority)
	object := map[string]any{
		"kind": "refresh", "category": "claimed", "observedAt": now,
		"tenantId": tenantID, "effectiveTenantId": tenantID,
		"materialId":      uuid.UUID(oidcPostgresTestID(10)).String(),
		"sessionFamilyId": uuid.UUID(oidcPostgresTestID(11)).String(),
		"generation":      uint64(3), "version": uint64(7), "leaseExpiresAt": now.Add(time.Minute),
		"provider": provider, "bindingId": bindingID, "clientSecretRevision": uint64(4),
		"endpoint": "https://idp.example.invalid/oauth/token", "clientAuthentication": "client_secret_basic",
		"clientId": "worker-client", "token": map[string]any{"keyVersion": 1, "ciphertext": make([]byte, 29)},
		"tokenDigest":       sha256.Sum256([]byte("claimed-refresh-token")),
		"materialExpiresAt": now.Add(time.Hour), "absoluteSessionExpiry": now.Add(2 * time.Hour),
	}
	if admission != nil {
		object["admission"] = admission
	}
	if authority == "direct_platform" {
		object["effectiveTenantId"] = nil
	}
	if authority == "switched_direct_platform" {
		object["effectiveTenantId"] = uuid.UUID(oidcPostgresTestID(1)).String()
	}
	return object
}

func oidcLogoutProjectionDocument(t *testing.T, authority string, now time.Time) []byte {
	t.Helper()
	tenantID, provider, admission, _ := oidcPostgresWireAuthority(authority)
	object := map[string]any{
		"kind": "logout_retry", "observedAt": now,
		"jobId":    uuid.UUID(oidcPostgresTestID(12)).String(),
		"tenantId": tenantID, "materialId": uuid.UUID(oidcPostgresTestID(10)).String(),
		"sessionFamilyId": uuid.UUID(oidcPostgresTestID(11)).String(),
		"attempt":         1, "maximumAttempts": 3, "claimVersion": uint64(8),
		"leaseExpiresAt": now.Add(time.Minute), "notBefore": now, "provider": provider,
		"clientSecretRevision": uint64(4), "clientAuthentication": "client_secret_post",
		"clientId": "worker-client", "endpoint": "https://idp.example.invalid/oauth/revoke",
		"refreshGeneration": uint64(3), "tokenDigest": sha256.Sum256([]byte("claimed-refresh-token")),
		"materialExpiresAt": now.Add(time.Hour),
		"opaqueReference":   map[string]any{"keyVersion": 1, "ciphertext": make([]byte, 29)},
	}
	if admission != nil {
		object["admission"] = admission
	}
	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func oidcPostgresWireAuthority(authority string) (any, map[string]any, map[string]any, any) {
	tenantID := uuid.UUID(oidcPostgresTestID(1)).String()
	providerID := uuid.UUID(oidcPostgresTestID(2)).String()
	bindingID := uuid.UUID(oidcPostgresTestID(3)).String()
	switch authority {
	case "tenant":
		return tenantID, map[string]any{
			"scope": "tenant", "tenantId": tenantID, "providerId": providerID, "bindingId": bindingID,
		}, nil, bindingID
	case "admitted_platform":
		return tenantID, map[string]any{"scope": "platform", "providerId": providerID},
			map[string]any{"tenantId": tenantID, "bindingId": bindingID}, bindingID
	case "direct_platform", "switched_direct_platform":
		return nil, map[string]any{"scope": "platform", "providerId": providerID}, nil, nil
	default:
		panic("unknown authority")
	}
}

func oidcPostgresSecretLookup(authority string) oidcmaintenance.ClientSecretLookup {
	tenantID := oidcPostgresTestID(1)
	providerID := oidcPostgresTestID(2)
	bindingID := oidcPostgresTestID(3)
	proof := oidcmaintenance.ClientSecretLookup{
		Kind: oidcmaintenance.KindRefresh, MaterialID: oidcPostgresTestID(4),
		SessionFamilyID: oidcPostgresTestID(5), ClaimVersion: 6, RefreshGeneration: 7,
	}
	switch authority {
	case "tenant":
		proof.Provider = identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID,
		}
		proof.BindingID, proof.Revision = bindingID, 4
		return proof
	case "admitted_platform":
		proof.Provider = identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: providerID}
		proof.Admission = identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}
		proof.Revision = 4
		return proof
	case "direct_platform", "switched_direct_platform":
		proof.Provider = identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: providerID}
		proof.Revision = 4
		return proof
	default:
		panic("unknown authority")
	}
}

func assertOIDCSecretLookupJSON(t *testing.T, authority string, document map[string]any) {
	t.Helper()
	assertExactOIDCKeys(t, document, func() []string {
		if authority == "admitted_platform" {
			return []string{"provider", "admission", "bindingId", "revision", "kind", "materialId", "sessionFamilyId", "claimVersion", "refreshGeneration"}
		}
		return []string{"provider", "bindingId", "revision", "kind", "materialId", "sessionFamilyId", "claimVersion", "refreshGeneration"}
	}()...)
	if document["kind"] != string(oidcmaintenance.KindRefresh) || document["claimVersion"] != float64(6) ||
		document["refreshGeneration"] != float64(7) {
		t.Fatalf("claim proof drifted: %#v", document)
	}
	provider := document["provider"].(map[string]any)
	if authority == "tenant" {
		assertExactOIDCKeys(t, provider, "scope", "tenantId", "providerId", "bindingId")
		if document["bindingId"] != provider["bindingId"] {
			t.Fatal("tenant binding was not repeated exactly")
		}
	} else {
		assertExactOIDCKeys(t, provider, "scope", "providerId")
		if authority == "admitted_platform" {
			admission := document["admission"].(map[string]any)
			assertExactOIDCKeys(t, admission, "tenantId", "bindingId")
			if document["bindingId"] != admission["bindingId"] {
				t.Fatal("admitted binding was not repeated exactly")
			}
		} else if document["bindingId"] != nil {
			t.Fatal("direct platform binding was not explicit null")
		}
	}
}

func assertOIDCDecodedAuthority(
	t *testing.T,
	authority string,
	tenantID identity.EntityID,
	provider identity.ProviderContext,
	admission identity.TenantAdmissionContext,
	bindingID identity.EntityID,
) {
	t.Helper()
	wantTenant := oidcPostgresTestID(1)
	wantProvider := oidcPostgresTestID(2)
	wantBinding := oidcPostgresTestID(3)
	if provider.ProviderID != wantProvider {
		t.Fatalf("provider ID mismatch: %+v", provider)
	}
	switch authority {
	case "tenant":
		if tenantID != wantTenant || provider.Scope != identity.TenantProviderScope ||
			provider.TenantID != wantTenant || bindingID != wantBinding ||
			admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("tenant authority mismatch: %+v %+v", provider, admission)
		}
	case "admitted_platform":
		if tenantID != wantTenant || provider.Scope != identity.PlatformProviderScope ||
			provider.TenantID != (identity.EntityID{}) || bindingID != wantBinding ||
			admission != (identity.TenantAdmissionContext{TenantID: wantTenant, BindingID: wantBinding}) {
			t.Fatalf("admitted authority mismatch: %+v %+v", provider, admission)
		}
	case "direct_platform":
		if tenantID != (identity.EntityID{}) || provider.Scope != identity.PlatformProviderScope ||
			bindingID != (identity.EntityID{}) || admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("direct authority mismatch: %+v %+v", provider, admission)
		}
	}
}

func assertExactOIDCKeys(t *testing.T, document map[string]any, keys ...string) {
	t.Helper()
	want := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		want[key] = struct{}{}
	}
	if len(document) != len(want) {
		t.Fatalf("document keys = %v, want %v", reflect.ValueOf(document).MapKeys(), keys)
	}
	for key := range document {
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected document key %q", key)
		}
	}
}

func mutateOIDCMap(source map[string]any, mutate func(map[string]any)) map[string]any {
	document, err := json.Marshal(source)
	if err != nil {
		panic(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(document, &clone); err != nil {
		panic(err)
	}
	mutate(clone)
	return clone
}

func oidcPostgresTestID(suffix int) identity.EntityID {
	return identity.EntityID(uuid.MustParse(fmt.Sprintf("01890f00-0000-7000-8000-%012d", suffix)))
}

func oidcPostgresTestNow() time.Time {
	return time.Date(2026, time.September, 4, 12, 0, 0, 123000, time.UTC)
}
