package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
)

func TestPlatformIdentityBindingCreateUsesOneProtectedTransactionAndCorrelatedAudits(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	bindingID := mustPostgresUUIDv7(t)
	commandID := mustPostgresUUIDv7(t)
	tenantAuditID := mustPostgresUUIDv7(t)
	platformAuditID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 28, 15, 0, 0, 123_456_000, time.UTC)
	params := platformidentitybinding.CreateParams{
		SessionParams: session, CommandID: commandID, BindingID: bindingID,
		ProviderID: providerID, TenantID: tenantID, LoginKey: "corporate_login", ProfilePriority: 42,
		Reason: "Approved explicit tenant admission", Event: event,
		ValidateResult: func(result platformidentitybinding.CreateResult) (platformidentitybinding.CreateResult, error) {
			binding := result.Binding()
			if binding.ProviderID != providerID || binding.Tenant.ID != tenantID ||
				binding.Tenant.Version != 11 || binding.Enabled {
				return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
			}
			return result, nil
		},
	}
	params.KeyDigest = sha256.Sum256([]byte("binding-create-key"))
	params.RequestDigest = sha256.Sum256([]byte("binding-create-request"))
	tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.create_tenant_platform_auth_provider_binding_v1") || len(destinations) != 4 {
			return errors.New("unexpected create query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(bindingID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		*destinations[3].(*[]byte) = platformIdentityBindingDocument(
			t, bindingID, providerID, tenantID, "corporate_login", 42, 1, now,
		)
		tx.keyDigest = append([]byte(nil), arguments[7].([]byte)...)
		tx.requestDigest = append([]byte(nil), arguments[8].([]byte)...)
		return nil
	}
	repository, beginCalls := platformIdentityBindingRepositoryHarness(
		t, tx, []uuid.UUID{tenantAuditID, platformAuditID},
	)

	result, err := repository.Create(context.Background(), params)
	if err != nil || result.BindingID() != bindingID || result.Version() != 1 || result.Replayed() {
		t.Fatalf("Create() = %#v, %v", result, err)
	}
	assertPlatformIdentityBindingTransaction(
		t, tx, beginCalls, "app.create_tenant_platform_auth_provider_binding_v1",
	)
	if len(tx.arguments[1]) != 17 {
		t.Fatalf("create argument count = %d", len(tx.arguments[1]))
	}
	wantPrefix := []any{
		toDatabaseUUID(session.SessionID), toDatabaseUUID(commandID), toDatabaseUUID(bindingID),
		toDatabaseUUID(providerID), toDatabaseUUID(tenantID), "corporate_login", int32(42),
	}
	if !reflect.DeepEqual(tx.arguments[1][:7], wantPrefix) ||
		!reflect.DeepEqual(tx.arguments[1][9], toDatabaseUUID(tenantAuditID)) ||
		!reflect.DeepEqual(tx.arguments[1][10], toDatabaseUUID(platformAuditID)) ||
		!reflect.DeepEqual(tx.arguments[1][11], toDatabaseUUID(event.RequestID)) ||
		!reflect.DeepEqual(tx.arguments[1][12], toDatabaseUUID(event.CorrelationID)) ||
		tx.arguments[1][13] != event.RemoteAddress || tx.arguments[1][14] != event.UserAgent ||
		tx.arguments[1][15] != session.AuthenticationMethod || tx.arguments[1][16] != params.Reason {
		t.Fatalf("create arguments = %#v", tx.arguments[1])
	}
	if !reflect.DeepEqual(tx.keyDigest, params.KeyDigest[:]) ||
		!reflect.DeepEqual(tx.requestDigest, params.RequestDigest[:]) {
		t.Fatalf("create digests were not bound exactly")
	}
}

func TestPlatformIdentityBindingCreateReplayKeepsInitialReceiptAndCurrentProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	replayedBindingID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 28, 15, 0, 0, 123_456_000, time.UTC)
	params := platformidentitybinding.CreateParams{
		SessionParams: session, CommandID: mustPostgresUUIDv7(t), BindingID: mustPostgresUUIDv7(t),
		ProviderID: providerID, TenantID: tenantID, LoginKey: "original_login", ProfilePriority: 10,
		Reason: "Approved explicit tenant admission", Event: event,
		ValidateResult: func(result platformidentitybinding.CreateResult) (platformidentitybinding.CreateResult, error) {
			return result, nil
		},
	}
	params.KeyDigest = sha256.Sum256([]byte("binding-replay-key"))
	params.RequestDigest = sha256.Sum256([]byte("binding-replay-request"))
	tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "app.create_tenant_platform_auth_provider_binding_v1") {
			return errors.New("unexpected replay query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(replayedBindingID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = true
		*destinations[3].(*[]byte) = platformIdentityBindingDocument(
			t, replayedBindingID, providerID, tenantID, "renamed_later", 91, 4, now,
		)
		return nil
	}
	repository, beginCalls := platformIdentityBindingRepositoryHarness(
		t, tx, []uuid.UUID{mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)},
	)

	result, err := repository.Create(context.Background(), params)
	binding := result.Binding()
	if err != nil || !result.Replayed() || result.BindingID() != replayedBindingID || result.Version() != 1 ||
		binding.Version != 4 || binding.LoginKey != "renamed_later" || binding.ProfilePriority != 91 {
		t.Fatalf("Create() replay result=%#v binding=%#v error=%v", result, binding, err)
	}
	assertPlatformIdentityBindingTransaction(
		t, tx, beginCalls, "app.create_tenant_platform_auth_provider_binding_v1",
	)
}

func TestPlatformIdentityBindingReadsDecodeOnlyClosedLifecycleProjection(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	firstID := mustPostgresUUIDv7(t)
	secondID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 28, 15, 0, 0, 123_456_000, time.UTC)

	listTx := &platformIdentityBindingTransaction{
		actorID: session.ActorID,
		documents: [][]byte{
			platformIdentityBindingDocument(t, firstID, providerID, tenantID, "first_login", 10, 1, now),
			platformIdentityBindingDocument(t, secondID, providerID, tenantID, "second_login", 20, 1, now),
		},
	}
	listRepository, listBeginCalls := platformIdentityBindingRepositoryHarness(t, listTx, nil)
	bindings, err := listRepository.List(context.Background(), platformidentitybinding.ListParams{
		SessionParams: session, ProviderID: providerID, Limit: 51,
	})
	if err != nil || len(bindings) != 2 || bindings[0].ID != firstID || bindings[0].Enabled ||
		bindings[0].Tenant.Name != "Acme Security" || bindings[0].Tenant.Version != 11 ||
		bindings[0].MappingRevision != 1 {
		t.Fatalf("List() = %#v, %v", bindings, err)
	}
	assertPlatformIdentityBindingTransaction(
		t, listTx, listBeginCalls, "app.list_tenant_platform_auth_provider_bindings_v1",
	)

	base := platformIdentityBindingDocument(t, firstID, providerID, tenantID, "first_login", 10, 1, now)
	ready := mutatePlatformIdentityBindingDocument(t, base, func(value map[string]any) {
		value["activationAvailable"] = true
	})
	readyTx := &platformIdentityBindingTransaction{actorID: session.ActorID}
	readyTx.row = platformIdentityBindingDocumentRow(
		"app.get_tenant_platform_auth_provider_binding_v1", ready,
	)
	readyRepository, _ := platformIdentityBindingRepositoryHarness(t, readyTx, nil)
	readyBinding, readyErr := readyRepository.Get(context.Background(), platformidentitybinding.GetParams{
		SessionParams: session, ProviderID: providerID, BindingID: firstID,
	})
	if readyErr != nil || !readyBinding.ActivationAvailable || readyBinding.Enabled {
		t.Fatalf("Get() ready projection = %#v, %v", readyBinding, readyErr)
	}

	epochID := mustPostgresUUIDv7(t)
	active := mutatePlatformIdentityBindingDocument(t, base, func(value map[string]any) {
		value["enabled"] = true
		value["jitMode"] = string(platformidentitybinding.JITModeCreate)
		value["noMatchPolicy"] = string(platformidentitybinding.NoMatchPolicyProviderAccessOnly)
		value["currentAccessEpochId"] = epochID
	})
	activeTx := &platformIdentityBindingTransaction{actorID: session.ActorID}
	activeTx.row = platformIdentityBindingDocumentRow(
		"app.get_tenant_platform_auth_provider_binding_v1", active,
	)
	activeRepository, _ := platformIdentityBindingRepositoryHarness(t, activeTx, nil)
	activeBinding, activeErr := activeRepository.Get(context.Background(), platformidentitybinding.GetParams{
		SessionParams: session, ProviderID: providerID, BindingID: firstID,
	})
	if activeErr != nil || !activeBinding.Enabled || activeBinding.CurrentAccessEpochID == nil ||
		*activeBinding.CurrentAccessEpochID != epochID {
		t.Fatalf("Get() active projection = %#v, %v", activeBinding, activeErr)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "enabled without epoch", mutate: func(value map[string]any) { value["enabled"] = true }},
		{name: "epoch while disabled", mutate: func(value map[string]any) { value["currentAccessEpochId"] = mustPostgresUUIDv7(t) }},
		{name: "activation available while enabled", mutate: func(value map[string]any) {
			value["enabled"] = true
			value["activationAvailable"] = true
			value["currentAccessEpochId"] = mustPostgresUUIDv7(t)
		}},
		{name: "unknown jit mode", mutate: func(value map[string]any) { value["jitMode"] = "grant_roles" }},
		{name: "unknown no-match policy", mutate: func(value map[string]any) { value["noMatchPolicy"] = "allow" }},
		{name: "wrong origin", mutate: func(value map[string]any) { value["origin"] = "tenant" }},
		{name: "epoch present", mutate: func(value map[string]any) { value["currentAccessEpochId"] = mustPostgresUUIDv7(t) }},
		{name: "unknown top field", mutate: func(value map[string]any) { value["secret"] = "leak" }},
		{name: "unknown tenant field", mutate: func(value map[string]any) {
			value["tenant"].(map[string]any)["timezone"] = "UTC"
		}},
		{name: "missing tenant version", mutate: func(value map[string]any) {
			delete(value["tenant"].(map[string]any), "version")
		}},
		{name: "missing revision", mutate: func(value map[string]any) { delete(value, "mappingRevision") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := mutatePlatformIdentityBindingDocument(t, base, test.mutate)
			tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
			tx.row = platformIdentityBindingDocumentRow(
				"app.get_tenant_platform_auth_provider_binding_v1", document,
			)
			repository, _ := platformIdentityBindingRepositoryHarness(t, tx, nil)
			_, getErr := repository.Get(context.Background(), platformidentitybinding.GetParams{
				SessionParams: session, ProviderID: providerID, BindingID: firstID,
			})
			if !errors.Is(getErr, authentication.ErrUnavailable) {
				t.Fatalf("Get() unsafe projection error = %v", getErr)
			}
		})
	}
}

func TestPlatformIdentityBindingMutationsValidateBeforeCommit(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	bindingID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 28, 15, 0, 0, 123_456_000, time.UTC)

	t.Run("update", func(t *testing.T) {
		document := platformIdentityBindingDocument(t, bindingID, providerID, tenantID, "renamed_login", 77, 2, now)
		tenantAuditID := mustPostgresUUIDv7(t)
		platformAuditID := mustPostgresUUIDv7(t)
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.update_tenant_platform_auth_provider_binding_v1") || len(destinations) != 2 {
				return errors.New("unexpected update query")
			}
			*destinations[0].(*int64) = 2
			*destinations[1].(*[]byte) = document
			return nil
		}
		repository, beginCalls := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{tenantAuditID, platformAuditID},
		)
		result, err := repository.Update(context.Background(), platformidentitybinding.UpdateParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID, ExpectedVersion: 1,
			ExpectedTenantVersion: 11,
			LoginKey:              "renamed_login", ProfilePriority: 77, Reason: "Approved update", Event: event,
			ValidateResult: func(result platformidentitybinding.UpdateResult) (platformidentitybinding.UpdateResult, error) {
				if result.Binding().LoginKey != "renamed_login" {
					return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
				}
				return result, nil
			},
		})
		if err != nil || result.Version() != 2 || result.Binding().ProfilePriority != 77 {
			t.Fatalf("Update() = %#v, %v", result, err)
		}
		assertPlatformIdentityBindingTransaction(
			t, tx, beginCalls, "app.update_tenant_platform_auth_provider_binding_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), toDatabaseUUID(bindingID),
			int64(1), int32(11), "renamed_login", int32(77),
			toDatabaseUUID(tenantAuditID), toDatabaseUUID(platformAuditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod, "Approved update",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("update CAS arguments = %#v", tx.arguments[1])
		}
	})

	t.Run("validator failure rolls back dual audit", func(t *testing.T) {
		document := platformIdentityBindingDocument(t, bindingID, providerID, tenantID, "renamed_login", 77, 2, now)
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(_ string, _ []any, destinations []any) error {
			*destinations[0].(*int64) = 2
			*destinations[1].(*[]byte) = document
			return nil
		}
		repository, _ := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)},
		)
		_, err := repository.Update(context.Background(), platformidentitybinding.UpdateParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID, ExpectedVersion: 1,
			ExpectedTenantVersion: 11,
			LoginKey:              "renamed_login", ProfilePriority: 77, Reason: "Approved update", Event: event,
			ValidateResult: func(platformidentitybinding.UpdateResult) (platformidentitybinding.UpdateResult, error) {
				return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
			},
		})
		if !errors.Is(err, authentication.ErrUnavailable) || tx.committed || !tx.rolledBack {
			t.Fatalf("Update() rollback error=%v commit=%t rollback=%t", err, tx.committed, tx.rolledBack)
		}
	})

	t.Run("archive exact next version", func(t *testing.T) {
		tenantAuditID := mustPostgresUUIDv7(t)
		platformAuditID := mustPostgresUUIDv7(t)
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.archive_tenant_platform_auth_provider_binding_v1") || len(destinations) != 2 {
				return errors.New("unexpected archive query")
			}
			*destinations[0].(*int64) = 3
			*destinations[1].(*int32) = 11
			return nil
		}
		repository, beginCalls := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{tenantAuditID, platformAuditID},
		)
		receipt, err := repository.Archive(context.Background(), platformidentitybinding.ArchiveParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID, ExpectedVersion: 2,
			ExpectedTenantVersion: 11,
			Reason:                "Approved archive", Event: event,
		})
		if err != nil || receipt.Version() != 3 || receipt.TenantVersion() != 11 {
			t.Fatalf("Archive() = %#v, %v", receipt, err)
		}
		assertPlatformIdentityBindingTransaction(
			t, tx, beginCalls, "app.archive_tenant_platform_auth_provider_binding_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), toDatabaseUUID(bindingID),
			int64(2), int32(11), toDatabaseUUID(tenantAuditID), toDatabaseUUID(platformAuditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod, "Approved archive",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("archive CAS arguments = %#v", tx.arguments[1])
		}
	})

	t.Run("archive stale tenant receipt rolls back dual audit", func(t *testing.T) {
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(_ string, _ []any, destinations []any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int32) = 12
			return nil
		}
		repository, _ := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)},
		)
		_, err := repository.Archive(context.Background(), platformidentitybinding.ArchiveParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID,
			ExpectedVersion: 2, ExpectedTenantVersion: 11,
			Reason: "Approved archive", Event: event,
		})
		if !errors.Is(err, authentication.ErrUnavailable) || tx.committed || !tx.rolledBack {
			t.Fatalf("Archive() stale tenant error=%v commit=%t rollback=%t", err, tx.committed, tx.rolledBack)
		}
	})
}

func TestPlatformIdentityBindingLifecycleBindsCompositeCASAndCorrelatedAudits(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	bindingID := mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 29, 2, 0, 0, 123_456_000, time.UTC)

	t.Run("activate", func(t *testing.T) {
		tenantAuditID := mustPostgresUUIDv7(t)
		platformAuditID := mustPostgresUUIDv7(t)
		epochID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityBindingDocument(
			t, platformIdentityBindingDocument(
				t, bindingID, providerID, tenantID, "corporate_login", 42, 2, now,
			),
			func(value map[string]any) {
				value["enabled"] = true
				value["jitMode"] = "create"
				value["noMatchPolicy"] = "provider_access_only"
				value["currentAccessEpochId"] = epochID
			},
		)
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.activate_tenant_platform_auth_provider_binding_v1") || len(destinations) != 2 {
				return errors.New("unexpected activate query")
			}
			*destinations[0].(*int64) = 2
			*destinations[1].(*[]byte) = document
			return nil
		}
		repository, beginCalls := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{tenantAuditID, platformAuditID},
		)
		result, err := repository.Activate(context.Background(), platformidentitybinding.ActivationParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID,
			ExpectedVersion: 1, ExpectedTenantVersion: 11,
			JITMode:       platformidentitybinding.JITModeCreate,
			NoMatchPolicy: platformidentitybinding.NoMatchPolicyProviderAccessOnly,
			Reason:        "Approved tenant admission", Event: event,
			ValidateResult: func(result platformidentitybinding.UpdateResult) (platformidentitybinding.UpdateResult, error) {
				if !result.Binding().Enabled || result.Binding().CurrentAccessEpochID == nil {
					return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
				}
				return result, nil
			},
		})
		if err != nil || result.Version() != 2 || !result.Binding().Enabled {
			t.Fatalf("Activate() = %#v, %v", result, err)
		}
		assertPlatformIdentityBindingTransaction(
			t, tx, beginCalls, "app.activate_tenant_platform_auth_provider_binding_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), toDatabaseUUID(bindingID),
			int64(1), int32(11), "create", "provider_access_only",
			toDatabaseUUID(tenantAuditID), toDatabaseUUID(platformAuditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod, "Approved tenant admission",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Activate() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})

	t.Run("deactivate", func(t *testing.T) {
		tenantAuditID := mustPostgresUUIDv7(t)
		platformAuditID := mustPostgresUUIDv7(t)
		document := mutatePlatformIdentityBindingDocument(
			t, platformIdentityBindingDocument(
				t, bindingID, providerID, tenantID, "corporate_login", 42, 3, now,
			),
			func(value map[string]any) { value["activationAvailable"] = true },
		)
		tx := &platformIdentityBindingTransaction{actorID: session.ActorID}
		tx.row = func(query string, _ []any, destinations []any) error {
			if !strings.Contains(query, "app.deactivate_tenant_platform_auth_provider_binding_v1") || len(destinations) != 2 {
				return errors.New("unexpected deactivate query")
			}
			*destinations[0].(*int64) = 3
			*destinations[1].(*[]byte) = document
			return nil
		}
		repository, beginCalls := platformIdentityBindingRepositoryHarness(
			t, tx, []uuid.UUID{tenantAuditID, platformAuditID},
		)
		result, err := repository.Deactivate(context.Background(), platformidentitybinding.DeactivationParams{
			SessionParams: session, ProviderID: providerID, BindingID: bindingID,
			ExpectedVersion: 2, ExpectedTenantVersion: 11,
			Reason: "Approved tenant admission withdrawal", Event: event,
			ValidateResult: func(result platformidentitybinding.UpdateResult) (platformidentitybinding.UpdateResult, error) {
				if result.Binding().Enabled || result.Binding().CurrentAccessEpochID != nil {
					return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
				}
				return result, nil
			},
		})
		if err != nil || result.Version() != 3 || result.Binding().Enabled {
			t.Fatalf("Deactivate() = %#v, %v", result, err)
		}
		assertPlatformIdentityBindingTransaction(
			t, tx, beginCalls, "app.deactivate_tenant_platform_auth_provider_binding_v1",
		)
		wantArguments := []any{
			toDatabaseUUID(session.SessionID), toDatabaseUUID(providerID), toDatabaseUUID(bindingID),
			int64(2), int32(11), toDatabaseUUID(tenantAuditID), toDatabaseUUID(platformAuditID),
			toDatabaseUUID(event.RequestID), toDatabaseUUID(event.CorrelationID),
			event.RemoteAddress, event.UserAgent, session.AuthenticationMethod,
			"Approved tenant admission withdrawal",
		}
		if !reflect.DeepEqual(tx.arguments[1], wantArguments) {
			t.Fatalf("Deactivate() arguments = %#v, want %#v", tx.arguments[1], wantArguments)
		}
	})
}

func TestPlatformIdentityBindingMutationsRejectInvalidTenantVersionBeforeTransaction(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityBindingAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	bindingID := mustPostgresUUIDv7(t)

	for _, tenantVersion := range []int64{0, 2_147_483_648} {
		tenantVersion := tenantVersion
		t.Run(strconv.FormatInt(tenantVersion, 10), func(t *testing.T) {
			beginCalls := 0
			repository := &PlatformIdentityBindingRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
					beginCalls++
					return nil, errors.New("unexpected transaction")
				},
				newID: uuid.NewV7,
			}
			_, updateErr := repository.Update(context.Background(), platformidentitybinding.UpdateParams{
				SessionParams: session, ProviderID: providerID, BindingID: bindingID,
				ExpectedVersion: 1, ExpectedTenantVersion: tenantVersion,
				LoginKey: "renamed_login", ProfilePriority: 77, Reason: "Approved update", Event: event,
				ValidateResult: func(result platformidentitybinding.UpdateResult) (platformidentitybinding.UpdateResult, error) {
					return result, nil
				},
			})
			_, archiveErr := repository.Archive(context.Background(), platformidentitybinding.ArchiveParams{
				SessionParams: session, ProviderID: providerID, BindingID: bindingID,
				ExpectedVersion: 1, ExpectedTenantVersion: tenantVersion,
				Reason: "Approved archive", Event: event,
			})
			if !errors.Is(updateErr, authentication.ErrInvalidInput) ||
				!errors.Is(archiveErr, authentication.ErrInvalidInput) || beginCalls != 0 {
				t.Fatalf(
					"tenant version %d errors update=%v archive=%v begin=%d",
					tenantVersion, updateErr, archiveErr, beginCalls,
				)
			}
		})
	}
}

func TestMapPlatformIdentityBindingDatabaseErrorIsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "forbidden", err: &pgconn.PgError{Code: "42501"}, want: authentication.ErrForbidden},
		{name: "not found", err: &pgconn.PgError{Code: "P0002"}, want: authentication.ErrNotFound},
		{name: "no rows", err: pgx.ErrNoRows, want: authentication.ErrNotFound},
		{name: "precondition", err: &pgconn.PgError{Code: "40001", Message: platformIdentityBindingRevisionConflictMessage}, want: platformidentitybinding.ErrPreconditionFailed},
		{name: "real serialization", err: &pgconn.PgError{Code: "40001", Message: "could not serialize access"}, want: authentication.ErrUnavailable},
		{name: "state conflict", err: &pgconn.PgError{Code: "55000"}, want: authentication.ErrConflict},
		{name: "idempotency conflict", err: &pgconn.PgError{Code: "23505"}, want: authentication.ErrConflict},
		{name: "invalid", err: &pgconn.PgError{Code: "22023"}, want: authentication.ErrInvalidInput},
		{name: "unknown", err: errors.New("private database detail"), want: authentication.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mapPlatformIdentityBindingDatabaseError(test.err); !errors.Is(got, test.want) {
				t.Fatalf("mapped error = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPlatformIdentityBindingCanceledContextDoesNotBegin(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityBindingAuthority(t)
	beginCalls := 0
	repository := &PlatformIdentityBindingRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			return nil, errors.New("unexpected transaction")
		},
		newID: uuid.NewV7,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := repository.List(ctx, platformidentitybinding.ListParams{
		SessionParams: session, ProviderID: mustPostgresUUIDv7(t), Limit: 1,
	})
	if !errors.Is(err, context.Canceled) || beginCalls != 0 {
		t.Fatalf("List() error=%v begin calls=%d", err, beginCalls)
	}
	_, err = repository.List(nil, platformidentitybinding.ListParams{
		SessionParams: session, ProviderID: mustPostgresUUIDv7(t), Limit: 1,
	})
	if !errors.Is(err, authentication.ErrUnavailable) || beginCalls != 0 {
		t.Fatalf("List(nil) error=%v begin calls=%d", err, beginCalls)
	}
}

type platformIdentityBindingTransaction struct {
	recordingTransaction
	actorID       uuid.UUID
	row           func(string, []any, []any) error
	documents     [][]byte
	queries       []string
	arguments     [][]any
	keyDigest     []byte
	requestDigest []byte
}

func (tx *platformIdentityBindingTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if strings.Contains(query, "set_config('app.user_id'") {
		return platformIdentityBindingRow(func(destinations ...any) error {
			if len(destinations) != 1 {
				return errors.New("unexpected context result cardinality")
			}
			*destinations[0].(*string) = tx.actorID.String()
			return nil
		})
	}
	return platformIdentityBindingRow(func(destinations ...any) error {
		if tx.row == nil {
			return errors.New("unexpected binding QueryRow")
		}
		return tx.row(query, arguments, destinations)
	})
}

func (tx *platformIdentityBindingTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (pgx.Rows, error) {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if !strings.Contains(query, "app.list_tenant_platform_auth_provider_bindings_v1") {
		return nil, errors.New("unexpected binding Query")
	}
	return &platformIdentityBindingRows{documents: tx.documents}, nil
}

type platformIdentityBindingRow func(...any) error

func (row platformIdentityBindingRow) Scan(destinations ...any) error { return row(destinations...) }

type platformIdentityBindingRows struct {
	documents [][]byte
	index     int
}

func (*platformIdentityBindingRows) Close()                                       {}
func (*platformIdentityBindingRows) Err() error                                   { return nil }
func (*platformIdentityBindingRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (*platformIdentityBindingRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *platformIdentityBindingRows) Next() bool {
	if rows.index >= len(rows.documents) {
		return false
	}
	rows.index++
	return true
}
func (rows *platformIdentityBindingRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.documents) || len(destinations) != 1 {
		return errors.New("invalid binding row scan")
	}
	value, ok := destinations[0].(*[]byte)
	if !ok {
		return errors.New("invalid binding destination")
	}
	*value = append((*value)[:0], rows.documents[rows.index-1]...)
	return nil
}
func (rows *platformIdentityBindingRows) Values() ([]any, error) {
	if rows.index == 0 || rows.index > len(rows.documents) {
		return nil, errors.New("binding row is not current")
	}
	return []any{rows.documents[rows.index-1]}, nil
}
func (*platformIdentityBindingRows) RawValues() [][]byte { return nil }
func (*platformIdentityBindingRows) Conn() *pgx.Conn     { return nil }

func platformIdentityBindingRepositoryHarness(
	t testing.TB,
	tx *platformIdentityBindingTransaction,
	ids []uuid.UUID,
) (*PlatformIdentityBindingRepository, *int) {
	t.Helper()
	beginCalls := 0
	nextID := 0
	repository := &PlatformIdentityBindingRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			if options.IsoLevel != pgx.ReadCommitted {
				t.Fatalf("transaction isolation = %q", options.IsoLevel)
			}
			return tx, nil
		},
		newID: func() (uuid.UUID, error) {
			if nextID >= len(ids) {
				return uuid.Nil, errors.New("unexpected ID generation")
			}
			id := ids[nextID]
			nextID++
			return id, nil
		},
	}
	return repository, &beginCalls
}

func assertPlatformIdentityBindingTransaction(
	t testing.TB,
	tx *platformIdentityBindingTransaction,
	beginCalls *int,
	abi string,
) {
	t.Helper()
	if *beginCalls != 1 || !tx.committed || !tx.rolledBack {
		t.Fatalf("transaction state = begin:%d commit:%t rollback:%t", *beginCalls, tx.committed, tx.rolledBack)
	}
	if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "set_config('app.user_id'") ||
		!strings.Contains(tx.queries[1], abi) {
		t.Fatalf("queries = %#v", tx.queries)
	}
	if len(tx.arguments[0]) != 1 || !reflect.DeepEqual(tx.arguments[0][0], toDatabaseUUID(tx.actorID)) {
		t.Fatalf("actor context arguments = %#v", tx.arguments[0])
	}
}

func platformIdentityBindingAuthority(
	t testing.TB,
) (platformidentitybinding.SessionParams, authentication.EventContext) {
	t.Helper()
	return platformidentitybinding.SessionParams{
			ActorID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t), AuthenticationMethod: "passkey",
		}, authentication.EventContext{
			RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("198.51.100.67"), UserAgent: "platform-binding-adapter-test/1",
		}
}

func platformIdentityBindingDocument(
	t testing.TB,
	bindingID, providerID, tenantID uuid.UUID,
	loginKey string,
	priority int,
	version int64,
	now time.Time,
) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"id": bindingID, "providerId": providerID,
		"tenant": map[string]any{
			"id": tenantID, "slug": "acme-security", "name": "Acme Security", "status": "active",
			"version": int64(11),
		},
		"origin": "platform", "loginKey": loginKey, "profilePriority": priority,
		"jitMode":       string(platformidentitybinding.JITModeDisabled),
		"noMatchPolicy": string(platformidentitybinding.NoMatchPolicyDeny),
		"enabled":       false, "activationAvailable": false, "authRevision": int64(1),
		"mappingRevision": int64(1), "currentAccessEpochId": nil, "archivedAt": nil,
		"version": version, "createdAt": now, "updatedAt": now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func mutatePlatformIdentityBindingDocument(
	t testing.TB,
	document []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func platformIdentityBindingDocumentRow(
	abi string,
	document []byte,
) func(string, []any, []any) error {
	return func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, abi) || len(destinations) != 1 {
			return errors.New("unexpected binding document query")
		}
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
}
