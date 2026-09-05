package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestFederatedAuthRepositoryRevokesSAMLSessionWithExactMaterialIdentity(t *testing.T) {
	command := postgresSAMLLogoutCommandFixture()
	provider := postgresSAMLLogoutProviderWire(t, command)
	materialID := postgresFederatedID(210)
	revokedAt := time.Date(2026, time.August, 26, 16, 30, 0, 123000, time.UTC)
	var retainedPayload []byte
	tx := &samlLogoutTransactionStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query == installSAMLLogoutActorContextSQL {
			if len(arguments) != 2 || arguments[0] != entityIDWire(command.TenantID) ||
				arguments[1] != entityIDWire(command.AuthenticatedUserID) {
				t.Fatalf("context args = %#v", arguments)
			}
			return samlLogoutRowFunc(func(destinations ...any) error {
				*destinations[0].(*string) = arguments[0].(string)
				*destinations[1].(*string) = arguments[1].(string)
				return nil
			})
		}
		if query != revokeLocalSAMLSessionSQL || len(arguments) != 1 {
			t.Fatalf("query = %q args = %d", query, len(arguments))
		}
		retainedPayload = arguments[0].([]byte)
		var wire samlLogoutCommandWire
		if err := json.Unmarshal(retainedPayload, &wire); err != nil {
			t.Fatalf("logout command wire: %v", err)
		}
		requestDocument, err := json.Marshal(samlLogoutRequestWire{
			OperationRunID: wire.OperationRunID, TenantID: wire.TenantID,
			AuthenticatedUserID: wire.AuthenticatedUserID, SessionID: wire.SessionID,
			ExpectedVersion: wire.ExpectedVersion,
			RequestUpstream: wire.RequestUpstream,
		})
		if err != nil {
			t.Fatal(err)
		}
		requestDigest := sha256.Sum256(requestDocument)
		clear(requestDocument)
		if wire.OperationRunID != entityIDWire(command.OperationRunID) ||
			wire.TenantID != entityIDWire(command.TenantID) ||
			wire.AuthenticatedUserID != entityIDWire(command.AuthenticatedUserID) ||
			wire.SessionID != entityIDWire(command.SessionID) ||
			wire.ExpectedVersion != command.ExpectedVersion ||
			wire.RequestUpstream != command.RequestUpstream ||
			!bytes.Equal(wire.RequestDigest, requestDigest[:]) {
			t.Fatalf("logout command drifted: %#v", wire)
		}
		response := samlLogoutSnapshotWire{
			OperationRunID: wire.OperationRunID, TenantID: wire.TenantID,
			AuthenticatedUserID: wire.AuthenticatedUserID, SessionID: wire.SessionID,
			PreviousVersion: wire.ExpectedVersion,
			Provider:        provider, BindingID: provider.BindingID,
			MaterialID: entityIDWire(materialID), RevokedAt: revokedAt,
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return federatedAuthJSONRow(encoded)
	}}
	repository := &FederatedAuthRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			if options.IsoLevel != pgx.ReadCommitted || options.AccessMode != pgx.ReadWrite {
				t.Fatalf("transaction options = %#v", options)
			}
			return tx, nil
		},
	}

	snapshot, err := repository.RevokeLocalSAMLSession(context.Background(), command)
	if err != nil || snapshot.OperationRunID != command.OperationRunID ||
		snapshot.TenantID != command.TenantID || snapshot.AuthenticatedUserID != command.AuthenticatedUserID ||
		snapshot.SessionID != command.SessionID ||
		snapshot.PreviousVersion != command.ExpectedVersion ||
		snapshot.MaterialID != materialID || !snapshot.RevokedAt.Equal(revokedAt) ||
		snapshot.Configuration.Authentication.Provider.ProviderID != (identity.EntityID{}) ||
		snapshot.ProtectedMaterial.KeyVersion != 0 || len(snapshot.ProtectedMaterial.Ciphertext) != 0 {
		t.Fatalf("RevokeLocalSAMLSession() = %s, %v", snapshot, err)
	}
	if !allZeroFederatedBytes(retainedPayload) {
		t.Fatal("logout query retained command or digest bytes")
	}
	if !tx.committed {
		t.Fatal("validated logout snapshot was not committed")
	}
}

func TestSAMLLogoutSnapshotOptionalUpstreamMaterialFailsClosed(t *testing.T) {
	command := postgresSAMLLogoutCommandFixture()
	provider := postgresSAMLLogoutProviderWire(t, command)
	valid := samlLogoutSnapshotWire{
		OperationRunID:      entityIDWire(command.OperationRunID),
		TenantID:            entityIDWire(command.TenantID),
		AuthenticatedUserID: entityIDWire(command.AuthenticatedUserID),
		SessionID:           entityIDWire(command.SessionID),
		PreviousVersion:     command.ExpectedVersion,
		Provider:            provider,
		BindingID:           provider.BindingID,
		MaterialID:          entityIDWire(postgresFederatedID(205)),
		RevokedAt:           time.Date(2026, time.August, 26, 16, 31, 0, 0, time.UTC),
	}
	invalidConfiguration := postgresSAMLConfigurationRecordWire(t, postgresSAMLCreateFixture().Current.Pins)
	valid.Configuration = &invalidConfiguration
	invalidMaterial := samlLogoutProtectedMaterialWire{KeyVersion: 9, Ciphertext: []byte("short")}
	valid.ProtectedMaterial = &invalidMaterial

	snapshot, err := samlLogoutSnapshotFromWire(valid, command)
	if err != nil || snapshot.Configuration.Authentication.Provider.ProviderID != (identity.EntityID{}) ||
		snapshot.ProtectedMaterial.KeyVersion != 0 || len(snapshot.ProtectedMaterial.Ciphertext) != 0 {
		t.Fatalf("optional upstream fallback = %s, %v", snapshot, err)
	}
}

func TestSAMLLogoutWireRejectsIdentityVersionAndCancellationDrift(t *testing.T) {
	command := postgresSAMLLogoutCommandFixture()
	provider := postgresSAMLLogoutProviderWire(t, command)
	valid := samlLogoutSnapshotWire{
		OperationRunID:      entityIDWire(command.OperationRunID),
		TenantID:            entityIDWire(command.TenantID),
		AuthenticatedUserID: entityIDWire(command.AuthenticatedUserID),
		SessionID:           entityIDWire(command.SessionID),
		PreviousVersion:     command.ExpectedVersion,
		Provider:            provider,
		BindingID:           provider.BindingID,
		MaterialID:          entityIDWire(postgresFederatedID(206)),
		RevokedAt:           time.Date(2026, time.August, 26, 16, 32, 0, 0, time.UTC),
	}
	for name, mutate := range map[string]func(*samlLogoutSnapshotWire){
		"tenant": func(value *samlLogoutSnapshotWire) {
			value.TenantID = entityIDWire(postgresFederatedID(207))
		},
		"session": func(value *samlLogoutSnapshotWire) {
			value.SessionID = entityIDWire(postgresFederatedID(208))
		},
		"authenticated user": func(value *samlLogoutSnapshotWire) {
			value.AuthenticatedUserID = entityIDWire(postgresFederatedID(218))
		},
		"version": func(value *samlLogoutSnapshotWire) { value.PreviousVersion++ },
		"material aliases operation": func(value *samlLogoutSnapshotWire) {
			value.MaterialID = value.OperationRunID
		},
		"material aliases user": func(value *samlLogoutSnapshotWire) {
			value.MaterialID = value.AuthenticatedUserID
		},
		"provider tenant": func(value *samlLogoutSnapshotWire) {
			value.Provider.TenantID = entityIDWire(postgresFederatedID(209))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := samlLogoutSnapshotFromWire(candidate, command); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}

	called := false
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		called = true
		return nil, errors.New("unexpected begin")
	}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.RevokeLocalSAMLSession(cancelled, command); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("cancelled logout error = %v", err)
	}
	if called {
		t.Fatal("cancelled logout reached PostgreSQL")
	}
}

func TestFederatedAuthRepositoryRollsBackSAMLLogoutOnActorContextOrResponseDrift(t *testing.T) {
	command := postgresSAMLLogoutCommandFixture()
	for name, configure := range map[string]func(*samlLogoutTransactionStub){
		"context echo": func(tx *samlLogoutTransactionStub) {
			tx.query = func(_ context.Context, query string, _ ...any) pgx.Row {
				if query != installSAMLLogoutActorContextSQL {
					t.Fatalf("unexpected query after mismatched context: %q", query)
				}
				return samlLogoutRowFunc(func(destinations ...any) error {
					*destinations[0].(*string) = entityIDWire(command.TenantID)
					*destinations[1].(*string) = entityIDWire(postgresFederatedID(219))
					return nil
				})
			}
		},
		"response user": func(tx *samlLogoutTransactionStub) {
			tx.query = func(_ context.Context, query string, arguments ...any) pgx.Row {
				if query == installSAMLLogoutActorContextSQL {
					return samlLogoutRowFunc(func(destinations ...any) error {
						*destinations[0].(*string) = arguments[0].(string)
						*destinations[1].(*string) = arguments[1].(string)
						return nil
					})
				}
				provider := postgresSAMLLogoutProviderWire(t, command)
				response, err := json.Marshal(samlLogoutSnapshotWire{
					OperationRunID:      entityIDWire(command.OperationRunID),
					TenantID:            entityIDWire(command.TenantID),
					AuthenticatedUserID: entityIDWire(postgresFederatedID(220)),
					SessionID:           entityIDWire(command.SessionID),
					PreviousVersion:     command.ExpectedVersion,
					Provider:            provider,
					BindingID:           provider.BindingID,
					MaterialID:          entityIDWire(postgresFederatedID(221)),
					RevokedAt: time.Date(
						2026, time.August, 26, 16, 33, 0, 0, time.UTC,
					),
				})
				if err != nil {
					t.Fatal(err)
				}
				return federatedAuthJSONRow(response)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &samlLogoutTransactionStub{}
			configure(tx)
			repository := &FederatedAuthRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
			}
			if _, err := repository.RevokeLocalSAMLSession(context.Background(), command); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("RevokeLocalSAMLSession() error = %v", err)
			}
			if tx.committed || !tx.rolledBack {
				t.Fatalf("committed=%t rolledBack=%t", tx.committed, tx.rolledBack)
			}
		})
	}
}

func TestFederatedProviderBindingWireUsesClosedTextScopes(t *testing.T) {
	bindingID := postgresFederatedID(213)
	for name, provider := range map[string]identity.ProviderContext{
		federatedTenantProviderScopeWire: {
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(211),
			ProviderID: postgresFederatedID(212),
		},
		federatedPlatformProviderScopeWire: {
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(214),
		},
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := providerBindingToWire(provider, bindingID, false)
			if err != nil || wire.Scope != name {
				t.Fatalf("providerBindingToWire() = %#v, %v", wire, err)
			}
			gotProvider, gotBinding, err := providerBindingFromWire(wire, false)
			if err != nil || gotProvider != provider || gotBinding != bindingID {
				t.Fatalf("providerBindingFromWire() = %#v, %x, %v", gotProvider, gotBinding, err)
			}
		})
	}

	valid := federatedProviderBindingWire{
		TenantID:   entityIDWire(postgresFederatedID(215)),
		ProviderID: entityIDWire(postgresFederatedID(216)),
		BindingID:  entityIDWire(postgresFederatedID(217)),
	}
	for _, hostileScope := range []string{"\x01", "\x02", "tenant-v2", ""} {
		candidate := valid
		candidate.Scope = hostileScope
		if _, _, err := providerBindingFromWire(candidate, false); !errors.Is(err, errFederatedAuthPersistence) {
			t.Fatalf("hostile provider scope %q accepted: %v", hostileScope, err)
		}
	}
}

func postgresSAMLLogoutCommandFixture() federatedauth.SAMLLogoutCommand {
	return federatedauth.SAMLLogoutCommand{
		OperationRunID:      postgresFederatedID(200),
		TenantID:            postgresFederatedID(201),
		AuthenticatedUserID: postgresFederatedID(222),
		SessionID:           postgresFederatedID(202),
		ExpectedVersion:     7,
		RequestUpstream:     true,
	}
}

func postgresSAMLLogoutProviderWire(
	t *testing.T,
	command federatedauth.SAMLLogoutCommand,
) federatedProviderBindingWire {
	t.Helper()
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: command.TenantID,
		ProviderID: postgresFederatedID(203),
	}
	return mustProviderBindingWire(t, provider, postgresFederatedID(204), false)
}

type samlLogoutRowFunc func(...any) error

func (row samlLogoutRowFunc) Scan(destinations ...any) error { return row(destinations...) }

type samlLogoutTransactionStub struct {
	recordingTransaction
	query func(context.Context, string, ...any) pgx.Row
}

func (tx *samlLogoutTransactionStub) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	if tx.query == nil {
		panic("unexpected SAML logout query")
	}
	return tx.query(ctx, query, arguments...)
}
