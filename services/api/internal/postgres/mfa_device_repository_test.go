package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

func TestMFADeviceRepositoryReturnsOnlySafeProjection(t *testing.T) {
	t.Parallel()
	repository := &MFADeviceRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != listMFADevicesSQL || len(arguments) != 5 || arguments[1] != nil || arguments[2] != nil || arguments[3] != 3 {
			t.Fatalf("query/arguments = %q/%#v", query, arguments)
		}
		return mfaRowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = []byte(`{"items":[{"id":"018fd7a2-c814-7f31-8f09-111111111111","kind":"passkey","status":"active","displayName":"Laptop","version":2,"discoverable":true,"backupEligible":true,"backedUp":false,"transports":["internal"],"createdAt":"2026-08-26T08:00:00Z","lastUsedAt":null,"revokedAt":null}]}`)
			return nil
		})
	}}}
	items, err := repository.ListDevices(context.Background(), mfaDeviceAuthorityFixture(), mfaauth.DeviceListInput{Limit: 3})
	if err != nil || len(items) != 1 || items[0].DisplayName() != "Laptop" || items[0].Version() != 2 {
		t.Fatalf("items = %#v, %v", items, err)
	}
}

func TestMFADeviceMutationPayloadContainsNoCredentialMaterial(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	deviceID := mfaPersistenceID(5)
	repository := &MFADeviceRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != renameMFADeviceSQL || len(arguments) != 1 {
			t.Fatalf("query = %q", query)
		}
		payload := arguments[0].([]byte)
		for _, forbidden := range [][]byte{[]byte("credentialId"), []byte("publicKey"), []byte("secret"), []byte("aaguid")} {
			if bytes.Contains(bytes.ToLower(payload), bytes.ToLower(forbidden)) {
				t.Fatalf("payload contains %q: %s", forbidden, payload)
			}
		}
		return mfaRowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = []byte(`{"device":{"id":"` + entityIDWire(deviceID) + `","kind":"passkey","status":"active","displayName":"Renamed","version":2,"discoverable":true,"backupEligible":false,"backedUp":false,"transports":[],"createdAt":"2026-08-26T07:00:00Z","lastUsedAt":null,"revokedAt":null},"currentSessionRevoked":false}`)
			return nil
		})
	}}}
	result, err := repository.RenamePasskey(context.Background(), mfaauth.DeviceMutation{
		Authority: mfaDeviceAuthorityFixture(), DeviceID: deviceID, Kind: mfaauth.DevicePasskey,
		DisplayName: "Renamed", ExpectedVersion: 1, OccurredAt: now,
	})
	if err != nil || result.Device.Version() != 2 || result.CurrentSessionRevoked {
		t.Fatalf("result = %#v, %v", result, err)
	}
}

func TestMFADeviceRepositoryMapsClosedDatabaseOutcomes(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]error{
		"22023": mfaauth.ErrInvalidInput,
		"42501": mfaauth.ErrDenied,
		"P0002": mfaauth.ErrNotFound,
		"40001": mfaauth.ErrPrecondition,
		"23505": mfaauth.ErrConflict,
		"XX000": errMFAPersistence,
	} {
		if got := mapMFADeviceDatabaseError(&pgconn.PgError{Code: code}); !errors.Is(got, want) {
			t.Fatalf("code %s = %v, want %v", code, got, want)
		}
	}
}

func TestMFADeviceRepositoryRejectsUnknownProjectionFields(t *testing.T) {
	t.Parallel()
	repository := &MFADeviceRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		_ string,
		_ ...any,
	) pgx.Row {
		return mfaRowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = []byte(`{"items":[],"credentialId":"leak"}`)
			return nil
		})
	}}}
	if _, err := repository.ListDevices(context.Background(), mfaDeviceAuthorityFixture(), mfaauth.DeviceListInput{Limit: 2}); !errors.Is(err, errMFAPersistence) {
		t.Fatalf("error = %v", err)
	}
}

func mfaDeviceAuthorityFixture() mfaauth.DeviceAuthority {
	return mfaauth.DeviceAuthority{
		SessionID: mfaPersistenceID(1), TenantID: mfaPersistenceID(2), UserID: mfaPersistenceID(3),
	}
}
