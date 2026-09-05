package mfaauth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type deviceRepositoryStub struct {
	items        []Device
	renameResult DeviceMutationResult
	revokeResult DeviceMutationResult
	err          error
	listInput    DeviceListInput
	mutation     DeviceMutation
}

func (repository *deviceRepositoryStub) ListDevices(
	_ context.Context,
	_ DeviceAuthority,
	input DeviceListInput,
) ([]Device, error) {
	repository.listInput = input
	return append([]Device(nil), repository.items...), repository.err
}

func (repository *deviceRepositoryStub) RenamePasskey(
	_ context.Context,
	mutation DeviceMutation,
) (DeviceMutationResult, error) {
	repository.mutation = mutation
	return repository.renameResult, repository.err
}

func (repository *deviceRepositoryStub) RevokeDevice(
	_ context.Context,
	mutation DeviceMutation,
) (DeviceMutationResult, error) {
	repository.mutation = mutation
	return repository.revokeResult, repository.err
}

func TestDeviceManagerListsBoundedCanonicalPage(t *testing.T) {
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	items := []Device{
		mustPasskeyDevice(t, deviceTestID(10), 2, "Office key", now),
		mustPasskeyDevice(t, deviceTestID(9), 1, "Phone", now.Add(-time.Minute)),
		mustTOTPDevice(t, deviceTestID(8), 1, now.Add(-2*time.Minute), nil),
	}
	repository := &deviceRepositoryStub{items: items}
	manager, err := NewDeviceManager(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	page, err := manager.List(context.Background(), deviceAuthority(), DeviceListInput{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil ||
		page.NextCursor.ID != items[1].ID() || page.NextCursor.Kind != items[1].Kind() {
		t.Fatalf("page = %#v, %v", page, err)
	}
	if repository.listInput.Limit != 3 || len(page.Items) != 2 ||
		!slices.EqualFunc(page.Items, items[:2], func(left, right Device) bool { return left.ID() == right.ID() }) {
		t.Fatalf("repository limit/items = %d/%#v", repository.listInput.Limit, page.Items)
	}
}

func TestDeviceManagerRejectsHostileRepositoryProjection(t *testing.T) {
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	newer := mustTOTPDevice(t, deviceTestID(4), 1, now, nil)
	older := mustTOTPDevice(t, deviceTestID(5), 1, now.Add(time.Minute), nil)
	manager, err := NewDeviceManager(&deviceRepositoryStub{items: []Device{newer, older}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.List(context.Background(), deviceAuthority(), DeviceListInput{Limit: 2}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestDeviceManagerRenameAndRevokeRequireExactProjection(t *testing.T) {
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	deviceID := deviceTestID(7)
	renamed := mustPasskeyDevice(t, deviceID, 3, "Travel key", now)
	revokedAt := now
	revoked := mustTOTPDevice(t, deviceID, 4, now.Add(-time.Hour), &revokedAt)
	repository := &deviceRepositoryStub{
		renameResult: DeviceMutationResult{Device: renamed},
		revokeResult: DeviceMutationResult{Device: revoked, CurrentSessionRevoked: true},
	}
	manager, err := NewDeviceManager(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if result, renameErr := manager.RenamePasskey(context.Background(), deviceAuthority(), deviceID, " Travel key ", 2); renameErr != nil || result.Device.DisplayName() != "Travel key" || repository.mutation.DisplayName != "Travel key" {
		t.Fatalf("rename = %#v, %v, mutation=%#v", result, renameErr, repository.mutation)
	}
	if result, revokeErr := manager.Revoke(context.Background(), deviceAuthority(), deviceID, DeviceTOTP, 3); revokeErr != nil || !result.CurrentSessionRevoked || repository.mutation.Kind != DeviceTOTP {
		t.Fatalf("revoke = %#v, %v, mutation=%#v", result, revokeErr, repository.mutation)
	}
}

func TestDeviceConstructorRejectsSensitiveOrAmbiguousShapes(t *testing.T) {
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	base := DeviceProjection{
		ID: deviceTestID(3), Kind: DevicePasskey, Status: DeviceActive,
		DisplayName: "Key", Version: 1, Discoverable: true,
		Transports: []webauthn.CredentialTransport{webauthn.TransportInternal}, CreatedAt: now,
	}
	tests := map[string]func(*DeviceProjection){
		"HTML name":           func(value *DeviceProjection) { value.DisplayName = "<secret>" },
		"duplicate transport": func(value *DeviceProjection) { value.Transports = append(value.Transports, webauthn.TransportInternal) },
		"invalid backup":      func(value *DeviceProjection) { value.BackedUp = true },
		"TOTP passkey fields": func(value *DeviceProjection) { value.Kind = DeviceTOTP },
		"unknown status":      func(value *DeviceProjection) { value.Status = "pending" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Transports = append([]webauthn.CredentialTransport(nil), base.Transports...)
			mutate(&value)
			if _, err := NewDevice(value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDeviceFormattingRedactsIdentityAndName(t *testing.T) {
	device := mustPasskeyDevice(t, deviceTestID(3), 1, "Sensitive key name", time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC))
	if got := device.String(); got == "" || got == uuid.UUID(device.ID()).String() || got == device.DisplayName() {
		t.Fatalf("unsafe formatting = %q", got)
	}
}

func FuzzDeviceDisplayName(f *testing.F) {
	for _, seed := range []string{"Key", " <x> ", "phone\x00key", string(make([]byte, 130))} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, displayName string) {
		_, _ = NewDevice(DeviceProjection{
			ID: deviceTestID(3), Kind: DevicePasskey, Status: DeviceActive,
			DisplayName: displayName, Version: 1,
			Transports: []webauthn.CredentialTransport{},
			CreatedAt:  time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC),
		})
	})
}

func mustPasskeyDevice(t *testing.T, id identity.EntityID, version uint64, name string, created time.Time) Device {
	t.Helper()
	device, err := NewDevice(DeviceProjection{
		ID: id, Kind: DevicePasskey, Status: DeviceActive, DisplayName: name,
		Version: version, Discoverable: true, BackupEligible: true, BackedUp: true,
		Transports: []webauthn.CredentialTransport{webauthn.TransportInternal}, CreatedAt: created,
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func mustTOTPDevice(t *testing.T, id identity.EntityID, version uint64, created time.Time, revokedAt *time.Time) Device {
	t.Helper()
	status := DeviceActive
	if revokedAt != nil {
		status = DeviceRevoked
	}
	device, err := NewDevice(DeviceProjection{
		ID: id, Kind: DeviceTOTP, Status: status, Version: version,
		CreatedAt: created, RevokedAt: revokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func deviceAuthority() DeviceAuthority {
	return DeviceAuthority{SessionID: deviceTestID(1), TenantID: deviceTestID(2), UserID: deviceTestID(3)}
}

func deviceTestID(tail byte) identity.EntityID {
	identifier := uuid.Must(uuid.NewV7())
	identifier[15] = tail
	return identity.EntityID(identifier)
}
