package mfaauth

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

const (
	defaultDevicePageSize  = 25
	maximumDevicePageSize  = 100
	maximumDeviceNameRunes = 120
)

type DeviceKind string

const (
	DeviceTOTP    DeviceKind = "totp"
	DevicePasskey DeviceKind = "passkey"
)

type DeviceStatus string

const (
	DeviceActive         DeviceStatus = "active"
	DeviceRevoked        DeviceStatus = "revoked"
	DeviceCloneSuspected DeviceStatus = "clone_suspected"
)

// Device is a customer-safe projection. WebAuthn credential IDs, public keys,
// AAGUIDs, counters, TOTP envelopes, and key versions never cross this boundary.
type Device struct {
	id             identity.EntityID
	kind           DeviceKind
	status         DeviceStatus
	displayName    string
	version        uint64
	discoverable   bool
	backupEligible bool
	backedUp       bool
	transports     []webauthn.CredentialTransport
	createdAt      time.Time
	lastUsedAt     *time.Time
	revokedAt      *time.Time
}

type DeviceProjection struct {
	ID             identity.EntityID
	Kind           DeviceKind
	Status         DeviceStatus
	DisplayName    string
	Version        uint64
	Discoverable   bool
	BackupEligible bool
	BackedUp       bool
	Transports     []webauthn.CredentialTransport
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
}

func NewDevice(projection DeviceProjection) (Device, error) {
	projection.CreatedAt = projection.CreatedAt.UTC().Truncate(time.Microsecond)
	projection.LastUsedAt = canonicalOptionalInstant(projection.LastUsedAt)
	projection.RevokedAt = canonicalOptionalInstant(projection.RevokedAt)
	projection.DisplayName = strings.TrimSpace(projection.DisplayName)
	if !validEntityID(projection.ID) || !validStoredVersion(projection.Version) || !validInstant(projection.CreatedAt) ||
		!validDeviceLifecycle(projection.Status, projection.CreatedAt, projection.RevokedAt) {
		return Device{}, ErrInvalidInput
	}
	if projection.LastUsedAt != nil && projection.LastUsedAt.Before(projection.CreatedAt) {
		return Device{}, ErrInvalidInput
	}
	switch projection.Kind {
	case DeviceTOTP:
		if projection.DisplayName != "" || projection.Discoverable || projection.BackupEligible || projection.BackedUp ||
			len(projection.Transports) != 0 || projection.LastUsedAt != nil {
			return Device{}, ErrInvalidInput
		}
	case DevicePasskey:
		if !validDisplayName(projection.DisplayName) || projection.BackedUp && !projection.BackupEligible ||
			!validTransports(projection.Transports) {
			return Device{}, ErrInvalidInput
		}
	default:
		return Device{}, ErrInvalidInput
	}
	return Device{
		id: projection.ID, kind: projection.Kind, status: projection.Status,
		displayName: projection.DisplayName, version: projection.Version,
		discoverable: projection.Discoverable, backupEligible: projection.BackupEligible,
		backedUp: projection.BackedUp, transports: append([]webauthn.CredentialTransport(nil), projection.Transports...),
		createdAt: projection.CreatedAt, lastUsedAt: cloneInstant(projection.LastUsedAt),
		revokedAt: cloneInstant(projection.RevokedAt),
	}, nil
}

func (device Device) ID() identity.EntityID  { return device.id }
func (device Device) Kind() DeviceKind       { return device.kind }
func (device Device) Status() DeviceStatus   { return device.status }
func (device Device) DisplayName() string    { return device.displayName }
func (device Device) Version() uint64        { return device.version }
func (device Device) Discoverable() bool     { return device.discoverable }
func (device Device) BackupEligible() bool   { return device.backupEligible }
func (device Device) BackedUp() bool         { return device.backedUp }
func (device Device) CreatedAt() time.Time   { return device.createdAt }
func (device Device) LastUsedAt() *time.Time { return cloneInstant(device.lastUsedAt) }
func (device Device) RevokedAt() *time.Time  { return cloneInstant(device.revokedAt) }
func (device Device) Transports() []webauthn.CredentialTransport {
	return append([]webauthn.CredentialTransport(nil), device.transports...)
}
func (device Device) String() string {
	return "mfaauth.Device{kind:" + string(device.kind) + ",status:" + string(device.status) + ",id:[REDACTED]}"
}
func (device Device) GoString() string { return device.String() }

type DeviceAuthority struct {
	SessionID identity.EntityID
	TenantID  identity.EntityID
	UserID    identity.EntityID
}

type DeviceCursor struct {
	Kind DeviceKind
	ID   identity.EntityID
}

type DeviceListInput struct {
	After          *DeviceCursor
	Limit          int
	IncludeRevoked bool
}

type DevicePage struct {
	Items      []Device
	NextCursor *DeviceCursor
}

type DeviceMutation struct {
	Authority       DeviceAuthority
	DeviceID        identity.EntityID
	Kind            DeviceKind
	DisplayName     string
	ExpectedVersion uint64
	OccurredAt      time.Time
}

type DeviceMutationResult struct {
	Device                Device
	CurrentSessionRevoked bool
}

type DeviceRepository interface {
	ListDevices(context.Context, DeviceAuthority, DeviceListInput) ([]Device, error)
	RenamePasskey(context.Context, DeviceMutation) (DeviceMutationResult, error)
	RevokeDevice(context.Context, DeviceMutation) (DeviceMutationResult, error)
}

type DeviceManager struct {
	repository DeviceRepository
	clock      func() time.Time
}

func NewDeviceManager(repository DeviceRepository, clock func() time.Time) (*DeviceManager, error) {
	if repository == nil || clock == nil {
		return nil, ErrUnavailable
	}
	if now := canonicalInstant(clock()); !validInstant(now) {
		return nil, ErrUnavailable
	}
	return &DeviceManager{repository: repository, clock: clock}, nil
}

func (manager *DeviceManager) List(
	ctx context.Context,
	authority DeviceAuthority,
	input DeviceListInput,
) (DevicePage, error) {
	if manager == nil || manager.repository == nil || !validDeviceAuthority(authority) || ctx == nil || ctx.Err() != nil {
		return DevicePage{}, ErrDenied
	}
	if input.Limit == 0 {
		input.Limit = defaultDevicePageSize
	}
	if input.Limit < 1 || input.Limit > maximumDevicePageSize || input.After != nil && !validDeviceCursor(*input.After) {
		return DevicePage{}, ErrInvalidInput
	}
	repositoryInput := input
	repositoryInput.Limit++
	items, err := manager.repository.ListDevices(ctx, authority, repositoryInput)
	if err != nil {
		return DevicePage{}, deviceRepositoryError(err)
	}
	if len(items) > repositoryInput.Limit {
		return DevicePage{}, ErrUnavailable
	}
	for index, item := range items {
		if !validDevice(item) || !input.IncludeRevoked && item.Status() != DeviceActive ||
			index > 0 && !deviceBefore(items[index-1], item) {
			return DevicePage{}, ErrUnavailable
		}
	}
	page := DevicePage{Items: items}
	if len(page.Items) > input.Limit {
		cursor := DeviceCursor{Kind: page.Items[input.Limit-1].Kind(), ID: page.Items[input.Limit-1].ID()}
		page.NextCursor = &cursor
		page.Items = page.Items[:input.Limit]
	}
	page.Items = append([]Device(nil), page.Items...)
	return page, nil
}

func (manager *DeviceManager) RenamePasskey(
	ctx context.Context,
	authority DeviceAuthority,
	deviceID identity.EntityID,
	displayName string,
	expectedVersion uint64,
) (DeviceMutationResult, error) {
	displayName = strings.TrimSpace(displayName)
	if !validDeviceAuthority(authority) || !validEntityID(deviceID) || !validStoredSuccessorVersion(expectedVersion) ||
		!validDisplayName(displayName) || ctx == nil || ctx.Err() != nil {
		return DeviceMutationResult{}, ErrInvalidInput
	}
	now, err := manager.now()
	if err != nil {
		return DeviceMutationResult{}, err
	}
	result, err := manager.repository.RenamePasskey(ctx, DeviceMutation{
		Authority: authority, DeviceID: deviceID, Kind: DevicePasskey,
		DisplayName: displayName, ExpectedVersion: expectedVersion, OccurredAt: now,
	})
	if err != nil {
		return DeviceMutationResult{}, deviceRepositoryError(err)
	}
	if result.CurrentSessionRevoked || !validMutationProjection(result.Device, deviceID, DevicePasskey, expectedVersion+1) ||
		result.Device.DisplayName() != displayName {
		return DeviceMutationResult{}, ErrUnavailable
	}
	return result, nil
}

func (manager *DeviceManager) Revoke(
	ctx context.Context,
	authority DeviceAuthority,
	deviceID identity.EntityID,
	kind DeviceKind,
	expectedVersion uint64,
) (DeviceMutationResult, error) {
	if !validDeviceAuthority(authority) || !validEntityID(deviceID) || !validStoredSuccessorVersion(expectedVersion) ||
		(kind != DeviceTOTP && kind != DevicePasskey) || ctx == nil || ctx.Err() != nil {
		return DeviceMutationResult{}, ErrInvalidInput
	}
	now, err := manager.now()
	if err != nil {
		return DeviceMutationResult{}, err
	}
	result, err := manager.repository.RevokeDevice(ctx, DeviceMutation{
		Authority: authority, DeviceID: deviceID, Kind: kind,
		ExpectedVersion: expectedVersion, OccurredAt: now,
	})
	if err != nil {
		return DeviceMutationResult{}, deviceRepositoryError(err)
	}
	if !validMutationProjection(result.Device, deviceID, kind, expectedVersion+1) ||
		result.Device.Status() != DeviceRevoked || result.Device.RevokedAt() == nil {
		return DeviceMutationResult{}, ErrUnavailable
	}
	return result, nil
}

func (manager *DeviceManager) now() (time.Time, error) {
	if manager == nil || manager.repository == nil || manager.clock == nil {
		return time.Time{}, ErrUnavailable
	}
	now := canonicalInstant(manager.clock())
	if !validInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func validDeviceAuthority(value DeviceAuthority) bool {
	return validEntityID(value.SessionID) && validEntityID(value.TenantID) && validEntityID(value.UserID) &&
		value.SessionID != value.TenantID && value.SessionID != value.UserID && value.TenantID != value.UserID
}

func validDeviceCursor(value DeviceCursor) bool {
	return validEntityID(value.ID) && (value.Kind == DeviceTOTP || value.Kind == DevicePasskey)
}

func validMutationProjection(device Device, id identity.EntityID, kind DeviceKind, version uint64) bool {
	return validDevice(device) && device.ID() == id && device.Kind() == kind && device.Version() == version
}

func validDevice(device Device) bool {
	projection := DeviceProjection{
		ID: device.ID(), Kind: device.Kind(), Status: device.Status(), DisplayName: device.DisplayName(),
		Version: device.Version(), Discoverable: device.Discoverable(), BackupEligible: device.BackupEligible(),
		BackedUp: device.BackedUp(), Transports: device.Transports(), CreatedAt: device.CreatedAt(),
		LastUsedAt: device.LastUsedAt(), RevokedAt: device.RevokedAt(),
	}
	canonical, err := NewDevice(projection)
	return err == nil && canonical.ID() == device.ID()
}

func validDeviceLifecycle(status DeviceStatus, created time.Time, revoked *time.Time) bool {
	switch status {
	case DeviceActive:
		return revoked == nil
	case DeviceRevoked, DeviceCloneSuspected:
		return revoked != nil && !revoked.Before(created)
	default:
		return false
	}
}

func validDisplayName(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximumDeviceNameRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '<' || character == '>' {
			return false
		}
	}
	return true
}

func validTransports(values []webauthn.CredentialTransport) bool {
	if len(values) > 6 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if index > 0 && values[index-1] == value {
			return false
		}
		switch value {
		case webauthn.TransportUSB, webauthn.TransportNFC, webauthn.TransportBLE,
			webauthn.TransportInternal, webauthn.TransportHybrid, webauthn.TransportSmartCard:
		default:
			return false
		}
	}
	return true
}

func deviceBefore(previous, current Device) bool {
	if previous.CreatedAt().After(current.CreatedAt()) {
		return true
	}
	if !previous.CreatedAt().Equal(current.CreatedAt()) {
		return false
	}
	if previous.Kind() != current.Kind() {
		return previous.Kind() < current.Kind()
	}
	previousID, currentID := previous.ID(), current.ID()
	return bytes.Compare(previousID[:], currentID[:]) > 0
}

func canonicalInstant(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func canonicalOptionalInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	canonical := canonicalInstant(*value)
	return &canonical
}

func cloneInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validEntityID(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func deviceRepositoryError(err error) error {
	switch err {
	case nil:
		return nil
	case ErrInvalidInput, ErrDenied, ErrNotFound, ErrConflict, ErrPrecondition:
		return err
	default:
		return ErrUnavailable
	}
}
