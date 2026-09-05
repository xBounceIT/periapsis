package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	listMFADevicesSQL  = `select app.list_my_mfa_devices_v1($1::uuid, $2::text, $3::uuid, $4::integer, $5::boolean)`
	renameMFADeviceSQL = `select app.rename_my_passkey_v1($1::jsonb)`
	revokeMFADeviceSQL = `select app.revoke_my_mfa_device_v1($1::jsonb)`
)

type MFADeviceRepository struct {
	queryer mfaQueryer
	begin   transactionBeginner
}

var _ mfaauth.DeviceRepository = (*MFADeviceRepository)(nil)

func NewMFADeviceRepository(pool *pgxpool.Pool) *MFADeviceRepository {
	return &MFADeviceRepository{begin: poolTransactionBeginner(pool)}
}

type mfaDeviceWire struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Status         string     `json:"status"`
	DisplayName    string     `json:"displayName"`
	Version        int64      `json:"version"`
	Discoverable   bool       `json:"discoverable"`
	BackupEligible bool       `json:"backupEligible"`
	BackedUp       bool       `json:"backedUp"`
	Transports     []string   `json:"transports"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
}

type mfaDevicePageWire struct {
	Items []mfaDeviceWire `json:"items"`
}

type mfaDeviceMutationWire struct {
	SessionID       string    `json:"sessionId"`
	TenantID        string    `json:"tenantId"`
	UserID          string    `json:"userId"`
	DeviceID        string    `json:"deviceId"`
	Kind            string    `json:"kind"`
	DisplayName     string    `json:"displayName,omitempty"`
	ExpectedVersion int64     `json:"expectedVersion"`
	OccurredAt      time.Time `json:"occurredAt"`
}

type mfaDeviceMutationResultWire struct {
	Device                mfaDeviceWire `json:"device"`
	CurrentSessionRevoked bool          `json:"currentSessionRevoked"`
}

func (repository *MFADeviceRepository) ListDevices(
	ctx context.Context,
	authority mfaauth.DeviceAuthority,
	input mfaauth.DeviceListInput,
) ([]mfaauth.Device, error) {
	if repository == nil || repository.queryer == nil && repository.begin == nil || input.Limit < 1 || input.Limit > 101 {
		return nil, mfaauth.ErrInvalidInput
	}
	afterKind, afterID := "", ""
	if input.After != nil {
		afterKind, afterID = string(input.After.Kind), entityIDWire(input.After.ID)
		if afterID == "" || afterKind != string(mfaauth.DeviceTOTP) && afterKind != string(mfaauth.DevicePasskey) {
			return nil, mfaauth.ErrInvalidInput
		}
	}
	return withMFADeviceAuthority(ctx, repository, authority, func(queryer mfaQueryer) ([]mfaauth.Device, error) {
		return listMFADevices(ctx, queryer, authority, afterKind, afterID, input)
	})
}

func listMFADevices(
	ctx context.Context,
	queryer mfaQueryer,
	authority mfaauth.DeviceAuthority,
	afterKind string,
	afterID string,
	input mfaauth.DeviceListInput,
) ([]mfaauth.Device, error) {
	var raw []byte
	err := queryer.QueryRow(ctx, listMFADevicesSQL, entityIDWire(authority.SessionID),
		nullableText(afterKind), nullableEntityIDWire(afterID), input.Limit, input.IncludeRevoked).Scan(&raw)
	if err != nil {
		return nil, mapMFADeviceDatabaseError(err)
	}
	defer clear(raw)
	var wire mfaDevicePageWire
	if err := unmarshalMFAWire(raw, &wire); err != nil || len(wire.Items) > input.Limit {
		return nil, errMFAPersistence
	}
	devices := make([]mfaauth.Device, len(wire.Items))
	for index, item := range wire.Items {
		device, mapErr := mfaDeviceFromWire(item)
		if mapErr != nil {
			return nil, errMFAPersistence
		}
		devices[index] = device
	}
	return devices, nil
}

func (repository *MFADeviceRepository) RenamePasskey(
	ctx context.Context,
	mutation mfaauth.DeviceMutation,
) (mfaauth.DeviceMutationResult, error) {
	return repository.mutate(ctx, renameMFADeviceSQL, mutation)
}

func (repository *MFADeviceRepository) RevokeDevice(
	ctx context.Context,
	mutation mfaauth.DeviceMutation,
) (mfaauth.DeviceMutationResult, error) {
	return repository.mutate(ctx, revokeMFADeviceSQL, mutation)
}

func (repository *MFADeviceRepository) mutate(
	ctx context.Context,
	query string,
	mutation mfaauth.DeviceMutation,
) (mfaauth.DeviceMutationResult, error) {
	if repository == nil || repository.queryer == nil && repository.begin == nil || mutation.ExpectedVersion == 0 ||
		!validMFAJSONSuccessorVersion(mutation.ExpectedVersion) {
		return mfaauth.DeviceMutationResult{}, mfaauth.ErrInvalidInput
	}
	wire := mfaDeviceMutationWire{
		SessionID: entityIDWire(mutation.Authority.SessionID), TenantID: entityIDWire(mutation.Authority.TenantID),
		UserID: entityIDWire(mutation.Authority.UserID), DeviceID: entityIDWire(mutation.DeviceID),
		Kind: string(mutation.Kind), DisplayName: mutation.DisplayName,
		ExpectedVersion: int64(mutation.ExpectedVersion), OccurredAt: mutation.OccurredAt.UTC().Truncate(time.Microsecond),
	}
	payload, err := marshalMFAWire(wire)
	if err != nil {
		return mfaauth.DeviceMutationResult{}, mfaauth.ErrInvalidInput
	}
	defer clear(payload)
	return withMFADeviceAuthority(ctx, repository, mutation.Authority, func(queryer mfaQueryer) (mfaauth.DeviceMutationResult, error) {
		return mutateMFADevice(ctx, queryer, query, payload)
	})
}

func mutateMFADevice(
	ctx context.Context,
	queryer mfaQueryer,
	query string,
	payload []byte,
) (mfaauth.DeviceMutationResult, error) {
	var raw []byte
	if err := queryer.QueryRow(ctx, query, payload).Scan(&raw); err != nil {
		return mfaauth.DeviceMutationResult{}, mapMFADeviceDatabaseError(err)
	}
	defer clear(raw)
	var resultWire mfaDeviceMutationResultWire
	if err := unmarshalMFAWire(raw, &resultWire); err != nil {
		return mfaauth.DeviceMutationResult{}, errMFAPersistence
	}
	device, err := mfaDeviceFromWire(resultWire.Device)
	if err != nil {
		return mfaauth.DeviceMutationResult{}, errMFAPersistence
	}
	return mfaauth.DeviceMutationResult{Device: device, CurrentSessionRevoked: resultWire.CurrentSessionRevoked}, nil
}

func withMFADeviceAuthority[T any](
	ctx context.Context,
	repository *MFADeviceRepository,
	authority mfaauth.DeviceAuthority,
	work func(mfaQueryer) (T, error),
) (T, error) {
	var zero T
	if repository == nil || work == nil {
		return zero, errMFAPersistence
	}
	if repository.begin == nil {
		if repository.queryer == nil {
			return zero, errMFAPersistence
		}
		return work(repository.queryer)
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := dbsql.New(tx)
		installed, err := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(uuid.UUID(authority.TenantID)),
			UserID:   toDatabaseUUID(uuid.UUID(authority.UserID)),
		})
		if err != nil || installed.TenantID != entityIDWire(authority.TenantID) ||
			installed.UserID != entityIDWire(authority.UserID) {
			return zero, errMFAPersistence
		}
		return work(tx)
	})
}

func mfaDeviceFromWire(wire mfaDeviceWire) (mfaauth.Device, error) {
	id, err := parseEntityIDWire(wire.ID, false)
	if err != nil || !validMFAJSONRevision(wire.Version) {
		return mfaauth.Device{}, errInvalidMFAWire
	}
	transports := make([]webauthn.CredentialTransport, len(wire.Transports))
	for index, transport := range wire.Transports {
		transports[index] = webauthn.CredentialTransport(transport)
	}
	device, err := mfaauth.NewDevice(mfaauth.DeviceProjection{
		ID: id, Kind: mfaauth.DeviceKind(wire.Kind), Status: mfaauth.DeviceStatus(wire.Status),
		DisplayName: wire.DisplayName, Version: uint64(wire.Version), Discoverable: wire.Discoverable,
		BackupEligible: wire.BackupEligible, BackedUp: wire.BackedUp, Transports: transports,
		CreatedAt: wire.CreatedAt, LastUsedAt: wire.LastUsedAt, RevokedAt: wire.RevokedAt,
	})
	if err != nil {
		return mfaauth.Device{}, errInvalidMFAWire
	}
	return device, nil
}

func nullableEntityIDWire(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func mapMFADeviceDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return mfaauth.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023":
		return mfaauth.ErrInvalidInput
	case "42501":
		return mfaauth.ErrDenied
	case "P0002":
		return mfaauth.ErrNotFound
	case "40001":
		return mfaauth.ErrPrecondition
	case "23505", "55000":
		return mfaauth.ErrConflict
	default:
		return errMFAPersistence
	}
}
