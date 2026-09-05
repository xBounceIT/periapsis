package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const admitMFAOperationSQL = `
select decision.outcome::text, decision.retry_at::timestamptz
from app.admit_mfa_operation_v1(
  $1::uuid, $2::bytea, $3::bytea, $4::bytea, $5::timestamptz
) as decision(outcome, retry_at)`

// MFAAdmissionRepository applies all three purpose-separated meters in one
// database transaction. A partial or unknown result denies the operation.
type MFAAdmissionRepository struct {
	queryer mfaQueryer
}

var _ mfaauth.AdmissionGate = (*MFAAdmissionRepository)(nil)

func NewMFAAdmissionRepository(pool *pgxpool.Pool) *MFAAdmissionRepository {
	return &MFAAdmissionRepository{queryer: pool}
}

func (repository *MFAAdmissionRepository) Admit(
	ctx context.Context,
	value mfaauth.AdmissionContext,
	now time.Time,
) (mfaauth.AdmissionDecision, error) {
	if repository == nil || repository.queryer == nil {
		return mfaauth.AdmissionDecision{}, errMFAPersistence
	}
	var outcome string
	var retryAt pgtype.Timestamptz
	if err := repository.queryer.QueryRow(
		ctx, admitMFAOperationSQL, entityIDWire(value.OperationID), value.NetworkDigest[:],
		value.PrincipalDigest[:], value.ResourceDigest[:], databaseTime(now),
	).Scan(&outcome, &retryAt); err != nil {
		return mfaauth.AdmissionDecision{}, errMFAPersistence
	}
	switch outcome {
	case "allowed":
		if retryAt.Valid {
			return mfaauth.AdmissionDecision{}, errMFAPersistence
		}
		return mfaauth.AdmissionDecision{Outcome: mfaauth.AdmissionAllowed}, nil
	case "rate_limited", "locked":
		if !retryAt.Valid || retryAt.Time.IsZero() {
			return mfaauth.AdmissionDecision{}, errMFAPersistence
		}
		decision := mfaauth.AdmissionRateLimited
		if outcome == "locked" {
			decision = mfaauth.AdmissionLocked
		}
		return mfaauth.AdmissionDecision{Outcome: decision, RetryAt: retryAt.Time.UTC()}, nil
	default:
		return mfaauth.AdmissionDecision{}, errMFAPersistence
	}
}
