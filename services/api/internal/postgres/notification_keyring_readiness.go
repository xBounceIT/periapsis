package postgres

import (
	"context"
	"errors"

	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

const verifyNotificationKeyringQuery = `
select app.verify_notification_keyring_v1($1::smallint[])
`

type NotificationKeyVersionVerifier struct {
	pool SchemaQuerier
}

func NewNotificationKeyVersionVerifier(pool SchemaQuerier) NotificationKeyVersionVerifier {
	return NotificationKeyVersionVerifier{pool: pool}
}

var _ notification.KeyVersionVerifier = NotificationKeyVersionVerifier{}

func (v NotificationKeyVersionVerifier) VerifyNotificationKeyring(
	ctx context.Context,
	versions []int16,
) (bool, error) {
	if v.pool == nil || len(versions) < 1 || len(versions) > 16 {
		return false, notification.ErrInvalidInput
	}
	values := make([]int16, len(versions))
	for index, version := range versions {
		if version < 1 || index > 0 && versions[index-1] >= version {
			return false, notification.ErrInvalidInput
		}
		values[index] = version
	}
	var verified bool
	if err := v.pool.QueryRow(ctx, verifyNotificationKeyringQuery, values).Scan(&verified); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, notification.ErrUnavailable
	}
	return verified, nil
}
