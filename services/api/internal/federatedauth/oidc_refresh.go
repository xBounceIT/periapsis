package federatedauth

import (
	"context"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

// OIDCRefreshExchanger is the narrow credential-bearing boundary used by the
// application service after it has atomically claimed a refresh generation.
type OIDCRefreshExchanger interface {
	ExchangeOIDCRefresh(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (*OIDCRotation, error)
}

// OIDCRotation contains only the successor material needed by the atomic
// completion. Its formatting methods are always redacted.
type OIDCRotation struct {
	successor       []byte
	accessExpiresAt time.Time
}

func (rotation *OIDCRotation) RefreshToken() []byte {
	if rotation == nil {
		return nil
	}
	return append([]byte(nil), rotation.successor...)
}

func (rotation *OIDCRotation) AccessExpiresAt() time.Time {
	if rotation == nil {
		return time.Time{}
	}
	return rotation.accessExpiresAt
}

func (rotation *OIDCRotation) Destroy() {
	if rotation == nil {
		return
	}
	clear(rotation.successor)
	rotation.successor = nil
	rotation.accessExpiresAt = time.Time{}
}

func (rotation OIDCRotation) String() string {
	return "federatedauth.OIDCRotation{material:[REDACTED]}"
}
func (rotation OIDCRotation) GoString() string { return rotation.String() }

// UpstreamOIDCRefreshExchanger adapts the concrete pinned OIDC transport to
// the application port without letting access/ID tokens escape this boundary.
type UpstreamOIDCRefreshExchanger struct {
	upstream *federatedoidc.UpstreamHTTP
}

func NewUpstreamOIDCRefreshExchanger(upstream *federatedoidc.UpstreamHTTP) (*UpstreamOIDCRefreshExchanger, error) {
	if upstream == nil {
		return nil, ErrInvalidOptions
	}
	return &UpstreamOIDCRefreshExchanger{upstream: upstream}, nil
}

func (exchanger *UpstreamOIDCRefreshExchanger) ExchangeOIDCRefresh(
	ctx context.Context,
	request federatedoidc.StoredRefreshExchangeRequest,
	now time.Time,
) (*OIDCRotation, error) {
	if exchanger == nil || exchanger.upstream == nil {
		clear(request.ClientSecret)
		clear(request.RefreshToken)
		return nil, ErrRefreshRejected
	}
	tokens, err := exchanger.upstream.RefreshStored(ctx, request, now)
	if err != nil {
		return nil, err
	}
	if tokens == nil {
		return nil, ErrRefreshRejected
	}
	defer tokens.Destroy()
	return &OIDCRotation{successor: tokens.RefreshToken(), accessExpiresAt: tokens.ExpiresAt()}, nil
}
