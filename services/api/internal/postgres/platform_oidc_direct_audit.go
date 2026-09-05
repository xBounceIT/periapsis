package postgres

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const platformOIDCDirectStableAuditDomain = "periapsis/platform-oidc/direct-audit-event/v1"

// platformOIDCDirectStableAuditEventID keeps the audit identifier stable when
// the application retries an exact persistence request after response loss.
// The timestamp prefix comes from the request UUIDv7; the remaining bits are
// domain-separated from every semantic identity that owns the effect.
func platformOIDCDirectStableAuditEventID(
	audit platformoidcauth.DirectAuditContext,
	action string,
	authorities ...[]byte,
) (uuid.UUID, error) {
	requestID := uuid.UUID(audit.RequestID)
	correlationID := uuid.UUID(audit.CorrelationID)
	if !platformOIDCDirectUUIDv7(requestID) || !platformOIDCDirectUUIDv7(correlationID) ||
		action == "" || len(action) > 128 || len(authorities) == 0 || len(authorities) > 8 {
		return uuid.Nil, errFederatedAuthPersistence
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(platformOIDCDirectStableAuditDomain))
	writePlatformOIDCDirectAuditPart(digest, []byte(action))
	writePlatformOIDCDirectAuditPart(digest, requestID[:])
	writePlatformOIDCDirectAuditPart(digest, correlationID[:])
	for _, authority := range authorities {
		if len(authority) == 0 || len(authority) > 4*1024 {
			return uuid.Nil, errFederatedAuthPersistence
		}
		writePlatformOIDCDirectAuditPart(digest, authority)
	}
	sum := digest.Sum(nil)
	defer clear(sum)
	var result uuid.UUID
	copy(result[:6], requestID[:6])
	copy(result[6:], sum[:10])
	result[6] = result[6]&0x0f | 0x70
	result[8] = result[8]&0x3f | 0x80
	if result == requestID || result == correlationID {
		result[15] ^= 1
	}
	if !platformOIDCDirectUUIDv7(result) || result == requestID || result == correlationID {
		return uuid.Nil, errFederatedAuthPersistence
	}
	return result, nil
}

type platformOIDCDirectHashWriter interface {
	Write([]byte) (int, error)
}

func writePlatformOIDCDirectAuditPart(writer platformOIDCDirectHashWriter, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
