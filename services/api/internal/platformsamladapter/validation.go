package platformsamladapter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
	"github.com/periapsis-im/periapsis/services/api/internal/returnpath"
)

const (
	maximumExactRevision       = uint64(9_007_199_254_740_991)
	maximumUUIDMilliseconds    = uint64(253_402_300_799_999)
	maximumAuditUserAgentBytes = 512
	maximumRedirectBytes       = 64 * 1024
	maximumCertificateBytes    = 64 * 1024
	maximumEnvelopeBytes       = 128 * 1024
	maximumRelayStateBytes     = 80
)

var providerKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

func validUUIDv7(value identity.EntityID) bool {
	if value == (identity.EntityID{}) || value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return false
	}
	milliseconds := uint64(value[0])<<40 | uint64(value[1])<<32 | uint64(value[2])<<24 |
		uint64(value[3])<<16 | uint64(value[4])<<8 | uint64(value[5])
	return milliseconds <= maximumUUIDMilliseconds && binary.BigEndian.Uint64(value[8:]) != 0
}

func validRevision(value uint64) bool { return value > 0 && value <= maximumExactRevision }

func validSuccessorRevision(value uint64) bool { return value > 0 && value < maximumExactRevision }

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func canonicalNow(source func() time.Time) (time.Time, bool) {
	if source == nil {
		return time.Time{}, false
	}
	value := source().UTC().Truncate(time.Microsecond)
	return value, validInstant(value)
}

func validTransactionID(value federatedsaml.TransactionID) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}

func validDirectProvider(provider identity.ProviderContext) bool {
	return provider.Scope == identity.PlatformProviderScope && provider.TenantID == (identity.EntityID{}) &&
		validUUIDv7(provider.ProviderID)
}

func validDirectProtocolPins(pins federatedsaml.TransactionPins) bool {
	return pins.Authority == federatedsaml.DirectPlatformCeremonyAuthority &&
		validDirectProvider(pins.Provider) && pins.BindingID == (identity.EntityID{}) &&
		validRevision(pins.ProviderRevision) && pins.BindingRevision == 0 &&
		validRevision(pins.PlatformLoginRevision) && validRevision(pins.ConfigurationRevision) &&
		validRevision(pins.SecurityRevision) && validRevision(pins.PlanRevision) &&
		pins.MappingRevision == 0 && pins.AuthorizationRevision == 0 &&
		validRevision(pins.AssurancePolicyRevision) && validRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{})
}

func validDirectPins(pins platformsamlauth.DirectSAMLPins) bool {
	return validDirectProtocolPins(pins.Protocol) && validUUIDv7(pins.PlatformFloorPolicyID) &&
		validRevision(pins.PlatformFloorPolicyRevision)
}

func validBegin(begin federatedsaml.AuthenticationBegin) bool {
	receipt := [sha256.Size]byte(begin.ReceiptDigest)
	network := [sha256.Size]byte(begin.NetworkDigest)
	account := [sha256.Size]byte(begin.AccountDigest)
	provider := [sha256.Size]byte(begin.ProviderDigest)
	zero := [sha256.Size]byte{}
	return validUUIDv7(begin.OperationRunID) && receipt != zero && network != zero && account != zero && provider != zero &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validAudit(audit platformsamlauth.AuditContext) bool {
	return validUUIDv7(audit.RequestID) && validUUIDv7(audit.CorrelationID) &&
		validRemoteAddress(audit.RemoteAddress) && validText(audit.UserAgent, maximumAuditUserAgentBytes, false)
}

func validRemoteAddress(value netip.Addr) bool {
	return value.IsValid() && value.Zone() == "" && value == value.Unmap()
}

func validText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' || character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func validReturnPath(value string) bool {
	return returnpath.Valid(value)
}

func validBrowserHandle(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	var decoded [sha256.Size]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	canonical := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	base64.RawURLEncoding.Encode(canonical, decoded[:])
	valid := err == nil && written == len(decoded) && [sha256.Size]byte(decoded) != ([sha256.Size]byte{}) &&
		string(canonical) == string(value)
	clear(decoded[:])
	clear(canonical)
	return valid
}

func validStartRequest(request platformsamlauth.StartProtocolRequest) bool {
	protocol := request.Protocol
	grant := request.Grant
	pins := grant.Pins.Protocol
	configuration := protocol.Configuration
	return validBegin(protocol.Begin) && protocol.Begin == grant.Authority.Lookup.Begin &&
		providerKeyPattern.MatchString(grant.Authority.Lookup.LoginKey) &&
		validAudit(grant.Authority.Audit) && validReturnPath(grant.Authority.ReturnPath) &&
		grant.Authority.ReturnPath == protocol.ReturnPath && validDirectPins(grant.Pins) && !protocol.HasLiveSession &&
		(len(protocol.PreviousBrowserHandle) == 0 || validBrowserHandle(protocol.PreviousBrowserHandle)) &&
		configuration.Authority == federatedsaml.DirectPlatformCeremonyAuthority &&
		configuration.Provider == pins.Provider && configuration.BindingID == (identity.EntityID{}) &&
		configuration.ProviderRevision == pins.ProviderRevision && configuration.BindingRevision == 0 &&
		configuration.PlatformLoginRevision == pins.PlatformLoginRevision &&
		configuration.ConfigurationRevision == pins.ConfigurationRevision &&
		configuration.SecurityRevision == pins.SecurityRevision && configuration.PlanRevision == pins.PlanRevision &&
		configuration.MappingRevision == 0 && configuration.AuthorizationRevision == 0 &&
		configuration.AssurancePolicyRevision == pins.AssurancePolicyRevision &&
		configuration.Metadata.Revision() == pins.MetadataRevision && configuration.Metadata.Digest() == pins.MetadataDigest &&
		configuration.SPKeyRevision == pins.SPKeyRevision && len(configuration.Mapping.Scalars) == 0 &&
		len(configuration.Mapping.Profiles) == 0 && configuration.Mapping.Groups == nil
}

func validCallbackLookup(lookup federatedsaml.CallbackConfigurationLookup) bool {
	return validTransactionID(lookup.TransactionID) && validSuccessorRevision(lookup.ExpectedVersion) &&
		validDirectProtocolPins(lookup.Pins)
}

func validPendingForLookup(
	pending federatedsaml.PendingTransaction,
	pins platformsamlauth.DirectSAMLPins,
	request federatedsaml.LookupTransactionRequest,
) bool {
	return validDirectPins(pins) && pending.Pins == pins.Protocol && validTransactionID(pending.ID) &&
		validUUIDv7(pending.MaterialID) && pending.State == federatedsaml.TransactionPending &&
		validSuccessorRevision(pending.Version) && validInstant(pending.CreatedAt) && validInstant(pending.ExpiresAt) &&
		!request.ObservedAt.Before(pending.CreatedAt) && request.ObservedAt.Before(pending.ExpiresAt) &&
		pending.ExpiresAt.Sub(pending.CreatedAt) >= time.Minute && pending.ExpiresAt.Sub(pending.CreatedAt) <= 15*time.Minute &&
		pending.RelayStateDigest == request.RelayStateDigest && pending.BrowserDigest == request.BrowserDigest &&
		pending.RelayStateDigest != ([sha256.Size]byte{}) && pending.BrowserDigest != ([sha256.Size]byte{}) &&
		pending.RelayStateDigest != pending.BrowserDigest && validReturnPath(pending.ReturnPath)
}

func cloneConfiguration(value federatedsaml.Configuration) federatedsaml.Configuration {
	value.DecryptionKeyVersions = append([]uint32(nil), value.DecryptionKeyVersions...)
	value.DirectPlatformDecryptionKeyRevisions = append([]uint64(nil), value.DirectPlatformDecryptionKeyRevisions...)
	value.RequestedAuthnContexts = append([]string(nil), value.RequestedAuthnContexts...)
	value.Mapping.Scalars = append([]federatedsaml.ScalarAttributeRule(nil), value.Mapping.Scalars...)
	value.Mapping.Profiles = append([]federatedsaml.ProfileAttributeRule(nil), value.Mapping.Profiles...)
	if value.Mapping.Groups != nil {
		copyValue := *value.Mapping.Groups
		value.Mapping.Groups = &copyValue
	}
	value.TrustRules = append([]federatedsaml.AuthnContextTrustRule(nil), value.TrustRules...)
	return value
}

func cloneStartRequest(value federatedsaml.StartRequest) federatedsaml.StartRequest {
	value.Configuration = cloneConfiguration(value.Configuration)
	value.PreviousBrowserHandle = append([]byte(nil), value.PreviousBrowserHandle...)
	return value
}

func clearStartRequest(value *federatedsaml.StartRequest) {
	if value == nil {
		return
	}
	clear(value.PreviousBrowserHandle)
	*value = federatedsaml.StartRequest{}
}
