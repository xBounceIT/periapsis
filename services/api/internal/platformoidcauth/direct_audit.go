package platformoidcauth

import (
	"fmt"
	"net/netip"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const maximumDirectAuditUserAgentBytes = 512

// DirectAuditContext is request-owned attribution for one anonymous direct
// platform OIDC effect. Adapters must persist these exact values and must not
// recover them from context.Context, forwarded headers, or process globals.
type DirectAuditContext struct {
	RequestID     identity.EntityID
	CorrelationID identity.EntityID
	RemoteAddress netip.Addr
	UserAgent     string `json:"-"`
}

func (audit DirectAuditContext) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectAuditContext{request:%t,correlation:%t,remote:%t,userAgent:%t,material:[REDACTED]}",
		audit.RequestID != (identity.EntityID{}), audit.CorrelationID != (identity.EntityID{}),
		audit.RemoteAddress.IsValid(), audit.UserAgent != "",
	)
}

func (audit DirectAuditContext) GoString() string { return audit.String() }

func validDirectAuditContext(audit DirectAuditContext) bool {
	if !validDirectEntityID(audit.RequestID) || !validDirectEntityID(audit.CorrelationID) ||
		!audit.RemoteAddress.IsValid() || audit.RemoteAddress.Zone() != "" ||
		audit.RemoteAddress != audit.RemoteAddress.Unmap() || audit.UserAgent == "" ||
		len(audit.UserAgent) > maximumDirectAuditUserAgentBytes || !utf8.ValidString(audit.UserAgent) {
		return false
	}
	for _, character := range audit.UserAgent {
		if unicode.IsControl(character) || directOIDCDirectionalControl(character) {
			return false
		}
	}
	return true
}
