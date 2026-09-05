package postgres

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const maximumAuditUserAgentBytes = 512

func validateEventContext(event authentication.EventContext) error {
	if event.RequestID == [16]byte{} || event.CorrelationID == [16]byte{} ||
		!event.RemoteAddress.IsValid() || event.RemoteAddress.Zone() != "" {
		return errors.New("audit attribution identifiers and remote address are required")
	}
	if len(event.UserAgent) > maximumAuditUserAgentBytes || !utf8.ValidString(event.UserAgent) {
		return errors.New("audit user agent is invalid")
	}
	for _, character := range event.UserAgent {
		if unicode.IsControl(character) {
			return errors.New("audit user agent contains a control character")
		}
	}
	return nil
}
