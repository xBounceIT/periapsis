package postgres

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

func TestValidateEventContextRequiresBoundedCompleteAttribution(t *testing.T) {
	valid := authentication.EventContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("198.51.100.20"), UserAgent: "repository-test",
	}
	if err := validateEventContext(valid); err != nil {
		t.Fatalf("validateEventContext() error = %v", err)
	}

	tests := map[string]authentication.EventContext{
		"missing request":     {CorrelationID: valid.CorrelationID, RemoteAddress: valid.RemoteAddress},
		"missing correlation": {RequestID: valid.RequestID, RemoteAddress: valid.RemoteAddress},
		"missing address":     {RequestID: valid.RequestID, CorrelationID: valid.CorrelationID},
		"zoned address": {
			RequestID: valid.RequestID, CorrelationID: valid.CorrelationID,
			RemoteAddress: netip.MustParseAddr("fe80::1%ethernet"),
		},
		"oversized agent": {
			RequestID: valid.RequestID, CorrelationID: valid.CorrelationID,
			RemoteAddress: valid.RemoteAddress, UserAgent: strings.Repeat("a", maximumAuditUserAgentBytes+1),
		},
		"control in agent": {
			RequestID: valid.RequestID, CorrelationID: valid.CorrelationID,
			RemoteAddress: valid.RemoteAddress, UserAgent: "agent\u0085value",
		},
	}
	for name, event := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateEventContext(event); err == nil {
				t.Fatal("invalid audit attribution was accepted")
			}
		})
	}
}
