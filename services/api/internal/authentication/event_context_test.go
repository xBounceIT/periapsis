package authentication

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEventContextCarrierIsValidatedAndPrivateToAuthentication(t *testing.T) {
	t.Parallel()
	event := EventContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("198.51.100.25"), UserAgent: "Periapsis test",
	}
	ctx, err := WithEventContext(context.Background(), event)
	if err != nil {
		t.Fatalf("WithEventContext() error = %v", err)
	}
	got, ok := EventContextFromContext(ctx)
	if !ok || got != event {
		t.Fatalf("EventContextFromContext() = %#v, %t", got, ok)
	}
	if got, ok = EventContextFromContext(context.Background()); ok || got != (EventContext{}) {
		t.Fatalf("empty context yielded %#v, %t", got, ok)
	}

	for name, invalid := range map[string]EventContext{
		"zero request": {
			CorrelationID: event.CorrelationID, RemoteAddress: event.RemoteAddress,
		},
		"version four request": {
			RequestID: uuid.New(), CorrelationID: event.CorrelationID,
			RemoteAddress: event.RemoteAddress,
		},
		"version four correlation": {
			RequestID: event.RequestID, CorrelationID: uuid.New(),
			RemoteAddress: event.RemoteAddress,
		},
		"invalid address": {
			RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		},
		"control user agent": {
			RequestID: event.RequestID, CorrelationID: event.CorrelationID,
			RemoteAddress: event.RemoteAddress, UserAgent: "hidden\nvalue",
		},
		"oversized user agent": {
			RequestID: event.RequestID, CorrelationID: event.CorrelationID,
			RemoteAddress: event.RemoteAddress, UserAgent: strings.Repeat("a", maximumContextUserAgentBytes+1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, err := WithEventContext(context.Background(), invalid)
			if err == nil || ctx != nil {
				t.Fatalf("WithEventContext() = %v, %v", ctx, err)
			}
		})
	}
}
