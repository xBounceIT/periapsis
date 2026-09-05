package authentication

import (
	"context"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const maximumContextUserAgentBytes = 512

type eventContextKey struct{}

// WithEventContext attaches one already-normalized request attribution value
// to the authentication call graph. The private key prevents raw request
// headers from becoming an implicit authority boundary.
func WithEventContext(ctx context.Context, event EventContext) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil || !validContextEvent(event) {
		return nil, ErrInvalidInput
	}
	return context.WithValue(ctx, eventContextKey{}, event), nil
}

// EventContextFromContext returns only values installed through
// WithEventContext. Direct-provider session mutation adapters use it to build
// redacted, transactionally coupled audit facts before any authority decision.
func EventContextFromContext(ctx context.Context) (EventContext, bool) {
	if ctx == nil {
		return EventContext{}, false
	}
	event, ok := ctx.Value(eventContextKey{}).(EventContext)
	return event, ok && validContextEvent(event)
}

func validContextEvent(event EventContext) bool {
	if event.RequestID == uuid.Nil || event.CorrelationID == uuid.Nil ||
		event.RequestID.Version() != 7 || event.CorrelationID.Version() != 7 ||
		event.RequestID.Variant() != uuid.RFC4122 || event.CorrelationID.Variant() != uuid.RFC4122 ||
		!event.RemoteAddress.IsValid() || len(event.UserAgent) > maximumContextUserAgentBytes ||
		!utf8.ValidString(event.UserAgent) {
		return false
	}
	for _, character := range event.UserAgent {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
