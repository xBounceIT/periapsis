package federatedauth

import (
	"context"
	"time"
)

// SessionServiceOptions compose only the request-time session provenance
// boundary. Keeping this smaller than the browser federation graph lets
// passkey sessions retain live factor/policy revalidation when OIDC and SAML
// browser routes are intentionally disabled on a non-TLS development origin.
type SessionServiceOptions struct {
	Sessions         SessionStore
	Credentials      ApplyCredentialIssuer
	OperationTimeout time.Duration
	Now              func() time.Time
}

// SessionService owns live session provenance decisions independently from
// protocol start/callback transport. It never performs provider network I/O.
type SessionService struct {
	sessions         SessionStore
	credentials      ApplyCredentialIssuer
	operationTimeout time.Duration
	now              func() time.Time
}

func NewSessionService(options SessionServiceOptions) (*SessionService, error) {
	if options.Sessions == nil || options.Credentials == nil ||
		options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SessionService{
		sessions: options.Sessions, credentials: options.Credentials,
		operationTimeout: options.OperationTimeout, now: options.Now,
	}, nil
}

func (service *SessionService) RevalidateSession(
	ctx context.Context,
	lookup SessionLookup,
) (SessionResult, error) {
	if service == nil {
		return SessionResult{}, ErrInvalidInput
	}
	return revalidateSession(
		ctx, lookup, service.sessions, service.credentials, service.operationTimeout, service.now,
	)
}
