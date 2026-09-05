package federatedauth

import (
	"context"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type SAMLLogoutCommand struct {
	OperationRunID      identity.EntityID
	TenantID            identity.EntityID
	AuthenticatedUserID identity.EntityID
	SessionID           identity.EntityID
	ExpectedVersion     uint64
	RequestUpstream     bool
}

func (command SAMLLogoutCommand) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLLogoutCommand{operation:%t,tenant:%t,user:%t,session:%t,version:%t,upstream:%t}",
		command.OperationRunID != (identity.EntityID{}), command.TenantID != (identity.EntityID{}),
		command.AuthenticatedUserID != (identity.EntityID{}), command.SessionID != (identity.EntityID{}),
		command.ExpectedVersion > 0, command.RequestUpstream,
	)
}
func (command SAMLLogoutCommand) GoString() string { return command.String() }

// SAMLLogoutSnapshot is returned only after the local session has been
// idempotently revoked. ProtectedMaterial is an encrypted, immutable-row-bound
// NameID/SessionIndex envelope; routine formatting never exposes it.
type SAMLLogoutSnapshot struct {
	OperationRunID      identity.EntityID
	TenantID            identity.EntityID
	AuthenticatedUserID identity.EntityID
	SessionID           identity.EntityID
	PreviousVersion     uint64
	Provider            identity.ProviderContext
	BindingID           identity.EntityID
	MaterialID          identity.EntityID
	Configuration       TenantSAMLConfiguration
	ProtectedMaterial   federatedsaml.ProtectedSessionMaterial
	RevokedAt           time.Time
}

func (snapshot SAMLLogoutSnapshot) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLLogoutSnapshot{operation:%t,tenant:%t,user:%t,session:%t,version:%t,provider:%t,binding:%t,material_id:%t,material:%q,revoked:%t}",
		snapshot.OperationRunID != (identity.EntityID{}), snapshot.TenantID != (identity.EntityID{}),
		snapshot.AuthenticatedUserID != (identity.EntityID{}), snapshot.SessionID != (identity.EntityID{}),
		snapshot.PreviousVersion > 0,
		snapshot.Provider.ProviderID != (identity.EntityID{}), snapshot.BindingID != (identity.EntityID{}),
		snapshot.MaterialID != (identity.EntityID{}),
		snapshot.ProtectedMaterial.String(), !snapshot.RevokedAt.IsZero(),
	)
}
func (snapshot SAMLLogoutSnapshot) GoString() string { return snapshot.String() }

// SAMLLogoutStore must atomically revoke the exact local session/version and
// return its immutable SAML provenance. Repeating the same OperationRunID must
// return the same snapshot; divergent reuse must fail closed. Ownership of the
// returned ProtectedMaterial ciphertext transfers to the caller, which clears
// it before returning from the use case.
type SAMLLogoutStore interface {
	RevokeLocalSAMLSession(context.Context, SAMLLogoutCommand) (SAMLLogoutSnapshot, error)
}

type SAMLLogoutFlow interface {
	BuildLogoutRequest(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error)
}

type SAMLUpstreamLogoutStatus string

const (
	SAMLUpstreamLogoutNotRequested  SAMLUpstreamLogoutStatus = "not_requested"
	SAMLUpstreamLogoutNotConfigured SAMLUpstreamLogoutStatus = "not_configured"
	SAMLUpstreamLogoutReady         SAMLUpstreamLogoutStatus = "redirect_ready"
	SAMLUpstreamLogoutNotConfirmed  SAMLUpstreamLogoutStatus = "not_confirmed"
)

type SAMLLogoutResult struct {
	LocalRevoked bool
	Upstream     SAMLUpstreamLogoutStatus
	RedirectURL  string `json:"-"`
}

func (result SAMLLogoutResult) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLLogoutResult{local_revoked:%t,upstream:%s,redirect_present:%t,material:[REDACTED]}",
		result.LocalRevoked, result.Upstream, result.RedirectURL != "",
	)
}
func (result SAMLLogoutResult) GoString() string { return result.String() }

type SAMLLogoutOptions struct {
	Flow             SAMLLogoutFlow
	Store            SAMLLogoutStore
	OperationTimeout time.Duration
	Now              func() time.Time
}

type SAMLLogout struct {
	flow             SAMLLogoutFlow
	store            SAMLLogoutStore
	operationTimeout time.Duration
	now              func() time.Time
}

func NewSAMLLogout(options SAMLLogoutOptions) (*SAMLLogout, error) {
	if options.Flow == nil || options.Store == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SAMLLogout{
		flow: options.Flow, store: options.Store, operationTimeout: options.OperationTimeout, now: options.Now,
	}, nil
}

func (logout *SAMLLogout) Logout(ctx context.Context, command SAMLLogoutCommand) (SAMLLogoutResult, error) {
	if logout == nil || logout.flow == nil || logout.store == nil || !validSAMLLogoutCommand(command) {
		return SAMLLogoutResult{}, ErrInvalidInput
	}
	operation, cancel, err := logout.operation(ctx)
	if err != nil {
		return SAMLLogoutResult{}, ErrSessionRejected
	}
	defer cancel()
	var returnedSnapshot SAMLLogoutSnapshot
	for range 2 {
		returnedSnapshot, err = logout.store.RevokeLocalSAMLSession(operation, command)
		if err == nil || operation.Err() != nil {
			break
		}
		clear(returnedSnapshot.ProtectedMaterial.Ciphertext)
		returnedSnapshot = SAMLLogoutSnapshot{}
	}
	snapshot := cloneSAMLLogoutSnapshot(returnedSnapshot)
	clear(returnedSnapshot.ProtectedMaterial.Ciphertext)
	defer clear(snapshot.ProtectedMaterial.Ciphertext)
	now := logout.currentTime()
	if err != nil || !validSAMLLogoutSnapshot(command, snapshot, now) {
		return SAMLLogoutResult{}, ErrSessionRejected
	}
	result := SAMLLogoutResult{LocalRevoked: true, Upstream: SAMLUpstreamLogoutNotRequested}
	if !command.RequestUpstream {
		return result, nil
	}
	if !validTenantSAMLConfiguration(snapshot.Configuration) ||
		snapshot.Configuration.Authentication.Provider != snapshot.Provider ||
		snapshot.Configuration.Authentication.BindingID != snapshot.BindingID ||
		snapshot.Configuration.Authentication.Metadata.SLORedirectURL() == "" {
		result.Upstream = SAMLUpstreamLogoutNotConfigured
		return result, nil
	}
	if snapshot.ProtectedMaterial.KeyVersion == 0 || len(snapshot.ProtectedMaterial.Ciphertext) == 0 {
		result.Upstream = SAMLUpstreamLogoutNotConfirmed
		return result, nil
	}
	if now.Sub(snapshot.RevokedAt) > 15*time.Minute {
		result.Upstream = SAMLUpstreamLogoutNotConfirmed
		return result, nil
	}
	buildRequest := federatedsaml.LogoutBuildRequest{
		Configuration: snapshot.Configuration.Authentication,
		SessionID:     snapshot.SessionID,
		MaterialID:    snapshot.MaterialID,
		ProtectedMaterial: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: snapshot.ProtectedMaterial.KeyVersion,
			Ciphertext: append([]byte(nil), snapshot.ProtectedMaterial.Ciphertext...),
		},
		Confirmation: samlLocalLogoutConfirmation{
			provider: snapshot.Provider, bindingID: snapshot.BindingID,
			sessionID: snapshot.SessionID, revokedAt: snapshot.RevokedAt,
		},
	}
	defer clear(buildRequest.ProtectedMaterial.Ciphertext)
	artifact, buildErr := logout.flow.BuildLogoutRequest(operation, buildRequest)
	clear(buildRequest.ProtectedMaterial.Ciphertext)
	if buildErr != nil || artifact.RedirectURL() == "" || artifact.RequestID() == "" || artifact.IssuedAt().IsZero() {
		result.Upstream = SAMLUpstreamLogoutNotConfirmed
		return result, nil
	}
	result.Upstream = SAMLUpstreamLogoutReady
	result.RedirectURL = artifact.RedirectURL()
	return result, nil
}

func (logout *SAMLLogout) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || logout == nil || logout.operationTimeout <= 0 {
		return nil, nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, logout.operationTimeout)
	return bounded, cancel, nil
}

func (logout *SAMLLogout) currentTime() time.Time {
	return logout.now().UTC().Truncate(time.Microsecond)
}

type samlLocalLogoutConfirmation struct {
	provider  identity.ProviderContext
	bindingID identity.EntityID
	sessionID identity.EntityID
	revokedAt time.Time
}

func (confirmation samlLocalLogoutConfirmation) SAMLProvider() identity.ProviderContext {
	return confirmation.provider
}
func (confirmation samlLocalLogoutConfirmation) SAMLBindingID() identity.EntityID {
	return confirmation.bindingID
}
func (confirmation samlLocalLogoutConfirmation) LocalSessionID() identity.EntityID {
	return confirmation.sessionID
}
func (confirmation samlLocalLogoutConfirmation) LocalSessionRevokedAt() time.Time {
	return confirmation.revokedAt
}

func validSAMLLogoutCommand(command SAMLLogoutCommand) bool {
	return validSAMLLogoutEntityID(command.OperationRunID) &&
		validSAMLLogoutEntityID(command.TenantID) &&
		validSAMLLogoutEntityID(command.AuthenticatedUserID) &&
		validSAMLLogoutEntityID(command.SessionID) &&
		command.OperationRunID != command.TenantID &&
		command.OperationRunID != command.AuthenticatedUserID &&
		command.OperationRunID != command.SessionID &&
		command.TenantID != command.AuthenticatedUserID &&
		command.TenantID != command.SessionID &&
		command.AuthenticatedUserID != command.SessionID &&
		validSAMLSuccessorRevision(command.ExpectedVersion)
}

func validSAMLLogoutSnapshot(command SAMLLogoutCommand, snapshot SAMLLogoutSnapshot, now time.Time) bool {
	configurationValid := validTenantSAMLConfiguration(snapshot.Configuration)
	configurationConsistent := !configurationValid ||
		snapshot.Provider == snapshot.Configuration.Authentication.Provider &&
			snapshot.BindingID == snapshot.Configuration.Authentication.BindingID
	materialAbsent := snapshot.ProtectedMaterial.KeyVersion == 0 && len(snapshot.ProtectedMaterial.Ciphertext) == 0
	materialPresent := snapshot.ProtectedMaterial.KeyVersion > 0 &&
		len(snapshot.ProtectedMaterial.Ciphertext) >= 16 &&
		len(snapshot.ProtectedMaterial.Ciphertext) <= maximumSAMLSessionMaterialEnvelope
	return snapshot.OperationRunID == command.OperationRunID && snapshot.TenantID == command.TenantID &&
		snapshot.AuthenticatedUserID == command.AuthenticatedUserID &&
		snapshot.SessionID == command.SessionID && snapshot.PreviousVersion == command.ExpectedVersion &&
		snapshot.Provider.Scope == identity.TenantProviderScope && snapshot.Provider.TenantID == snapshot.TenantID &&
		validSAMLLogoutEntityID(snapshot.Provider.ProviderID) &&
		validSAMLLogoutEntityID(snapshot.BindingID) && validSAMLLogoutEntityID(snapshot.MaterialID) &&
		snapshot.MaterialID != snapshot.OperationRunID && snapshot.MaterialID != snapshot.TenantID &&
		snapshot.MaterialID != snapshot.AuthenticatedUserID && snapshot.MaterialID != snapshot.SessionID &&
		configurationConsistent &&
		(materialAbsent || materialPresent) && validInstant(snapshot.RevokedAt) &&
		validInstant(now) && !snapshot.RevokedAt.After(now)
}

func validSAMLLogoutEntityID(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func cloneSAMLLogoutSnapshot(value SAMLLogoutSnapshot) SAMLLogoutSnapshot {
	value.Configuration = cloneTenantSAMLConfiguration(value.Configuration)
	value.ProtectedMaterial.Ciphertext = append([]byte(nil), value.ProtectedMaterial.Ciphertext...)
	return value
}
