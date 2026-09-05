package federatedoidc

import (
	"fmt"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// SessionMaterial owns the minimum token bundle that may outlive the login
// request. It can be consumed exactly once; all other token-bundle material is
// cleared before this value is returned.
type SessionMaterial struct {
	state *sessionMaterialState
}

type sessionMaterialState struct {
	mu           sync.Mutex
	materialID   identity.EntityID
	idToken      []byte
	refreshToken []byte
	accessExpiry time.Time
	destroyed    bool
	consumed     bool
}

// OwnedSessionTokens transfers plaintext ownership to the persistence
// protection boundary. Call Destroy immediately after sealing.
type OwnedSessionTokens struct {
	IDToken         []byte `json:"-"`
	RefreshToken    []byte `json:"-"`
	AccessExpiresAt time.Time
}

func (tokens OwnedSessionTokens) String() string {
	return fmt.Sprintf(
		"federatedoidc.OwnedSessionTokens{id_token:%t,refresh_token:%t,access_expiry:%t,material:[REDACTED]}",
		len(tokens.IDToken) != 0, len(tokens.RefreshToken) != 0, !tokens.AccessExpiresAt.IsZero(),
	)
}

func (tokens OwnedSessionTokens) GoString() string { return tokens.String() }

func (tokens *OwnedSessionTokens) Destroy() {
	if tokens == nil {
		return
	}
	clear(tokens.IDToken)
	clear(tokens.RefreshToken)
	tokens.IDToken = nil
	tokens.RefreshToken = nil
	tokens.AccessExpiresAt = time.Time{}
}

func (material *SessionMaterial) MaterialID() identity.EntityID {
	if material == nil || material.state == nil {
		return identity.EntityID{}
	}
	material.state.mu.Lock()
	defer material.state.mu.Unlock()
	if material.state.destroyed || material.state.consumed {
		return identity.EntityID{}
	}
	return material.state.materialID
}

func (material *SessionMaterial) HasIDToken() bool {
	if material == nil || material.state == nil {
		return false
	}
	material.state.mu.Lock()
	defer material.state.mu.Unlock()
	return !material.state.destroyed && !material.state.consumed && len(material.state.idToken) != 0
}

func (material *SessionMaterial) HasRefreshToken() bool {
	if material == nil || material.state == nil {
		return false
	}
	material.state.mu.Lock()
	defer material.state.mu.Unlock()
	return !material.state.destroyed && !material.state.consumed && len(material.state.refreshToken) != 0
}

// TakeTokens moves the only plaintext token slices to the caller. A replay or
// any call after Destroy fails closed without returning material.
func (material *SessionMaterial) TakeTokens() (*OwnedSessionTokens, bool) {
	if material == nil || material.state == nil {
		return nil, false
	}
	material.state.mu.Lock()
	defer material.state.mu.Unlock()
	if material.state.destroyed || material.state.consumed ||
		len(material.state.idToken) == 0 && len(material.state.refreshToken) == 0 {
		return nil, false
	}
	tokens := &OwnedSessionTokens{
		IDToken: material.state.idToken, RefreshToken: material.state.refreshToken,
		AccessExpiresAt: material.state.accessExpiry,
	}
	material.state.idToken = nil
	material.state.refreshToken = nil
	material.state.accessExpiry = time.Time{}
	material.state.materialID = identity.EntityID{}
	material.state.consumed = true
	return tokens, true
}

func (material *SessionMaterial) Destroy() {
	if material == nil || material.state == nil {
		return
	}
	material.state.mu.Lock()
	defer material.state.mu.Unlock()
	clear(material.state.idToken)
	clear(material.state.refreshToken)
	material.state.idToken = nil
	material.state.refreshToken = nil
	material.state.accessExpiry = time.Time{}
	material.state.materialID = identity.EntityID{}
	material.state.destroyed = true
}

func (material *SessionMaterial) String() string {
	return fmt.Sprintf(
		"federatedoidc.SessionMaterial{id_token:%t,refresh_token:%t,material:[REDACTED]}",
		material.HasIDToken(), material.HasRefreshToken(),
	)
}

func (material *SessionMaterial) GoString() string { return material.String() }

// TakeSessionMaterial validates the exact pinned configuration and moves only
// useful long-lived material out of the exchange bundle. ID tokens are kept
// only for a configured end-session endpoint; refresh tokens only for explicit
// tenant opt-in. Access tokens are always cleared and never leave the kernel.
func (flow *Flow) TakeSessionMaterial(
	configuration AuthorizationConfiguration,
	bundle *TokenBundle,
) (*SessionMaterial, error) {
	if flow == nil || bundle == nil || bundle.state == nil {
		return nil, ErrUpstreamArtifactRejected
	}
	configuration, _, err := flow.normalizeConfiguration(configuration)
	if err != nil {
		return nil, ErrUpstreamArtifactRejected
	}
	endpoints := configuration.Discovery.Endpoints()
	wantIDToken := endpoints.EndSession != ""
	wantRefreshToken := configuration.AllowRefreshToken

	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	state := bundle.state
	if state.destroyed || state.owner != flow || state.pins != transactionPins(configuration) ||
		state.useUserInfo != configuration.UseUserInfo ||
		state.postLogoutRedirectURI != configuration.PostLogoutRedirectURI ||
		!validMaterialID(state.materialID) || len(state.idToken) == 0 || len(state.accessToken) == 0 ||
		(len(state.refreshToken) != 0) != configuration.AllowRefreshToken {
		return nil, ErrUpstreamArtifactRejected
	}

	var material *SessionMaterial
	if wantIDToken || wantRefreshToken {
		materialState := &sessionMaterialState{materialID: state.materialID}
		if wantIDToken {
			materialState.idToken = state.idToken
			state.idToken = nil
		}
		if wantRefreshToken {
			materialState.refreshToken = state.refreshToken
			materialState.accessExpiry = state.accessExpiry
			state.refreshToken = nil
		}
		material = &SessionMaterial{state: materialState}
	}

	clear(state.idToken)
	clear(state.accessToken)
	clear(state.refreshToken)
	state.idToken = nil
	state.accessToken = nil
	state.refreshToken = nil
	state.scopes = nil
	state.tokenType = ""
	state.accessExpiry = time.Time{}
	state.transactionID = TransactionID{}
	state.materialID = identity.EntityID{}
	state.pins = TransactionPins{}
	state.owner = nil
	state.useUserInfo = false
	state.postLogoutRedirectURI = ""
	state.destroyed = true
	return material, nil
}
