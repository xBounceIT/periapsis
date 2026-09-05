package federatedauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

// OIDCLogoutMaterialOpener reconstructs one refresh-token revocation request
// only after the retry row has been atomically claimed. Plaintext ownership is
// transferred to the executor, which clears it on every return.
type OIDCLogoutMaterialOpener struct {
	tokens  TokenProtector
	secrets ClientSecretSource
}

func NewOIDCLogoutMaterialOpener(
	tokens TokenProtector,
	secrets ClientSecretSource,
) (*OIDCLogoutMaterialOpener, error) {
	if tokens == nil || secrets == nil {
		return nil, ErrInvalidOptions
	}
	return &OIDCLogoutMaterialOpener{tokens: tokens, secrets: secrets}, nil
}

func (opener *OIDCLogoutMaterialOpener) OpenOIDCLogoutRetry(
	ctx context.Context,
	job LogoutRetryJob,
) (federatedoidc.StoredRevocationMaterial, error) {
	if opener == nil || opener.tokens == nil || opener.secrets == nil || ctx == nil || ctx.Err() != nil ||
		!validLogoutJobShape(job, job.JobID) {
		return federatedoidc.StoredRevocationMaterial{}, ErrUpstreamLogoutRetry
	}
	token, err := opener.tokens.OpenRefreshToken(ctx, RefreshTokenContext{
		TenantID: job.TenantID, MaterialID: job.MaterialID, SessionFamilyID: job.SessionFamilyID,
		Provider: job.Provider, BindingID: job.BindingID, Generation: job.RefreshGeneration,
	}, job.OpaqueReference)
	if err != nil || !validRefreshToken(token) {
		clear(token)
		return federatedoidc.StoredRevocationMaterial{}, ErrUpstreamLogoutRetry
	}
	digest := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(digest[:], job.TokenDigest[:]) != 1 {
		clear(token)
		return federatedoidc.StoredRevocationMaterial{}, ErrUpstreamLogoutRetry
	}
	clientBindingID := job.BindingID
	clientAdmission := job.Admission
	if job.Provider.Scope == identity.TenantProviderScope {
		clientAdmission = identity.TenantAdmissionContext{}
	}
	if job.Provider.Scope == identity.PlatformProviderScope {
		clientBindingID = identity.EntityID{}
	}
	secret, err := opener.secrets.OpenOIDCClientSecret(ctx, ClientSecretContext{
		Provider: job.Provider, Admission: clientAdmission,
		BindingID: clientBindingID, Revision: job.ClientSecretRevision,
		Maintenance: OIDCMaintenanceSecretProof{
			Kind: OIDCMaintenanceSecretLogoutRetry, MaterialID: job.MaterialID,
			SessionFamilyID: job.SessionFamilyID, ClaimVersion: job.ClaimVersion,
			RefreshGeneration: job.RefreshGeneration, JobID: job.JobID, Attempt: job.Attempt,
		},
	})
	if err != nil || len(secret) == 0 {
		clear(token)
		clear(secret)
		return federatedoidc.StoredRevocationMaterial{}, ErrUpstreamLogoutRetry
	}
	return federatedoidc.StoredRevocationMaterial{
		EndpointURL: job.Endpoint, TokenKind: federatedoidc.TokenRefresh,
		Token: token, ClientAuthentication: job.ClientAuthentication,
		ClientID: job.ClientID, ClientSecret: secret,
	}, nil
}

func (opener *OIDCLogoutMaterialOpener) String() string {
	return "federatedauth.OIDCLogoutMaterialOpener{material:[REDACTED]}"
}
func (opener *OIDCLogoutMaterialOpener) GoString() string { return opener.String() }
