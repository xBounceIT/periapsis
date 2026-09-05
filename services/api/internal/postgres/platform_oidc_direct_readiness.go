package postgres

import "context"

const platformOIDCDirectReadinessSQL = `select app.platform_oidc_direct_runtime_schema_readiness_v49()`

// ReadyDirectPlatformOIDC verifies the sealed, direct-platform OIDC runtime
// independently from tenant federation. A missing, stale, or inaccessible
// schema is never treated as a disabled-but-usable login path.
func (repository *FederatedAuthRepository) ReadyDirectPlatformOIDC(ctx context.Context) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errFederatedAuthPersistence
	}
	var ready bool
	if err := repository.queryer.QueryRow(ctx, platformOIDCDirectReadinessSQL).Scan(&ready); err != nil ||
		ctx.Err() != nil || !ready {
		return errFederatedAuthPersistence
	}
	return nil
}
