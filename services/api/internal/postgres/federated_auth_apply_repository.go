package postgres

import (
	"context"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const applyFederatedAuthenticationSQL = `select app.apply_federated_authentication_v1($1::jsonb)`

var _ federatedauth.TransactionalApplier = (*FederatedAuthRepository)(nil)
var _ federatedauth.OIDCTransactionalApplier = (*FederatedAuthRepository)(nil)
var _ federatedauth.SAMLTransactionalApplier = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) ApplyFederatedAuthentication(
	ctx context.Context,
	request federatedauth.ApplyRequest,
) (federatedauth.ApplyResult, error) {
	return repository.applyFederatedAuthentication(ctx, request, nil, identity.EntityID{})
}

func (repository *FederatedAuthRepository) ApplyOIDCAuthentication(
	ctx context.Context,
	request federatedauth.OIDCApplyRequest,
) (federatedauth.ApplyResult, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	command, err := federatedOIDCApplyToWire(request)
	if err != nil {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	defer clearFederatedApplyCommandWire(&command)
	var response federatedApplyResultWire
	defer clearFederatedApplyResultWire(&response)
	if err := repository.queryJSON(ctx, applyFederatedAuthenticationSQL, command, &response); err != nil {
		return federatedauth.ApplyResult{}, err
	}
	return federatedApplyResultFromWire(response, command)
}

func (repository *FederatedAuthRepository) ApplySAMLAuthentication(
	ctx context.Context,
	request federatedauth.SAMLApplyRequest,
) (federatedauth.ApplyResult, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil ||
		request.Apply.Authentication.Protocol != federatedauth.ProtocolSAML ||
		request.MaterialID == (identity.EntityID{}) || request.MaterialID[6]>>4 != 7 ||
		request.MaterialID[8]&0xc0 != 0x80 || request.Apply.Authentication.SAMLConsumption == nil ||
		request.Apply.Authentication.SAMLConsumption.MaterialID != request.MaterialID {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	ownerID := request.Apply.Session.SessionID()
	if request.Apply.Disposition == federatedauth.ApplyContinuation {
		ownerID = request.Apply.Continuation.ContinuationID()
	}
	if ownerID == (identity.EntityID{}) || request.MaterialID == ownerID {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	if request.SessionMaterial == (federatedsaml.SessionMaterial{}) {
		return repository.applyFederatedAuthentication(ctx, request.Apply, nil, request.MaterialID)
	}
	if repository.samlSessionSealer == nil {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	provider, bindingID, ok := samlApplyProvider(request.Apply.Authentication)
	if !ok || !validSAMLApplySessionMaterial(request.SessionMaterial) {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	protected, err := repository.samlSessionSealer.SealSAMLSession(ctx, federatedauth.SAMLSessionMaterialSealContext{
		Provider: provider, BindingID: bindingID, MaterialID: request.MaterialID,
	}, request.SessionMaterial)
	if err != nil || ctx.Err() != nil || protected.KeyVersion == 0 || len(protected.Ciphertext) < 16 ||
		len(protected.Ciphertext) > 16*1024 {
		clear(protected.Ciphertext)
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	defer clear(protected.Ciphertext)
	return repository.applyFederatedAuthentication(ctx, request.Apply, &protected, request.MaterialID)
}

func (repository *FederatedAuthRepository) applyFederatedAuthentication(
	ctx context.Context,
	request federatedauth.ApplyRequest,
	protected *federatedsaml.ProtectedSessionMaterial,
	materialID identity.EntityID,
) (federatedauth.ApplyResult, error) {
	command, err := federatedApplyToWire(request, protected, materialID)
	if err != nil {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	defer clearFederatedApplyCommandWire(&command)
	var response federatedApplyResultWire
	defer clearFederatedApplyResultWire(&response)
	if err := repository.queryJSON(ctx, applyFederatedAuthenticationSQL, command, &response); err != nil {
		return federatedauth.ApplyResult{}, err
	}
	return federatedApplyResultFromWire(response, command)
}

func samlApplyProvider(
	value federatedauth.ApplyAuthenticationProjection,
) (identity.ProviderContext, identity.EntityID, bool) {
	if value.SAMLConsumption == nil {
		return identity.ProviderContext{}, identity.EntityID{}, false
	}
	pins := value.SAMLConsumption.Pins
	return pins.Provider, pins.BindingID, pins.Provider.ProviderID != (identity.EntityID{}) &&
		pins.BindingID != (identity.EntityID{})
}

func validSAMLApplySessionMaterial(value federatedsaml.SessionMaterial) bool {
	if (value.NameID == "") != (value.NameIDFormat == "") || value == (federatedsaml.SessionMaterial{}) {
		return false
	}
	return (value.NameID == "" || validFederatedPublicText(value.NameID, 16*1024)) &&
		(value.NameID == "" || value.NameIDFormat == federatedsaml.PersistentNameIDFormat) &&
		(value.SessionIndex == "" || validFederatedPublicText(value.SessionIndex, 2048))
}

func clearFederatedApplyResultWire(value *federatedApplyResultWire) {
	if value == nil {
		return
	}
	clear(value.OperationDigest)
	*value = federatedApplyResultWire{}
}
