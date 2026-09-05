package httpserver

import (
	"context"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func tenantFederationAdministrationServiceIsNil(service TenantFederationAdministrationService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

type unavailableTenantFederationAdministrationService struct{}

func (unavailableTenantFederationAdministrationService) List(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	identityprovider.FederationListInput,
) (identityprovider.FederationProviderPage, error) {
	return identityprovider.FederationProviderPage{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) Get(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
) (identityprovider.FederationProvider, error) {
	return identityprovider.FederationProvider{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) Create(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	identityprovider.FederationCreateInput,
) (identityprovider.FederationCreateResult, error) {
	return identityprovider.FederationCreateResult{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) Update(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationUpdateInput,
) (identityprovider.FederationProvider, error) {
	return identityprovider.FederationProvider{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) Archive(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationArchiveInput,
) (int64, error) {
	return 0, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ReplaceOIDCClientSecret(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceOIDCSecretInput,
) (identityprovider.FederationSecretMutationReceipt, error) {
	return identityprovider.FederationSecretMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ClearOIDCClientSecret(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationClearOIDCSecretInput,
) (identityprovider.FederationSecretMutationReceipt, error) {
	return identityprovider.FederationSecretMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) RefreshOIDCTrustDocuments(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationOIDCTrustDocumentsInput,
) (identityprovider.FederationOIDCTrustDocumentsReceipt, error) {
	return identityprovider.FederationOIDCTrustDocumentsReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ReplaceSAMLMetadata(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceSAMLMetadataInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ReplaceSAMLSPCredential(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceSAMLSPCredentialInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ClearSAMLSPCredential(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationClearSAMLSPCredentialInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) GetMappingPolicy(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
) (identityprovider.FederationMappingPolicy, error) {
	return identityprovider.FederationMappingPolicy{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ReplaceMappingPolicy(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceMappingPolicyInput,
) (identityprovider.FederationPolicyMutationReceipt, error) {
	return identityprovider.FederationPolicyMutationReceipt{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) GetAssurancePolicy(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
) (identityprovider.FederationAssurancePolicy, error) {
	return identityprovider.FederationAssurancePolicy{}, identityprovider.ErrUnavailable
}

func (unavailableTenantFederationAdministrationService) ReplaceAssurancePolicy(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceAssurancePolicyInput,
) (identityprovider.FederationPolicyMutationReceipt, error) {
	return identityprovider.FederationPolicyMutationReceipt{}, identityprovider.ErrUnavailable
}
