package httpserver

import (
	"errors"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
)

func mapPlatformIdentityBindingPage(
	value platformidentitybinding.BindingPage,
) (contract.PlatformAuthProviderTenantBindingList, error) {
	items := make([]contract.PlatformAuthProviderTenantBinding, len(value.Items))
	for index := range value.Items {
		mapped, err := mapPlatformIdentityBinding(value.Items[index])
		if err != nil {
			return contract.PlatformAuthProviderTenantBindingList{}, err
		}
		items[index] = mapped
	}
	return contract.PlatformAuthProviderTenantBindingList{
		Items: items, NextCursor: value.NextCursor,
	}, nil
}

func mapPlatformIdentityBinding(
	value platformidentitybinding.Binding,
) (contract.PlatformAuthProviderTenantBinding, error) {
	status := contract.PlatformAuthProviderTenantBindingTenantStatus(value.Tenant.Status)
	jitMode := contract.PlatformAuthProviderTenantBindingJitMode(value.JITMode)
	noMatchPolicy := contract.PlatformAuthProviderTenantBindingNoMatchPolicy(value.NoMatchPolicy)
	if !status.Valid() || !jitMode.Valid() || !noMatchPolicy.Valid() ||
		value.Enabled != (value.CurrentAccessEpochID != nil) ||
		value.AuthRevision < 1 || value.MappingRevision < 1 ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		value.Tenant.Version < 1 || value.Tenant.Version > maximumResourceVersion {
		return contract.PlatformAuthProviderTenantBinding{}, errors.New("invalid platform identity binding")
	}
	return contract.PlatformAuthProviderTenantBinding{
		ActivationAvailable:  value.ActivationAvailable,
		ArchivedAt:           utcTimePointer(value.ArchivedAt),
		AuthRevision:         contract.PlatformAuthProviderRevision(value.AuthRevision),
		CreatedAt:            value.CreatedAt.UTC(),
		CurrentAccessEpochId: value.CurrentAccessEpochID,
		Enabled:              value.Enabled,
		Id:                   value.ID,
		LoginKey:             value.LoginKey,
		JitMode:              jitMode,
		NoMatchPolicy:        noMatchPolicy,
		MappingRevision:      contract.PlatformAuthProviderRevision(value.MappingRevision),
		Origin:               contract.PlatformAuthProviderTenantBindingOriginPlatform,
		ProfilePriority:      value.ProfilePriority,
		ProviderId:           value.ProviderID,
		Tenant: contract.PlatformAuthProviderTenantBindingTenant{
			Id: value.Tenant.ID, Name: value.Tenant.Name, Slug: value.Tenant.Slug, Status: status,
			Version: contract.ResourceVersion(value.Tenant.Version),
		},
		UpdatedAt: value.UpdatedAt.UTC(),
		Version:   contract.ResourceVersion(value.Version),
	}, nil
}
