package httpserver

import (
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func decodePlatformIdentityBindingCreateBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderTenantBindingCreateRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"tenantId", "loginKey", "profilePriority"},
		[]string{"tenantId", "loginKey", "profilePriority"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"tenantId", "loginKey"},
		nil,
		nil,
		[]string{"profilePriority"},
	)
}

func decodePlatformIdentityBindingUpdateBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderTenantBindingPatchRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedTenantVersion", "expectedVersion", "loginKey", "profilePriority"},
		[]string{"expectedTenantVersion", "expectedVersion", "loginKey", "profilePriority"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"loginKey"},
		nil,
		nil,
		[]string{"expectedTenantVersion", "expectedVersion", "profilePriority"},
	)
}

func decodePlatformIdentityBindingArchiveBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderTenantBindingArchiveRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedTenantVersion", "expectedVersion"},
		[]string{"expectedTenantVersion", "expectedVersion"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object, nil, nil, nil, []string{"expectedTenantVersion", "expectedVersion"},
	)
}

func decodePlatformIdentityBindingActivationBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderTenantBindingActivationRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedTenantVersion", "expectedVersion", "jitMode", "noMatchPolicy"},
		[]string{"expectedTenantVersion", "expectedVersion", "jitMode", "noMatchPolicy"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"jitMode", "noMatchPolicy"},
		nil,
		nil,
		[]string{"expectedTenantVersion", "expectedVersion"},
	)
}

func decodePlatformIdentityBindingDeactivationBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderTenantBindingDeactivationRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedTenantVersion", "expectedVersion"},
		[]string{"expectedTenantVersion", "expectedVersion"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object, nil, nil, nil, []string{"expectedTenantVersion", "expectedVersion"},
	)
}
