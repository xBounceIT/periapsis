package httpserver

import (
	"errors"
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func decodePlatformIdentityAccountPrelinkBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderAccountPrelinkRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"userId", "issuer", "subject"},
		[]string{"userId", "issuer", "subject"},
	)
	if err != nil {
		return err
	}
	if err := requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"userId", "issuer", "subject"},
		nil,
		nil,
		nil,
	); err != nil {
		return err
	}
	if destination == nil || destination.Issuer == nil || destination.Subject == nil {
		return errors.New("platform identity-account prelink body is incomplete")
	}
	return nil
}

func decodePlatformIdentityAccountRetireBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderAccountRetireRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedVersion"},
		[]string{"expectedVersion"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		nil,
		nil,
		nil,
		[]string{"expectedVersion"},
	)
}
