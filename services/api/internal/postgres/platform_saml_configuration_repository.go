package postgres

import (
	"context"
	"regexp"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	beginPlatformSAMLDirectSQL   = `select app.begin_platform_saml_authentication_v1($1::jsonb)`
	loadPlatformSAMLStartSQL     = `select app.load_platform_saml_start_configuration_v1($1::jsonb)`
	resolvePlatformSAMLDirectSQL = `select app.resolve_platform_saml_authentication_configuration_v1($1::jsonb)`
)

var platformSAMLLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

type platformSAMLBeginWire struct {
	LoginKey string `json:"loginKey"`
}

type platformSAMLStartConfigurationLookupWire struct {
	ProviderID string                       `json:"providerId"`
	Pins       platformSAMLProtocolPinsWire `json:"pins"`
}

type platformSAMLCallbackConfigurationLookupWire struct {
	TransactionID   []byte                       `json:"transactionId"`
	ExpectedVersion uint64                       `json:"expectedVersion"`
	Pins            platformSAMLProtocolPinsWire `json:"pins"`
}

var (
	_ platformsamlauth.StartSource         = (*FederatedAuthRepository)(nil)
	_ platformsamlauth.ConfigurationSource = (*FederatedAuthRepository)(nil)
)

func (repository *FederatedAuthRepository) BeginDirectSAMLLogin(
	ctx context.Context,
	authority platformsamlauth.StartAuthority,
) (platformsamlauth.StartGrant, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		!platformSAMLLoginKeyPattern.MatchString(authority.Lookup.LoginKey) {
		return platformsamlauth.StartGrant{}, errPlatformSAMLPersistence
	}
	var response directPlatformSAMLConfigurationWire
	defer clearPlatformSAMLConfigurationWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, beginPlatformSAMLDirectSQL,
		platformSAMLBeginWire{LoginKey: authority.Lookup.LoginKey}, &response,
		maximumPlatformSAMLWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.StartGrant{}, errPlatformSAMLPersistence
	}
	snapshot, providerKey, err := platformSAMLConfigurationFromWire(response)
	if err != nil || providerKey != authority.Lookup.LoginKey {
		return platformsamlauth.StartGrant{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.StartGrant{Authority: authority, Pins: snapshot.Pins}, nil
}

func (repository *FederatedAuthRepository) LoadDirectSAMLStartConfiguration(
	ctx context.Context,
	grant platformsamlauth.StartGrant,
) (platformsamlauth.StartConfigurationSnapshot, error) {
	wirePins, err := platformSAMLProtocolPinsToWire(grant.Pins.Protocol)
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || err != nil {
		return platformsamlauth.StartConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	lookup := platformSAMLStartConfigurationLookupWire{
		ProviderID: entityIDWire(grant.Pins.Protocol.Provider.ProviderID), Pins: wirePins,
	}
	defer clearPlatformSAMLProtocolPinsWire(&lookup.Pins)
	var response directPlatformSAMLConfigurationWire
	defer clearPlatformSAMLConfigurationWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, loadPlatformSAMLStartSQL, lookup, &response, maximumPlatformSAMLWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.StartConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	snapshot, _, err := platformSAMLConfigurationFromWire(response)
	if err != nil || snapshot.Pins != grant.Pins {
		return platformsamlauth.StartConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.StartConfigurationSnapshot{Grant: grant, Configuration: snapshot}, nil
}

func (repository *FederatedAuthRepository) ResolveDirectSAMLCallbackConfiguration(
	ctx context.Context,
	lookup platformsamlauth.CallbackConfigurationLookup,
) (platformsamlauth.CallbackConfigurationSnapshot, error) {
	// The callback port intentionally carries protocol pins only. The database
	// returns the complete floor pins persisted in the transaction row; they
	// are never reconstructed from current live policy state.
	wirePins, err := platformSAMLProtocolPinsToWire(lookup.Transaction.Pins)
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || err != nil {
		return platformsamlauth.CallbackConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLCallbackConfigurationLookupWire{
		TransactionID:   append([]byte(nil), lookup.Transaction.TransactionID[:]...),
		ExpectedVersion: lookup.Transaction.ExpectedVersion,
		Pins:            wirePins,
	}
	defer clear(wire.TransactionID)
	defer clearPlatformSAMLProtocolPinsWire(&wire.Pins)
	var response directPlatformSAMLConfigurationWire
	defer clearPlatformSAMLConfigurationWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, resolvePlatformSAMLDirectSQL, wire, &response, maximumPlatformSAMLWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.CallbackConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	snapshot, _, err := platformSAMLConfigurationFromWire(response)
	if err != nil || response.DirectPins == nil || snapshot.Pins.Protocol != lookup.Transaction.Pins {
		return platformsamlauth.CallbackConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	directPins, pinsErr := platformSAMLDirectPinsFromWire(*response.DirectPins)
	if pinsErr != nil || directPins.Protocol != lookup.Transaction.Pins || directPins != snapshot.Pins {
		return platformsamlauth.CallbackConfigurationSnapshot{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.CallbackConfigurationSnapshot{Lookup: lookup, Configuration: snapshot}, nil
}

var _ federatedsaml.CallbackConfigurationResolver = nil
