package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestFederatedAuthRepositoryLoadsOnlyExactPublicTenantSAMLMetadata(t *testing.T) {
	t.Parallel()
	tenantID := mustPostgresUUIDv7(t)
	providerID := mustPostgresUUIDv7(t)
	bindingID := mustPostgresUUIDv7(t)
	keyID := mustPostgresUUIDv7(t)
	observedAt := time.Date(2026, time.September, 3, 18, 0, 0, 0, time.UTC)
	wire := tenantSAMLSPMetadataResponseWire{
		Found: true,
		Projection: &tenantSAMLSPMetadataProjectionWire{
			TenantSlug: "acme-soc", LoginKey: "workforce_saml", TenantID: tenantID,
			ProviderID: providerID, BindingID: bindingID, ProviderVersion: 8, BindingVersion: 9,
			ConfigurationRevision: 10, SecurityRevision: 11, PlanRevision: 12,
			AuthorizationRevision: 13, SPEntityID: "https://console.example.test/api/v1/auth/federated/saml/acme-soc/workforce_saml/metadata",
			ACSURL: "https://console.example.test/api/v1/auth/federated/saml/acs", SPKeyRevision: 4,
			RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
			SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
			SubjectSource: federatedsaml.SubjectPersistentNameID,
			TenantActive:  true, ProviderEnabled: true, BindingEnabled: true, PolicyEnabled: true,
			AccessEpochLive: true, ObservedAt: observedAt,
			Certificates: []tenantSAMLPublicCertificateWire{{
				TenantID: tenantID, ProviderID: providerID, BindingID: bindingID, KeyID: keyID,
				KeyRevision: 4, CertificateSequence: 0, CertificateDER: []byte{0x30, 0x01, 0x00},
			}},
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	queryCalls := 0
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queryCalls++
		if query != loadTenantSAMLSPMetadataSQL || len(arguments) != 1 {
			t.Fatalf("query = %q, arguments = %#v", query, arguments)
		}
		request, ok := arguments[0].([]byte)
		if !ok {
			t.Fatalf("request type = %T", arguments[0])
		}
		var locator tenantSAMLSPMetadataLookupWire
		if err := json.Unmarshal(request, &locator); err != nil || locator.TenantSlug != "acme-soc" ||
			locator.LoginKey != "workforce_saml" {
			t.Fatalf("locator = %#v, error = %v", locator, err)
		}
		return federatedAuthRowFunc(func(destinations ...any) error {
			if len(destinations) != 1 {
				return errors.New("unexpected destination count")
			}
			*destinations[0].(*[]byte) = append([]byte(nil), encoded...)
			return nil
		})
	}}}

	projection, found, err := repository.LoadTenantSAMLMetadata(
		context.Background(), "acme-soc", "workforce_saml",
	)
	if err != nil || !found || queryCalls != 1 || projection.TenantID != identity.EntityID(tenantID) ||
		projection.ProviderID != identity.EntityID(providerID) || projection.BindingID != identity.EntityID(bindingID) ||
		projection.SPKeyRevision != 4 || len(projection.Certificates) != 1 ||
		projection.Certificates[0].Context.KeyID != identity.EntityID(keyID) ||
		projection.Certificates[0].CertificateSequence != 0 {
		t.Fatalf("LoadTenantSAMLMetadata() = (%#v, %t, %v), calls = %d", projection, found, err, queryCalls)
	}
	clearTenantSAMLMetadataProjection(&projection)
}

func TestFederatedAuthRepositoryRejectsTenantSAMLMetadataProjectionSubstitution(t *testing.T) {
	t.Parallel()
	response := tenantSAMLSPMetadataResponseWire{
		Found: true,
		Projection: &tenantSAMLSPMetadataProjectionWire{
			TenantSlug: "other-tenant", LoginKey: "workforce_saml",
			TenantID: mustPostgresUUIDv7(t), ProviderID: mustPostgresUUIDv7(t), BindingID: mustPostgresUUIDv7(t),
			ProviderVersion: 1, BindingVersion: 1, ConfigurationRevision: 1, SecurityRevision: 1,
			PlanRevision: 1, AuthorizationRevision: 1, SPKeyRevision: 1,
			Certificates: []tenantSAMLPublicCertificateWire{{
				TenantID: mustPostgresUUIDv7(t), ProviderID: mustPostgresUUIDv7(t), BindingID: mustPostgresUUIDv7(t),
				KeyID: mustPostgresUUIDv7(t), KeyRevision: 1, CertificateDER: []byte{1},
			}},
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		return federatedAuthRowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = append([]byte(nil), encoded...)
			return nil
		})
	}}}
	if _, found, err := repository.LoadTenantSAMLMetadata(
		context.Background(), "acme-soc", "workforce_saml",
	); found || !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("substituted projection result = found:%t error:%v", found, err)
	}
}

func TestFederatedAuthRepositoryRejectsNonCanonicalTenantSAMLMetadataEnvelope(t *testing.T) {
	t.Parallel()
	for _, document := range [][]byte{
		[]byte(`{"found":false,"projection":{}}`),
		[]byte(`{"found":false,"privateKey":"forbidden"}`),
		[]byte(`{"found":true}`),
	} {
		document := append([]byte(nil), document...)
		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			context.Context,
			string,
			...any,
		) pgx.Row {
			return federatedAuthRowFunc(func(destinations ...any) error {
				*destinations[0].(*[]byte) = append([]byte(nil), document...)
				return nil
			})
		}}}
		if _, found, err := repository.LoadTenantSAMLMetadata(
			context.Background(), "acme-soc", "workforce_saml",
		); found || !errors.Is(err, errFederatedAuthPersistence) {
			t.Fatalf("non-canonical envelope %s result = found:%t error:%v", document, found, err)
		}
	}
}

func TestTenantSAMLMetadataFunctionsUseDedicatedAllowlists(t *testing.T) {
	t.Parallel()
	if loadTenantSAMLSPMetadataSQL != `select app.get_tenant_saml_sp_metadata_v1($1::jsonb)` {
		t.Fatalf("tenant SAML metadata ABI = %q", loadTenantSAMLSPMetadataSQL)
	}
	for _, function := range []string{
		"app.prepare_tenant_saml_metadata_v1",
		"app.replace_tenant_saml_metadata_v1",
		"app.prepare_tenant_saml_sp_credential_v1",
		"app.replace_tenant_saml_sp_credential_v1",
		"app.clear_tenant_saml_sp_credential_v1",
	} {
		if !slices.Contains(federationAdministrationFunctions, function) {
			t.Fatalf("tenant SAML administration ABI %q is not allowlisted", function)
		}
	}
	if slices.Contains(federationAdministrationFunctions, "app.get_tenant_saml_sp_metadata_v1") {
		t.Fatal("anonymous tenant SAML metadata ABI must not share the administration writer allowlist")
	}
}
