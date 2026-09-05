package main

import (
	"bytes"
	"crypto/x509"
	"net"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type directPlatformOIDCRuntimeRepositoryStub struct {
	platformoidcauth.DirectOIDCTransactionPersistence
	platformoidcauth.DirectOIDCStartSource
	platformoidcauth.DirectOIDCConfigurationSource
	platformoidcauth.DirectOIDCClientSecretEnvelopeSource
	platformoidcauth.DirectPlatformPlanningStateSource
	platformoidcauth.DirectOIDCAtomicApplyPort
	platformoidcauth.DirectTOTPStore
	httpserver.PlatformOIDCReadiness
}

type directPlatformOIDCTokenEndpointStub struct {
	federatedoidc.TokenEndpointPort
}

type directPlatformOIDCCredentialIssuerStub struct {
	federatedauth.ApplyCredentialIssuer
}

type directPlatformOIDCTOTPVerifierStub struct {
	platformoidcauth.DirectTOTPVerifier
}

func TestDirectPlatformOIDCRuntimeComposesOnlyCompleteDedicatedGraph(t *testing.T) {
	t.Parallel()
	options := directPlatformOIDCRuntimeFixture(t)
	runtime, err := newDirectPlatformOIDCRuntime(options)
	if err != nil || runtime == nil {
		t.Fatalf("newDirectPlatformOIDCRuntime() = %v, %v", runtime, err)
	}
	if runtime.String() != "httpserver.RuntimePlatformOIDCBrowserAuthentication{configured:true}" {
		t.Fatalf("runtime = %s", runtime)
	}
}

func TestDirectPlatformOIDCRuntimeRejectsPartialOrCrossPathComposition(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*directPlatformOIDCRuntimeOptions){
		"missing direct repository": func(options *directPlatformOIDCRuntimeOptions) {
			options.Repository = nil
		},
		"typed nil direct repository": func(options *directPlatformOIDCRuntimeOptions) {
			var repository *directPlatformOIDCRuntimeRepositoryStub
			options.Repository = repository
		},
		"typed nil token endpoint": func(options *directPlatformOIDCRuntimeOptions) {
			var endpoint *directPlatformOIDCTokenEndpointStub
			options.TokenEndpoint = endpoint
		},
		"missing session sealer": func(options *directPlatformOIDCRuntimeOptions) {
			options.SessionSealer = nil
		},
		"invalid start protection": func(options *directPlatformOIDCRuntimeOptions) {
			options.StartKey = bytes.Repeat([]byte{0x00}, 32)
		},
		"wrong callback base path": func(options *directPlatformOIDCRuntimeOptions) {
			options.PublicOrigin = "https://app.example.test/base"
		},
		"invalid operation timeout": func(options *directPlatformOIDCRuntimeOptions) {
			options.OperationTimeout = 99 * time.Millisecond
		},
		"invalid direct challenge ttl": func(options *directPlatformOIDCRuntimeOptions) {
			options.ChallengeTTL = 11 * time.Minute
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := directPlatformOIDCRuntimeFixture(t)
			mutate(&options)
			if runtime, err := newDirectPlatformOIDCRuntime(options); err == nil || runtime != nil {
				t.Fatalf("newDirectPlatformOIDCRuntime() = %v, %v", runtime, err)
			}
		})
	}
}

func directPlatformOIDCRuntimeFixture(t *testing.T) directPlatformOIDCRuntimeOptions {
	t.Helper()
	const operationTimeout = 2 * time.Second
	keyring, err := identity.NewKeyring(1, map[int16][]byte{
		1: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	httpClient, err := federatedauth.NewDeploymentHTTPClient(federatedauth.DeploymentHTTPOptions{
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		AllowedHTTPSPorts: []uint16{443}, RootCAs: x509.NewCertPool(),
		OperationTimeout: operationTimeout, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatalf("NewDeploymentHTTPClient() error = %v", err)
	}
	trust, err := federatedoidc.New(federatedoidc.Options{
		HTTP: httpClient, Limits: federatedoidc.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("federatedoidc.New() error = %v", err)
	}
	protector, err := federatedauth.NewIdentityPKCEVerifierProtector(keyring)
	if err != nil {
		t.Fatalf("NewIdentityPKCEVerifierProtector() error = %v", err)
	}
	sessionSealer, err := federatedauth.NewIdentityOIDCSessionTokenProtector(keyring)
	if err != nil {
		t.Fatalf("NewIdentityOIDCSessionTokenProtector() error = %v", err)
	}
	return directPlatformOIDCRuntimeOptions{
		Repository:        &directPlatformOIDCRuntimeRepositoryStub{},
		Trust:             trust,
		VerifierProtector: protector,
		TokenEndpoint:     &directPlatformOIDCTokenEndpointStub{},
		IdentityKeyring:   keyring,
		StartKey:          bytes.Repeat([]byte{0x52}, 32),
		Credentials:       &directPlatformOIDCCredentialIssuerStub{},
		SessionSealer:     sessionSealer,
		TOTPVerifier:      &directPlatformOIDCTOTPVerifierStub{},
		PublicOrigin:      "https://app.example.test",
		Policy:            federatedoidc.DefaultFlowPolicy(),
		OperationTimeout:  operationTimeout,
		ChallengeTTL:      5 * time.Minute,
		Now: func() time.Time {
			return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		},
	}
}
