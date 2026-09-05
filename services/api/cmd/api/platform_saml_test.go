package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

type directPlatformSAMLRuntimeRepositoryStub struct {
	platformsamladapter.DirectSAMLTransactionPersistence
	platformsamladapter.DirectSAMLSPKeyEnvelopeRepository
	platformsamlauth.StartSource
	platformsamlauth.ConfigurationSource
	platformsamlauth.PlanningStateSource
	platformsamlauth.AtomicApplyPort
	platformsamlauth.DirectSAMLTOTPStore
	platformsamlauth.DirectSAMLSessionRevalidationStore
}

type directPlatformSAMLPublicRepositoryStub struct {
	readyErr error
}

func (stub *directPlatformSAMLPublicRepositoryStub) LoadDirectPlatformSAMLMetadata(
	context.Context,
	string,
) (platformsamladapter.DirectSAMLMetadataProjection, bool, error) {
	return platformsamladapter.DirectSAMLMetadataProjection{}, false, nil
}

func (stub *directPlatformSAMLPublicRepositoryStub) ReadyDirectPlatformSAML(context.Context) error {
	return stub.readyErr
}

type directPlatformSAMLCredentialIssuerStub struct {
	platformsamlauth.CredentialIssuer
}

type directPlatformSAMLTOTPVerifierStub struct {
	platformsamlauth.DirectSAMLTOTPVerifier
}

type directPlatformSAMLSessionProtectorStub struct {
	federatedsaml.SessionMaterialProtector
}

func TestDirectPlatformSAMLRuntimeComposesOnlyCompleteDedicatedGraph(t *testing.T) {
	t.Parallel()
	options := directPlatformSAMLRuntimeFixture(t)
	runtime, err := newDirectPlatformSAMLRuntime(options)
	if err != nil || runtime.browser == nil || runtime.continuation == nil || runtime.sessionAuthority == nil {
		t.Fatalf("newDirectPlatformSAMLRuntime() = %#v, %v", runtime, err)
	}
	if runtime.browser.String() != "httpserver.RuntimePlatformSAMLBrowserAuthentication{configured:true}" ||
		runtime.continuation.String() !=
			"httpserver.RuntimePlatformSAMLContinuation{configured:true,authority:direct_platform_saml}" ||
		runtime.sessionAuthority.String() !=
			"platformsamlauth.DirectSAMLSessionAuthority{configured:true,authority:direct_platform_saml}" {
		t.Fatalf(
			"runtime graph = browser:%s continuation:%s session:%s",
			runtime.browser, runtime.continuation, runtime.sessionAuthority,
		)
	}
}

func TestDirectPlatformSAMLRuntimeRejectsPartialOrCrossPathComposition(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*directPlatformSAMLRuntimeOptions){
		"missing private repository": func(options *directPlatformSAMLRuntimeOptions) {
			options.Repository = nil
		},
		"typed nil private repository": func(options *directPlatformSAMLRuntimeOptions) {
			var repository *directPlatformSAMLRuntimeRepositoryStub
			options.Repository = repository
		},
		"missing public repository": func(options *directPlatformSAMLRuntimeOptions) {
			options.PublicRepository = nil
		},
		"typed nil public repository": func(options *directPlatformSAMLRuntimeOptions) {
			var repository *directPlatformSAMLPublicRepositoryStub
			options.PublicRepository = repository
		},
		"typed nil session protector": func(options *directPlatformSAMLRuntimeOptions) {
			var protector *directPlatformSAMLSessionProtectorStub
			options.SessionProtector = protector
		},
		"typed nil credential issuer": func(options *directPlatformSAMLRuntimeOptions) {
			var issuer *directPlatformSAMLCredentialIssuerStub
			options.Credentials = issuer
		},
		"typed nil TOTP verifier": func(options *directPlatformSAMLRuntimeOptions) {
			var verifier *directPlatformSAMLTOTPVerifierStub
			options.TOTPVerifier = verifier
		},
		"invalid identity keyring": func(options *directPlatformSAMLRuntimeOptions) {
			options.IdentityKeyring = identity.Keyring{}
		},
		"invalid start protection": func(options *directPlatformSAMLRuntimeOptions) {
			options.StartKey = bytes.Repeat([]byte{0x00}, 32)
		},
		"invalid operation timeout": func(options *directPlatformSAMLRuntimeOptions) {
			options.OperationTimeout = 99 * time.Millisecond
		},
		"invalid transaction ttl": func(options *directPlatformSAMLRuntimeOptions) {
			options.TransactionTTL = 16 * time.Minute
		},
		"invalid challenge ttl": func(options *directPlatformSAMLRuntimeOptions) {
			options.ChallengeTTL = 16 * time.Minute
		},
		"missing clock": func(options *directPlatformSAMLRuntimeOptions) {
			options.Now = nil
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := directPlatformSAMLRuntimeFixture(t)
			mutate(&options)
			if runtime, err := newDirectPlatformSAMLRuntime(options); err == nil ||
				runtime != (directPlatformSAMLRuntime{}) {
				t.Fatalf("newDirectPlatformSAMLRuntime() = %#v, %v", runtime, err)
			}
		})
	}
}

func TestDirectPlatformSAMLRuntimeReadinessUsesPublicCapability(t *testing.T) {
	t.Parallel()
	options := directPlatformSAMLRuntimeFixture(t)
	public := &directPlatformSAMLPublicRepositoryStub{readyErr: errors.New("schema unavailable")}
	options.PublicRepository = public
	runtime, err := newDirectPlatformSAMLRuntime(options)
	if err != nil {
		t.Fatalf("newDirectPlatformSAMLRuntime() error = %v", err)
	}
	if err := runtime.browser.Ready(context.Background()); err == nil {
		t.Fatal("browser readiness ignored the direct SAML schema capability")
	}
	if err := runtime.continuation.Ready(context.Background()); err == nil {
		t.Fatal("continuation readiness ignored the direct SAML schema capability")
	}
}

func TestDirectPlatformSAMLTransportContractMatchesHTTPContinuation(t *testing.T) {
	t.Parallel()
	if httpserver.FederatedContinuationPath != "/?auth=federated-mfa" ||
		platformsamladapter.DirectSAMLProductionTransactionCookie !=
			"__Host-periapsis_platform_saml_transaction" {
		t.Fatalf(
			"transport contract = path:%q cookie:%q",
			httpserver.FederatedContinuationPath,
			platformsamladapter.DirectSAMLProductionTransactionCookie,
		)
	}
}

func directPlatformSAMLRuntimeFixture(t *testing.T) directPlatformSAMLRuntimeOptions {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{
		1: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	sessionProtector, err := federatedauth.NewIdentitySAMLSessionMaterialProtector(keyring)
	if err != nil {
		t.Fatalf("NewIdentitySAMLSessionMaterialProtector() error = %v", err)
	}
	return directPlatformSAMLRuntimeOptions{
		Repository:       &directPlatformSAMLRuntimeRepositoryStub{},
		PublicRepository: &directPlatformSAMLPublicRepositoryStub{},
		SessionProtector: sessionProtector,
		IdentityKeyring:  keyring,
		StartKey:         bytes.Repeat([]byte{0x52}, 32),
		Credentials:      &directPlatformSAMLCredentialIssuerStub{},
		TOTPVerifier:     &directPlatformSAMLTOTPVerifierStub{},
		OperationTimeout: time.Second,
		TransactionTTL:   5 * time.Minute,
		ChallengeTTL:     5 * time.Minute,
		Now: func() time.Time {
			return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		},
	}
}
