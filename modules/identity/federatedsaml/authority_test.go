package federatedsaml

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectPlatformCeremonyPreservesAuthorityThroughAtomicConsumption(t *testing.T) {
	fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
	pending := fixture.repo.current()
	loginRevision, direct := pending.Pins.DirectPlatformLogin()
	if !direct || loginRevision != fixture.config.PlatformLoginRevision ||
		pending.Pins.Provider != fixture.config.Provider || pending.Pins.BindingID != (identity.EntityID{}) ||
		pending.Pins.BindingRevision != 0 || pending.Pins.MappingRevision != 0 ||
		pending.Pins.AuthorizationRevision != 0 || pending.Pins.PlanRevision != fixture.config.PlanRevision {
		t.Fatalf("unexpected direct transaction pins: %v", pending)
	}
	fixture.signer.mu.Lock()
	if len(fixture.signer.requests) != 1 ||
		fixture.signer.requests[0].Authority != DirectPlatformCeremonyAuthority ||
		fixture.signer.requests[0].Provider != fixture.config.Provider ||
		fixture.signer.requests[0].BindingID != (identity.EntityID{}) ||
		fixture.signer.requests[0].PlatformLoginRevision != fixture.config.PlatformLoginRevision ||
		fixture.signer.requests[0].KeyRevision != fixture.config.SPKeyRevision ||
		fixture.signer.requests[0].LogoutMaterialID != (identity.EntityID{}) {
		fixture.signer.mu.Unlock()
		t.Fatal("direct start did not preserve the exact signer authority")
	}
	fixture.signer.mu.Unlock()

	callback := callbackRequest(fixture, validResponseDocument(fixture))
	var resolverCalls atomic.Int32
	validated, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
		MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
	}, callbackConfigurationResolverFunc(func(_ context.Context, lookup CallbackConfigurationLookup) (Configuration, error) {
		resolverCalls.Add(1)
		if lookup.Pins.Authority != DirectPlatformCeremonyAuthority ||
			lookup.Pins.Provider != fixture.config.Provider || lookup.Pins.BindingID != (identity.EntityID{}) ||
			lookup.Pins.PlatformLoginRevision != fixture.config.PlatformLoginRevision ||
			lookup.Pins.PlanRevision != fixture.config.PlanRevision {
			return Configuration{}, errors.New("direct authority was not pinned")
		}
		return fixture.config, nil
	}))
	if err != nil || validated == nil || resolverCalls.Load() != 1 {
		t.Fatalf("ValidateCallbackResolved() = %v, %v, resolver calls=%d", validated, err, resolverCalls.Load())
	}
	fixture.verifier.mu.Lock()
	for _, request := range fixture.verifier.calls {
		if request.Authority != DirectPlatformCeremonyAuthority || request.Provider != fixture.config.Provider ||
			request.BindingID != (identity.EntityID{}) ||
			request.PlatformLoginRevision != fixture.config.PlatformLoginRevision {
			fixture.verifier.mu.Unlock()
			t.Fatal("direct signature proof request lost its authority")
		}
	}
	if !bytes.Equal(fixture.verifier.rawDocument, make([]byte, len(fixture.verifier.rawDocument))) {
		fixture.verifier.mu.Unlock()
		t.Fatal("kernel retained the direct signature-verification document clone")
	}
	fixture.verifier.mu.Unlock()

	jit := validated.JIT()
	evidence := jit.AssuranceEvidence()
	if len(jit.Scalars()) != 0 || len(jit.Profiles()) != 0 || len(jit.Groups()) != 0 ||
		evidence == nil || evidence.Source.ProviderID != fixture.config.Provider.ProviderID ||
		evidence.Source.BindingID != (identity.EntityID{}) || evidence.TrustRuleRevision == nil {
		t.Fatalf("direct mapping or assurance projection = %v", jit)
	}
	tenant := newTestFixture(t)
	consumer := &atomicConsumer{}
	if _, err := tenant.kernel.Consume(context.Background(), validated, consumer); !errors.Is(err, ErrConsumptionRejected) || consumer.calls != 0 {
		t.Fatalf("tenant kernel consumed direct proof: err=%v calls=%d", err, consumer.calls)
	}
	result, err := fixture.kernel.Consume(context.Background(), validated, consumer)
	if err != nil || result.Category != ConsumerSuccess || consumer.calls != 1 ||
		consumer.request.Pins.Authority != DirectPlatformCeremonyAuthority ||
		consumer.request.Pins.PlatformLoginRevision != fixture.config.PlatformLoginRevision ||
		consumer.request.Pins.PlanRevision != fixture.config.PlanRevision {
		t.Fatalf("direct Consume() = %v, %v, request=%v", result, err, consumer.request)
	}
	sessionContext, ok := consumer.request.SessionProtectionContext()
	directContext, directOK := sessionContext.DirectPlatformProtectionContext()
	if !ok || !directOK || directContext.Provider != fixture.config.Provider ||
		directContext.MaterialID != pending.MaterialID ||
		directContext.PlatformLoginRevision != fixture.config.PlatformLoginRevision {
		t.Fatalf("direct consumption session context = %v, %t/%t", sessionContext, ok, directOK)
	}
}

func TestCeremonyAuthorityAndConfigurationAreFailClosed(t *testing.T) {
	tenant := newTestFixture(t)
	direct := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
	if _, err := tenant.kernel.StartAuthentication(context.Background(), StartRequest{
		Begin: testAuthenticationBegin(20), Configuration: direct.config, ReturnPath: "/safe",
	}); !errors.Is(err, ErrAuthenticationStart) {
		t.Fatalf("tenant kernel accepted direct configuration: %v", err)
	}
	if _, err := direct.kernel.StartAuthentication(context.Background(), StartRequest{
		Begin: testAuthenticationBegin(21), Configuration: tenant.config, ReturnPath: "/safe",
	}); !errors.Is(err, ErrAuthenticationStart) {
		t.Fatalf("direct kernel accepted tenant configuration: %v", err)
	}
	if _, err := New(Options{
		Authority: CeremonyAuthority(99), Transactions: direct.repo, RedirectSigner: direct.signer,
		SignatureVerifier: direct.verifier, AssertionDecrypter: direct.decrypter,
		SessionProtector: direct.protector, Limits: DefaultLimits(),
		TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("unknown authority New() error = %v", err)
	}

	tests := map[string]func(*Configuration){
		"unknown authority": func(value *Configuration) { value.Authority = CeremonyAuthority(99) },
		"tenant scope": func(value *Configuration) {
			value.Provider.Scope = identity.TenantProviderScope
			value.Provider.TenantID = testID(90)
		},
		"fake tenant":            func(value *Configuration) { value.Provider.TenantID = testID(90) },
		"nonzero binding":        func(value *Configuration) { value.BindingID = testID(91) },
		"binding revision":       func(value *Configuration) { value.BindingRevision = 1 },
		"zero provider revision": func(value *Configuration) { value.ProviderRevision = 0 },
		"provider revision overflow": func(value *Configuration) {
			value.ProviderRevision = maximumPersistentRevision + 1
		},
		"zero platform login":     func(value *Configuration) { value.PlatformLoginRevision = 0 },
		"platform login overflow": func(value *Configuration) { value.PlatformLoginRevision = maximumPersistentRevision + 1 },
		"zero configuration":      func(value *Configuration) { value.ConfigurationRevision = 0 },
		"configuration overflow": func(value *Configuration) {
			value.ConfigurationRevision = maximumPersistentRevision + 1
		},
		"zero security":           func(value *Configuration) { value.SecurityRevision = 0 },
		"security overflow":       func(value *Configuration) { value.SecurityRevision = maximumPersistentRevision + 1 },
		"zero plan":               func(value *Configuration) { value.PlanRevision = 0 },
		"plan overflow":           func(value *Configuration) { value.PlanRevision = maximumPersistentRevision + 1 },
		"mapping revision":        func(value *Configuration) { value.MappingRevision = 1 },
		"authorization revision":  func(value *Configuration) { value.AuthorizationRevision = 1 },
		"zero assurance revision": func(value *Configuration) { value.AssurancePolicyRevision = 0 },
		"assurance revision overflow": func(value *Configuration) {
			value.AssurancePolicyRevision = maximumPersistentRevision + 1
		},
		"zero metadata revision": func(value *Configuration) { value.Metadata.revision = 0 },
		"metadata revision overflow": func(value *Configuration) {
			value.Metadata.revision = maximumPersistentRevision + 1
		},
		"zero SP key revision":     func(value *Configuration) { value.SPKeyRevision = 0 },
		"SP key revision overflow": func(value *Configuration) { value.SPKeyRevision = maximumPersistentRevision + 1 },
		"tenant ACS":               func(value *Configuration) { value.ACSURL = "https://sp.example.test" + samlACSPath },
		"tenant decryption keys":   func(value *Configuration) { value.DecryptionKeyVersions = []uint32{1} },
		"direct keys while disabled": func(value *Configuration) {
			value.DirectPlatformDecryptionKeyRevisions = []uint64{1}
		},
		"unsorted direct keys": func(value *Configuration) {
			value.EncryptionPolicy = EncryptionRequired
			value.DirectPlatformDecryptionKeyRevisions = []uint64{2, 1}
		},
		"duplicate direct keys": func(value *Configuration) {
			value.EncryptionPolicy = EncryptionRequired
			value.DirectPlatformDecryptionKeyRevisions = []uint64{1, 1}
		},
		"direct key overflow": func(value *Configuration) {
			value.EncryptionPolicy = EncryptionRequired
			value.DirectPlatformDecryptionKeyRevisions = []uint64{maximumPersistentRevision + 1}
		},
		"scalar mapping": func(value *Configuration) {
			value.Mapping.Scalars = []ScalarAttributeRule{{Name: "role", NameFormat: "urn:test"}}
		},
		"profile mapping": func(value *Configuration) {
			value.Mapping.Profiles = []ProfileAttributeRule{{Name: "email", NameFormat: "urn:test", Field: ProfileEmail}}
		},
		"group mapping": func(value *Configuration) {
			value.Mapping.Groups = &GroupAttributeRule{Name: "groups", NameFormat: "urn:test"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			configuration := cloneTestConfiguration(direct.config)
			mutate(&configuration)
			before := len(direct.signer.requests)
			_, err := direct.kernel.StartAuthentication(context.Background(), StartRequest{
				Begin: testAuthenticationBegin(22), Configuration: configuration, ReturnPath: "/safe",
			})
			if !errors.Is(err, ErrAuthenticationStart) || len(direct.signer.requests) != before {
				t.Fatalf("StartAuthentication() error=%v signer calls=%d/%d", err, len(direct.signer.requests), before)
			}
		})
	}
}

func TestDirectPlatformCallbackRejectsPendingAndConfigurationSubstitution(t *testing.T) {
	t.Run("pending authority", func(t *testing.T) {
		fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
		callback := callbackRequest(fixture, validResponseDocument(fixture))
		fixture.repo.mu.Lock()
		fixture.repo.pending.Pins.Authority = TenantCeremonyAuthority
		fixture.repo.mu.Unlock()
		var resolverCalls atomic.Int32
		_, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
			MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
		}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
			resolverCalls.Add(1)
			return fixture.config, nil
		}))
		if !errors.Is(err, ErrCallbackRejected) || resolverCalls.Load() != 0 {
			t.Fatalf("pending substitution error=%v resolver calls=%d", err, resolverCalls.Load())
		}
	})

	tests := map[string]func(*Configuration){
		"provider":                func(value *Configuration) { value.Provider.ProviderID = testID(70) },
		"provider revision":       func(value *Configuration) { value.ProviderRevision++ },
		"platform login revision": func(value *Configuration) { value.PlatformLoginRevision++ },
		"configuration revision":  func(value *Configuration) { value.ConfigurationRevision++ },
		"security revision":       func(value *Configuration) { value.SecurityRevision++ },
		"plan revision":           func(value *Configuration) { value.PlanRevision++ },
		"assurance revision":      func(value *Configuration) { value.AssurancePolicyRevision++ },
		"metadata revision":       func(value *Configuration) { value.Metadata.revision++ },
		"metadata digest":         func(value *Configuration) { value.Metadata.digest[0] ^= 0xff },
		"SP key revision":         func(value *Configuration) { value.SPKeyRevision++ },
		"direct ACS":              func(value *Configuration) { value.ACSURL = "https://other.example.test" + directPlatformSAMLACSPath },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
			callback := callbackRequest(fixture, validResponseDocument(fixture))
			changed := cloneTestConfiguration(fixture.config)
			mutate(&changed)
			var resolverCalls atomic.Int32
			_, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
				MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
				resolverCalls.Add(1)
				return changed, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) || resolverCalls.Load() != 1 {
				t.Fatalf("configuration substitution error=%v resolver calls=%d", err, resolverCalls.Load())
			}
		})
	}
}

func TestDirectPlatformSignatureAndDecryptionProofsAreAuthorityBound(t *testing.T) {
	signatureTests := map[string]func(*SignatureVerificationResult){
		"authority":               func(value *SignatureVerificationResult) { value.Authority = TenantCeremonyAuthority },
		"provider":                func(value *SignatureVerificationResult) { value.Provider.ProviderID = testID(80) },
		"binding":                 func(value *SignatureVerificationResult) { value.BindingID = testID(81) },
		"platform login revision": func(value *SignatureVerificationResult) { value.PlatformLoginRevision++ },
	}
	for name, mutate := range signatureTests {
		t.Run("signature "+name, func(t *testing.T) {
			fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
			fixture.verifier.mutate = mutate
			if _, err := fixture.kernel.ValidateCallback(
				context.Background(), callbackRequest(fixture, validResponseDocument(fixture)),
			); !errors.Is(err, ErrSignatureRejected) {
				t.Fatalf("ValidateCallback() error = %v", err)
			}
		})
	}

	decryptionTests := map[string]func(*DecryptionResult){
		"authority":               func(value *DecryptionResult) { value.Authority = TenantCeremonyAuthority },
		"provider":                func(value *DecryptionResult) { value.Provider.ProviderID = testID(82) },
		"binding":                 func(value *DecryptionResult) { value.BindingID = testID(83) },
		"platform login revision": func(value *DecryptionResult) { value.PlatformLoginRevision++ },
		"tenant key version":      func(value *DecryptionResult) { value.KeyVersion = 1 },
		"direct key revision":     func(value *DecryptionResult) { value.DirectPlatformKeyRevision++ },
	}
	for name, mutate := range decryptionTests {
		t.Run("decryption "+name, func(t *testing.T) {
			fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
			fixture.config.EncryptionPolicy = EncryptionRequired
			fixture.config.DirectPlatformDecryptionKeyRevisions = []uint64{11}
			restartFixture(t, &fixture)
			fixture.decrypter.assertion = validAssertionDocument(fixture, true)
			fixture.decrypter.mutate = mutate
			document := responseDocument(
				fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256),
			)
			if _, err := fixture.kernel.ValidateCallback(
				context.Background(), callbackRequest(fixture, document),
			); !errors.Is(err, ErrEncryptionRejected) {
				t.Fatalf("ValidateCallback() error = %v", err)
			}
		})
	}
}

func TestDirectPlatformEncryptedCeremonyUsesOnlyDirectKeyRevisions(t *testing.T) {
	fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DirectPlatformDecryptionKeyRevisions = []uint64{11}
	restartFixture(t, &fixture)
	fixture.decrypter.assertion = validAssertionDocument(fixture, true)
	document := responseDocument(
		fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256),
	)
	if _, err := fixture.kernel.ValidateCallback(
		context.Background(), callbackRequest(fixture, document),
	); err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	fixture.decrypter.mu.Lock()
	request := fixture.decrypter.last
	rawResponse := fixture.decrypter.raw
	fixture.decrypter.mu.Unlock()
	if request.Authority != DirectPlatformCeremonyAuthority || request.Provider != fixture.config.Provider ||
		request.BindingID != (identity.EntityID{}) ||
		request.PlatformLoginRevision != fixture.config.PlatformLoginRevision ||
		len(request.AllowedKeyVersions) != 0 || len(request.DirectPlatformKeyRevisions) != 1 ||
		request.DirectPlatformKeyRevisions[0] != 11 {
		t.Fatalf("direct decryption request = %v", request)
	}
	if !bytes.Equal(rawResponse, make([]byte, len(rawResponse))) {
		t.Fatal("kernel retained the direct decryption response clone")
	}
}

type directAdapterKeySource struct {
	materials map[uint64]DirectPlatformSPKeyMaterial
	calls     []DirectPlatformSPKeyRequest
}

func (source *directAdapterKeySource) LoadDirectPlatformSAMLSPKey(
	_ context.Context,
	request DirectPlatformSPKeyRequest,
) (DirectPlatformSPKeyMaterial, error) {
	source.calls = append(source.calls, request)
	material, ok := source.materials[request.KeyRevision]
	if !ok {
		return DirectPlatformSPKeyMaterial{}, ErrSPKeyUnavailable
	}
	return material, nil
}

func TestDirectPlatformCryptoAdapterUsesOnlyDirectPurposeAndExactRevisions(t *testing.T) {
	provider := identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testID(40)}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := adapterCertificate(t, ecdsaKey, 401)
	directSource := &directAdapterKeySource{materials: map[uint64]DirectPlatformSPKeyMaterial{7: {
		Context: identity.DirectPlatformSAMLSPKeyContext{
			Provider: provider, KeyID: testID(41), KeyRevision: 7,
		},
		Signer: ecdsaKey, CertificateDER: [][]byte{certificate},
	}}}
	directAdapter, err := NewDirectPlatformLibraryCryptoAdapter(directSource)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("direct-platform-signer-payload")
	logoutMaterialID := testID(42)
	signature, err := directAdapter.SignRedirect(context.Background(), RedirectSignRequest{
		Authority: DirectPlatformCeremonyAuthority, Provider: provider,
		PlatformLoginRevision: 6, KeyRevision: 7,
		LogoutMaterialID: logoutMaterialID, Algorithm: RedirectECDSASHA256, Payload: payload,
	})
	if err != nil || len(signature) == 0 || len(directSource.calls) != 1 ||
		directSource.calls[0].Provider != provider || directSource.calls[0].PlatformLoginRevision != 6 ||
		directSource.calls[0].KeyRevision != 7 || directSource.calls[0].LogoutMaterialID != logoutMaterialID {
		t.Fatalf("direct SignRedirect() signature=%d error=%v calls=%v", len(signature), err, directSource.calls)
	}
	clear(signature)
	baseMaterial := directSource.materials[7]
	for name, mutate := range map[string]func(*DirectPlatformSPKeyMaterial){
		"provider": func(value *DirectPlatformSPKeyMaterial) {
			value.Context.Provider.ProviderID = testID(43)
		},
		"tenant purpose": func(value *DirectPlatformSPKeyMaterial) {
			value.Context.Provider.Scope = identity.TenantProviderScope
			value.Context.Provider.TenantID = testID(44)
		},
		"key revision": func(value *DirectPlatformSPKeyMaterial) { value.Context.KeyRevision++ },
		"zero key row": func(value *DirectPlatformSPKeyMaterial) { value.Context.KeyID = identity.EntityID{} },
	} {
		t.Run("material "+name, func(t *testing.T) {
			material := baseMaterial
			mutate(&material)
			directSource.materials[7] = material
			if signature, err := directAdapter.SignRedirect(context.Background(), RedirectSignRequest{
				Authority: DirectPlatformCeremonyAuthority, Provider: provider,
				PlatformLoginRevision: 6, KeyRevision: 7,
				Algorithm: RedirectECDSASHA256, Payload: payload,
			}); !errors.Is(err, ErrSPKeyUnavailable) || len(signature) != 0 {
				clear(signature)
				t.Fatalf("substituted direct material accepted: %v", err)
			}
		})
	}
	directSource.materials[7] = baseMaterial
	directCalls := len(directSource.calls)
	if _, err := directAdapter.SignRedirect(context.Background(), RedirectSignRequest{
		Provider:  identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: testID(1), ProviderID: testID(2)},
		BindingID: testID(3), KeyRevision: 7, Algorithm: RedirectECDSASHA256, Payload: payload,
	}); !errors.Is(err, ErrSPKeyUnavailable) || len(directSource.calls) != directCalls {
		t.Fatalf("direct adapter crossed into tenant purpose: %v calls=%d", err, len(directSource.calls))
	}
	tenantSource := &adapterKeySource{materials: map[uint32]SPKeyMaterial{}}
	tenantAdapter, err := NewLibraryCryptoAdapter(tenantSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenantAdapter.SignRedirect(context.Background(), RedirectSignRequest{
		Authority: DirectPlatformCeremonyAuthority, Provider: provider,
		PlatformLoginRevision: 6, KeyRevision: 7,
		Algorithm: RedirectECDSASHA256, Payload: payload,
	}); !errors.Is(err, ErrSPKeyUnavailable) || len(tenantSource.calls) != 0 {
		t.Fatalf("tenant adapter crossed into direct purpose: %v calls=%d", err, len(tenantSource.calls))
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	directSource.materials[9] = DirectPlatformSPKeyMaterial{
		Context: identity.DirectPlatformSAMLSPKeyContext{
			Provider: provider, KeyID: testID(42), KeyRevision: 9,
		},
		RSADecrypter: rsaKey,
	}
	assertion := []byte(`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `" ID="_assertion"></saml:Assertion>`)
	response := encryptedResponseDocument(t, &rsaKey.PublicKey, assertion, aes128GCM)
	result, err := directAdapter.DecryptAssertion(context.Background(), DecryptionRequest{
		Authority: DirectPlatformCeremonyAuthority, Response: response,
		ResponseID: "_response", EncryptedObjectID: "_encrypted_data", Provider: provider,
		PlatformLoginRevision: 6, DirectPlatformKeyRevisions: []uint64{9},
	})
	if err != nil || !bytes.Equal(result.Assertion, assertion) || result.KeyVersion != 0 ||
		result.DirectPlatformKeyRevision != 9 || result.Authority != DirectPlatformCeremonyAuthority ||
		result.Provider != provider || result.PlatformLoginRevision != 6 {
		t.Fatalf("direct DecryptAssertion() = %v, %v", result, err)
	}
	clear(result.Assertion)
	before := len(directSource.calls)
	if _, err := directAdapter.DecryptAssertion(context.Background(), DecryptionRequest{
		Authority: DirectPlatformCeremonyAuthority, Response: response,
		ResponseID: "_response", EncryptedObjectID: "_encrypted_data", Provider: provider,
		PlatformLoginRevision: 6, AllowedKeyVersions: []uint32{9},
	}); !errors.Is(err, ErrEncryptionRejected) || len(directSource.calls) != before {
		t.Fatalf("tenant key list crossed direct adapter: %v calls=%d/%d", err, len(directSource.calls), before)
	}
}

func TestSessionMaterialContextsCannotCrossCeremonyAuthority(t *testing.T) {
	tenantProvider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: testID(1), ProviderID: testID(2),
	}
	tenant := SessionMaterialContext{
		Provider: tenantProvider, BindingID: testID(3), MaterialID: testID(4),
	}
	if converted, ok := tenant.TenantProtectionContext(); !ok || converted.Provider != tenantProvider ||
		converted.BindingID != tenant.BindingID || converted.MaterialID != tenant.MaterialID {
		t.Fatalf("tenant protection context = %v, %t", converted, ok)
	}
	if _, ok := tenant.DirectPlatformProtectionContext(); ok {
		t.Fatal("tenant session material converted to direct purpose")
	}
	provider := identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testID(5)}
	direct := SessionMaterialContext{
		Authority: DirectPlatformCeremonyAuthority, Provider: provider,
		MaterialID: testID(6), PlatformLoginRevision: 7,
	}
	converted, ok := direct.DirectPlatformProtectionContext()
	if !ok || converted.Provider != provider || converted.MaterialID != direct.MaterialID ||
		converted.PlatformLoginRevision != 7 {
		t.Fatalf("direct protection context = %v, %t", converted, ok)
	}
	if _, ok := direct.TenantProtectionContext(); ok {
		t.Fatal("direct session material converted to tenant purpose")
	}
	for name, mutate := range map[string]func(*SessionMaterialContext){
		"tenant scope": func(value *SessionMaterialContext) {
			value.Provider.Scope = identity.TenantProviderScope
			value.Provider.TenantID = testID(8)
		},
		"fake tenant":      func(value *SessionMaterialContext) { value.Provider.TenantID = testID(8) },
		"binding":          func(value *SessionMaterialContext) { value.BindingID = testID(8) },
		"zero login":       func(value *SessionMaterialContext) { value.PlatformLoginRevision = 0 },
		"login overflow":   func(value *SessionMaterialContext) { value.PlatformLoginRevision = maximumPersistentRevision + 1 },
		"tenant authority": func(value *SessionMaterialContext) { value.Authority = TenantCeremonyAuthority },
	} {
		t.Run(name, func(t *testing.T) {
			changed := direct
			mutate(&changed)
			if _, ok := changed.DirectPlatformProtectionContext(); ok {
				t.Fatal("invalid direct session context converted")
			}
		})
	}
}

func TestDirectPlatformLogoutUsesDirectSessionAndSignerContexts(t *testing.T) {
	fixture := newTestFixtureForAuthority(t, DirectPlatformCeremonyAuthority)
	request := LogoutBuildRequest{
		Configuration: fixture.config, SessionID: testID(60), MaterialID: testID(61),
		ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("direct-session-ciphertext")},
		Confirmation: logoutConfirmation{
			provider: fixture.config.Provider, binding: identity.EntityID{},
			session: testID(60), revoked: fixtureTime,
		},
	}
	if _, err := fixture.kernel.BuildLogoutRequest(context.Background(), request); err != nil {
		t.Fatalf("BuildLogoutRequest() error = %v", err)
	}
	context := fixture.protector.context
	directContext, ok := context.DirectPlatformProtectionContext()
	if fixture.protector.calls != 1 || !ok || context.Authority != DirectPlatformCeremonyAuthority ||
		context.BindingID != (identity.EntityID{}) || directContext.Provider != fixture.config.Provider ||
		directContext.MaterialID != request.MaterialID ||
		directContext.PlatformLoginRevision != fixture.config.PlatformLoginRevision {
		t.Fatalf("direct logout session context = %v, %t", context, ok)
	}
	fixture.signer.mu.Lock()
	last := fixture.signer.requests[len(fixture.signer.requests)-1]
	fixture.signer.mu.Unlock()
	if last.Authority != DirectPlatformCeremonyAuthority || last.Provider != fixture.config.Provider ||
		last.BindingID != (identity.EntityID{}) ||
		last.PlatformLoginRevision != fixture.config.PlatformLoginRevision ||
		last.KeyRevision != fixture.config.SPKeyRevision || last.LogoutMaterialID != request.MaterialID {
		t.Fatalf("direct logout signer request = %v", last)
	}
}

func TestTenantConfigurationDigestRemainsLegacyByteExact(t *testing.T) {
	fixture := newTestFixture(t)
	normalized, digest, err := normalizeConfiguration(fixture.config, fixtureTime, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if legacy := legacyTenantConfigurationDigest(normalized); digest != legacy {
		t.Fatalf("tenant digest changed: current=%x legacy=%x", digest, legacy)
	}
}

func TestDirectAuthorityStringFormsAreRedacted(t *testing.T) {
	provider := identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testID(50)}
	request := DirectPlatformSPKeyRequest{Provider: provider, PlatformLoginRevision: 51, KeyRevision: 52}
	material := DirectPlatformSPKeyMaterial{Context: identity.DirectPlatformSAMLSPKeyContext{
		Provider: provider, KeyID: testID(53), KeyRevision: 52,
	}}
	pins := TransactionPins{
		Authority: DirectPlatformCeremonyAuthority, Provider: provider,
		PlatformLoginRevision: 51, PlanRevision: 54,
	}
	formatted := fmt.Sprintf("%v %#v %v %#v %v %#v", request, request, material, material, pins, pins)
	for _, secret := range []string{fmt.Sprint(provider.ProviderID), fmt.Sprint(material.Context.KeyID)} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("direct authority formatter leaked an identifier: %s", formatted)
		}
	}
	if !strings.Contains(formatted, "direct_platform") || strings.Contains(formatted, "Signer") ||
		strings.Contains(formatted, "RSADecrypter") {
		t.Fatalf("unexpected direct authority formatting: %s", formatted)
	}
}

func cloneTestConfiguration(input Configuration) Configuration {
	result := input
	result.DecryptionKeyVersions = append([]uint32(nil), input.DecryptionKeyVersions...)
	result.DirectPlatformDecryptionKeyRevisions = append(
		[]uint64(nil), input.DirectPlatformDecryptionKeyRevisions...,
	)
	result.RequestedAuthnContexts = append([]string(nil), input.RequestedAuthnContexts...)
	result.Mapping.Scalars = append([]ScalarAttributeRule(nil), input.Mapping.Scalars...)
	result.Mapping.Profiles = append([]ProfileAttributeRule(nil), input.Mapping.Profiles...)
	if input.Mapping.Groups != nil {
		group := *input.Mapping.Groups
		result.Mapping.Groups = &group
	}
	result.TrustRules = append([]AuthnContextTrustRule(nil), input.TrustRules...)
	return result
}

func legacyTenantConfigurationDigest(configuration Configuration) [32]byte {
	fields := make([][]byte, 0, 48)
	fields = append(fields,
		[]byte{byte(configuration.Provider.Scope)}, configuration.Provider.TenantID[:],
		configuration.Provider.ProviderID[:], configuration.BindingID[:],
		u64(configuration.ProviderRevision), u64(configuration.BindingRevision), u64(configuration.ConfigurationRevision),
		u64(configuration.SecurityRevision), u64(configuration.MappingRevision),
		u64(configuration.AuthorizationRevision), u64(configuration.AssurancePolicyRevision), []byte(configuration.SPEntityID),
		[]byte(configuration.ACSURL), u64(configuration.Metadata.revision),
		configuration.Metadata.digest[:], u64(configuration.SPKeyRevision),
		[]byte(configuration.RedirectSignatureAlgorithm), []byte(configuration.SignaturePolicy),
		[]byte(configuration.EncryptionPolicy), u64(uint64(configuration.ClockSkew)),
		u64(uint64(configuration.MaxAuthenticationAge)), []byte(configuration.Subject.Source),
		[]byte(configuration.Subject.AttributeName), []byte(configuration.Subject.AttributeNameFormat),
	)
	for _, version := range configuration.DecryptionKeyVersions {
		fields = append(fields, u64(uint64(version)))
	}
	for _, context := range configuration.RequestedAuthnContexts {
		fields = append(fields, []byte(context))
	}
	for _, rule := range configuration.Mapping.Scalars {
		fields = append(fields, []byte("scalar"), []byte(rule.Name), []byte(rule.NameFormat), boolByte(rule.Required))
	}
	for _, rule := range configuration.Mapping.Profiles {
		fields = append(fields, []byte("profile"), []byte(rule.Name), []byte(rule.NameFormat), []byte(rule.Field), boolByte(rule.Required))
	}
	if configuration.Mapping.Groups != nil {
		fields = append(fields, []byte("groups"), []byte(configuration.Mapping.Groups.Name),
			[]byte(configuration.Mapping.Groups.NameFormat), boolByte(configuration.Mapping.Groups.Required))
	}
	for _, rule := range configuration.TrustRules {
		fields = append(fields, []byte("trust"), []byte(rule.ClassRef), []byte{byte(rule.Level)},
			u64(uint64(rule.Revision)), u64(uint64(rule.MaxAge)))
	}
	return digestFields(fields...)
}
