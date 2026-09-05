package federatedsaml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type logoutConfirmation struct {
	provider identity.ProviderContext
	binding  identity.EntityID
	session  identity.EntityID
	revoked  time.Time
}

func (confirmation logoutConfirmation) SAMLProvider() identity.ProviderContext {
	return confirmation.provider
}
func (confirmation logoutConfirmation) SAMLBindingID() identity.EntityID { return confirmation.binding }
func (confirmation logoutConfirmation) LocalSessionID() identity.EntityID {
	return confirmation.session
}
func (confirmation logoutConfirmation) LocalSessionRevokedAt() time.Time { return confirmation.revoked }

type observedLogoutConfirmation struct {
	logoutConfirmation
	observedAt time.Time
}

func (confirmation observedLogoutConfirmation) LocalLogoutObservedAt() time.Time {
	return confirmation.observedAt
}

func TestBuildLogoutRequestRequiresLocalRevocationAndRedactsArtifact(t *testing.T) {
	fixture := newTestFixture(t)
	confirmation := logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: testID(44), revoked: fixtureTime}
	request := LogoutBuildRequest{
		Configuration: fixture.config, SessionID: testID(44), MaterialID: testID(45),
		ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("ciphertext-secret-marker")},
		Confirmation:      confirmation,
	}
	artifact, err := fixture.kernel.BuildLogoutRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("BuildLogoutRequest() error = %v", err)
	}
	if fixture.protector.calls != 1 || fixture.protector.context.Provider != fixture.config.Provider ||
		fixture.protector.context.BindingID != fixture.config.BindingID || fixture.protector.context.MaterialID != request.MaterialID {
		t.Fatalf("unexpected protector call: %#v", fixture.protector.context)
	}
	if !bytes.Equal(request.ProtectedMaterial.Ciphertext, []byte("ciphertext-secret-marker")) {
		t.Fatal("BuildLogoutRequest cleared caller-owned protected material")
	}
	if !bytes.Equal(
		fixture.protector.protected.Ciphertext,
		make([]byte, len(fixture.protector.protected.Ciphertext)),
	) {
		t.Fatal("BuildLogoutRequest retained its protected-material clone")
	}
	parsed, err := url.Parse(artifact.RedirectURL())
	if err != nil || parsed.Scheme != "https" || parsed.Host != "idp.example.test" || parsed.Path != "/slo" ||
		parsed.Query().Get("RelayState") != "" || parsed.Query().Get("Signature") == "" {
		t.Fatalf("unexpected logout redirect: %v, %v", artifact, err)
	}
	compressed, err := base64.StdEncoding.Strict().DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode logout request: %v", err)
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	document, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !strings.Contains(string(document), "logout-secret-subject") ||
		!strings.Contains(string(document), "logout-secret-session") || !strings.Contains(string(document), fixture.config.SPEntityID) {
		t.Fatalf("unexpected LogoutRequest document: %q, %v, %v", document, readErr, closeErr)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v", request, request, artifact, artifact)
	for _, secret := range []string{"ciphertext-secret-marker", "logout-secret-subject", "logout-secret-session", artifact.RedirectURL()} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted artifact leaked %q: %s", secret, formatted)
		}
	}
}

func TestBuildLogoutRequestRejectsMissingOrStaleLocalRevocation(t *testing.T) {
	fixture := newTestFixture(t)
	base := LogoutBuildRequest{
		Configuration: fixture.config, SessionID: testID(45), MaterialID: testID(46),
		ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("cipher")},
	}
	tests := []LocalLogoutConfirmation{
		nil,
		logoutConfirmation{provider: fixture.config.Provider, binding: testID(99), session: base.SessionID, revoked: fixtureTime},
		logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: testID(99), revoked: fixtureTime},
		logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: base.SessionID, revoked: fixtureTime.Add(-16 * time.Minute)},
		logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: base.SessionID, revoked: fixtureTime.Add(time.Minute)},
	}
	for index, confirmation := range tests {
		request := base
		request.Confirmation = confirmation
		if _, err := fixture.kernel.BuildLogoutRequest(context.Background(), request); !errors.Is(err, ErrLogoutArtifactRejected) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
	withoutSLO := base
	withoutSLO.Configuration.Metadata = compileTestMetadata(t, 12, fixture.config.Metadata.EntityID(), fixture.config.Metadata.SSORedirectURL(), "", fixture.config.Metadata.CertificateDER()[0])
	withoutSLO.Confirmation = logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: base.SessionID, revoked: fixtureTime}
	if _, err := fixture.kernel.BuildLogoutRequest(context.Background(), withoutSLO); !errors.Is(err, ErrLogoutArtifactRejected) {
		t.Fatalf("missing SLO endpoint error = %v", err)
	}
	if fixture.protector.calls != 0 {
		t.Fatalf("protector called before local-revocation validation: %d", fixture.protector.calls)
	}
}

func TestBuildLogoutRequestUsesDatabaseObservedRevocationAcrossClockSkew(t *testing.T) {
	for _, offset := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			fixture := newTestFixture(t)
			observedAt := fixtureTime.Add(offset)
			request := LogoutBuildRequest{
				Configuration: fixture.config, SessionID: testID(55), MaterialID: testID(56),
				ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("cipher")},
				Confirmation: observedLogoutConfirmation{
					logoutConfirmation: logoutConfirmation{
						provider: fixture.config.Provider, binding: fixture.config.BindingID,
						session: testID(55), revoked: observedAt,
					},
					observedAt: observedAt,
				},
			}
			if _, err := fixture.kernel.BuildLogoutRequest(context.Background(), request); err != nil {
				t.Fatalf("DB offset %s rejected: %v", offset, err)
			}
		})
	}
}

func TestBuildStoredLogoutRequestUsesPinnedProjectionWithoutLiveMetadata(t *testing.T) {
	for _, authority := range []CeremonyAuthority{TenantCeremonyAuthority, DirectPlatformCeremonyAuthority} {
		t.Run(authority.String(), func(t *testing.T) {
			fixture := newTestFixtureForAuthority(t, authority)
			configuration := storedLogoutConfiguration(fixture.config)
			request := StoredLogoutBuildRequest{
				Configuration: configuration, SessionID: testID(65), MaterialID: testID(66),
				ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("stored-ciphertext-secret-marker")},
				Confirmation: logoutConfirmation{
					provider: configuration.Provider, binding: configuration.MaterialBindingID,
					session: testID(65), revoked: fixtureTime,
				},
			}
			artifact, err := fixture.kernel.BuildStoredLogoutRequest(context.Background(), request)
			if err != nil {
				t.Fatalf("BuildStoredLogoutRequest() error = %v", err)
			}
			parsed, err := url.Parse(artifact.RedirectURL())
			if err != nil || parsed.Scheme != "https" || parsed.Query().Get("SAMLRequest") == "" ||
				parsed.Query().Get("Signature") == "" {
				t.Fatalf("unexpected stored logout redirect: %v, %v", artifact, err)
			}
			if fixture.protector.context.Authority != authority ||
				fixture.protector.context.BindingID != configuration.MaterialBindingID ||
				fixture.protector.context.PlatformLoginRevision != configuration.PlatformLoginRevision {
				t.Fatalf("stored material context = %v", fixture.protector.context)
			}
			fixture.signer.mu.Lock()
			signerRequest := fixture.signer.requests[len(fixture.signer.requests)-1]
			fixture.signer.mu.Unlock()
			if signerRequest.LogoutMaterialID != request.MaterialID {
				t.Fatalf("stored logout signer material = %v, want %v", signerRequest.LogoutMaterialID, request.MaterialID)
			}
			formatted := fmt.Sprintf("%v %+v %#v", request, request, request)
			for _, secret := range []string{"stored-ciphertext-secret-marker", configuration.SLORedirectURL} {
				if strings.Contains(formatted, secret) {
					t.Fatalf("stored request formatting leaked %q: %s", secret, formatted)
				}
			}
		})
	}
}

func TestBuildStoredLogoutRequestRejectsCrossAuthorityAndMutableEndpoints(t *testing.T) {
	fixture := newTestFixture(t)
	base := StoredLogoutBuildRequest{
		Configuration: storedLogoutConfiguration(fixture.config), SessionID: testID(67), MaterialID: testID(68),
		ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: []byte("cipher")},
	}
	base.Confirmation = logoutConfirmation{
		provider: base.Configuration.Provider, binding: base.Configuration.MaterialBindingID,
		session: base.SessionID, revoked: fixtureTime,
	}
	for name, mutate := range map[string]func(*StoredLogoutBuildRequest){
		"authority": func(value *StoredLogoutBuildRequest) {
			value.Configuration.Authority = DirectPlatformCeremonyAuthority
		},
		"provider": func(value *StoredLogoutBuildRequest) {
			value.Configuration.Provider = identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testID(69)}
		},
		"binding": func(value *StoredLogoutBuildRequest) {
			value.Configuration.MaterialBindingID = identity.EntityID{}
		},
		"endpoint query": func(value *StoredLogoutBuildRequest) {
			value.Configuration.SLORedirectURL += "?destination=mutable"
		},
		"endpoint path": func(value *StoredLogoutBuildRequest) {
			value.Configuration.SLORedirectURL += "/../other"
		},
		"key overflow": func(value *StoredLogoutBuildRequest) {
			value.Configuration.SPKeyRevision = maximumPersistentRevision + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := fixture.kernel.BuildStoredLogoutRequest(context.Background(), request); !errors.Is(err, ErrLogoutArtifactRejected) {
				t.Fatalf("BuildStoredLogoutRequest() error = %v", err)
			}
		})
	}
}

func TestSensitiveArtifactsHaveRedactedStringForms(t *testing.T) {
	fixture := newTestFixture(t)
	document := validResponseDocument(fixture)
	callback := callbackRequest(fixture, document)
	validated, err := fixture.kernel.ValidateCallback(context.Background(), callback)
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	verification := SignatureVerificationRequest{Document: []byte("raw-document-secret"), ObjectKind: SignedObjectAssertion, ObjectID: "raw-id-secret", Metadata: fixture.config.Metadata}
	decryption := DecryptionRequest{Response: []byte("raw-response-secret"), ResponseID: "raw-response-id", EncryptedObjectID: "raw-encrypted-id", Provider: fixture.config.Provider, BindingID: fixture.config.BindingID, AllowedKeyVersions: []uint32{1}}
	formatted := fmt.Sprintf("%v %#v %v %#v %v %#v %v %#v %v %#v %v %#v %v %#v %v %#v",
		callback, callback, validated.JIT(), validated.JIT(), verification, verification,
		decryption, decryption, fixture.start, fixture.start, validated, validated, fixture.kernel, fixture.kernel,
		SessionMaterial{NameID: "raw-nameid-secret", NameIDFormat: samlPersistentNameID, SessionIndex: "raw-session-secret"},
		SessionMaterial{NameID: "raw-nameid-secret", NameIDFormat: samlPersistentNameID, SessionIndex: "raw-session-secret"})
	for _, secret := range []string{
		"subject-secret-value", "department-secret", "email-secret", "alpha-secret-group", "session-secret-index",
		"raw-document-secret", "raw-id-secret", "raw-response-secret", "raw-response-id", "raw-encrypted-id",
		"raw-nameid-secret", "raw-session-secret", fixture.relay, string(fixture.start.BrowserHandle()),
	} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("String/GoString leaked %q: %s", secret, formatted)
		}
	}
}
