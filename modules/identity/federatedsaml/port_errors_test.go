package federatedsaml

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestInjectedPortErrorsAreCategorizedAndRedacted(t *testing.T) {
	secretError := errors.New("SECRET upstream material")

	t.Run("redirect signer", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.signer.err = secretError
		_, err := fixture.kernel.StartAuthentication(context.Background(), StartRequest{Begin: testAuthenticationBegin(2), Configuration: fixture.config, ReturnPath: "/safe"})
		assertSafePortError(t, err, ErrAuthenticationStart)
	})

	t.Run("transaction create", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.repo.createErr = secretError
		_, err := fixture.kernel.StartAuthentication(context.Background(), StartRequest{Begin: testAuthenticationBegin(2), Configuration: fixture.config, ReturnPath: "/safe"})
		assertSafePortError(t, err, ErrTransactionPersistence)
	})

	t.Run("transaction lookup", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.repo.lookupErr = secretError
		_, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
		assertSafePortError(t, err, ErrCallbackRejected)
	})

	t.Run("signature verifier", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.verifier.err = secretError
		_, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
		assertSafePortError(t, err, ErrSignatureRejected)
	})

	t.Run("assertion decrypter", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.config.EncryptionPolicy = EncryptionRequired
		fixture.config.DecryptionKeyVersions = []uint32{11}
		restartFixture(t, &fixture)
		fixture.decrypter.err = secretError
		document := responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
		_, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document))
		assertSafePortError(t, err, ErrEncryptionRejected)
	})

	t.Run("session protector", func(t *testing.T) {
		fixture := newTestFixture(t)
		fixture.protector.err = secretError
		_, err := fixture.kernel.BuildLogoutRequest(context.Background(), LogoutBuildRequest{
			Configuration: fixture.config, SessionID: testID(77), MaterialID: testID(78),
			ProtectedMaterial: ProtectedSessionMaterial{KeyVersion: 1, Ciphertext: []byte("protected")},
			Confirmation:      logoutConfirmation{provider: fixture.config.Provider, binding: fixture.config.BindingID, session: testID(77), revoked: fixtureTime},
		})
		assertSafePortError(t, err, ErrLogoutArtifactRejected)
	})

	t.Run("authentication consumer", func(t *testing.T) {
		fixture := newTestFixture(t)
		validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
		if err != nil {
			t.Fatalf("ValidateCallback() error = %v", err)
		}
		_, err = fixture.kernel.Consume(context.Background(), validated, consumerFunction(func(context.Context, ConsumptionRequest) (ConsumptionResult, error) {
			return ConsumptionResult{Category: ConsumerUnavailable}, secretError
		}))
		assertSafePortError(t, err, ErrConsumptionRejected)
	})
}

func assertSafePortError(t *testing.T, actual, category error) {
	t.Helper()
	if actual == nil || !errors.Is(actual, category) || strings.Contains(actual.Error(), "SECRET") {
		t.Fatalf("error = %v, want safe category %v", actual, category)
	}
}
