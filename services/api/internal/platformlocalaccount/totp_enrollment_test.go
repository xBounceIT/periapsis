package platformlocalaccount

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const enrollmentTestSecret = "JBSWY3DPEHPK3PXP"

type enrollmentEngineRecorder struct {
	account         string
	generateSecret  string
	generateURI     string
	validateCalls   int
	validatedSecret string
	validatedCode   string
	validatedAt     time.Time
	validatedLast   int64
	acceptedCounter int64
	validationError error
}

func (engine *enrollmentEngineRecorder) Generate(account string) (string, string, error) {
	engine.account = account
	secret := engine.generateSecret
	if secret == "" {
		secret = enrollmentTestSecret
	}
	return secret, engine.generateURI, nil
}

func (engine *enrollmentEngineRecorder) Validate(
	secret string,
	code string,
	at time.Time,
	lastAcceptedCounter int64,
) (int64, error) {
	engine.validateCalls++
	engine.validatedSecret = secret
	engine.validatedCode = code
	engine.validatedAt = at
	engine.validatedLast = lastAcceptedCounter
	return engine.acceptedCounter, engine.validationError
}

type enrollmentCipherRecorder struct {
	decryptCalls    int
	decryptContexts []string
	encryptCalls    int
	encryptContexts []string
	secret          string
	onEncrypt       func()
	lastEncrypted   authentication.EncryptedSecret
}

func (cipher *enrollmentCipherRecorder) EncryptTOTP(context, secret string) (authentication.EncryptedSecret, error) {
	cipher.encryptCalls++
	cipher.encryptContexts = append(cipher.encryptContexts, context)
	if secret != enrollmentTestSecret {
		return authentication.EncryptedSecret{}, errors.New("unexpected enrollment secret")
	}
	protected := testEncryptedTOTP(context)
	cipher.lastEncrypted = protected
	if cipher.onEncrypt != nil {
		cipher.onEncrypt()
	}
	return protected, nil
}

func (cipher *enrollmentCipherRecorder) DecryptTOTP(
	context string,
	protected authentication.EncryptedSecret,
) (string, error) {
	cipher.decryptCalls++
	cipher.decryptContexts = append(cipher.decryptContexts, context)
	if string(protected.AAD) != context {
		return "", errors.New("unexpected enrollment context")
	}
	return cipher.secret, nil
}

func TestEncryptedTOTPEnrollmentCreatesCanonicalAccountBoundArtifact(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	engine := &enrollmentEngineRecorder{generateURI: enrollmentURI(request.AccountID)}
	cipher := &enrollmentCipherRecorder{}
	security, err := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)
	if err != nil {
		t.Fatal(err)
	}

	material, err := security.New(context.Background(), request)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	expectedContext, _ := pendingTOTPContext(request)
	if engine.account != request.AccountID.String() || cipher.encryptCalls != 1 ||
		len(cipher.encryptContexts) != 1 || cipher.encryptContexts[0] != expectedContext ||
		string(material.DisplaySecret) != enrollmentTestSecret ||
		string(material.ProvisioningURI) != enrollmentURI(request.AccountID) ||
		string(material.ProtectedSecret.AAD) != expectedContext ||
		strings.Contains(string(material.ProvisioningURI), "tenant") ||
		strings.Contains(string(material.ProvisioningURI), "example") {
		t.Fatalf("unexpected enrollment material: account=%q contexts=%q material=%#v", engine.account, cipher.encryptContexts, material)
	}
	display := material.DisplaySecret
	uri := material.ProvisioningURI
	protected := material.ProtectedSecret
	material.Destroy()
	if !allZero(display) || !allZero(uri) || !allZero(protected.Ciphertext) ||
		!allZero(protected.Nonce) || !allZero(protected.AAD) {
		t.Fatal("Destroy() retained enrollment material")
	}
}

func TestTOTPEnrollmentMaterialValidationBindsEveryArtifactField(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	context, err := pendingTOTPContext(request)
	if err != nil {
		t.Fatal(err)
	}
	material := TOTPEnrollmentMaterial{
		ProtectedSecret: testEncryptedTOTP(context),
		DisplaySecret:   []byte(enrollmentTestSecret),
		ProvisioningURI: []byte(enrollmentURI(request.AccountID)),
	}
	defer material.Destroy()
	if !validTOTPEnrollmentMaterial(material, request) {
		t.Fatal("valid enrollment material was rejected")
	}
	material.DisplaySecret = []byte(strings.Repeat("A", 16))
	if validTOTPEnrollmentMaterial(material, request) {
		t.Fatal("zero enrollment material was accepted")
	}
}

func TestEncryptedTOTPEnrollmentConfirmsOnceAndRewrapsAtFactorRevision(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentRecover)
	pendingContext, _ := pendingTOTPContext(request)
	pending := PendingTOTPEnrollment{
		AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
		Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
		CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
		ExpiresAt: serviceTestNow.Add(time.Minute),
	}
	pendingCiphertext := pending.ProtectedSecret.Ciphertext
	pendingNonce := pending.ProtectedSecret.Nonce
	pendingAAD := pending.ProtectedSecret.AAD
	proof := []byte("123456")
	lastAcceptedCounter := int64(100)
	engine := &enrollmentEngineRecorder{acceptedCounter: 101}
	cipher := &enrollmentCipherRecorder{secret: enrollmentTestSecret}
	security, err := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)
	if err != nil {
		t.Fatal(err)
	}

	factor, err := security.Confirm(context.Background(), ConfirmTOTPEnrollmentRequest{
		Pending: pending, Code: proof, At: serviceTestNow, LastAcceptedCounter: &lastAcceptedCounter,
	})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	confirmedContext, _ := authentication.CredentialTOTPContextAtRevision(
		request.FactorID, request.UserID, initialTOTPFactorRevision,
	)
	if cipher.decryptCalls != 1 || cipher.encryptCalls != 1 || cipher.decryptContexts[0] != pendingContext ||
		cipher.encryptContexts[0] != confirmedContext || engine.validateCalls != 1 ||
		engine.validatedSecret != enrollmentTestSecret || engine.validatedCode != "123456" ||
		!engine.validatedAt.Equal(serviceTestNow) || engine.validatedLast != lastAcceptedCounter ||
		factor.FactorID != request.FactorID || factor.Revision != initialTOTPFactorRevision ||
		factor.AcceptedCounter != 101 || string(factor.ProtectedSecret.AAD) != confirmedContext {
		t.Fatalf("unexpected confirmation: factor=%#v engine=%#v cipher=%#v", factor, engine, cipher)
	}
	if !allZero(proof) || !allZero(pendingCiphertext) || !allZero(pendingNonce) || !allZero(pendingAAD) {
		t.Fatal("Confirm() retained proof or transferred pending envelope")
	}
	factor.Destroy()
}

func TestEncryptedTOTPEnrollmentRejectsMismatchedBindingBeforeOpeningEnvelope(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	pendingContext, _ := pendingTOTPContext(request)
	pending := PendingTOTPEnrollment{
		AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
		Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
		CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
		ExpiresAt: serviceTestNow.Add(time.Minute),
	}
	pending.ProtectedSecret.AAD = []byte(strings.Replace(pendingContext, request.AccountID.String(), localTestID(90).String(), 1))
	engine := &enrollmentEngineRecorder{acceptedCounter: 1}
	cipher := &enrollmentCipherRecorder{secret: enrollmentTestSecret}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.Confirm(context.Background(), ConfirmTOTPEnrollmentRequest{
		Pending: pending, Code: []byte("123456"), At: serviceTestNow,
	})
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.decryptCalls != 0 ||
		cipher.encryptCalls != 0 || engine.validateCalls != 0 {
		t.Fatalf("mismatched binding = %v, decrypt=%d encrypt=%d validate=%d", err, cipher.decryptCalls, cipher.encryptCalls, engine.validateCalls)
	}
}

func TestEncryptedTOTPEnrollmentMapsOnlyProofRejectionAndDoesNotRewrap(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	pendingContext, _ := pendingTOTPContext(request)
	pending := PendingTOTPEnrollment{
		AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
		Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
		CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
		ExpiresAt: serviceTestNow.Add(time.Minute),
	}
	engine := &enrollmentEngineRecorder{validationError: authentication.ErrInvalidAuthentication}
	cipher := &enrollmentCipherRecorder{secret: enrollmentTestSecret}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.Confirm(context.Background(), ConfirmTOTPEnrollmentRequest{
		Pending: pending, Code: []byte("123456"), At: serviceTestNow,
	})
	if !errors.Is(err, ErrEnrollmentProofRejected) || cipher.decryptCalls != 1 ||
		engine.validateCalls != 1 || cipher.encryptCalls != 0 {
		t.Fatalf("proof rejection = %v, decrypt=%d encrypt=%d validate=%d", err, cipher.decryptCalls, cipher.encryptCalls, engine.validateCalls)
	}
}

func TestEncryptedTOTPEnrollmentClearsRewrappedSecretWhenContextCancels(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	pendingContext, _ := pendingTOTPContext(request)
	pending := PendingTOTPEnrollment{
		AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
		Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
		CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
		ExpiresAt: serviceTestNow.Add(time.Minute),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cipher := &enrollmentCipherRecorder{secret: enrollmentTestSecret, onEncrypt: cancel}
	engine := &enrollmentEngineRecorder{acceptedCounter: 1}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.Confirm(ctx, ConfirmTOTPEnrollmentRequest{
		Pending: pending, Code: []byte("123456"), At: serviceTestNow,
	})
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.decryptCalls != 1 ||
		engine.validateCalls != 1 || cipher.encryptCalls != 1 ||
		!allZero(cipher.lastEncrypted.Ciphertext) || !allZero(cipher.lastEncrypted.Nonce) ||
		!allZero(cipher.lastEncrypted.AAD) {
		t.Fatalf("canceled confirmation = %v, engine=%#v cipher=%#v", err, engine, cipher)
	}
}

func TestEncryptedTOTPEnrollmentRejectsInvalidDecryptedSecretBeforeProofValidation(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	pendingContext, _ := pendingTOTPContext(request)
	pending := PendingTOTPEnrollment{
		AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
		Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
		CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
		ExpiresAt: serviceTestNow.Add(time.Minute),
	}
	engine := &enrollmentEngineRecorder{acceptedCounter: 1}
	cipher := &enrollmentCipherRecorder{secret: "not-a-canonical-base32-secret"}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.Confirm(context.Background(), ConfirmTOTPEnrollmentRequest{
		Pending: pending, Code: []byte("123456"), At: serviceTestNow,
	})
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.decryptCalls != 1 ||
		cipher.encryptCalls != 0 || engine.validateCalls != 0 {
		t.Fatalf("invalid decrypted secret = %v, decrypt=%d encrypt=%d validate=%d", err, cipher.decryptCalls, cipher.encryptCalls, engine.validateCalls)
	}
}

func TestEncryptedTOTPEnrollmentEnforcesBoundedExclusiveExpiry(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	pendingContext, _ := pendingTOTPContext(request)
	for _, expiresAt := range []time.Time{serviceTestNow, serviceTestNow.Add(ceremonyLifetime + time.Millisecond)} {
		pending := PendingTOTPEnrollment{
			AccountID: request.AccountID, UserID: request.UserID, FactorID: request.FactorID,
			Purpose: request.Purpose, Version: request.Version, FactorRevision: initialTOTPFactorRevision,
			CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(pendingContext),
			ExpiresAt: expiresAt,
		}
		engine := &enrollmentEngineRecorder{acceptedCounter: 1}
		cipher := &enrollmentCipherRecorder{secret: enrollmentTestSecret}
		security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

		_, err := security.Confirm(context.Background(), ConfirmTOTPEnrollmentRequest{
			Pending: pending, Code: []byte("123456"), At: serviceTestNow,
		})
		if !errors.Is(err, authentication.ErrUnavailable) || cipher.decryptCalls != 0 || engine.validateCalls != 0 {
			t.Fatalf("expiry %s = %v, decrypt=%d validate=%d", expiresAt, err, cipher.decryptCalls, engine.validateCalls)
		}
	}
}

func TestEncryptedTOTPEnrollmentRejectsCustomerBearingURI(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	engine := &enrollmentEngineRecorder{
		generateURI: "otpauth://totp/Periapsis:customer@example.test?issuer=Periapsis&secret=" + enrollmentTestSecret,
	}
	cipher := &enrollmentCipherRecorder{}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.New(context.Background(), request)
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.encryptCalls != 0 {
		t.Fatalf("customer-bearing URI = %v, encrypt=%d", err, cipher.encryptCalls)
	}
}

func TestEncryptedTOTPEnrollmentRejectsZeroSecret(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	zeroSecret := strings.Repeat("A", 16)
	engine := &enrollmentEngineRecorder{
		generateSecret: zeroSecret,
		generateURI: "otpauth://totp/Periapsis:" + request.AccountID.String() +
			"?issuer=Periapsis&secret=" + zeroSecret,
	}
	cipher := &enrollmentCipherRecorder{}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.New(context.Background(), request)
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.encryptCalls != 0 {
		t.Fatalf("zero secret = %v, encrypt=%d", err, cipher.encryptCalls)
	}
}

func TestEncryptedTOTPEnrollmentRejectsAlternatePathEncoding(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	engine := &enrollmentEngineRecorder{
		generateURI: "otpauth://totp/Periapsis%3A" + request.AccountID.String() +
			"?issuer=Periapsis&secret=" + enrollmentTestSecret,
	}
	cipher := &enrollmentCipherRecorder{}
	security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

	_, err := security.New(context.Background(), request)
	if !errors.Is(err, authentication.ErrUnavailable) || cipher.encryptCalls != 0 {
		t.Fatalf("alternate path encoding = %v, encrypt=%d", err, cipher.encryptCalls)
	}
}

func TestEncryptedTOTPEnrollmentRejectsExplicitEmptyOptionalParameter(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	for _, parameter := range []string{"algorithm", "digits", "period"} {
		engine := &enrollmentEngineRecorder{
			generateURI: enrollmentURI(request.AccountID) + "&" + parameter + "=",
		}
		cipher := &enrollmentCipherRecorder{}
		security, _ := NewEncryptedTOTPEnrollmentSecurity(engine, cipher)

		_, err := security.New(context.Background(), request)
		if !errors.Is(err, authentication.ErrUnavailable) || cipher.encryptCalls != 0 {
			t.Fatalf("empty %s = %v, encrypt=%d", parameter, err, cipher.encryptCalls)
		}
	}
}

func TestEncryptedTOTPEnrollmentAcceptsOnlyCurrentEnvelopeKeyVersion(t *testing.T) {
	request := enrollmentRequest(TOTPEnrollmentInvite)
	context, err := pendingTOTPContext(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int16{-1, 0, 2, 32_767} {
		protected := testEncryptedTOTP(context)
		protected.KeyVersion = version
		if validEncryptedTOTPSecret(protected, context) {
			t.Fatalf("key version %d was accepted", version)
		}
	}
	if !validEncryptedTOTPSecret(testEncryptedTOTP(context), context) {
		t.Fatal("current key version was rejected")
	}
}

func enrollmentRequest(purpose TOTPEnrollmentPurpose) NewTOTPEnrollmentRequest {
	return NewTOTPEnrollmentRequest{
		AccountID: localTestID(20), UserID: localTestID(21), FactorID: localTestID(22),
		Purpose: purpose, Version: initialTOTPEnrollmentVersion,
		CeremonyTokenDigest: [32]byte{1, 2, 3, 4},
	}
}

func enrollmentURI(accountID uuid.UUID) string {
	return "otpauth://totp/Periapsis:" + accountID.String() +
		"?issuer=Periapsis&secret=" + enrollmentTestSecret
}

var _ TOTPEnrollmentEngine = (*enrollmentEngineRecorder)(nil)
var _ TOTPEnrollmentCipher = (*enrollmentCipherRecorder)(nil)
