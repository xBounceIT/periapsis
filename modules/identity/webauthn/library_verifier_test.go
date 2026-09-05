package webauthn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestLibraryVerifierVerifiesRealES256Authentication(t *testing.T) {
	request := signedAuthenticationRequest(t)
	verifier, err := NewLibraryVerifier(LibraryVerifierOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.VerifyAuthentication(context.Background(), request)
	if err != nil {
		t.Fatalf("VerifyAuthentication() error = %v", err)
	}
	if proof.ChallengeDigest != request.ChallengeDigest || proof.Origin != request.AllowedOrigins[0] ||
		!proof.UserPresent || !proof.UserVerified || proof.CrossOrigin || proof.SignCount != 9 ||
		!bytes.Equal(proof.CredentialID, request.CredentialID) || !bytes.Equal(proof.UserHandle, request.UserHandle) {
		t.Fatalf("unexpected normalized proof: %v", proof)
	}
}

func TestLibraryVerifierVerifiesRealNoneAttestationRegistration(t *testing.T) {
	request := registrationVerificationRequest(t)
	verifier, err := NewLibraryVerifier(LibraryVerifierOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.VerifyRegistration(context.Background(), request)
	if err != nil {
		t.Fatalf("VerifyRegistration() error = %v", err)
	}
	if proof.ChallengeDigest != request.ChallengeDigest || proof.Origin != request.AllowedOrigins[0] ||
		!proof.UserPresent || !proof.UserVerified || proof.CrossOrigin || !proof.Discoverable ||
		proof.AttestationType != AttestationTypeNone || proof.AttestationTrusted || proof.MetadataRevision != 0 ||
		!bytes.Equal(proof.CredentialID, request.CredentialID) || len(proof.PublicKey) < minimumPublicKeyBytes {
		t.Fatalf("unexpected registration proof: %v", proof)
	}
}

func TestLibraryVerifierRejectsTamperingDuplicateMembersAndCancellation(t *testing.T) {
	base := signedAuthenticationRequest(t)
	tests := map[string]func(*AuthenticationVerificationRequest, *context.Context){
		"signature tamper": func(request *AuthenticationVerificationRequest, _ *context.Context) {
			request.Signature[len(request.Signature)-1] ^= 1
		},
		"duplicate challenge": func(request *AuthenticationVerificationRequest, _ *context.Context) {
			request.ClientDataJSON = []byte(`{"type":"webauthn.get","challenge":"a","challenge":"b","origin":"https://app.example"}`)
		},
		"wrong challenge digest": func(request *AuthenticationVerificationRequest, _ *context.Context) {
			request.ChallengeDigest[0] ^= 1
		},
		"cancelled": func(_ *AuthenticationVerificationRequest, ctx *context.Context) {
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			*ctx = cancelled
		},
	}
	verifier, err := NewLibraryVerifier(LibraryVerifierOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneAuthenticationVerificationRequest(base)
			ctx := context.Background()
			mutate(&request, &ctx)
			if _, err := verifier.VerifyAuthentication(ctx, request); err == nil {
				t.Fatal("VerifyAuthentication() unexpectedly succeeded")
			}
		})
	}
}

func TestRegistrationResidentKeyRequiresCredPropsEvidence(t *testing.T) {
	required := CeremonyPolicy{
		RequireUserPresence: true, UserVerification: UserVerificationRequired,
		ResidentKey: ResidentKeyRequired, Attestation: AttestationNone,
	}
	if _, _, err := parseRegistrationExtensions(nil, required.ResidentKey); err == nil {
		t.Fatal("required resident key accepted without credProps")
	}
	outputs, resident, err := parseRegistrationExtensions([]byte(`{"credProps":{"rk":true}}`), required.ResidentKey)
	if err != nil || !resident || outputs == nil {
		t.Fatalf("parseRegistrationExtensions() = %v, %t, %v", outputs, resident, err)
	}
	for _, document := range [][]byte{
		[]byte(`{"credProps":{"rk":false}}`),
		[]byte(`{"credProps":{"rk":true,"rk":false}}`),
		[]byte(`{"credProps":{"rk":true},"other":true}`),
	} {
		if _, _, err := parseRegistrationExtensions(document, required.ResidentKey); err == nil {
			t.Fatal("hostile extension result unexpectedly accepted")
		}
	}
}

func FuzzDuplicateSafeClientData(f *testing.F) {
	f.Add([]byte(`{"type":"webauthn.get","challenge":"YWFhYWFhYWFhYWFhYWFhYQ","origin":"https://app.example"}`))
	f.Add([]byte(`{"type":"webauthn.get","type":"webauthn.create"}`))
	f.Fuzz(func(t *testing.T, document []byte) {
		_ = validateDuplicateSafeObject(document, 8, 128)
	})
}

func signedAuthenticationRequest(t *testing.T) AuthenticationVerificationRequest {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	credentialID := make([]byte, 32)
	userHandle := make([]byte, 32)
	for _, target := range [][]byte{challenge, credentialID, userHandle} {
		if _, err := rand.Read(target); err != nil {
			t.Fatal(err)
		}
	}
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	origin := "https://app.example"
	clientData := []byte(fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		encodedChallenge, origin,
	))
	rpID := "app.example"
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := append([]byte(nil), rpIDHash[:]...)
	authenticatorData = append(authenticatorData, byte(0x05)) // UP and UV.
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 9)
	authenticatorData = append(authenticatorData, counter...)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authenticatorData...), clientHash[:]...)
	signedHash := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: privateKey.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord: privateKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return AuthenticationVerificationRequest{
		ChallengeDigest: sha256.Sum256(challenge), RPID: rpID, AllowedOrigins: []string{origin},
		Policy: CeremonyPolicy{
			RequireUserPresence: true, UserVerification: UserVerificationRequired,
			ResidentKey: ResidentKeyPreferred, Attestation: AttestationNone,
		},
		Credential:   Credential{ID: append([]byte(nil), credentialID...), PublicKey: publicKey},
		CredentialID: credentialID, ClientDataJSON: clientData, AuthenticatorData: authenticatorData,
		Signature: signature, UserHandle: userHandle,
	}
}

func registrationVerificationRequest(t *testing.T) RegistrationVerificationRequest {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	credentialID := make([]byte, 32)
	aaguid := make([]byte, 16)
	for _, target := range [][]byte{challenge, credentialID, aaguid} {
		if _, err := rand.Read(target); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: privateKey.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord: privateKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpID := "app.example"
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := append([]byte(nil), rpIDHash[:]...)
	authenticatorData = append(authenticatorData, byte(0x45)) // UP, UV, and attested credential data.
	authenticatorData = append(authenticatorData, 0, 0, 0, 0)
	authenticatorData = append(authenticatorData, aaguid...)
	credentialLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialLength, uint16(len(credentialID)))
	authenticatorData = append(authenticatorData, credentialLength...)
	authenticatorData = append(authenticatorData, credentialID...)
	authenticatorData = append(authenticatorData, publicKey...)
	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt": "none", "authData": authenticatorData, "attStmt": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://app.example"
	clientData := []byte(fmt.Sprintf(
		`{"type":"webauthn.create","challenge":"%s","origin":"%s","crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge), origin,
	))
	return RegistrationVerificationRequest{
		ChallengeDigest: sha256.Sum256(challenge), RPID: rpID, AllowedOrigins: []string{origin},
		Policy: CeremonyPolicy{
			RequireUserPresence: true, UserVerification: UserVerificationRequired,
			ResidentKey: ResidentKeyRequired, Attestation: AttestationNone,
		},
		CredentialID: credentialID, ClientDataJSON: clientData, AttestationObject: attestationObject,
		ClientExtensionResults: []byte(`{"credProps":{"rk":true}}`), Transports: []CredentialTransport{TransportInternal},
	}
}

func cloneAuthenticationVerificationRequest(source AuthenticationVerificationRequest) AuthenticationVerificationRequest {
	result := source
	result.AllowedOrigins = append([]string(nil), source.AllowedOrigins...)
	result.Credential = source.Credential
	result.Credential.ID = append([]byte(nil), source.Credential.ID...)
	result.Credential.PublicKey = append([]byte(nil), source.Credential.PublicKey...)
	result.CredentialID = append([]byte(nil), source.CredentialID...)
	result.ClientDataJSON = append([]byte(nil), source.ClientDataJSON...)
	result.AuthenticatorData = append([]byte(nil), source.AuthenticatorData...)
	result.Signature = append([]byte(nil), source.Signature...)
	result.UserHandle = append([]byte(nil), source.UserHandle...)
	return result
}
