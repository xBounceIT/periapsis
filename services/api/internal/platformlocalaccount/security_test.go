package platformlocalaccount

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestArgon2idPasswordHasherUsesRequiredBoundedProfile(t *testing.T) {
	hasher := Argon2idPasswordHasher{}
	password := []byte("correct horse battery staple")
	encoded, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if !strings.Contains(string(encoded), "$argon2id$v=19$m=65536,t=3,p=1$") ||
		!validGeneratedPasswordPHC(encoded) || !hasher.Verify(password, encoded) ||
		hasher.Verify([]byte("wrong password material"), encoded) {
		t.Fatalf("unexpected Argon2id result: %q", encoded)
	}
	if validGeneratedPasswordPHC(bytes.Repeat([]byte{'x'}, 64)) ||
		validGeneratedPasswordPHC([]byte(strings.Replace(string(encoded), "p=1", "p=01", 1))) {
		t.Fatal("generated password PHC validation accepted a malformed encoding")
	}
	abusive := []byte("$argon2id$v=19$m=1048576,t=20,p=8$c2FsdHNhbHQ$aGFzaA")
	if hasher.Verify(password, abusive) {
		t.Fatal("accepted abusive Argon2id verification parameters")
	}
}

func TestSecretAndModelFormattingRemainRedacted(t *testing.T) {
	canary := []byte("local-password-canary")
	input := PasswordTransitionInput{NewPassword: canary, Reason: "security rotation"}
	if strings.Contains(fmt.Sprintf("%#v", input), string(canary)) {
		t.Fatal("password input formatting leaked material")
	}
	artifact := newOneTimeArtifact(
		append([]byte(nil), canary...), append([]byte(nil), canary...), append([]byte(nil), canary...),
	)
	defer artifact.Destroy()
	if strings.Contains(fmt.Sprintf("%#v", artifact), string(canary)) {
		t.Fatal("one-time artifact formatting leaked material")
	}
	params := ApplyParams{ReplacementPasswordPHC: append([]byte(nil), canary...)}
	defer clear(params.ReplacementPasswordPHC)
	if strings.Contains(fmt.Sprintf("%#v", params), string(canary)) {
		t.Fatal("repository command formatting leaked material")
	}
	options := Options{CommandDigestKey: canary}
	if strings.Contains(fmt.Sprintf("%#v", options), string(canary)) {
		t.Fatal("service options formatting leaked digest key material")
	}
	if !bytes.Equal(canary, []byte("local-password-canary")) {
		t.Fatal("formatting mutated source material")
	}
}

func TestOneTimeArtifactCopiesShareOneConsumeAndDestroyState(t *testing.T) {
	token := []byte(strings.Repeat("A", 43))
	secret := []byte(strings.Repeat("B", 32))
	uri := []byte("otpauth://totp/Periapsis:01900000-0000-7000-8000-000000000001")
	artifact := newOneTimeArtifact(token, secret, uri)
	copyOfArtifact := artifact

	material, ok := copyOfArtifact.Consume()
	if !ok || !bytes.Equal(material.CeremonyToken, token) || !bytes.Equal(material.TOTPSecret, secret) ||
		!bytes.Equal(material.ProvisioningURI, uri) {
		t.Fatalf("Consume() = %#v, %t", material, ok)
	}
	if replay, replayOK := artifact.Consume(); replayOK || len(replay.CeremonyToken) != 0 ||
		len(replay.TOTPSecret) != 0 || len(replay.ProvisioningURI) != 0 {
		t.Fatalf("copied artifact replay = %#v, %t", replay, replayOK)
	}
	material.Destroy()
	if !allZero(token) || !allZero(secret) || !allZero(uri) {
		t.Fatal("destroying consumed artifact did not clear shared buffers")
	}
}

func TestSecretGeneratorRejectsZeroKeyAndZeroEntropy(t *testing.T) {
	if _, err := newSecretGenerator(bytes.NewReader(bytes.Repeat([]byte{1}, opaqueTokenBytes)), make([]byte, digestKeyBytes)); err == nil {
		t.Fatal("accepted an all-zero command digest key")
	}
	generator, err := newSecretGenerator(
		bytes.NewReader(make([]byte, opaqueTokenBytes)), bytes.Repeat([]byte{1}, digestKeyBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if token, digest, err := generator.issue("ceremony-token"); err == nil || token != nil || digest != ([32]byte{}) {
		t.Fatalf("zero entropy issue = %q, %x, %v", token, digest, err)
	}
}
