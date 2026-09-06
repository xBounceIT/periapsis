package postgres

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

func TestNotificationMutationDigestBindsEncryptedEnvelopeNotPasswordStorage(t *testing.T) {
	root, material := make([]byte, 32), make([]byte, 32)
	rand.Read(root)
	rand.Read(material)
	defer clear(root)
	defer clear(material)
	plaintext := []byte(base64.RawURLEncoding.EncodeToString(material))
	defer clear(plaintext)
	keyring, err := notification.NewKeyring(7, map[int16][]byte{7: root})
	if err != nil {
		t.Fatal("construct ephemeral notification keyring")
	}
	defer keyring.Close()
	actorID := uuid.MustParse("019d9000-0000-7000-8000-000000000001")
	secretID := uuid.MustParse("019d9000-0000-7000-8000-000000000002")
	secretContext := notification.SecretContext{SecretID: secretID, SecretVersion: 1, Kind: notification.SecretKindSMTPPassword}
	envelope, err := keyring.Protect(secretContext, plaintext)
	if err != nil {
		t.Fatal("protect ephemeral SMTP material")
	}
	defer clear(envelope.Nonce)
	defer clear(envelope.Ciphertext)
	write := notification.SMTPPersistedWrite{
		Name: "Envelope boundary", Host: "smtp.example.invalid", Port: 465,
		Password: &notification.ProtectedSecret{ID: secretID, Version: 1, Kind: notification.SecretKindSMTPPassword, Envelope: envelope},
	}
	protected, ok := smtpNotificationPayload(write)["password"].(map[string]any)
	if !ok || len(protected) != 6 {
		t.Fatal("SMTP persistence no longer contains only the protected-secret envelope")
	}
	for _, field := range []string{"id", "version", "kind", "keyVersion", "nonce", "ciphertext"} {
		if _, present := protected[field]; !present {
			t.Fatal("protected-secret envelope field missing")
		}
	}
	if protected["nonce"] != base64.StdEncoding.EncodeToString(envelope.Nonce) || protected["ciphertext"] != base64.StdEncoding.EncodeToString(envelope.Ciphertext) || protected["keyVersion"] != envelope.KeyVersion {
		t.Fatal("persistence does not bind the actual encrypted envelope")
	}
	payload := smtpNotificationPayload(write)
	encoded, err := json.Marshal(payload)
	if err != nil || bytes.Contains(encoded, plaintext) {
		t.Fatal("SMTP digest payload exposed plaintext")
	}
	decrypted, err := keyring.Unprotect(secretContext, envelope)
	defer clear(decrypted)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatal("SMTP credential must remain authenticated-encrypted and recoverable, not a password verifier")
	}

	const scope, operation, command = "platform", "smtp.version", "envelope-boundary-command"
	digests, err := notificationMutationDigests(scope, actorID, operation, command, payload)
	if err != nil {
		t.Fatal("create notification receipt digest")
	}
	// Pin the persisted receipt protocol independently of the production constant.
	const protocol = "periapsis/notification/admin-request/sha256/v1"
	expectedKey := sha256.Sum256([]byte(protocol + "\x00key\x00" + scope + "\x00" + actorID.String() + "\x00" + operation + "\x00" + command))
	expectedRequest := sha256.Sum256(append([]byte(protocol+"\x00request\x00"+scope+"\x00"+actorID.String()+"\x00"+operation+"\x00"), encoded...))
	if !bytes.Equal(digests.key, expectedKey[:]) || !bytes.Equal(digests.request, expectedRequest[:]) {
		t.Fatal("domain-separated receipt protocol changed")
	}
	replay, err := notificationMutationDigests(scope, actorID, operation, command, payload)
	if err != nil || !bytes.Equal(replay.key, digests.key) || !bytes.Equal(replay.request, digests.request) {
		t.Fatal("same persisted request no longer has the same idempotency digests")
	}
	for _, change := range []struct {
		name  string
		apply func(*notification.SMTPPersistedWrite)
	}{
		{"ciphertext", func(value *notification.SMTPPersistedWrite) { value.Password.Envelope.Ciphertext[0] ^= 1 }},
		{"nonce", func(value *notification.SMTPPersistedWrite) { value.Password.Envelope.Nonce[0] ^= 1 }},
		{"key-version", func(value *notification.SMTPPersistedWrite) { value.Password.Envelope.KeyVersion++ }},
		{"retain", func(value *notification.SMTPPersistedWrite) { value.RetainPassword = true }},
		{"remove", func(value *notification.SMTPPersistedWrite) { value.RemovePassword = true }},
	} {
		t.Run(change.name, func(t *testing.T) {
			candidate := write
			secret := *write.Password
			secret.Envelope.Nonce = slices.Clone(envelope.Nonce)
			secret.Envelope.Ciphertext = slices.Clone(envelope.Ciphertext)
			defer clear(secret.Envelope.Nonce)
			defer clear(secret.Envelope.Ciphertext)
			candidate.Password = &secret
			change.apply(&candidate)
			changed, digestErr := notificationMutationDigests(scope, actorID, operation, command, smtpNotificationPayload(candidate))
			if digestErr != nil || !bytes.Equal(changed.key, digests.key) || bytes.Equal(changed.request, digests.request) {
				t.Fatal("changed encrypted request did not retain the key and invalidate the request receipt")
			}
		})
	}
	for _, changed := range []struct {
		scope     string
		actor     uuid.UUID
		operation string
	}{
		{"tenant", actorID, operation},
		{scope, secretID, operation},
		{scope, actorID, "smtp.test"},
	} {
		candidate, digestErr := notificationMutationDigests(changed.scope, changed.actor, changed.operation, command, payload)
		if digestErr != nil || bytes.Equal(candidate.key, digests.key) || bytes.Equal(candidate.request, digests.request) {
			t.Fatal("receipt digest lost scope, actor or operation separation")
		}
	}
}
