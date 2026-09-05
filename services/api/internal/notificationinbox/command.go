package notificationinbox

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"

	"github.com/google/uuid"
)

const (
	operationSetReadState = "notification_inbox.set_read_state"
	operationMarkAllRead  = "notification_inbox.mark_all_read"
)

func bindSetReadStateCommand(tenantID, userID, itemID uuid.UUID, input SetReadStateInput) (CommandBinding, error) {
	return bindCommand(operationSetReadState, input.IdempotencyKey,
		tenantID.String(), userID.String(), itemID.String(), strconv.FormatBool(input.Read),
		strconv.FormatUint(input.ExpectedRevision, 10),
	)
}

func bindMarkAllReadCommand(tenantID, userID uuid.UUID, input MarkAllReadInput) (CommandBinding, error) {
	return bindCommand(operationMarkAllRead, input.IdempotencyKey,
		tenantID.String(), userID.String(), strconv.FormatUint(input.ExpectedRevision, 10),
	)
}

func bindCommand(operation, key string, parts ...string) (CommandBinding, error) {
	if !validStableKey(operation, 64) || !validIdempotencyKey(key) {
		return CommandBinding{}, ErrInvalidInput
	}
	keyDigest := sha256.Sum256([]byte("periapsis.notification_inbox.idempotency.v1\x00" + key))
	hash := sha256.New()
	writeHashText(hash, "periapsis.notification_inbox.command.v1")
	writeHashText(hash, operation)
	for _, part := range parts {
		writeHashText(hash, part)
	}
	var requestDigest [sha256.Size]byte
	copy(requestDigest[:], hash.Sum(nil))
	return CommandBinding{Operation: operation, KeyDigest: keyDigest, RequestDigest: requestDigest}, nil
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeHashText(writer hashWriter, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}
