package identitysync

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

const (
	observationDigestPurpose = "periapsis/identity/ldap-sync/observation/v1"
	cursorDigestPurpose      = "periapsis/identity/ldap-sync/enumeration/v1"
)

func newClaimProof() (ClaimProof, error) {
	claimID, err := uuid.NewV7()
	if err != nil {
		return ClaimProof{}, err
	}
	receipt := make([]byte, 32)
	if _, err := rand.Read(receipt); err != nil {
		clear(receipt)
		return ClaimProof{}, err
	}
	digest := sha256.Sum256(receipt)
	clear(receipt)
	return ClaimProof{ID: claimID, ReceiptDigest: digest}, nil
}

func observationDigest(
	claim Claim,
	ordinal int,
	observation ldapclient.DirectoryObservation,
) [sha256.Size]byte {
	hasher := sha256.New()
	writeDigestPart(hasher, []byte(observationDigestPurpose))
	writeDigestPart(hasher, claim.RunID[:])
	writeDigestPart(hasher, claim.TenantID[:])
	writeDigestPart(hasher, claim.ProviderID[:])
	writeDigestPart(hasher, claim.BindingID[:])
	writeDigestInt64(hasher, int64(claim.ProviderVersion))
	writeDigestInt64(hasher, int64(claim.ConfigurationVersion))
	writeDigestInt64(hasher, int64(claim.BindingVersion))
	writeDigestInt64(hasher, int64(claim.BindingAuthRevision))
	writeDigestPart(hasher, claim.BindingAccessEpochID[:])
	writeDigestInt64(hasher, claim.RuleSetRevision)
	writeDigestInt64(hasher, claim.AuthorizationRevision)
	writeDigestInt64(hasher, int64(ordinal))
	writeDirectoryEntry(hasher, observation.User)
	groups := append([]ldapclient.DirectoryEntry(nil), observation.Groups...)
	slices.SortFunc(groups, func(left, right ldapclient.DirectoryEntry) int {
		return strings.Compare(left.DistinguishedName, right.DistinguishedName)
	})
	writeDigestInt64(hasher, int64(len(groups)))
	for _, group := range groups {
		writeDirectoryEntry(hasher, group)
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func enumerationDigest(observations []preparedObservation) [sha256.Size]byte {
	hasher := sha256.New()
	writeDigestPart(hasher, []byte(cursorDigestPurpose))
	writeDigestInt64(hasher, int64(len(observations)))
	for _, observation := range observations {
		writeDigestInt64(hasher, int64(observation.Staged.Ordinal))
		writeDigestPart(hasher, observation.Staged.ObservationDigest[:])
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func writeDirectoryEntry(hasher hash.Hash, entry ldapclient.DirectoryEntry) {
	writeDigestPart(hasher, []byte(entry.DistinguishedName))
	attributes := append([]ldapclient.DirectoryAttribute(nil), entry.Attributes...)
	slices.SortFunc(attributes, func(left, right ldapclient.DirectoryAttribute) int {
		return strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
	})
	writeDigestInt64(hasher, int64(len(attributes)))
	for _, attribute := range attributes {
		writeDigestPart(hasher, []byte(strings.ToLower(attribute.Name)))
		values := append([][]byte(nil), attribute.Values...)
		slices.SortFunc(values, bytes.Compare)
		writeDigestInt64(hasher, int64(len(values)))
		for _, value := range values {
			writeDigestPart(hasher, value)
		}
	}
}

func writeDigestInt64(hasher hash.Hash, value int64) {
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeDigestPart(hasher, encoded[:])
}

func writeDigestPart(hasher hash.Hash, value []byte) {
	length := [8]byte{}
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func clearDirectoryEntry(entry *ldapclient.DirectoryEntry) {
	if entry == nil {
		return
	}
	for attributeIndex := range entry.Attributes {
		attribute := &entry.Attributes[attributeIndex]
		for valueIndex := range attribute.Values {
			clear(attribute.Values[valueIndex])
			attribute.Values[valueIndex] = nil
		}
		attribute.Values = nil
		attribute.Name = ""
	}
	entry.Attributes = nil
	entry.DistinguishedName = ""
}

func clearDirectoryObservation(observation *ldapclient.DirectoryObservation) {
	if observation == nil {
		return
	}
	clearDirectoryEntry(&observation.User)
	for index := range observation.Groups {
		clearDirectoryEntry(&observation.Groups[index])
	}
	observation.Groups = nil
}
