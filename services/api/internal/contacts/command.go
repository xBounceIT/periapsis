package contacts

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

func bindCommand(operation, key string, parts ...string) (CommandBinding, error) {
	if !validStableKey(operation, 64) || !idempotencyKeyPattern.MatchString(key) {
		return CommandBinding{}, ErrInvalidInput
	}
	keyDigest := sha256.Sum256([]byte("periapsis.contacts.idempotency.v1\x00" + key))
	hash := sha256.New()
	writeHashText(hash, "periapsis.contacts.command.v1")
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
	writer.Write(length[:])
	writer.Write([]byte(value))
}

func contactFingerprint(fields kernel.ContactFields) []string {
	parts := []string{
		fields.FirstName, fields.LastName, fields.Email.String(), fields.Phone, fields.Function,
		fields.Language, fields.Timezone, strconv.Itoa(int(fields.EscalationPriority)),
		fields.Class.String(), strconv.FormatBool(fields.EmailAllowed), strconv.FormatBool(fields.Active),
	}
	parts = append(parts, "categories")
	for _, category := range fields.NotificationCategories {
		parts = append(parts, category.String())
	}
	parts = append(parts, "windows")
	for _, window := range fields.NotificationWindows {
		parts = append(parts, strconv.Itoa(int(window.Weekday())), strconv.Itoa(window.StartMinute()), strconv.Itoa(window.EndMinute()))
	}
	parts = append(parts, "tags")
	for _, tag := range fields.Tags {
		parts = append(parts, tag.String())
	}
	parts = append(parts, "linked_account")
	if fields.LinkedAccount != nil {
		parts = append(parts, fields.LinkedAccount.MembershipID().String(), fields.LinkedAccount.UserID().String())
	}
	return parts
}

func groupFingerprint(key kernel.Key, version kernel.GroupVersion) []string {
	return groupContentFingerprint(
		key, version.Name(), version.Description(), version.Mode(), version.Rule(), version.Members(),
	)
}

func groupContentFingerprint(
	key kernel.Key,
	name, description string,
	mode kernel.GroupMode,
	rule kernel.RuleNode,
	members []kernel.EntityID,
) []string {
	parts := []string{
		key.String(), name, description, mode.String(),
	}
	parts = append(parts, ruleFingerprint(rule)...)
	parts = append(parts, "members")
	for _, member := range members {
		parts = append(parts, member.String())
	}
	return parts
}

func linkCreateFingerprint(tenantID uuid.UUID, input LinkInput) []string {
	return []string{
		tenantID.String(), input.TicketKind.String(), input.TicketID.String(), input.ContactID.String(),
		input.Role.String(), kernel.OriginManual.String(), "1",
	}
}

func ruleFingerprint(rule kernel.RuleNode) []string {
	parts := []string{rule.Kind().String(), rule.Field().String(), rule.Operator().String()}
	parts = append(parts, rule.Values()...)
	for _, child := range rule.Children() {
		childParts := ruleFingerprint(child)
		parts = append(parts, "child", strconv.Itoa(len(childParts)))
		parts = append(parts, childParts...)
	}
	return parts
}

func linkFingerprint(link kernel.TicketContactLink) []string {
	parts := []string{
		link.TenantID().String(), link.TicketKind().String(), link.TicketID().String(), link.ContactID().String(),
		link.Role().String(), link.Origin().String(), strconv.FormatUint(link.Version(), 10),
	}
	if provenance := link.Provenance(); provenance != nil {
		parts = append(parts, provenance.SourceAlertID().String(), strconv.FormatUint(provenance.SourceAlertVersion(), 10))
	}
	return parts
}

func instantFingerprint(value time.Time) string { return strconv.FormatInt(value.UnixMilli(), 10) }
