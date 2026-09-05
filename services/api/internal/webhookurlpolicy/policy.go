package webhookurlpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaximumPolicyVersion = int64(2_147_483_647)
	MaximumPolicyRules   = 256
)

type RuleEffect string

const (
	RuleAllow RuleEffect = "allow"
	RuleDeny  RuleEffect = "deny"
)

type RuleMatch string

const (
	RuleExact      RuleMatch = "exact"
	RuleSubdomains RuleMatch = "subdomains"
)

type RuleInput struct {
	Effect   RuleEffect
	Match    RuleMatch
	Hostname string
	Port     int
}

func (RuleInput) String() string         { return "webhookurlpolicy.RuleInput{redacted}" }
func (value RuleInput) GoString() string { return value.String() }

type Rule struct {
	effect   RuleEffect
	match    RuleMatch
	hostname string
	port     int
	digest   [sha256.Size]byte
}

func (rule Rule) Effect() RuleEffect        { return rule.effect }
func (rule Rule) Match() RuleMatch          { return rule.match }
func (rule Rule) Hostname() string          { return rule.hostname }
func (rule Rule) Port() int                 { return rule.port }
func (rule Rule) Digest() [sha256.Size]byte { return rule.digest }
func (Rule) String() string                 { return "webhookurlpolicy.Rule{redacted}" }
func (value Rule) GoString() string         { return value.String() }
func validRuleEffect(value RuleEffect) bool { return value == RuleAllow || value == RuleDeny }
func validRuleMatch(value RuleMatch) bool   { return value == RuleExact || value == RuleSubdomains }
func validRulePort(value int) bool          { return value >= 1 && value <= 65_535 }
func canonicalRuleRecord(rule Rule) string {
	return string(rule.effect) + "\x00" + string(rule.match) + "\x00" + rule.hostname + "\x00" + strconv.Itoa(rule.port)
}
func sameRule(left, right Rule) bool    { return left == right }
func sameRules(left, right []Rule) bool { return slices.EqualFunc(left, right, sameRule) }
func rulesClone(input []Rule) []Rule    { return slices.Clone(input) }
func defaultRulePort(input int) int {
	if input == 0 {
		return 443
	}
	return input
}
func canonicalRuleDigest(rule Rule) [sha256.Size]byte {
	return framedDigest("periapsis.webhook-url-policy-rule.v1", string(rule.effect), string(rule.match), rule.hostname, strconv.Itoa(rule.port))
}

type PolicyInput struct {
	ID                      uuid.UUID
	VersionID               uuid.UUID
	TenantID                uuid.UUID
	Version                 int64
	Rules                   []RuleInput
	PublishedByMembershipID uuid.UUID
	PublishedAt             time.Time
}

type Policy struct {
	id                      uuid.UUID
	versionID               uuid.UUID
	tenantID                uuid.UUID
	version                 int64
	rules                   []Rule
	publishedByMembershipID uuid.UUID
	publishedAt             time.Time
	digest                  [sha256.Size]byte
	semanticDigest          [sha256.Size]byte
}

func (policy Policy) ID() uuid.UUID                      { return policy.id }
func (policy Policy) VersionID() uuid.UUID               { return policy.versionID }
func (policy Policy) TenantID() uuid.UUID                { return policy.tenantID }
func (policy Policy) Version() int64                     { return policy.version }
func (Policy) Scheme() string                            { return "https" }
func (Policy) DefaultAction() RuleEffect                 { return RuleDeny }
func (policy Policy) Rules() []Rule                      { return rulesClone(policy.rules) }
func (policy Policy) PublishedByMembershipID() uuid.UUID { return policy.publishedByMembershipID }
func (policy Policy) PublishedAt() time.Time             { return policy.publishedAt }
func (policy Policy) Digest() [sha256.Size]byte          { return policy.digest }
func (policy Policy) SemanticDigest() [sha256.Size]byte  { return policy.semanticDigest }
func (policy Policy) String() string {
	return fmt.Sprintf("webhookurlpolicy.Policy{version:%d,rules:%d,content:[REDACTED]}", policy.version, len(policy.rules))
}
func (policy Policy) GoString() string { return policy.String() }

func NewPolicy(input PolicyInput) (Policy, error) {
	if !validUUIDv7(input.ID) || !validUUIDv7(input.VersionID) || input.ID == input.VersionID ||
		!validUUIDv7(input.TenantID) || !validUUIDv7(input.PublishedByMembershipID) ||
		input.Version < 1 || input.Version > MaximumPolicyVersion || !validPolicyInstant(input.PublishedAt) {
		return Policy{}, ErrInvalidInput
	}
	rules, err := canonicalRules(input.Rules)
	if err != nil {
		return Policy{}, err
	}
	semanticParts := []string{"periapsis.webhook-url-policy-semantics.v1", "https", "deny"}
	for _, rule := range rules {
		semanticParts = append(semanticParts, canonicalRuleRecord(rule))
	}
	semanticDigest := framedDigest(semanticParts...)
	publishedAt := input.PublishedAt.UTC()
	digest := framedDigest(
		"periapsis.webhook-url-policy-version.v1",
		input.TenantID.String(), input.ID.String(), input.VersionID.String(), strconv.FormatInt(input.Version, 10),
		input.PublishedByMembershipID.String(), formatPolicyInstant(publishedAt), fmt.Sprintf("%x", semanticDigest),
	)
	return Policy{
		id: input.ID, versionID: input.VersionID, tenantID: input.TenantID,
		version: input.Version, rules: rules, publishedByMembershipID: input.PublishedByMembershipID,
		publishedAt: publishedAt, digest: digest, semanticDigest: semanticDigest,
	}, nil
}

func SamePolicy(left, right Policy) bool {
	return validPolicy(left) && validPolicy(right) && left.id == right.id && left.versionID == right.versionID &&
		left.tenantID == right.tenantID && left.version == right.version && sameRules(left.rules, right.rules) &&
		left.publishedByMembershipID == right.publishedByMembershipID && left.publishedAt.Equal(right.publishedAt) &&
		left.digest == right.digest && left.semanticDigest == right.semanticDigest
}

func validPolicy(policy Policy) bool {
	if !validUUIDv7(policy.id) || !validUUIDv7(policy.versionID) || policy.id == policy.versionID ||
		!validUUIDv7(policy.tenantID) || !validUUIDv7(policy.publishedByMembershipID) ||
		policy.version < 1 || policy.version > MaximumPolicyVersion || !validPolicyInstant(policy.publishedAt) ||
		policy.digest == [sha256.Size]byte{} || policy.semanticDigest == [sha256.Size]byte{} {
		return false
	}
	restored, err := NewPolicy(PolicyInput{
		ID: policy.id, VersionID: policy.versionID, TenantID: policy.tenantID, Version: policy.version,
		Rules: ruleInputs(policy.rules), PublishedByMembershipID: policy.publishedByMembershipID, PublishedAt: policy.publishedAt,
	})
	return err == nil && restored.digest == policy.digest && restored.semanticDigest == policy.semanticDigest && sameRules(restored.rules, policy.rules)
}

type PolicyPlan struct {
	expectedVersion int64
	next            Policy
}

func (plan PolicyPlan) ExpectedVersion() int64 { return plan.expectedVersion }
func (plan PolicyPlan) Next() Policy           { return plan.next }

func PlanPolicyCreation(input PolicyInput) (PolicyPlan, error) {
	if input.Version != 1 {
		return PolicyPlan{}, ErrInvalidInput
	}
	next, err := NewPolicy(input)
	if err != nil {
		return PolicyPlan{}, err
	}
	return PolicyPlan{next: next}, nil
}

func PlanPolicyReplacement(current Policy, expectedVersion int64, input PolicyInput) (PolicyPlan, error) {
	if !validPolicy(current) || expectedVersion != current.version || current.version == MaximumPolicyVersion {
		return PolicyPlan{}, ErrConflict
	}
	if input.ID != current.id || input.TenantID != current.tenantID || input.Version != current.version+1 ||
		input.VersionID == current.versionID || input.PublishedAt.Before(current.publishedAt) {
		return PolicyPlan{}, ErrInvalidInput
	}
	next, err := NewPolicy(input)
	if err != nil {
		return PolicyPlan{}, err
	}
	if next.semanticDigest == current.semanticDigest {
		return PolicyPlan{}, ErrNoChange
	}
	return PolicyPlan{expectedVersion: expectedVersion, next: next}, nil
}

func canonicalRules(inputs []RuleInput) ([]Rule, error) {
	if len(inputs) > MaximumPolicyRules {
		return nil, ErrInvalidInput
	}
	rules := make([]Rule, 0, len(inputs))
	for _, input := range inputs {
		port := defaultRulePort(input.Port)
		hostname, ok := canonicalPolicyHostname(input.Hostname)
		if !validRuleEffect(input.Effect) || !validRuleMatch(input.Match) || !validRulePort(port) || !ok {
			return nil, ErrInvalidInput
		}
		rule := Rule{effect: input.Effect, match: input.Match, hostname: hostname, port: port}
		rule.digest = canonicalRuleDigest(rule)
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(left, right int) bool {
		return canonicalRuleRecord(rules[left]) < canonicalRuleRecord(rules[right])
	})
	for index := 1; index < len(rules); index++ {
		if canonicalRuleRecord(rules[index-1]) == canonicalRuleRecord(rules[index]) {
			return nil, ErrInvalidInput
		}
	}
	return rules, nil
}

func ruleInputs(rules []Rule) []RuleInput {
	result := make([]RuleInput, len(rules))
	for index, rule := range rules {
		result[index] = RuleInput{Effect: rule.effect, Match: rule.match, Hostname: rule.hostname, Port: rule.port}
	}
	return result
}

func framedDigest(parts ...string) [sha256.Size]byte {
	hash := sha256.New()
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validPolicyInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0 &&
		value.Year() >= 2000 && value.Year() <= 9999
}

func formatPolicyInstant(value time.Time) string {
	return value.Format("2006-01-02T15:04:05.000Z")
}

func validBoundedReason(value string) bool {
	if value == "" || len(value) > 2_048 || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e || value[index] == ',' {
			return false
		}
	}
	return true
}
