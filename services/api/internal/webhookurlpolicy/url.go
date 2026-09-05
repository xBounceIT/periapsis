package webhookurlpolicy

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

const maximumEndpointBytes = 2_048

type Endpoint struct {
	url      string
	hostname string
	port     int
	digest   [sha256.Size]byte
}

func (endpoint Endpoint) URL() string               { return endpoint.url }
func (endpoint Endpoint) Hostname() string          { return endpoint.hostname }
func (endpoint Endpoint) Port() int                 { return endpoint.port }
func (endpoint Endpoint) Digest() [sha256.Size]byte { return endpoint.digest }
func (Endpoint) String() string                     { return "webhookurlpolicy.Endpoint{redacted}" }
func (value Endpoint) GoString() string             { return value.String() }
func (endpoint Endpoint) valid() bool {
	restored, err := CanonicalEndpoint(endpoint.url)
	return err == nil && restored == endpoint
}
func sameEndpoint(left, right Endpoint) bool { return left == right && left.valid() && right.valid() }
func endpointDigest(url string) [sha256.Size]byte {
	return framedDigest("periapsis.webhook-endpoint.v1", url)
}
func endpointCanonicalPort(port int) string {
	if port == 443 {
		return ""
	}
	return ":" + strconv.Itoa(port)
}
func rawPathBeforeQuery(value string) string { path, _, _ := strings.Cut(value, "?"); return path }
func endpointSuffix(path, query string) string {
	if query == "" {
		return path
	}
	return path + "?" + query
}
func endpointAllowedSuffixByte(value byte) bool {
	return isASCIIAlphaNumeric(value) || strings.ContainsRune("-._~!$&'()*+,;=:@/?", rune(value))
}
func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
func canonicalEndpointAuthority(hostname string, port int) string {
	return hostname + endpointCanonicalPort(port)
}

func CanonicalEndpoint(input string) (Endpoint, error) {
	if input == "" || len(input) > maximumEndpointBytes || !safeText(input) ||
		!norm.NFC.IsNormalString(input) || strings.TrimSpace(input) != input ||
		strings.ContainsAny(input, "\\%#") {
		return Endpoint{}, ErrInvalidInput
	}
	separator := strings.Index(input, "://")
	if separator < 0 || !strings.EqualFold(input[:separator], "https") {
		return Endpoint{}, ErrInvalidInput
	}
	authorityStart := separator + 3
	authorityEnd := len(input)
	if offset := strings.IndexAny(input[authorityStart:], "/?#"); offset >= 0 {
		authorityEnd = authorityStart + offset
	}
	authority := input[authorityStart:authorityEnd]
	if authority == "" || strings.ContainsAny(authority, "@%[]") {
		return Endpoint{}, ErrInvalidInput
	}
	rawHostname, port, ok := splitEndpointAuthority(authority)
	if !ok {
		return Endpoint{}, ErrInvalidInput
	}
	hostname, ok := canonicalPolicyHostname(rawHostname)
	if !ok {
		return Endpoint{}, ErrInvalidInput
	}
	rawSuffix := input[authorityEnd:]
	path, query, hasQuery := strings.Cut(rawSuffix, "?")
	if path == "" {
		path = "/"
	}
	if path[0] != '/' || len(path) > 1_024 || len(query) > 1_024 ||
		!safeEndpointSuffix(path) || !safeEndpointSuffix(query) || hasDotPathSegment(rawPathBeforeQuery(rawSuffix)) {
		return Endpoint{}, ErrInvalidInput
	}
	suffix := path
	if hasQuery {
		suffix = endpointSuffix(path, query)
	}
	canonical := "https://" + canonicalEndpointAuthority(hostname, port) + suffix
	return Endpoint{url: canonical, hostname: hostname, port: port, digest: endpointDigest(canonical)}, nil
}

func canonicalPolicyHostname(input string) (string, bool) {
	if input == "" || len(input) > 253 || !safeText(input) || !norm.NFC.IsNormalString(input) ||
		strings.TrimSpace(input) != input || strings.ContainsAny(input, "%@[]/:\\*") || strings.HasSuffix(input, ".") {
		return "", false
	}
	hostname, err := idna.Lookup.ToASCII(input)
	if err != nil {
		return "", false
	}
	hostname = strings.ToLower(hostname)
	if hostname == "" || len(hostname) > 253 || strings.HasSuffix(hostname, ".") ||
		strings.HasSuffix(hostname, ".localhost") || looksLikeIPLiteral(hostname) {
		return "", false
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for index := range len(label) {
			if !isASCIIAlphaNumeric(label[index]) && label[index] != '-' {
				return "", false
			}
		}
	}
	return hostname, true
}

func splitEndpointAuthority(authority string) (string, int, bool) {
	if strings.Count(authority, ":") > 1 {
		return "", 0, false
	}
	hostname, rawPort, hasPort := strings.Cut(authority, ":")
	if !hasPort {
		return hostname, 443, true
	}
	if rawPort == "" || rawPort[0] == '0' || len(rawPort) > 5 {
		return "", 0, false
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65_535 || rawPort != strconv.Itoa(port) {
		return "", 0, false
	}
	return hostname, port, true
}

func safeEndpointSuffix(value string) bool {
	for index := range len(value) {
		if value[index] > unicode.MaxASCII || !endpointAllowedSuffixByte(value[index]) {
			return false
		}
	}
	return true
}

func hasDotPathSegment(path string) bool {
	return slices.ContainsFunc(strings.Split(path, "/"), func(segment string) bool {
		return segment == "." || segment == ".."
	})
}

func looksLikeIPLiteral(hostname string) bool {
	if address, err := netip.ParseAddr(hostname); err == nil && address.IsValid() {
		return true
	}
	labels := strings.Split(hostname, ".")
	return len(labels) > 0 && looksLikeIPv4Number(labels[len(labels)-1])
}

func looksLikeIPv4Number(label string) bool {
	if label == "" {
		return false
	}
	digits := label
	validDigit := func(character byte) bool { return character >= '0' && character <= '9' }
	if len(label) > 2 && (strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X")) {
		digits = label[2:]
		validDigit = func(character byte) bool {
			return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
		}
	}
	if digits == "" {
		return true
	}
	for index := range len(digits) {
		if !validDigit(digits[index]) {
			return false
		}
	}
	return true
}

func safeText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

type DecisionReason string

const (
	DecisionAllowedByRule DecisionReason = "allowed_by_rule"
	DecisionDeniedByRule  DecisionReason = "denied_by_rule"
	DecisionDefaultDeny   DecisionReason = "default_deny"
)

type DecisionEvidence struct {
	Allowed              bool
	Reason               DecisionReason
	PolicyID             uuid.UUID
	PolicyVersion        int64
	PolicyDigest         [sha256.Size]byte
	EndpointDigest       [sha256.Size]byte
	MatchedRuleDigest    [sha256.Size]byte
	HasMatchedRuleDigest bool
}

func (evidence DecisionEvidence) String() string {
	return fmt.Sprintf(
		"webhookurlpolicy.DecisionEvidence{allowed:%t,reason:%s,policy_version:%d,digests:[REDACTED]}",
		evidence.Allowed, evidence.Reason, evidence.PolicyVersion,
	)
}
func (evidence DecisionEvidence) GoString() string { return evidence.String() }

func Evaluate(policy Policy, endpoint Endpoint) (DecisionEvidence, error) {
	if !validPolicy(policy) || !endpoint.valid() {
		return DecisionEvidence{}, ErrInvalidInput
	}
	for _, effect := range []RuleEffect{RuleDeny, RuleAllow} {
		for _, rule := range policy.rules {
			if rule.effect == effect && ruleMatches(rule, endpoint) {
				return DecisionEvidence{
					Allowed: effect == RuleAllow, Reason: map[bool]DecisionReason{true: DecisionAllowedByRule, false: DecisionDeniedByRule}[effect == RuleAllow],
					PolicyID: policy.id, PolicyVersion: policy.version, PolicyDigest: policy.digest,
					EndpointDigest: endpoint.digest, MatchedRuleDigest: rule.digest, HasMatchedRuleDigest: true,
				}, nil
			}
		}
	}
	return DecisionEvidence{
		Allowed: false, Reason: DecisionDefaultDeny, PolicyID: policy.id, PolicyVersion: policy.version,
		PolicyDigest: policy.digest, EndpointDigest: endpoint.digest,
	}, nil
}

func ruleMatches(rule Rule, endpoint Endpoint) bool {
	if rule.port != endpoint.port {
		return false
	}
	if rule.match == RuleExact {
		return endpoint.hostname == rule.hostname
	}
	return endpoint.hostname != rule.hostname && strings.HasSuffix(endpoint.hostname, "."+rule.hostname)
}

type ConfigurationPin struct {
	configurationID      uuid.UUID
	configurationVersion int64
	tenantID             uuid.UUID
	endpoint             Endpoint
	policyID             uuid.UUID
	policyVersionID      uuid.UUID
	policyVersion        int64
	policyDigest         [sha256.Size]byte
	decision             DecisionEvidence
}

func (pin ConfigurationPin) ConfigurationID() uuid.UUID      { return pin.configurationID }
func (pin ConfigurationPin) ConfigurationVersion() int64     { return pin.configurationVersion }
func (pin ConfigurationPin) TenantID() uuid.UUID             { return pin.tenantID }
func (pin ConfigurationPin) Endpoint() Endpoint              { return pin.endpoint }
func (pin ConfigurationPin) PolicyID() uuid.UUID             { return pin.policyID }
func (pin ConfigurationPin) PolicyVersionID() uuid.UUID      { return pin.policyVersionID }
func (pin ConfigurationPin) PolicyVersion() int64            { return pin.policyVersion }
func (pin ConfigurationPin) PolicyDigest() [sha256.Size]byte { return pin.policyDigest }
func (pin ConfigurationPin) Decision() DecisionEvidence      { return pin.decision }
func (ConfigurationPin) String() string                      { return "webhookurlpolicy.ConfigurationPin{redacted}" }
func (value ConfigurationPin) GoString() string              { return value.String() }

func NewConfigurationPin(policy Policy, configurationID uuid.UUID, configurationVersion int64, tenantID uuid.UUID, endpointURL string) (ConfigurationPin, error) {
	endpoint, err := CanonicalEndpoint(endpointURL)
	if err != nil || !validPolicy(policy) || !validUUIDv7(configurationID) ||
		configurationVersion < 1 || configurationVersion > MaximumPolicyVersion || tenantID != policy.tenantID {
		return ConfigurationPin{}, ErrInvalidInput
	}
	decision, err := Evaluate(policy, endpoint)
	if err != nil || !decision.Allowed {
		return ConfigurationPin{}, ErrForbidden
	}
	return ConfigurationPin{
		configurationID: configurationID, configurationVersion: configurationVersion, tenantID: tenantID,
		endpoint: endpoint, policyID: policy.id, policyVersionID: policy.versionID,
		policyVersion: policy.version, policyDigest: policy.digest, decision: decision,
	}, nil
}

type DeliveryPin struct {
	deliveryID           uuid.UUID
	configurationID      uuid.UUID
	configurationVersion int64
	tenantID             uuid.UUID
	endpoint             Endpoint
	policyID             uuid.UUID
	policyVersionID      uuid.UUID
	policyVersion        int64
	policyDigest         [sha256.Size]byte
}

func (pin DeliveryPin) DeliveryID() uuid.UUID           { return pin.deliveryID }
func (pin DeliveryPin) ConfigurationID() uuid.UUID      { return pin.configurationID }
func (pin DeliveryPin) ConfigurationVersion() int64     { return pin.configurationVersion }
func (pin DeliveryPin) TenantID() uuid.UUID             { return pin.tenantID }
func (pin DeliveryPin) Endpoint() Endpoint              { return pin.endpoint }
func (pin DeliveryPin) PolicyID() uuid.UUID             { return pin.policyID }
func (pin DeliveryPin) PolicyVersionID() uuid.UUID      { return pin.policyVersionID }
func (pin DeliveryPin) PolicyVersion() int64            { return pin.policyVersion }
func (pin DeliveryPin) PolicyDigest() [sha256.Size]byte { return pin.policyDigest }
func (DeliveryPin) String() string                      { return "webhookurlpolicy.DeliveryPin{redacted}" }
func (value DeliveryPin) GoString() string              { return value.String() }

func NewDeliveryPin(configuration ConfigurationPin, deliveryID, configurationID uuid.UUID, configurationVersion int64, tenantID uuid.UUID, endpointURL string) (DeliveryPin, error) {
	endpoint, err := CanonicalEndpoint(endpointURL)
	if err != nil || !validUUIDv7(deliveryID) || configuration.configurationID != configurationID ||
		configuration.configurationVersion != configurationVersion || configuration.tenantID != tenantID ||
		!sameEndpoint(configuration.endpoint, endpoint) || !validConfigurationPin(configuration) {
		return DeliveryPin{}, ErrInvalidInput
	}
	return DeliveryPin{
		deliveryID: deliveryID, configurationID: configurationID, configurationVersion: configurationVersion,
		tenantID: tenantID, endpoint: endpoint, policyID: configuration.policyID,
		policyVersionID: configuration.policyVersionID, policyVersion: configuration.policyVersion,
		policyDigest: configuration.policyDigest,
	}, nil
}

func validConfigurationPin(pin ConfigurationPin) bool {
	return validUUIDv7(pin.configurationID) && pin.configurationVersion >= 1 &&
		pin.configurationVersion <= MaximumPolicyVersion && validUUIDv7(pin.tenantID) && pin.endpoint.valid() &&
		validUUIDv7(pin.policyID) && validUUIDv7(pin.policyVersionID) && pin.policyVersion >= 1 &&
		pin.policyVersion <= MaximumPolicyVersion && pin.policyDigest != [sha256.Size]byte{} &&
		pin.decision.Allowed && pin.decision.PolicyID == pin.policyID && pin.decision.PolicyVersion == pin.policyVersion &&
		pin.decision.PolicyDigest == pin.policyDigest && pin.decision.EndpointDigest == pin.endpoint.digest
}
